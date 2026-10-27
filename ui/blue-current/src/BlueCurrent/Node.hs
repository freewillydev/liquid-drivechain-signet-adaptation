module BlueCurrent.Node where

import BlueCurrent.Types
import Control.Monad (unless)
import Control.Exception (IOException, catch, finally, onException)
import System.IO (openBinaryTempFile, hClose)
import Data.Aeson
import Data.Aeson.Types (parseMaybe)
import Data.Text (Text)
import qualified Data.Text.Encoding
import qualified System.Exit
import qualified Data.Text as T
import qualified Data.ByteString.Lazy as B
import Data.Maybe (fromMaybe)
import System.Directory
import System.Environment (lookupEnv)
import System.FilePath
import System.Process

-- Arguments are passed directly to the CLI; no shell or password storage.
defaultConfig :: IO Config
defaultConfig = do
  cli <- fromMaybe "elements-cli" <$> lookupEnv "ELEMENTS_CLI"
  pure (Config cli Nothing "elements" Nothing Nothing "default" Nothing Nothing)

parseArgs :: Config -> [String] -> Either String Config
parseArgs c [] = Right c
parseArgs c (flag:value:rest) = case flag of
  "--elements-cli" -> parseArgs c {cfgElementsCli=value} rest
  "--chain" -> parseArgs c {cfgChain=value} rest
  "--datadir" -> parseArgs c {cfgDataDir=Just value} rest
  "--rpcport" -> parseArgs c {cfgRpcPort=Just value} rest
  "--wallet" -> parseArgs c {cfgWallet=value} rest
  _ -> Left ("Unknown option: "<>flag)
parseArgs _ _ = Left "Each connection option needs a value."

runCli :: Config -> [String] -> String -> [String] -> IO CliResult
runCli c extra method args = do
  verifyBinding c
  runCliUnchecked c extra method args

runCliUnchecked :: Config -> [String] -> String -> [String] -> IO CliResult
runCliUnchecked c extra method args = do
  unless (maybe False (not.null) (cfgDataDir c) && maybe False (not.null) (cfgRpcPort c))
    (ioError (userError "Choose an explicit node data folder and RPC port."))
  (code,out,err) <- readProcessWithExitCode (cfgElementsCli c)
    (["-chain="<>cfgChain c] <> maybe [] (\x->["-datadir="<>x]) (cfgDataDir c)
    <> maybe [] (\x->["-rpcport="<>x]) (cfgRpcPort c) <> extra <> [method] <> args) ""
  pure (CliResult code out err)

-- Check the selected chain before every operation, including signing/broadcast.
-- A port or the generic chain name "elements" is not a network identity.
verifyBinding :: Config -> IO ()
verifyBinding c = case cfgBinding c of
  Nothing -> pure ()
  Just binding -> do
    either (ioError . userError . T.unpack) pure (validateBinding binding)
    genesisResult <- runCliUnchecked c [] "getblockhash" ["0"]
    genesis <- cliText genesisResult
    unless (Just genesis == bindingGenesis binding) (ioError (userError "This node belongs to a different Elements network. Check the selected node profile."))
    result <- runCliUnchecked c [] "getsidechaininfo" []
    value <- cliJson result
    let asset = parseMaybe (withObject "sidechain" (.: "pegged_asset")) value :: Maybe Text
        parent = parseMaybe (withObject "sidechain" (.: "parent_blockhash")) value :: Maybe Text
    unless (asset == bindingAsset binding) (ioError (userError "The node's native asset does not match this wallet's network profile."))
    unless (parent == bindingParentGenesis binding) (ioError (userError "The Elements node is anchored to a different parent chain."))

cliText :: CliResult -> IO Text
cliText result = do
  ensureSuccess result
  let text=T.strip (T.pack (resultStdout result))
  pure $ case decode (B.fromStrict (Data.Text.Encoding.encodeUtf8 text)) of Just (String s)->s;_ -> text

cliJson :: CliResult -> IO Value
cliJson result = do
  ensureSuccess result
  either (ioError . userError) pure (eitherDecode (B.fromStrict (Data.Text.Encoding.encodeUtf8 (T.pack (resultStdout result)))))

ensureSuccess :: CliResult -> IO ()
ensureSuccess result = unless (resultExit result == System.Exit.ExitSuccess)
  (ioError (userError (resultStderr result)))

validateBinding :: NetworkBinding -> Either Text ()
validateBinding b
  | not (bindingReady b) && bindingTarget b=="bitwindow-setup" = Left "Open this wallet from Bitwindow to finish setting up its node."
  | not (bindingReady b) = Left "The Elements sidechain setup for the BTC to ECX fork at block 973,728 is not finalized. Its production genesis and native asset must be bound before this wallet can connect."
  | not (all validHash [bindingGenesis b,bindingAsset b,bindingParentGenesis b]) = Left "The node profile needs complete genesis, native-asset and parent-chain hashes."
  | bindingTarget b == "btc-ecx-mainnet" &&
      (bindingParentGenesis b /= Just bitcoinGenesis || bindingParentForkHeight b /= Just 973728) = Left "This profile does not describe the BTC to ECX fork at block 973,728."
  | bindingTarget b == "btc-ecx-mainnet" && bindingGenesis b `elem` map Just historicalChildren = Left "An old Alpha or Betanet sidechain cannot be used as the BTC to ECX production sidechain."
  | otherwise = Right ()
  where
    validHash=maybe False (\s -> T.length s==64 && T.all (`elem` (['0'..'9']<>['a'..'f'])) s && T.any (/='0') s)
    historicalChildren=["672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd","a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f"]

bitcoinGenesis :: Text
bitcoinGenesis="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

instance ToJSON NetworkBinding where
  toJSON b=object ["name" .= bindingName b,"target" .= bindingTarget b,"ready" .= bindingReady b,
    "genesis" .= bindingGenesis b,"asset" .= bindingAsset b,"parentGenesis" .= bindingParentGenesis b,"parentForkHeight" .= bindingParentForkHeight b]
instance FromJSON NetworkBinding where
  parseJSON=withObject "network binding" $ \o -> NetworkBinding <$> o .: "name" <*> o .: "target" <*> o .: "ready"
    <*> o .:? "genesis" <*> o .:? "asset" <*> o .:? "parentGenesis" <*> o .:? "parentForkHeight"
runWalletCli :: Config -> String -> [String] -> IO CliResult
runWalletCli c = runCli c ["-rpcwallet="<>cfgWallet c]

settingsFile :: IO FilePath
settingsFile = do
  profile <- lookupEnv "BLUE_CURRENT_PROFILE_DIR"
  directory <- maybe (getXdgDirectory XdgConfig "elements-blue-current") pure profile
  pure (directory </> "settings.json")

writeSettings :: Value -> IO ()
writeSettings value = do
  path <- settingsFile
  createDirectoryIfMissing True (takeDirectory path)
  (temporary, handle) <- openBinaryTempFile (takeDirectory path) "settings.json.tmp"
  let write = (B.hPut handle (encode value) `finally` hClose handle) >> renameFile temporary path
  write `onException` (removeFile temporary `catch` (\(_ :: IOException) -> pure ()))

saveConfig :: Config -> IO ()
saveConfig c = writeSettings (object ["cli" .= cfgElementsCli c,"chain" .= cfgChain c,
    "datadir" .= cfgDataDir c,"port" .= cfgRpcPort c,"wallet" .= cfgWallet c,"binding" .= cfgBinding c])

loadConfig :: IO (Maybe Config)
loadConfig = do
  path <- settingsFile
  exists <- doesFileExist path
  if not exists then pure Nothing else do
    raw <- B.readFile path
    pure $ decode raw >>= parseMaybe (withObject "settings" (\o ->
      Config <$> o .: "cli" <*> pure Nothing <*> o .: "chain" <*> o .: "datadir"
        <*> o .: "port" <*> o .: "wallet" <*> pure Nothing <*> o .:? "binding"))

saveDemo :: Text -> IO ()
saveDemo wallet = writeSettings (object ["demoWallet" .= wallet])

loadDemo :: IO (Maybe Text)
loadDemo = do
  path <- settingsFile
  exists <- doesFileExist path
  if not exists then pure Nothing else do
    raw <- B.readFile path
    pure $ decode raw >>= parseMaybe (withObject "settings" (.: "demoWallet"))
