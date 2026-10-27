module BlueCurrent.Runtime where

import BlueCurrent.Types
import qualified BlueCurrent.Node as Node
import Control.Exception
import Control.Monad (unless, when)
import Data.Aeson
import Data.Aeson.Types (parseEither)
import qualified Data.ByteString.Lazy as B
import qualified Data.Text as T
import System.Directory
import System.Environment (lookupEnv)
import System.Exit
import System.FilePath
import System.IO
import System.Process
import System.Timeout (timeout)

data NodeProfile = NodeProfile
  { profileConfig :: Config, profileDaemon :: FilePath
  , profileStartNode :: Bool, profileNodeArgs :: [String]
  } deriving (Eq,Show)

-- Paths in a distribution profile are relative to that profile, never cwd.
loadNodeProfile :: FilePath -> IO NodeProfile
loadNodeProfile path = do
  absolute <- makeAbsolute path
  bytes <- B.readFile absolute
  value <- either fail pure (eitherDecode bytes)
  (name,cli,daemon,chain,folder,port,wallet,start,args,binding) <- either fail pure $ parseEither
    (withObject "node profile" $ \o -> do
      schema <- o .: "schema"
      unless (schema == ("elements-blue-current-node-v1" :: T.Text)) (fail "Unsupported node profile")
      (,,,,,,,,,) <$> o .: "name" <*> o .: "cli" <*> o .: "daemon" <*> o .: "chain"
        <*> o .:? "datadir" <*> o .:? "rpcport" <*> o .: "wallet"
        <*> o .: "startNode" <*> o .:? "nodeArgs" .!= [] <*> o .: "identity") value
  let resolve p=normalise (if isAbsolute p then p else takeDirectory absolute </> p)
      b=binding {bindingName=name}
  when (bindingTarget b=="btc-ecx-mainnet" && chain/="elements") (fail "The production profile must use the Elements chain")
  when (bindingReady b) $ do
    either (fail . T.unpack) pure (Node.validateBinding b)
    unless (maybe False isAbsolute folder && maybe False (\n -> n>0 && n<65536) (port :: Maybe Int))
      (fail "A ready node profile needs an absolute data folder and a valid RPC port")
  unless (all safeArg args) (fail "Node profile overrides a launcher-owned argument or contains credentials")
  let config=Config (resolve cli) Nothing chain folder (show <$> port) wallet Nothing (Just b)
  pure (NodeProfile config (resolve daemon) start args)
  where
    safeArg arg = take 1 arg=="-" && not (take 2 arg=="--") && not (any (`isPrefix` arg) ["-daemon","-chain","-datadir","-rpcport","-rpcbind","-rpcallowip","-rpcpassword","-rpcuser","-mainchainrpcpassword","-mainchainrpcuser","-pid"])
      && not (any (`elem` ['\n','\r','\0']) arg)
    isPrefix prefix arg = take (length prefix) arg == prefix

findNodeProfile :: FilePath -> IO (Maybe FilePath)
findNodeProfile executable = do
  selected <- lookupEnv "BLUE_CURRENT_NODE_PROFILE"
  case selected of
    Just path -> pure (Just path)
    Nothing -> firstExisting [takeDirectory executable </> "../Resources/node-profile.json",
                             takeDirectory executable </> "../share/elements-blue-current/node-profile.json"]
  where
    firstExisting []=pure Nothing
    firstExisting (path:rest)=doesFileExist path >>= \yes -> if yes then pure (Just path) else firstExisting rest

-- Attach to existing nodes without taking ownership. A node started by this
-- process is kept in the foreground and stopped gracefully when the UI exits.
withNodeSession :: Maybe NodeProfile -> (Maybe T.Text -> IO a) -> IO a
withNodeSession Nothing action=action Nothing
withNodeSession (Just profile) action = case cfgBinding config >>= either Just (const Nothing) . Node.validateBinding of
  Just err -> action (Just err)
  Nothing -> do
    acquired <- try acquire
    case acquired of
      Left (err :: SomeException) -> action (Just (T.pack (displayException err)))
      Right Nothing -> action Nothing
      Right (Just process) -> action Nothing `finally` stopOwned process
  where
    config=profileConfig profile
    acquire
      | not (profileStartNode profile) = pure Nothing
      | otherwise = do
          cliExists <- doesFileExist (cfgElementsCli config)
          unless cliExists (fail "The bundled Elements command-line helper is missing")
          response <- timeout 3000000 (try (Node.runCliUnchecked config [] "getblockchaininfo" []) :: IO (Either IOException CliResult))
          let attach=case response of
                Nothing -> True -- slow/unavailable authentication is not permission to start another daemon
                Just (Right r) -> resultExit r==ExitSuccess || not (any (`T.isInfixOf` T.toLower (T.pack (resultStderr r))) ["could not connect","connection refused","couldn't connect"])
                Just (Left _) -> False
          if attach then pure Nothing else do
            folder <- maybe (fail "Node data folder missing") pure (cfgDataDir config)
            port <- maybe (fail "Node RPC port missing") pure (cfgRpcPort config)
            createDirectoryIfMissing True folder
            exists <- doesFileExist (profileDaemon profile)
            unless exists (fail "The bundled Elements daemon is missing")
            handle <- openFile (folder </> "blue-current-node-console.log") AppendMode
            let args=["-chain="<>cfgChain config,"-datadir="<>folder,"-rpcport="<>port,
                      "-server=1","-daemon=0","-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1",
                      "-pid="<>(folder </> "blue-current-node.pid")] <> profileNodeArgs profile
            (_,_,_,process) <- createProcess (proc (profileDaemon profile) args)
              {std_in=NoStream,std_out=UseHandle handle,std_err=UseHandle handle,create_group=True}
              `finally` hClose handle
            pure (Just process)
    stopOwned process = do
      status <- getProcessExitCode process
      when (status==Nothing) $ do
        -- Only use this session's data-folder cookie; never touch an attached service.
        _ <- timeout 10000000 (try (Node.runCliUnchecked config [] "stop" []) :: IO (Either IOException CliResult))
        stopped <- timeout 20000000 (waitForProcess process)
        when (stopped==Nothing) (terminateProcess process >> waitForProcess process >> pure ())
