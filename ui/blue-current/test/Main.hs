module Main where

import BlueCurrent.Model
import BlueCurrent.Backend
import BlueCurrent.QR
import qualified BlueCurrent.Node as Node
import BlueCurrent.Runtime
import BlueCurrent.Types
import System.Environment (setEnv)
import System.Directory
import System.FilePath
import Data.Time.Clock.POSIX
import Control.Monad (unless)
import Control.Exception (try, SomeException)
import Data.Aeson (Value, eitherDecodeStrict')
import qualified Data.Aeson
import Data.Aeson.Types (parseEither)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Either (isLeft)
import qualified Data.Text as T
import System.Exit (exitFailure, ExitCode(..))

check :: String -> Bool -> IO ()
check label result = unless result (putStrLn ("FAIL: " <> label) >> exitFailure)

json :: String -> Value
json source = either error id (eitherDecodeStrict' (BSC.pack source))

main :: IO ()
main = do
  check "one satoshi stays exact" (parseAmount "0.00000001" == Right 1)
  check "large amounts stay exact" (parseAmount "123456789.12345678" == Right 12345678912345678)
  mapM_ (\amount -> check ("reject invalid amount " <> T.unpack amount) (isLeft (parseAmount amount)))
    ["0", "-1", "+1", "1e3", "NaN", "1.000000001", "1.", "1..1", ".1", "１２", "1 2"]
  mapM_ (\amount -> check "amount round trip" (parseAmount (formatAmount amount) == Right amount)) [1, 99, 100000000, 12345678912345678]
  check "exact fee rate" (parseFeeRate "1.125" == Right 1125)
  check "reject fee exponent" (isLeft (parseFeeRate "1e2"))
  check "reject zero fee" (isLeft (parseFeeRate "0"))
  let loaded = (initialModel Demo "Everyday wallet") {modelSnapshot = Just demoSnapshot
        , modelRecipient = "demo-recipient-address", modelAmount = "0.01"}
  payment <- either (fail . T.unpack) pure (validatePayment loaded)
  let reviewed = loaded {modelReviewed = Just payment, modelPane = ReviewPane}
  check "valid review can confirm" (canConfirm reviewed)
  check "busy submission cannot confirm twice" (not (canConfirm reviewed {modelBusy = True}))
  check "review cannot follow wallet switch" (not (canConfirm reviewed {modelWallet = "Savings wallet"}))
  check "send requires review pane" (not (canConfirm reviewed {modelPane = SendPane}))
  check "insufficient funds rejected" (isLeft (validatePayment loaded {modelAmount = "0.2"}))
  check "unloaded wallet rejected" (isLeft (validatePayment loaded {modelSnapshot = Nothing}))
  let perAsset = json "{\"mine\":{\"trusted\":{\"bitcoin\":0.10000001,\"other\":999},\"untrusted_pending\":{\"bitcoin\":0.002}}}"
  check "only bitcoin balance included" (parseEither parseBalances perAsset == Right (10000001,200000))
  check "numeric balance accepted" (parseEither parseBalances (json "{\"mine\":{\"trusted\":1,\"untrusted_pending\":0}}") == Right (100000000,0))
  check "unknown asset never becomes L-ECX" (isLeft (parseEither assetSats (json "{\"other\":999}")))
  check "sub-satoshi node amount rejected" (isLeft (parseEither assetSats (json "0.000000001")))
  check "negative balance rejected" (isLeft (parseEither parseBalances (json "{\"mine\":{\"trusted\":-1,\"untrusted_pending\":0}}")))
  let txs = json "[{\"category\":\"receive\",\"amount\":1,\"assetlabel\":\"other\",\"txid\":\"other\"},{\"category\":\"receive\",\"amount\":0.01,\"assetlabel\":\"bitcoin\",\"txid\":\"btc\",\"confirmations\":0}]"
  check "activity filters other assets" (map activityId (parseTransactions txs) == ["btc"])
  check "unlabeled activity excluded" (null (parseTransactions (json "[{\"category\":\"receive\",\"amount\":1,\"txid\":\"unknown\"}]")))
  let identified=json "[{\"category\":\"receive\",\"amount\":0.006,\"asset\":\"btc-id\",\"txid\":\"combined\"},{\"category\":\"receive\",\"amount\":0.004,\"asset\":\"btc-id\",\"txid\":\"combined\"},{\"category\":\"send\",\"amount\":99,\"asset\":\"other\",\"assetlabel\":\"bitcoin\",\"txid\":\"wrong\"}]"
  check "real-node asset IDs and grouped outputs" (map activitySats (parseTransactionsForAsset (Just "btc-id") identified)==[1000000])
  check "malformed response rejected" (isLeft (parseEither parseBalances (json "{}")))
  check "confirmed retry matches exact transaction" (confirmedPayment "tx" (json "{\"txid\":\"tx\",\"confirmations\":1}"))
  mapM_ (\value -> check "wallet history alone is not submission success" (not (confirmedPayment "tx" (json value))))
    ["null", "{}", "{\"txid\":\"tx\",\"confirmations\":0}",
     "{\"txid\":\"tx\",\"confirmations\":-1}", "{\"txid\":\"other\",\"confirmations\":5}"]
  case qrPixels "ELEMENTS-DEMO-NOT-A-PAYMENT-ADDRESS" of
    Nothing -> fail "QR encoding failed"
    Just (side, pixels) -> do
      check "QR has exact RGBA dimensions" (BS.length pixels == side * side * 4)
      check "QR quiet zone is white" (BS.all (==255) (BS.take (side * 4 * 16) pixels))
      check "QR contains black modules" (BS.elem 0 pixels)
  demoSend <- sendReviewed Demo payment
  check "demo cannot move funds" (demoSend == Right "demo-payment-complete-no-funds-moved")
  temporary <- getTemporaryDirectory
  stamp <- show . (round :: RealFrac a => a -> Integer) <$> getPOSIXTime
  let profile=temporary </> ("blue-current-settings-test-"<>stamp)
      config=Config "/node path/elements-cli" Nothing "elementsregtest" (Just "/node data") (Just "29878") "wallet with spaces" Nothing Nothing
  setEnv "BLUE_CURRENT_PROFILE_DIR" profile
  Node.saveConfig config
  loadedConfig<-Node.loadConfig
  check "connection and selected wallet survive restart" (loadedConfig==Just config)
  Node.saveDemo "Savings wallet"
  loadedDemo<-Node.loadDemo
  check "demo wallet survives restart" (loadedDemo==Just "Savings wallet")
  clearedLive<-Node.loadConfig
  check "switching to demo removes automatic live connection" (clearedLive==Nothing)
  let binding=NetworkBinding "Production" "btc-ecx-mainnet" True (Just (T.replicate 64 "1")) (Just (T.replicate 64 "2")) (Just Node.bitcoinGenesis) (Just 973728)
  check "complete production identity accepted" (Node.validateBinding binding==Right ())
  check "unfinished production identity refused" (isLeft (Node.validateBinding binding {bindingReady=False}))
  check "wrong BTC fork height refused" (isLeft (Node.validateBinding binding {bindingParentForkHeight=Just 973729}))
  check "old Betanet refused as production" (isLeft (Node.validateBinding binding {bindingGenesis=Just "a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f"}))
  Node.saveConfig config {cfgBinding=Just binding}
  bound<-Node.loadConfig
  check "network binding survives restart" (fmap cfgBinding bound==Just (Just binding))
  let nodeProfile=profile </> "node-profile.json"
      profileJSON args=Data.Aeson.object ["schema" Data.Aeson..= ("elements-blue-current-node-v1"::T.Text),"name" Data.Aeson..= ("Production"::T.Text),"cli" Data.Aeson..= ("bin/elements-cli"::T.Text),"daemon" Data.Aeson..= ("bin/elementsd"::T.Text),"chain" Data.Aeson..= ("elements"::T.Text),"datadir" Data.Aeson..= profile,"rpcport" Data.Aeson..= (29878::Int),"wallet" Data.Aeson..= ("wallet with spaces"::T.Text),"startNode" Data.Aeson..= False,"nodeArgs" Data.Aeson..= (args::[String]),"identity" Data.Aeson..= binding]
  Data.Aeson.encodeFile nodeProfile (profileJSON [])
  loadedProfile<-loadNodeProfile nodeProfile
  check "profile paths resolve against profile folder" (cfgElementsCli (profileConfig loadedProfile)==normalise (profile </> "bin/elements-cli"))
  check "Bitwindow attached session does not take node ownership" (not (profileStartNode loadedProfile))
  Data.Aeson.encodeFile nodeProfile (profileJSON ["-rpcpassword=secret"])
  invalid<-try (loadNodeProfile nodeProfile)::IO (Either SomeException NodeProfile)
  check "profile cannot inject credentials or override setup" (isLeft invalid)
  removeDirectoryRecursive profile
  check "live confirmation requires exact signed quote" (not (canConfirm reviewed {modelMode=Live config}))
  check "CLI plain string recognized" (resultValue (CliResult ExitSuccess "el1-test-address\n" "")==Right (Data.Aeson.String "el1-test-address"))
  check "CLI empty success is null" (resultValue (CliResult ExitSuccess "" "")==Right Data.Aeson.Null)
  check "malformed CLI JSON is rejected" (isLeft (resultValue (CliResult ExitSuccess "{broken" "")))
  putStrLn "PASS: exact amounts, asset isolation, review guards, malformed data, QR, and demo submission."
