module Main where
import BlueCurrent.Model
import BlueCurrent.Backend
import qualified BlueCurrent.Types as Legacy
import Data.Aeson
import qualified Data.Aeson.Types
import qualified Data.Text as T
import Control.Monad (unless)
import System.Environment
import System.FilePath
import System.Directory
import Data.Time.Clock.POSIX (getPOSIXTime)

main :: IO ()
main = do
  setting <- lookupEnv "BLUE_CURRENT_TEST_ROOT"
  case setting of
    Nothing -> putStrLn "SKIP: set BLUE_CURRENT_TEST_ROOT to the isolated Elements test installation."
    Just root -> do
      cli <- maybe (root </> "node/elements-23.3.4/bin/elements-cli") id <$> lookupEnv "BLUE_CURRENT_TEST_CLI"
      datadir <- maybe (root </> "regtest-funded") id <$> lookupEnv "BLUE_CURRENT_TEST_DATADIR"
      port <- maybe "29878" id <$> lookupEnv "BLUE_CURRENT_TEST_PORT"
      let cfg=Legacy.Config cli Nothing "elementsregtest" (Just datadir) (Just port) "ui-test" Nothing Nothing
          mode=Live cfg
          right action=action >>= either (fail.T.unpack) pure
      chain <- rpc cfg False "getblockchaininfo" []
      network <- required "chain" chain
      unless (network == ("elementsregtest" :: T.Text)) (fail "Refusing to test outside regtest")
      suffix <- T.pack . show . (round :: RealFrac a => a -> Integer) <$> getPOSIXTime
      recipientWallet <- right (openWallet mode ("recipient-"<>suffix) True)
      recipient <- right (newAddress mode recipientWallet 1)
      _ <- right (newAddress mode "ui-test" 2)
      snapshot <- right (fetchSnapshot mode "ui-test")
      unless (snapshotAvailable snapshot > 1000000) (fail "Test wallet is not funded")
      let draft=Payment recipient 1000000 "1" "ui-test" Nothing Nothing Nothing
      review <- right (checkRecipient mode draft)
      unless (maybe False (>0) (paymentFee review) && paymentHex review/=Nothing) (fail "Review did not contain exact fee and signed transaction")
      txid <- right (sendReviewed mode review)
      repeated <- right (sendReviewed mode review)
      unless (txid==repeated) (fail "Retry changed transaction")
      transaction <- rpc cfg True "gettransaction" [T.unpack txid]
      actualFee <- required "fee" transaction :: IO Value
      paid <- either fail pure (Data.Aeson.Types.parseEither assetSats actualFee)
      unless (Just (abs paid)==paymentFee review) (fail "Reviewed fee differs from actual fee")
      pending<-right (fetchSnapshot mode recipientWallet)
      unless (snapshotPending pending==1000000 && any (\row -> activityId row==txid && activityConfirmations row==0) (snapshotActivity pending)) (fail "Pending receipt or activity missing")
      address <- right (newAddress mode "ui-test" 3)
      _ <- rpc cfg False "generatetoaddress" ["1",T.unpack address]
      received <- right (fetchSnapshot mode recipientWallet)
      unless (any (\row -> activityId row==txid && activityConfirmations row>0) (snapshotActivity received)) (fail "Confirmed receipt missing from activity")
      unless (snapshotAvailable received==1000000) (fail "Recipient was not credited")
      let path=root </> "wallet-backup.dat"
      exists<-doesFileExist path
      if exists then removeFile path else pure ()
      _ <- right (backupWallet mode "ui-test" (T.pack path))
      existsNow<-doesFileExist path
      unless existsNow (fail "Backup missing")
      _ <- right (restoreWallet mode ("recovered-"<>suffix) (T.pack path))
      recovered<-right (fetchSnapshot mode ("recovered-"<>suffix))
      unless (snapshotAvailable recovered>0) (fail "Recovered wallet has no balance")
      putStrLn "PASS: real-node address generation, exact fee review, signed broadcast, idempotent retry, confirmation, recipient balance, backup and recovery."
