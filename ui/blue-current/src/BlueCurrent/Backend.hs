module BlueCurrent.Backend where

import BlueCurrent.Model
import Control.Exception (SomeException, displayException, try)
import Data.Aeson
import Data.Aeson.Types (Parser, parseEither, parseMaybe)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Lazy as BL
import qualified Data.Aeson.Key as Key
import Data.List (nub, foldl')
import Data.Maybe (mapMaybe, fromMaybe)
import Data.Scientific (Scientific, floatingOrInteger)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import qualified BlueCurrent.Types as Legacy
import qualified BlueCurrent.Node as Core
import System.Exit (ExitCode(..))
import System.Timeout (timeout)

-- Exceptions and timeouts become visible UI errors; they never look like success.
guardIO :: IO a -> IO (Either Text a)
guardIO operation = do
  outcome <- try (timeout 30000000 operation)
  pure $ case outcome of
    Left (err :: SomeException) -> Left (cleanErrorText (T.pack (displayException err)))
    Right Nothing -> Left "The node took too long to respond. Refresh to check its state."
    Right (Just value) -> Right value

resultValue :: Legacy.CliResult -> Either Text Value
resultValue result = case Legacy.resultExit result of
  ExitFailure code -> let detail=cleanErrorText (T.pack (Legacy.resultStderr result)) in
    Left (if T.null detail then "The node command failed (exit " <> T.pack (show code) <> ")." else T.take 700 detail)
  ExitSuccess -> let output = T.strip (T.pack (Legacy.resultStdout result)) in
    if T.null output then Right Null else case eitherDecodeStrict' (TE.encodeUtf8 output) of
      Right value -> Right value
      Left err | T.take 1 output `elem` ["{", "["] -> Left (T.pack err)
               | otherwise -> Right (String output)

rpc :: Legacy.Config -> Bool -> Text -> [String] -> IO Value
rpc config wallet method args = do
  result <- if wallet then Core.runWalletCli config (T.unpack method) args
                      else Core.runCli config [] (T.unpack method) args
  either (ioError . userError . T.unpack) pure (resultValue result)

fetchSnapshot :: Mode -> Text -> IO (Either Text Snapshot)
fetchSnapshot Demo wallet = pure (Right demoSnapshot {snapshotWallets = nub (wallet : snapshotWallets demoSnapshot)})
fetchSnapshot (Live config) wallet = guardIO $ do
  let cfg = config {Legacy.cfgWallet = T.unpack wallet}
  chain <- rpc cfg False "getblockchaininfo" []
  labels <- rpc cfg False "dumpassetlabels" []
  asset <- required "bitcoin" labels :: IO Text
  balances <- rpc cfg True "getbalances" []
  let parsed = parseEither parseBalances balances
  (available, pending) <- either (ioError . userError) pure parsed
  walletsValue <- rpc cfg False "listwallets" []
  let wallets = fromMaybe [] (parseMaybe parseJSON walletsValue :: Maybe [Text])
  txs <- guardIO (rpc cfg True "listtransactions" ["*", "30", "0", "true"])
  let network = maybe (maybe "Elements" id (parseMaybe (withObject "chain" (.: "chain")) chain)) Legacy.bindingName (Legacy.cfgBinding cfg)
      transactions = either (const []) (parseTransactionsForAsset (Just asset)) txs
      warning = either (Just . ("Activity unavailable: " <>)) (const Nothing) txs
  pure $ Snapshot available pending transactions
    (nub (wallet : wallets)) network warning

-- Elements may return numeric balances or per-asset maps. Never sum other assets.
assetSats :: Value -> Parser Integer
assetSats (Object assets) = maybe (fail "The L-ECX balance is absent.") assetSats (KM.lookup "bitcoin" assets)
assetSats (Number value) = exactSats value
assetSats _ = fail "Unexpected balance format."

exactSats :: Scientific -> Parser Integer
exactSats value = case floatingOrInteger (value * 100000000) :: Either Double Integer of
  Right sats -> pure sats
  Left _ -> fail "The node returned an amount below one satoshi."

parseBalances :: Value -> Parser (Integer, Integer)
parseBalances = withObject "balances" $ \root -> do
  mine <- root .: "mine"
  withObject "mine" (\o -> do
    available <- o .: "trusted" >>= assetSats
    pending <- o .: "untrusted_pending" >>= assetSats
    if available < 0 || pending < 0 then fail "Negative wallet balance." else pure (available, pending)) mine

parseTransactions :: Value -> [Activity]
parseTransactions = parseTransactionsForAsset Nothing

parseTransactionsForAsset :: Maybe Text -> Value -> [Activity]
parseTransactionsForAsset asset (Array values) = take 8 $ foldl' combine [] $ reverse $
  mapMaybe (parseMaybe (parseActivityForAsset asset)) (foldr (:) [] values)
  where
    combine rows item = case break (\row -> activityId row==activityId item && activityDirection row==activityDirection item) rows of
      (_,[]) -> rows <> [item]
      (before,existing:after) -> before <> [existing {activitySats=activitySats existing+activitySats item}] <> after
parseTransactionsForAsset _ _ = []

parseActivity :: Value -> Parser Activity
parseActivity = parseActivityForAsset Nothing

parseActivityForAsset :: Maybe Text -> Value -> Parser Activity
parseActivityForAsset knownAsset = withObject "transaction" $ \o -> do
  category <- o .: "category" :: Parser Text
  if category `notElem` ["send", "receive"] then fail "Not a wallet payment." else pure ()
  label <- o .:? "assetlabel" :: Parser (Maybe Text)
  asset <- o .:? "asset" :: Parser (Maybe Text)
  let matches = case (knownAsset,asset) of
        (Just expected,Just actual) -> expected==actual
        _ -> label==Just "bitcoin"
  if matches then pure () else fail "Not a verified L-ECX payment."
  amount <- o .: "amount" >>= assetSats
  confirmations <- o .:? "confirmations" .!= 0
  txid <- o .: "txid"
  seconds <- o .:? "time" .!= 0
  let stamp = if seconds == (0 :: Integer) then "Time unavailable"
              else T.pack (formatTime defaultTimeLocale "%b %e · %H:%M UTC" (posixSecondsToUTCTime (fromInteger seconds)))
  pure $ Activity txid (if category == "send" then Outgoing else Incoming) (abs amount) confirmations stamp

newAddress :: Mode -> Text -> Int -> IO (Either Text Text)
newAddress Demo _ request = pure (Right ("ELEMENTS-DEMO-NOT-A-PAYMENT-ADDRESS-" <> T.pack (show request)))
newAddress (Live config) wallet _ = guardIO $ do
  value <- rpc (config {Legacy.cfgWallet = T.unpack wallet}) True "getnewaddress" []
  case value of String address | not (T.null address) -> pure address
                _ -> ioError (userError "The node did not return an address.")

jsonArg :: Value -> String
jsonArg = T.unpack . TE.decodeUtf8 . BL.toStrict . encode

required :: FromJSON a => Text -> Value -> IO a
required key value = maybe (ioError (userError ("Missing node result: " <> T.unpack key))) pure
  (parseMaybe (withObject "result" (.: Key.fromText key)) value)

checkRecipient :: Mode -> Payment -> IO (Either Text Payment)
checkRecipient Demo payment = pure (Right payment {paymentFee=Just 210})
checkRecipient (Live config) payment = guardIO $ do
  result <- rpc config False "validateaddress" [T.unpack (paymentRecipient payment)]
  valid <- required "isvalid" result
  if valid then pure () else ioError (userError "The recipient is not valid for this node.")
  labels <- rpc config False "dumpassetlabels" []
  asset <- required "bitcoin" labels :: IO Text
  let cfg = config {Legacy.cfgWallet = T.unpack (paymentWallet payment)}
      outputs = toJSON [object [Key.fromText (paymentRecipient payment) .= paymentAmount, "asset" .= asset]]
      paymentAmount = Number (fromInteger (paymentSats payment) / 100000000)
      options = object ["fee_rate" .= paymentFeeRate payment, "lockUnspents" .= False]
  funded <- rpc cfg True "walletcreatefundedpsbt" ["[]",jsonArg outputs,"0",jsonArg options]
  feeValue <- required "fee" funded :: IO Value
  fee <- either (ioError . userError) pure (parseEither assetSats feeValue)
  psbt <- required "psbt" funded
  processed <- rpc cfg True "walletprocesspsbt" [psbt]
  signed <- required "psbt" processed
  finalized <- rpc cfg True "finalizepsbt" [signed]
  complete <- required "complete" finalized
  if complete then pure () else ioError (userError "This wallet cannot completely sign the payment. Unlock it with your node before reviewing again.")
  raw <- required "hex" finalized
  decoded <- rpc cfg False "decoderawtransaction" [raw]
  txid <- required "txid" decoded
  pure payment {paymentFee=Just fee,paymentHex=Just (T.pack raw),paymentTxid=Just txid}

-- Broadcast exactly the reviewed bytes. Repeating this request cannot create a second payment.
sendReviewed :: Mode -> Payment -> IO (Either Text Text)
sendReviewed Demo _ = pure (Right "demo-payment-complete-no-funds-moved")
sendReviewed (Live config) payment = case (paymentHex payment,paymentTxid payment) of
  (Just raw,Just expected) -> do
    sent <- guardIO $ rpc config False "sendrawtransaction" [T.unpack raw]
    case sent of
      Right (String txid) | txid == expected -> pure (Right txid)
      _ -> do
        known <- guardIO $ rpc (config {Legacy.cfgWallet=T.unpack (paymentWallet payment)}) True "gettransaction" [T.unpack expected]
        if either (const False) (confirmedPayment expected) known then pure (Right expected) else do
          pending <- guardIO $ rpc config False "getmempoolentry" [T.unpack expected]
          pure $ case pending of
            Right (Object _) -> Right expected
            _ -> Left ("Submission could not be confirmed. Transaction " <> expected <> ". Check activity before creating another payment; retrying this review submits the same transaction.")
  _ -> pure (Left "Prepare a new review before sending.")

-- Wallet history also contains abandoned, replaced and conflicted transactions.
confirmedPayment :: Text -> Value -> Bool
confirmedPayment expected value = fromMaybe False $ parseMaybe (withObject "transaction" $ \o -> do
  txid <- o .: "txid"
  confirmations <- o .: "confirmations" :: Parser Int
  pure (txid==expected && confirmations>0)) value

backupWallet :: Mode -> Text -> Text -> IO (Either Text Text)
backupWallet Demo _ _ = pure (Left "Backups require a live wallet.")
backupWallet (Live config) wallet path = guardIO $ do
  _ <- rpc (config {Legacy.cfgWallet=T.unpack wallet}) True "backupwallet" [T.unpack path]
  pure ("Backup saved by your node to "<>path)

restoreWallet :: Mode -> Text -> Text -> IO (Either Text Text)
restoreWallet Demo _ _ = pure (Left "Recovery requires a live node.")
restoreWallet (Live config) name path = guardIO $ do
  _ <- rpc config False "restorewallet" [T.unpack name,T.unpack path,"true"]
  pure name

openWallet :: Mode -> Text -> Bool -> IO (Either Text Text)
openWallet Demo name _ = pure (Right name)
openWallet (Live config) name create = guardIO $ do
  _ <- rpc config False (if create then "createwallet" else "loadwallet") (if create then [T.unpack name,"false","false","","false","true","true"] else [T.unpack name])
  pure name
