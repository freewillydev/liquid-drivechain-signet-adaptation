module BlueCurrent.Model where

import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Text as T
import BlueCurrent.Types (Config)

data Mode = Demo | Live Config deriving (Eq, Show)
data Pane = HomePane | ReceivePane | SendPane | ReviewPane | SentPane | WalletPane | SettingsPane | BackupPane deriving (Eq, Show)
data Direction = Incoming | Outgoing deriving (Eq, Show)
data Activity = Activity
  { activityId :: Text, activityDirection :: Direction, activitySats :: Integer
  , activityConfirmations :: Int, activityTime :: Text
  } deriving (Eq, Show)
data Snapshot = Snapshot
  { snapshotAvailable :: Integer, snapshotPending :: Integer
  , snapshotActivity :: [Activity], snapshotWallets :: [Text]
  , snapshotNetwork :: Text, snapshotWarning :: Maybe Text
  } deriving (Eq, Show)
data Payment = Payment
  { paymentRecipient :: Text, paymentSats :: Integer, paymentFeeRate :: Text
  , paymentWallet :: Text, paymentFee :: Maybe Integer, paymentHex :: Maybe Text, paymentTxid :: Maybe Text
  } deriving (Eq, Show)
data AppModel = AppModel
  { modelMode :: Mode, modelPane :: Pane, modelWallet :: Text
  , modelSnapshot :: Maybe Snapshot, modelAddress :: Maybe Text
  , modelRecipient :: Text, modelAmount :: Text, modelFeeRate :: Text
  , modelReviewed :: Maybe Payment, modelBusy :: Bool, modelRequest :: Int
  , modelError :: Maybe Text, modelNotice :: Maybe Text, modelTxid :: Maybe Text
  , modelWalletName :: Text, modelCopied :: Bool, modelRefreshing :: Bool, modelRefreshRequest :: Int
  , modelCli :: Text, modelChain :: Text, modelDataDir :: Text, modelPort :: Text, modelBackupPath :: Text
  , modelWindowSize :: (Double, Double)
  } deriving (Eq, Show)

initialModel :: Mode -> Text -> AppModel
initialModel mode wallet = AppModel mode HomePane wallet Nothing Nothing "" "" "1"
  Nothing False 0 Nothing Nothing Nothing "" False False 0 "elements-cli" "elements" "" "" "" (0, 0)

-- Decimal parsing uses integer satoshis, never floating point or rounding.
parseAmount :: Text -> Either Text Integer
parseAmount raw = case T.splitOn "." (T.strip raw) of
  [whole] -> fromParts whole ""
  [whole, fraction] | not (T.null fraction) -> fromParts whole fraction
  _ -> Left "Enter an amount with at most 8 decimal places."
  where
    fromParts whole fraction
      | T.null whole || not (T.all asciiDigit whole && T.all asciiDigit fraction) = Left "Use digits and a decimal point only."
      | T.length whole > 12 || T.length fraction > 8 = Left "Enter an amount with at most 8 decimal places."
      | otherwise = let sats = read (T.unpack whole) * 100000000
                               + read (T.unpack (fraction <> T.replicate (8 - T.length fraction) "0"))
                    in if sats <= 0 then Left "The amount must be greater than zero." else Right sats
    asciiDigit c = isDigit c && c >= '0' && c <= '9'

formatAmount :: Integer -> Text
formatAmount sats = sign <> T.pack (show whole) <> "." <> T.justifyRight 8 '0' (T.pack (show fraction))
  where
    (whole, fraction) = abs sats `divMod` 100000000
    sign = if sats < 0 then "-" else ""

validatePayment :: AppModel -> Either Text Payment
validatePayment model = do
  snapshot <- maybe (Left "Load the wallet before sending.") Right (modelSnapshot model)
  let address = T.strip (modelRecipient model)
      fee = T.strip (modelFeeRate model)
  if T.length address < 8 || T.any (`elem` [' ', '\n', '\r', '\t']) address
    then Left "Enter the full recipient address." else Right ()
  amount <- parseAmount (modelAmount model)
  if amount > snapshotAvailable snapshot then Left "This amount exceeds your available balance." else Right ()
  _ <- parseFeeRate fee
  Right (Payment address amount fee (modelWallet model) Nothing Nothing Nothing)

parseFeeRate :: Text -> Either Text Integer
parseFeeRate raw = case T.splitOn "." raw of
  [whole] -> check whole ""
  [whole, fraction] | not (T.null fraction) -> check whole fraction
  _ -> Left "Enter a positive fee rate with up to 3 decimal places."
  where
    check whole fraction
      | T.null whole || T.length whole > 6 || T.length fraction > 3
        || not (T.all (\c -> c >= '0' && c <= '9') (whole <> fraction)) = Left "Enter a positive fee rate with up to 3 decimal places."
      | otherwise = let value = read (T.unpack whole) * 1000
                                 + read (T.unpack (fraction <> T.replicate (3 - T.length fraction) "0"))
                    in if value > 0 then Right value else Left "The fee rate must be greater than zero."

-- A review is tied to the wallet and immutable payment fields.
canConfirm :: AppModel -> Bool
canConfirm model = not (modelBusy model) && modelPane model == ReviewPane
  && maybe False (\p -> paymentWallet p == modelWallet model && case modelMode model of
       Demo -> True
       Live _ -> maybe False (>0) (paymentFee p) && paymentHex p /= Nothing && paymentTxid p /= Nothing) (modelReviewed model)

shortAddress :: Text -> Text
shortAddress address | T.length address <= 28 = address
                     | otherwise = T.take 13 address <> "…" <> T.takeEnd 9 address

demoSnapshot :: Snapshot
demoSnapshot = Snapshot 10000000 200000
  [ Activity "demo-received" Incoming 10000000 6 "Today · 10:24 AM"
  , Activity "demo-sent" Outgoing 1000000 3 "Today · 10:26 AM"
  , Activity "demo-pending" Incoming 200000 0 "Awaiting confirmation"
  ] ["Everyday wallet", "Savings wallet"] "Demo" Nothing

cleanErrorText :: Text -> Text
cleanErrorText raw = case T.stripPrefix "user error (" (T.strip raw) >>= T.stripSuffix ")" of
  Just inner -> cleanErrorText inner
  Nothing -> case T.breakOn "error message:\n" (T.strip raw) of
    (_,message) | not (T.null message) -> T.strip (T.drop (T.length ("error message:\n" :: Text)) message)
    _ -> T.strip raw
