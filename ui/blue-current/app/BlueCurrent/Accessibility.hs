{-# LANGUAGE CPP, ForeignFunctionInterface #-}
module BlueCurrent.Accessibility (syncAccessibility, accessibilityActionAllowed) where
import Control.Concurrent.MVar
#ifndef darwin_HOST_OS
import Control.Monad (forM_)
import qualified Data.Text.Encoding as TE
#endif
import System.IO.Unsafe (unsafePerformIO)
import BlueCurrent.Model
import BlueCurrent.View
import Control.Lens ((^.))
import Data.Aeson
#ifdef darwin_HOST_OS
import qualified Data.ByteString.Lazy as B
#endif
import qualified Data.ByteString as BS
import qualified Data.Aeson.KeyMap as KM
import Data.Foldable (toList)
import Data.Maybe (mapMaybe)
import qualified Data.Text as T
import Monomer
import qualified Monomer.Lens as L
import Foreign.C.String
#ifndef darwin_HOST_OS
import Foreign.C.Types
#endif
import Foreign.Marshal.Alloc (free)
#ifdef darwin_HOST_OS
foreign import ccall unsafe "bc_ax_update" update :: CString -> IO ()
#else
foreign import ccall unsafe "bc_ax_begin" beginUpdate :: IO ()
foreign import ccall unsafe "bc_ax_item" addItem :: CString -> CString -> CString -> CString -> CInt -> CInt -> CDouble -> CDouble -> CDouble -> CDouble -> IO ()
foreign import ccall safe "bc_ax_end" endUpdate :: IO ()
#endif
foreign import ccall unsafe "bc_ax_poll" poll :: IO CString

-- Monomer tasks may overlap; publish one complete accessibility snapshot at a time.
{-# NOINLINE bridgeLock #-}
bridgeLock :: MVar ()
bridgeLock = unsafePerformIO (newMVar ())

-- Reject queued requests if navigation or loading has since hidden/disabled the
-- original control. Native clients may retain old accessibility objects.
accessibilityActionAllowed :: WidgetNode AppModel AppEvent -> T.Text -> Bool
accessibilityActionAllowed root actionKey = walk True root where
  target = maybe actionKey id (T.stripPrefix "focus:" actionKey)
  walk parentEnabled n = let enabled=parentEnabled && n ^. L.info . L.enabled
    in n ^. L.info . L.visible && enabled &&
       (n ^. L.info . L.key == Just (WidgetKey target) || any (walk enabled) (toList (n ^. L.children)))

syncAccessibility :: WidgetEnv AppModel AppEvent -> WidgetNode AppModel AppEvent -> AppModel -> IO [AppEvent]
syncAccessibility env root model = withMVar bridgeLock $ \_ -> do
#ifdef darwin_HOST_OS
  BS.useAsCString (B.toStrict (encode items)) update
#else
  beginUpdate
  forM_ semanticItems $ \(key,caption,kind,value,enabled,focused,r) ->
    BS.useAsCString (TE.encodeUtf8 key) $ \k -> BS.useAsCString (TE.encodeUtf8 caption) $ \c ->
    BS.useAsCString (TE.encodeUtf8 kind) $ \t -> BS.useAsCString (TE.encodeUtf8 value) $ \v ->
      addItem k c t v (if enabled then 1 else 0) (if focused then 1 else 0)
        (realToFrac (r ^. L.x)) (realToFrac (r ^. L.y)) (realToFrac (r ^. L.w)) (realToFrac (r ^. L.h))
  endUpdate
#endif
  raw <- poll
  bytes <- BS.packCString raw
  free raw
  pure $ maybe [] (mapMaybe decodeAction) (decodeStrict' bytes :: Maybe [Value])
 where
  nodes parentEnabled n
    | not (n ^. L.info . L.visible) = []
    | otherwise = let enabled=parentEnabled && n ^. L.info . L.enabled
                  in (enabled,n) : concatMap (nodes enabled) (toList (n ^. L.children))
  keyed = [(key,enabled,n) | (enabled,n)<-nodes True root, Just (WidgetKey key)<-[n ^. L.info . L.key]]
  semanticItems = [(key,caption,kind,value,enabled,n ^. L.info . L.path == env ^. L.focusedPath,n ^. L.info . L.viewport)
     | (key,enabled,n)<-keyed, Just (caption,kind,value)<-[describe key]]
#ifdef darwin_HOST_OS
  items = [object ["id" .= key,"label" .= caption,"kind" .= kind,"value" .= value,
     "enabled" .= enabled,"focused" .= focused,"rect" .= [r ^. L.x,r ^. L.y,r ^. L.w,r ^. L.h]]
     | (key,caption,kind,value,enabled,focused,r)<-semanticItems]
#endif
  describe key = case lookup key fields of
    Just (caption,value) -> Just (caption,"field" :: T.Text,value)
    Nothing | Just caption<-T.stripPrefix "button:" key -> Just (caption,"button","")
    _ | key=="balance" -> Just ("Available L-ECX","text",maybe "Unavailable" (formatAmount.snapshotAvailable) (modelSnapshot model))
      | key=="address" -> Just ("Receive address","text",maybe "Unavailable" id (modelAddress model))
      | key=="review-recipient" -> Just ("Recipient","text",maybe "" paymentRecipient (modelReviewed model))
      | key=="review-fee" -> Just ("Network fee in L-ECX","text",maybe "" (maybe "" formatAmount . paymentFee) (modelReviewed model))
      | key=="review-total" -> Just ("Total in L-ECX","text",maybe "" (\p -> maybe "" (formatAmount . (+paymentSats p)) (paymentFee p)) (modelReviewed model))
      | key=="notice" -> Just ("Wallet status","text",maybe (maybe "" id (modelNotice model)) id (modelError model))
      | key=="transaction" -> Just ("Transaction identifier","text",maybe "" id (modelTxid model))
      | key=="panel-title" -> Just ("Current screen","text",case modelPane model of HomePane -> "Wallet"; ReceivePane -> "Receive L-ECX"; SendPane -> "Send L-ECX"; ReviewPane -> "Review payment"; SentPane -> "Payment submitted"; WalletPane -> "Wallets"; SettingsPane -> "Connection settings"; BackupPane -> "Backup and recovery")
      | Just activityKey<-T.stripPrefix "activity:" key
      , Just snapshot<-modelSnapshot model
      , item:_<-filter (\a -> (activityId a <> if activityDirection a==Incoming then ":in" else ":out")==activityKey) (snapshotActivity snapshot) ->
          Just ("Payment activity","text",(if activityDirection item==Incoming then "Received " else "Sent ") <> formatAmount (activitySats item) <> " L-ECX; " <> (if activityConfirmations item>0 then "confirmed" else if activityConfirmations item<0 then "conflicted" else "pending") <> "; " <> activityTime item)
      | otherwise -> Nothing
  fields=[("wallet-menu",("Selected wallet; type an available wallet name to switch",modelWallet model)),("recipient",("Recipient",modelRecipient model)),("amount",("Amount in L-ECX",modelAmount model)),("fee-rate",("Fee rate in satoshis per virtual byte",modelFeeRate model)),("wallet-name",("Wallet name",modelWalletName model)),("cli",("Elements CLI path",modelCli model)),("chain",("Chain",modelChain model)),("datadir",("Node data folder",modelDataDir model)),("port",("RPC port",modelPort model)),("backup-path",("Backup file path",modelBackupPath model))]
  decodeAction (Object o) = case (KM.lookup "key" o,KM.lookup "value" o) of
    (Just (String key),Just (String value)) -> Just (AccessibilityAction key value)
    _ -> Nothing
  decodeAction _ = Nothing
