{-# LANGUAGE CPP #-}
module Main where

import BlueCurrent.Runtime
import BlueCurrent.Model
import qualified BlueCurrent.Backend as Backend
import BlueCurrent.View
import BlueCurrent.Accessibility (syncAccessibility, accessibilityActionAllowed)
import Control.Monad (unless, forever, filterM)
import Control.Concurrent (threadDelay)
import Data.List (partition, stripPrefix)
import qualified Data.Text as T
import qualified BlueCurrent.Types as Legacy
import qualified BlueCurrent.Node as Core
import Monomer
import Paths_elements_blue_current (getDataFileName)
import System.Directory (doesFileExist)
import System.Environment (getArgs, getExecutablePath)
import System.FilePath ((</>), takeDirectory, isAbsolute)
import Text.Read (readMaybe)

main :: IO ()
main = do
  allArgs <- getArgs
  case allArgs of
    ["--check-node-profile",path] -> checkNodeProfile path
    _ -> runWallet allArgs

checkNodeProfile :: FilePath -> IO ()
checkNodeProfile path = do
  profile <- loadNodeProfile path
  withNodeSession (Just profile) $ \startupError -> case startupError of
    Just err -> fail (T.unpack err)
    Nothing -> awaitReady 100 (profileConfig profile)
  where
    awaitReady :: Int -> Legacy.Config -> IO ()
    awaitReady 0 _=fail "The selected Elements node did not become ready"
    awaitReady attempts config=do
      result <- Backend.guardIO (Core.verifyBinding config)
      case result of
        Right () -> putStrLn "PASS: selected Elements genesis, native asset and parent chain match the node profile"
        Left _ -> threadDelay 100000 >> awaitReady (attempts-1) config

runWallet :: [String] -> IO ()
runWallet allArgs = do
  let (previewArgs, args) = partition (\arg -> take 9 arg == "--window=" || take 7 arg == "--pane=") allArgs
  (dimensions, initialPane) <- either fail pure (previewOptions previewArgs)
  executable <- getExecutablePath
  profilePath <- case args of
    ["--node-profile",path] -> pure (Just path)
    [] -> findNodeProfile executable
    _ -> pure Nothing
  profile <- traverse loadNodeProfile profilePath
  (mode, wallet) <- case profile of
    Just p -> let config=profileConfig p in pure (Live config,T.pack (Legacy.cfgWallet config))
    Nothing -> selectConnection args
  let asset name = do
        let candidates = [takeDirectory executable </> "../Resources/assets" </> name,
                          takeDirectory executable </> "../share/elements-blue-current/assets" </> name]
        found <- filterM doesFileExist candidates
        case found of path:_ -> pure path;[] -> getDataFileName ("assets/" <> name)
  regular <- asset "Roboto-Regular.ttf"
  boldFont <- asset "Roboto-Bold.ttf"
  icons <- asset "remixicon.ttf"
  logo <- asset "elements-logo.png"
  withNodeSession profile $ \startupError -> do
    let initial=(withConnection mode (initialModel mode wallet))
          {modelPane=if startupError/=Nothing then SettingsPane else initialPane,modelError=startupError}
    startApp initial handleEvent (buildUI (T.pack logo))
      [ appWindowTitle "Elements · Blue Current"
      , appWindowIcon (T.pack logo)
      , appWindowState (MainWindowNormal dimensions)
#ifdef mingw32_HOST_OS
      , appRenderOnMainThread
#endif
      , appTheme darkTheme
      , appFontDef "Regular" (T.pack regular), appFontDef "Bold" (T.pack boldFont)
      , appFontDef "Icons" (T.pack icons), appInitEvent AppInit
      , appResizeEvent (\(Rect _ _ w h) -> WindowResized w h)
      ]

selectConnection :: [String] -> IO (Mode,T.Text)
selectConnection args = case args of
    [] -> do
      saved <- Backend.guardIO Core.loadConfig
      case saved of
        Right (Just config) -> pure (Live config, T.pack (Legacy.cfgWallet config))
        _ -> do
          demo <- Backend.guardIO Core.loadDemo
          pure (Demo, either (const "Everyday wallet") (maybe "Everyday wallet" id) demo)
    ["--demo"] -> pure (Demo, "Everyday wallet")
    "--live" : rest -> do
      defaults <- Core.defaultConfig
      config <- either fail pure (Core.parseArgs defaults rest)
      unless (maybe False (not . null) (Legacy.cfgDataDir config) && maybe False (not . null) (Legacy.cfgRpcPort config))
        (fail "Live mode needs an explicit --datadir and --rpcport.")
      pure (Live config, T.pack (Legacy.cfgWallet config))
    _ -> fail "Use --node-profile PATH, --demo, or --live with --elements-cli PATH --datadir PATH --rpcport PORT --wallet NAME."

previewOptions :: [String] -> Either String ((Int, Int), Pane)
previewOptions = foldl step (Right ((1280,820), HomePane)) where
  step accumulated arg = do
    (dimensions, pane) <- accumulated
    case stripPrefix "--window=" arg of
      Just value -> case break (=='x') value of
        (w, 'x':h) -> case (readMaybe w, readMaybe h) of
          (Just x, Just y) | x >= 320 && y >= 400 && x <= 4000 && y <= 4000 -> Right ((x,y),pane)
          _ -> Left "Window size must be between 320x400 and 4000x4000."
        _ -> Left "Use --window=1280x820."
      Nothing -> case stripPrefix "--pane=" arg of
        Just "home" -> Right (dimensions, HomePane)
        Just "receive" -> Right (dimensions, ReceivePane)
        Just "send" -> Right (dimensions, SendPane)
        Just "wallet" -> Right (dimensions, WalletPane)
        _ -> Left "Use --pane=home, receive, send, or wallet."

handleEvent :: WidgetEnv AppModel AppEvent -> WidgetNode AppModel AppEvent
  -> AppModel -> AppEvent -> [AppEventResponse AppModel AppEvent]
handleEvent env root model event = case event of
  AppInit -> [Event Refresh, Producer (\send -> forever (threadDelay 15000000 >> send Poll)), Producer (\send -> forever (threadDelay 200000 >> send AccessibilityTick))]
  -- Monomer only rebuilds the responsive view when the model changes.
  WindowResized w h -> [Model model {modelWindowSize=(w,h)}]
  NoOp -> []
  ConnectionSaved result -> case result of
    Left err -> [Model model {modelBusy=False,modelError=Just err}]
    Right () -> [Model model {modelBusy=False,modelNotice=Just "Connection saved."}, Event Refresh]
  PreferenceSaved result -> case result of
    Left err -> [Model model {modelNotice=Just ("Could not remember wallet: "<>err)}]
    Right () -> []
  AccessibilityTick -> [Task (AccessibilityDone <$> syncAccessibility env root model)]
  AccessibilityDone events -> map Event events
  AccessibilityAction key _ | not (accessibilityActionAllowed root key) -> []
  AccessibilityAction key value -> case T.stripPrefix "focus:" key of
    Just target -> [SetFocusOnKey (WidgetKey target)]
    Nothing | key=="wallet-menu", Just snapshot<-modelSnapshot model, value `elem` snapshotWallets snapshot -> [Event (WalletChosen value)]
    Nothing -> case lookup key fieldActions of
      Just updateModel | not (modelBusy model) -> [Model (updateModel value model)]
      _ -> maybe [] (\action -> [Event action]) (lookup key buttonActions)
    where
      fieldActions=[("recipient",\v m->m {modelRecipient=v}),("amount",\v m->m {modelAmount=v}),("fee-rate",\v m->m {modelFeeRate=v}),("wallet-name",\v m->m {modelWalletName=v}),("cli",\v m->m {modelCli=v}),("chain",\v m->m {modelChain=v}),("datadir",\v m->m {modelDataDir=v}),("port",\v m->m {modelPort=v}),("backup-path",\v m->m {modelBackupPath=v})]
      buttonActions=[("button:"<>caption,action) | (caption,action)<-[("Send",SelectPane SendPane),("Receive",SelectPane ReceivePane),("Dismiss error",ClearNotice),("Back to wallet",SelectPane HomePane),("Close panel",SelectPane HomePane),("Cancel",SelectPane HomePane),("Back",SelectPane HomePane),("Wallets",SelectPane WalletPane),("Copy address",CopyAddress),("Address copied",CopyAddress),("New address",GenerateAddress),("Refresh",Refresh),("Review payment",ReviewPayment),("Confirm demo payment",ConfirmPayment),("Confirm and send",ConfirmPayment),("Back to edit",SelectPane SendPane),("Load wallet",ManageWallet False),("Create wallet",ManageWallet True),("Connection settings",SelectPane SettingsPane),("Backup & recovery",SelectPane BackupPane),("Save and connect",SaveConnection),("Use demo",UseDemo),("Back up current wallet",BackupWallet),("Restore from backup",RestoreWallet)]]
  Poll | modelBusy model || modelPane model `elem` [SendPane, ReviewPane, SettingsPane, BackupPane, WalletPane] -> []
       | otherwise -> [Event Refresh]
  Notice result -> [Model model {modelBusy=False,modelNotice=either (const Nothing) Just result,modelError=either Just (const Nothing) result}]
  SaveConnection | modelBusy model -> []
    | otherwise -> case connectionConfig model of
      Left err -> [Model model {modelError=Just err}]
      Right config -> [Model (withConnection (Live config) model) {modelWallet=T.pack (Legacy.cfgWallet config),modelAddress=Nothing,modelSnapshot=Nothing,modelReviewed=Nothing,modelPane=HomePane,modelBusy=True,modelRefreshing=False,modelRefreshRequest=modelRefreshRequest model+1},Task (ConnectionSaved <$> Backend.guardIO (Core.saveConfig config))]
  UseDemo | modelBusy model -> []
    | otherwise -> [Model (initialModel Demo "Everyday wallet"), Task (PreferenceSaved <$> Backend.guardIO (Core.saveDemo "Everyday wallet")), Event Refresh]
  BackupWallet | modelBusy model -> []
    | not (isAbsolute (T.unpack (modelBackupPath model))) -> [Model model {modelError=Just "Enter an absolute backup file path on your node."}]
    | otherwise -> [Model model {modelBusy=True,modelError=Nothing}, Task (Notice <$> Backend.backupWallet (modelMode model) (modelWallet model) (modelBackupPath model))]
  RestoreWallet | modelBusy model -> []
    | T.null (T.strip (modelWalletName model)) || T.any (`elem` ['/', '\\', '\n', '\r']) (modelWalletName model) || not (isAbsolute (T.unpack (modelBackupPath model))) -> [Model model {modelError=Just "Enter a new wallet name and the backup file path."}]
    | otherwise -> let request=modelRequest model+1 in [Model model {modelBusy=True,modelRequest=request,modelError=Nothing},Task (WalletOpened request <$> Backend.restoreWallet (modelMode model) (T.strip (modelWalletName model)) (modelBackupPath model))]
  Refresh | modelBusy model || modelRefreshing model -> []
          | otherwise -> let request = modelRefreshRequest model + 1
                         in [ Model model {modelRefreshing = True, modelRefreshRequest = request, modelError = Nothing}
                            , Task (SnapshotLoaded request (modelMode model) (modelWallet model) <$> Backend.fetchSnapshot (modelMode model) (modelWallet model))]
  SnapshotLoaded request mode wallet result | request /= modelRefreshRequest model || mode /= modelMode model || wallet /= modelWallet model -> []
    | otherwise -> case result of
      Left err -> [Model model {modelRefreshing = False, modelSnapshot = Nothing, modelError = Just err}]
      Right snapshot -> [Model model {modelRefreshing = False, modelSnapshot = Just snapshot, modelError = Nothing}]
        <> [Event GenerateAddress | modelAddress model == Nothing]
  SelectPane pane | modelBusy model -> []
    | otherwise -> [Model model {modelPane = if pane == modelPane model && pane `elem` [ReceivePane, SendPane] then HomePane else pane,
                                 modelError = Nothing, modelNotice = Nothing, modelReviewed = Nothing}]
      <> [SetFocusOnKey "recipient" | pane == SendPane]
  WalletChosen wallet | modelBusy model -> []
    | otherwise -> [Model model {modelWallet = wallet, modelAddress = Nothing, modelSnapshot = Nothing
                                , modelReviewed = Nothing, modelPane = ReceivePane, modelCopied = False,modelRefreshing=False,modelRefreshRequest=modelRefreshRequest model+1}, persistWallet model wallet, Event Refresh]
  GenerateAddress | modelBusy model -> []
    | otherwise -> let request = modelRequest model + 1
                   in [Model model {modelBusy = True, modelRequest = request, modelCopied = False, modelError = Nothing}
                      , Task (AddressLoaded request <$> Backend.newAddress (modelMode model) (modelWallet model) request)]
  AddressLoaded request result | request /= modelRequest model -> []
    | otherwise -> case result of
      Left err -> [Model model {modelBusy = False, modelError = Just err}]
      Right address -> [Model model {modelBusy = False, modelAddress = Just address, modelError = Nothing}]
  CopyAddress -> case modelAddress model of
    Nothing -> []
    Just address -> [Request (SetClipboard (ClipboardText address)), Model model {modelCopied = True}]
  ClearNotice -> [Model model {modelNotice = Nothing, modelError = Nothing}]
  ReviewPayment | modelBusy model || modelPane model /= SendPane -> []
    | otherwise -> case validatePayment model of
      Left err -> [Model model {modelError = Just err}]
      Right payment -> let request = modelRequest model + 1
                       in [Model model {modelBusy = True, modelRequest = request, modelError = Nothing}
                          , Task (ReviewPrepared request <$> Backend.checkRecipient (modelMode model) payment)]
  ReviewPrepared request result | request /= modelRequest model -> []
    | otherwise -> case result of
      Left err -> [Model model {modelBusy = False, modelError = Just err}]
      Right payment -> [Model model {modelBusy = False, modelReviewed = Just payment, modelPane = ReviewPane}]
  ConfirmPayment | not (canConfirm model) -> []
    | otherwise -> case modelReviewed model of
      Nothing -> []
      Just payment -> let request = modelRequest model + 1
                      in [Model model {modelBusy = True, modelRequest = request, modelError = Nothing}
                         , Task (PaymentSent request <$> Backend.sendReviewed (modelMode model) payment)]
  PaymentSent request result | request /= modelRequest model -> []
    | otherwise -> case result of
      Left err -> [Model model {modelBusy = False, modelError = Just err, modelPane = ReviewPane}]
      Right txid -> [Model model {modelBusy = False, modelTxid = Just txid, modelReviewed = Nothing
                                , modelPane = SentPane, modelRecipient = "", modelAmount = ""}]
        <> [Event Refresh | case modelMode model of Live _ -> True; Demo -> False]
  ManageWallet create | modelBusy model -> []
    | T.null name || T.length name > 100 || T.any (`elem` ['/', '\\', '\n', '\r']) name ->
        [Model model {modelError = Just "Use a simple wallet name without slashes."}]
    | otherwise -> let request = modelRequest model + 1
                   in [Model model {modelBusy = True, modelRequest = request, modelError = Nothing}
                      , Task (WalletOpened request <$> Backend.openWallet (modelMode model) name create)]
    where name = T.strip (modelWalletName model)
  WalletOpened request result | request /= modelRequest model -> []
    | otherwise -> case result of
      Left err -> [Model model {modelBusy = False, modelError = Just err}]
      Right wallet -> [Model model {modelBusy = False, modelWallet = wallet, modelWalletName = ""
                                   , modelAddress = Nothing, modelSnapshot = Nothing, modelPane = ReceivePane,modelRefreshing=False,modelRefreshRequest=modelRefreshRequest model+1}, persistWallet model wallet, Event Refresh]

withConnection :: Mode -> AppModel -> AppModel
withConnection mode model = case mode of
  Demo -> model {modelMode=Demo}
  Live c -> model {modelMode=mode,modelCli=T.pack (Legacy.cfgElementsCli c),modelChain=T.pack (Legacy.cfgChain c),modelDataDir=maybe "" T.pack (Legacy.cfgDataDir c),modelPort=maybe "" T.pack (Legacy.cfgRpcPort c)}

connectionConfig :: AppModel -> Either T.Text Legacy.Config
connectionConfig m
  | any T.null [modelCli m,modelChain m,modelDataDir m,modelPort m] = Left "Fill in all connection fields."
  | otherwise = case readMaybe (T.unpack (modelPort m)) :: Maybe Int of
      Just port | port>0 && port<65536 -> Right (Legacy.Config (T.unpack (modelCli m)) Nothing (T.unpack (modelChain m)) (Just (T.unpack (modelDataDir m))) (Just (show port)) (T.unpack (modelWallet m)) Nothing (case modelMode m of Live c -> Legacy.cfgBinding c; Demo -> Nothing))
      _ -> Left "Use an RPC port between 1 and 65535."

persistWallet :: AppModel -> T.Text -> AppEventResponse AppModel AppEvent
persistWallet model wallet = Task $ do
  case modelMode model of
    Demo -> PreferenceSaved <$> Backend.guardIO (Core.saveDemo wallet)
    Live config -> do
      outcome <- Backend.guardIO (Core.saveConfig config {Legacy.cfgWallet=T.unpack wallet})
      pure (PreferenceSaved outcome)
