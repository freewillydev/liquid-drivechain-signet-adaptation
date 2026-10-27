module BlueCurrent.View where

import BlueCurrent.Model
import BlueCurrent.QR (qrPixels)
import Control.Lens (Lens', lens, (^.))
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import qualified Data.Text
import Monomer hiding (blue, green, red, gray)
import qualified Monomer.Lens as L

data AppEvent
  = AppInit | WindowResized Double Double | NoOp | ConnectionSaved (Either Text ()) | PreferenceSaved (Either Text ()) | AccessibilityTick | AccessibilityDone [AppEvent] | AccessibilityAction Text Text | Poll | SaveConnection | UseDemo | BackupWallet | RestoreWallet | Notice (Either Text Text) | Refresh | SnapshotLoaded Int Mode Text (Either Text Snapshot)
  | SelectPane Pane | WalletChosen Text | GenerateAddress
  | AddressLoaded Int (Either Text Text) | CopyAddress | ClearNotice
  | ReviewPayment | ReviewPrepared Int (Either Text Payment)
  | ConfirmPayment | PaymentSent Int (Either Text Text)
  | ManageWallet Bool | WalletOpened Int (Either Text Text)
  deriving (Eq, Show)

amber, blue, deepBlue, green, red, paleAmber, dark, charcoal, gray, ink :: Color
amber = rgbHex "#FEA028"
blue = rgbHex "#1175E9"
deepBlue = rgbHex "#0051B8"
green = rgbHex "#52ED6B"
red = rgbHex "#FF1D3E"
paleAmber = rgbHex "#FFBB67"
dark = rgbHex "#181818"
charcoal = rgbHex "#404040"
gray = rgbHex "#B4B4B4"
ink = rgbHex "#000000"

recipientLens, amountLens, feeLens, walletNameLens :: Lens' AppModel Text
recipientLens = lens modelRecipient (\m value -> m {modelRecipient = value})
amountLens = lens modelAmount (\m value -> m {modelAmount = value})
feeLens = lens modelFeeRate (\m value -> m {modelFeeRate = value})
walletNameLens = lens modelWalletName (\m value -> m {modelWalletName = value})

type Node = WidgetNode AppModel AppEvent

txt :: Double -> Color -> Text -> Node
txt size color caption = label caption `styleBasic` [textSize size, textColor color]

bold :: Double -> Color -> Text -> Node
bold size color caption = txt size color caption `styleBasic` [textFont "Bold"]

glyph :: Double -> Color -> Text -> Node
glyph size color codepoint = txt size color codepoint
  `styleBasic` [textFont "Icons", width (size * 1.35), height (size * 1.5), textMiddle, textCenter]

actionButton :: Color -> Color -> Text -> AppEvent -> Node
actionButton background foreground caption event = button caption event `nodeKey` ("button:" <> caption)
  `styleBasic` [bgColor background, textColor foreground, textSize 22, textFont "Bold", height 54, radius 8, border 1 background]
  `styleHover` [border 2 white]
  `styleFocus` [border 3 paleAmber]
  `styleDisabled` [textColor gray, bgColor charcoal, border 1 charcoal]

quietButton :: Text -> AppEvent -> Node
quietButton caption event = actionButton dark white caption event
  `styleBasic` [border 1 charcoal, textSize 17, height 42]

gap :: Double -> Node
gap pixels = spacer `styleBasic` [width pixels, height pixels]

mainAction :: Double -> Bool -> Color -> Color -> Text -> Text -> AppEvent -> Node
mainAction areaWidth compact background foreground symbol caption event = zstack_ [onlyTopActive_ False]
  [ actionButton background foreground "" event `nodeKey` ("button:" <> caption) `styleBasic` [height tileHeight]
  , box_ [onClick event, onClickEmpty event, alignCenter, alignMiddle]
      (hstack [glyph iconSize foreground symbol, gap 8, bold labelSize foreground caption])
      `styleBasic` [height tileHeight, cursorHand]
  ]
  where
    tileHeight = if compact then 70 else if areaWidth < 500 then 90 else 110
    iconSize = if compact then 23 else if areaWidth < 500 then 27 else 39
    labelSize = if compact then 20 else if areaWidth < 500 then 22 else 28

panelBackground :: AppModel -> Color
panelBackground model = case modelPane model of
  ReceivePane -> deepBlue
  WalletPane -> dark
  SettingsPane -> dark
  BackupPane -> dark
  HomePane -> dark
  _ -> amber

panelForeground :: AppModel -> Color
panelForeground model = case modelPane model of
  ReceivePane -> white
  WalletPane -> white
  SettingsPane -> white
  BackupPane -> white
  HomePane -> white
  _ -> ink

panelMuted :: AppModel -> Color
panelMuted model = if panelForeground model == ink then rgbHex "#49300F" else rgbHex "#D1E4FF"

buildUI :: Text -> WidgetEnv AppModel AppEvent -> AppModel -> Node
buildUI logoPath env model = keystroke [("Esc", SelectPane HomePane)] root where
  windowWidth = env ^. L.windowSize . L.w
  compact = env ^. L.windowSize . L.h < 620
  panelOpen = modelPane model /= HomePane
  narrow = windowWidth < 1080
  leftWidth = if panelOpen then windowWidth * 0.62 else windowWidth
  walletView = vstack [header logoPath leftWidth compact model, scroll (mainWallet (max 260 (leftWidth - 12)) compact model), footer leftWidth model]
    `styleBasic` [bgColor dark, if panelOpen then width leftWidth else flexWidth 320]
  right = vstack [panelToolbar model, scroll (detailPanel (windowWidth - leftWidth) model) `nodeKey` ("panel-" <> Data.Text.pack (show (modelPane model)))]
    `styleBasic` [bgColor (panelBackground model), flexWidth 320]
  root
    | panelOpen && narrow = vstack
        [header logoPath windowWidth compact model, panelToolbar model, scroll (detailPanel windowWidth model) `nodeKey` ("panel-" <> Data.Text.pack (show (modelPane model)))]
          `styleBasic` [bgColor (panelBackground model)]
    | panelOpen = hstack [walletView, right]
    | otherwise = walletView

header :: Text -> Double -> Bool -> AppModel -> Node
header logoPath areaWidth compact model = content `styleBasic` [paddingH pad, paddingV (if compact then 10 else 18), borderB 1 charcoal, bgColor dark] where
  pad = if areaWidth < 500 then 18 else 30
  markSize = if compact || areaWidth < 500 then 38 else 46
  brand = hstack
    [image_ logoPath [fitEither] `nodeKey` "elements-logo" `styleBasic` [width markSize, height markSize], gap 10,
     bold (if areaWidth < 400 then 21 else if compact then 23 else 25) white "ELEMENTS"]
  modeBadge = txt 12 gray (case modelMode model of Demo -> "DEMO"; Live _ -> "LIVE")
    `styleBasic` [bgColor charcoal, paddingH 10, paddingV 6, radius 14]
  logo = hstack [brand, gap 12, modeBadge]
  walletMenu = textDropdownV_ (modelWallet model) WalletChosen wallets id [] `nodeKey` "wallet-menu"
    `styleBasic` [height (if compact then 38 else 44), textSize 18, textFont "Bold", textColor paleAmber, bgColor dark, border 1 charcoal, radius 7]
    `nodeEnabled` not (modelBusy model)
  manage = quietButton "Wallets" (SelectPane WalletPane) `styleBasic` [width 82]
    `nodeEnabled` not (modelBusy model)
  content
    | areaWidth < 500 = vstack [hstack [brand, filler, modeBadge], gap 10,
        hstack [walletMenu `styleBasic` [flexWidth 100], gap 10, manage]]
    | areaWidth < 690 = vstack [hstack [logo, filler, manage], gap 12, walletMenu]
    | otherwise = hstack [logo, filler, walletMenu `styleBasic` [width 240], gap 10, manage]
  wallets = fromMaybe [modelWallet model] (snapshotWallets <$> modelSnapshot model)

mainWallet :: Double -> Bool -> AppModel -> Node
mainWallet areaWidth compact model = vstack
  [txt (if compact then 18 else 22) gray "Available", gap (if compact then 6 else 10), balanceLine, gap (if compact then 6 else 10),
   txt (if compact then 15 else if small then 17 else 21) gray pending, gap (if compact then 14 else 30),
   hgrid_ [childSpacing_ 14]
     [mainAction areaWidth compact amber ink remixArrowRightUpLine "Send" (SelectPane SendPane),
      mainAction areaWidth compact (if modelPane model == ReceivePane then deepBlue else blue) white remixArrowDownLine "Receive" (SelectPane ReceivePane)]
       `nodeEnabled` not (modelBusy model),
   gap 22, notice model `nodeVisible` (modelPane model == HomePane),
   hstack [bold 27 white "Activity", filler, quietButton (if modelBusy model || modelRefreshing model then "Loading…" else "Refresh") Refresh
     `styleBasic` [width 100, textSize 15] `nodeEnabled` not (modelBusy model)], gap 12,
   vstack (if null entries then [txt 17 gray "Your L-ECX payments will appear here." `styleBasic` [paddingV 24]] else map (activityRow areaWidth) entries)
  ] `styleBasic` [width areaWidth, padding pad, paddingT (if compact then 14 else 30)]
  where
    small = areaWidth < 500
    pad = (if small then 18 else 32) + max 0 ((areaWidth - 1180) / 2)
    hero = min (if compact then 40 else 88) (max 22 ((areaWidth - 2 * pad - (if small then 0 else 110)) / (0.59 * fromIntegral (max 10 (Data.Text.length available)))))
    amountNode = bold hero white available `nodeKey` "balance"
    unitNode = txt (if compact then 18 else if small then 21 else 28) gray "L-ECX"
    balanceLine = if small then vstack [amountNode, gap 5, unitNode] else hstack [amountNode, gap 12, unitNode]
    available = maybe "—" (formatAmount . snapshotAvailable) (modelSnapshot model)
    pending = maybe "Waiting for wallet data" (\s -> formatAmount (snapshotPending s) <> " L-ECX pending") (modelSnapshot model)
    entries = maybe [] snapshotActivity (modelSnapshot model)

notice :: AppModel -> Node
notice model = case modelError model of
  Just err -> errorCard (cleanErrorText err)
  Nothing -> case modelNotice model of
    Just info -> message gray info
    Nothing -> maybe spacer (message gray) (modelSnapshot model >>= snapshotWarning)
  where
    message color caption = label_ caption [multiline] `nodeKey` "notice"
      `styleBasic` [textSize 15, textColor color, bgColor dark, padding 12, radius 6]
    errorCard err = vstack
      [ hstack
          [ glyph 22 ink remixAlertLine, gap 8
          , label_ (heading err) [multiline]
              `styleBasic` [textSize 18, textFont "Bold", textColor ink, flexWidth 80]
          , gap 8
          , quietButton "×" ClearNotice `nodeKey` "button:Dismiss error"
              `styleBasic` [width 30, height 30, textSize 24, textColor ink, bgColor red, border 0 red]
          ]
      , gap 9
      , label_ err [multiline] `nodeKey` "notice"
          `styleBasic` [textSize 16, textColor ink]
      ] `styleBasic` [bgColor red, padding 16, radius 10, border 1 (rgbHex "#FF6A80")]
    heading err
      | contains ["node", "connect", "respond", "permission"] err = "Check your connection"
      | contains ["amount", "recipient", "fee", "balance"] err = "Check payment details"
      | contains ["submission", "transaction"] err = "Check payment status"
      | modelPane model == BackupPane = "Backup needs attention"
      | modelPane model == WalletPane = "Check wallet details"
      | otherwise = "Unable to complete request"
    contains terms value = any (`Data.Text.isInfixOf` Data.Text.toLower value) terms

activityRow :: Double -> Activity -> Node
activityRow areaWidth item = content `nodeKey` ("activity:" <> activityId item <> if activityDirection item==Incoming then ":in" else ":out") `styleBasic` [paddingV 18, borderT 1 charcoal] where
  small = areaWidth < 540
  incoming = activityDirection item == Incoming
  directionColor = if incoming then blue else amber
  directionGlyph = if incoming then remixArrowDownLine else remixArrowRightUpLine
  confirmed = activityConfirmations item > 0
  conflicted = activityConfirmations item < 0
  statusColor = if conflicted then red else if confirmed then green else gray
  statusGlyph = if conflicted then remixCloseCircleLine else if confirmed then remixCheckboxCircleFill else remixTimeLine
  statusText = if conflicted then "Conflicted" else if confirmed then "Confirmed" else "Pending"
  mark = box (glyph 28 (if incoming then white else directionColor) directionGlyph)
    `styleBasic` [width 54, height 54, radius 27, bgColor (if incoming then deepBlue else rgbHex "#49300F")]
  title = vstack [bold 22 white (if incoming then "Received" else "Sent"), gap 3,
    hstack [glyph 16 statusColor statusGlyph, gap 5, txt 15 gray statusText]]
  amount = (if incoming then "+" else "−") <> formatAmount (activitySats item)
  value = vstack [bold (if small then 21 else 23) white amount, gap 3, txt 14 gray "L-ECX" `styleBasic` [textRight]]
  content
    | small = vstack [hstack [mark, gap 12, title, filler], gap 10,
        hstack [bold 20 white amount, filler], gap 3, txt 14 gray "L-ECX", gap 5,
        txt 14 gray (activityTime item)]
    | otherwise = hstack [mark, gap 16, title, filler, value]

footer :: Double -> AppModel -> Node
footer areaWidth model = hstack
  [glyph 16 statusColor remixCheckboxCircleFill, gap 8,
   txt (if areaWidth < 500 then 13 else 15) gray status, filler,
   txt 13 gray network `nodeVisible` (areaWidth >= 650)]
  `styleBasic` [paddingH (if areaWidth < 500 then 18 else 32), paddingV 14, borderT 1 charcoal]
  where
    network = maybe "Elements" snapshotNetwork (modelSnapshot model)
    status = case modelMode model of
      Demo -> "Interactive demo · No funds move"
      Live _ | modelBusy model || modelRefreshing model -> "Contacting node…"
             | isJust (modelSnapshot model) -> "Connected"
             | otherwise -> "Offline · Refresh to reconnect"
    statusColor = case modelMode model of Demo -> gray; Live _ -> if isJust (modelSnapshot model) then green else gray

panelToolbar :: AppModel -> Node
panelToolbar model = hstack
  [quietButton "Back to wallet" (SelectPane HomePane) `nodeKey` "button:Close panel"
    `styleBasic` [bgColor (panelBackground model), textColor foreground, border 1 foreground, textSize 16, width 160]
    `nodeEnabled` not (modelBusy model), filler]
  `styleBasic` [paddingH 24, paddingV 16, bgColor (panelBackground model)]
  where foreground = panelForeground model

detailPanel :: Double -> AppModel -> Node
detailPanel areaWidth model = box_ [alignCenter, alignTop] body
  `styleBasic` [paddingH (if areaWidth < 450 then 22 else 30), paddingT 5, paddingB 26, bgColor (panelBackground model)] where
  foreground = panelForeground model
  body = vstack
    [hstack [glyph 33 foreground panelIcon, gap 12,
       vstack [label_ title [multiline] `nodeKey` "panel-title"
                 `styleBasic` [textSize (if areaWidth < 380 then 26 else 30), textFont "Bold", textColor foreground], gap 7,
         label_ subtitle [multiline] `styleBasic` [textSize 16, textColor (panelMuted model)]]
           `styleBasic` [flexWidth 120]],
     gap 18, notice model, gap 8, content]
    `styleBasic` [width (max 240 (min 560 (areaWidth - (if areaWidth < 450 then 44 else 60) - 12)))]
  (panelIcon, title, subtitle, content) = case modelPane model of
    HomePane -> (remixWallet3Line, "Your wallet", "Choose Send or Receive", spacer)
    ReceivePane -> (remixArrowDownLine, "Receive L-ECX", "Your wallet address", receiveContent model)
    SendPane -> (remixArrowRightUpLine, "Send L-ECX", "A clear path to your payment", sendContent model)
    ReviewPane -> (remixShieldCheckLine, "Review payment", "Check every detail before sending", reviewContent (max 240 (min 560 (areaWidth - (if areaWidth < 450 then 44 else 60) - 12))) model)
    SentPane -> (remixCheckboxCircleFill, "Payment submitted", "Waiting for confirmation", sentContent model)
    WalletPane -> (remixWallet3Line, "Your wallets", "Create or load a wallet", walletContent model)
    SettingsPane -> (remixSettings3Line, "Connection", "Connect to your Elements node", settingsContent model)
    BackupPane -> (remixShieldCheckLine, "Backup & recovery", "Keep a safe copy of your wallet", backupContent model)

receiveContent :: AppModel -> Node
receiveContent model = vstack
  [ box_ [alignCenter] $ case modelAddress model >>= qrPixels of
      Just (side, pixels) -> box (imageMem_ ("qr-" <> fromMaybe "" (modelAddress model)) pixels (Size (fromIntegral side) (fromIntegral side)) [imageNearest, fitEither]
        `styleBasic` [width 222, height 222]) `styleBasic` [width 234, height 234, padding 6, bgColor white, radius 10]
      Nothing -> box (txt 17 gray (if modelBusy model then "Preparing address…" else "Generate a receive address"))
        `styleBasic` [height 230, bgColor dark, radius 10]
  , (spacer `styleBasic` [height 12])
  , txt 13 (rgbHex "#D1E4FF") (case modelMode model of Demo -> "Demo QR · Not a payment address"; Live _ -> "Scan to receive L-ECX") `styleBasic` [textCenter]
  , (spacer `styleBasic` [height 13])
  , tooltip (fromMaybe "No address yet" (modelAddress model))
      (label_ (maybe "No address yet" shortAddress (modelAddress model)) [ellipsis] `nodeKey` "address"
        `styleBasic` [textSize 17, bgColor (rgbHex "#003878"), padding 15, radius 7])
  , (spacer `styleBasic` [height 12])
  , actionButton blue white (if modelCopied model then "Address copied" else "Copy address") CopyAddress
      `nodeEnabled` isJust (modelAddress model)
  , (spacer `styleBasic` [height 12])
  , actionButton deepBlue white (if modelBusy model then "Please wait…" else "New address") GenerateAddress
      `styleBasic` [border 1 (rgbHex "#8FBAF2"), textSize 18]
      `nodeEnabled` not (modelBusy model)
  , (spacer `styleBasic` [height 22])
  , hstack [glyph 19 white remixInformationLine, (spacer `styleBasic` [width 7]), txt 14 white "L-ECX only"]
  ]

sendContent :: AppModel -> Node
sendContent model = vstack
  [ field model "Recipient" (textField_ recipientLens [placeholder "Paste an address"] `nodeKey` "recipient")
  , (spacer `styleBasic` [height 20])
  , field model "Amount · L-ECX" (textField_ amountLens [placeholder "0.00"] `nodeKey` "amount")
  , (spacer `styleBasic` [height 20])
  , field model "Fee rate · sat/vB" (textField feeLens `nodeKey` "fee-rate")
  , (spacer `styleBasic` [height 25])
  , label_ "The next screen shows the exact network fee and total before you confirm." [multiline]
      `styleBasic` [textSize 15, textColor (panelMuted model)]
  , (spacer `styleBasic` [height 24])
  , actionButton ink paleAmber (if modelBusy model then "Checking…" else "Review payment") ReviewPayment
      `nodeEnabled` (not (modelBusy model) && isJust (modelSnapshot model))
  , (spacer `styleBasic` [height 12])
  , actionButton amber ink "Cancel" (SelectPane HomePane) `styleBasic` [textSize 17, border 1 ink]
      `nodeEnabled` not (modelBusy model)
  ] `nodeEnabled` not (modelBusy model)

field :: AppModel -> Text -> Node -> Node
field model caption input = vstack
  [txt 17 foreground caption, gap 9,
   input `styleBasic` [height 55, textSize 20, textColor foreground, bgColor background,
     border 1 (panelMuted model), sndColor (panelMuted model), radius 7, paddingH 13, textMiddle]
     `styleFocus` [border 2 foreground]]
  where
    foreground = panelForeground model
    background = if foreground == ink then paleAmber else rgbHex "#003878"

reviewContent :: Double -> AppModel -> Node
reviewContent contentWidth model = maybe spacer details (modelReviewed model) where
  fittedSize largest smallest value = min largest (max smallest (contentWidth / (0.59 * fromIntegral (max 1 (Data.Text.length value)))))
  details payment = vstack
    [ bold (fittedSize 31 18 (formatAmount (paymentSats payment))) (panelForeground model) (formatAmount (paymentSats payment)), txt 18 (panelForeground model) "L-ECX"
    , (spacer `styleBasic` [height 26]), txt 15 (panelMuted model) "To"
    , label_ (wrapIdentifier (max 18 (floor (contentWidth/10))) (paymentRecipient payment)) [multiline] `nodeKey` "review-recipient" `styleBasic` [textSize 17, textColor (panelForeground model), paddingV 10]
    , (spacer `styleBasic` [height 15]), txt 15 (panelMuted model) "From wallet"
    , label_ (wrapIdentifier (max 18 (floor (contentWidth/11))) (paymentWallet payment)) [multiline] `styleBasic` [textSize 18, textFont "Bold", textColor (panelForeground model)], (spacer `styleBasic` [height 20])
    , txt 15 (panelMuted model) "Fee rate", bold 19 (panelForeground model) (paymentFeeRate payment <> " sat/vB")
    , (spacer `styleBasic` [height 16])
    , txt 15 (panelMuted model) "Network fee"
    , bold 20 (panelForeground model) (maybe "Unavailable" (\fee -> formatAmount fee <> " L-ECX") (paymentFee payment)) `nodeKey` "review-fee"
    , gap 16, txt 15 (panelMuted model) "Total including fee"
    , bold (fittedSize 23 16 (formatAmount (paymentSats payment + maybe 0 id (paymentFee payment)))) (panelForeground model) (maybe "Unavailable" (\fee -> formatAmount (paymentSats payment+fee)) (paymentFee payment)) `nodeKey` "review-total"
    , txt 16 (panelForeground model) "L-ECX"
    , label_ "This exact transaction will be submitted. Double-check the full address above." [multiline]
        `styleBasic` [textSize 15, textColor (panelForeground model), paddingV 10]
    , (spacer `styleBasic` [height 18])
    , actionButton ink paleAmber (if modelBusy model then "Submitting…" else case modelMode model of Demo -> "Confirm demo payment"; Live _ -> "Confirm and send") ConfirmPayment
        `nodeEnabled` canConfirm model
    , (spacer `styleBasic` [height 12])
    , actionButton amber ink "Back to edit" (SelectPane SendPane) `styleBasic` [textSize 17, border 1 ink]
        `nodeEnabled` not (modelBusy model)
    ]

sentContent :: AppModel -> Node
sentContent model = vstack
  [ box (glyph 48 green remixCheckLine) `styleBasic` [width 72, height 72, radius 36, bgColor ink]
  , (spacer `styleBasic` [height 16])
  , label_ (case modelMode model of Demo -> "Demo complete. No funds moved."; Live _ -> "Your node accepted the payment. Confirmation is still pending.") [multiline]
      `styleBasic` [textSize 20, textColor (panelForeground model)]
  , (spacer `styleBasic` [height 22])
  , txt 14 (panelMuted model) "Transaction"
  , label_ (wrapIdentifier 24 (fromMaybe "" (modelTxid model))) [multiline] `nodeKey` "transaction" `styleBasic` [textSize 15, textColor (panelForeground model), paddingV 10]
  , (spacer `styleBasic` [height 26])
  , actionButton ink paleAmber "Back to wallet" (SelectPane HomePane)
  ]

walletContent :: AppModel -> Node
walletContent model = vstack
  [ field model "Wallet name" (textField_ walletNameLens [placeholder "My wallet"] `nodeKey` "wallet-name")
  , (spacer `styleBasic` [height 24])
  , actionButton blue white "Load wallet" (ManageWallet False)
  , (spacer `styleBasic` [height 12])
  , actionButton deepBlue white "Create wallet" (ManageWallet True) `styleBasic` [border 1 blue]
  , (spacer `styleBasic` [height 24])
  , label_ "Use the wallet menu above to switch between available wallets." [multiline] `styleBasic` [textSize 16]
  , (spacer `styleBasic` [height 24])
  , actionButton blue white "Connection settings" (SelectPane SettingsPane)
  , gap 12, actionButton dark white "Backup & recovery" (SelectPane BackupPane)
  , gap 24, actionButton dark white "Back" (SelectPane HomePane) `styleBasic` [textSize 17, border 1 blue]
  ] `nodeEnabled` not (modelBusy model)

cliLens, chainLens, dataDirLens, portLens, backupLens :: Lens' AppModel Text
cliLens = lens modelCli (\m v -> m {modelCli=v})
chainLens = lens modelChain (\m v -> m {modelChain=v})
dataDirLens = lens modelDataDir (\m v -> m {modelDataDir=v})
portLens = lens modelPort (\m v -> m {modelPort=v})
backupLens = lens modelBackupPath (\m v -> m {modelBackupPath=v})

settingsContent :: AppModel -> Node
settingsContent model = vstack
  [ field model "Elements CLI path" (textField cliLens `nodeKey` "cli"), gap 18
  , field model "Chain" (textField chainLens `nodeKey` "chain"), gap 18
  , field model "Node data folder" (textField dataDirLens `nodeKey` "datadir"), gap 18
  , field model "RPC port" (textField portLens `nodeKey` "port"), gap 24
  , label_ "Uses your node's local authentication. Your connection and selected wallet are remembered on this computer." [multiline] `styleBasic` [textSize 16], gap 24
  , actionButton blue white "Save and connect" SaveConnection, gap 12
  , actionButton dark white "Use demo" UseDemo
  ] `nodeEnabled` not (modelBusy model)

backupContent :: AppModel -> Node
backupContent model = vstack
  [ label_ "The backup contains private wallet information. Choose a new absolute file path on the node's computer and store the file securely. Recovery creates a separate wallet." [multiline] `styleBasic` [textSize 16], gap 20
  , field model "Backup file path" (textField backupLens `nodeKey` "backup-path"), gap 20
  , actionButton blue white "Back up current wallet" BackupWallet, gap 28
  , field model "New recovery wallet name" (textField walletNameLens `nodeKey` "wallet-name"), gap 20
  , actionButton dark white "Restore from backup" RestoreWallet
  ] `nodeEnabled` (not (modelBusy model) && case modelMode model of Live _ -> True; Demo -> False)

-- Explicit line boundaries keep unbroken addresses visible at every panel width.
wrapIdentifier :: Int -> Text -> Text
wrapIdentifier count = Data.Text.intercalate "\n" . Data.Text.chunksOf count
