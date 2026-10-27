{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, GADTs, ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Withdrawal (withdrawal, wordBE, wordLE, readBE, readLE,
  WithdrawalPayout(..), WithdrawalRequest(..), WithdrawalRule(..), WithdrawalFrame(..),
  WithdrawalAction(..), PreflightFlow(..), NativeSubmissionFlow(..), DestinationFlow(..), EventFlow(..), BundleEventFlow(..), SubmissionFlow(..), OutputFlow(..), JournalReadFlow(..), JournalPersistFlow(..), RpcBurnFlow(..), RpcClaimFlow(..), RpcVerifyFlow(..),
  WalletBalance(..), WalletCommandFlow(..), WalletIssueAmount(..), WalletIssueFlow(..), WalletBundleRequest(..), BundleFailure(..), BundlePlan, bundlePayout, bundleFeeScript, bundleInputs, bundleMarker, bundleLayout,
  WalletWithdrawal(..), WalletAdmission(..), WalletPreparation(..), WalletSubmission(..), withdrawFromWallet,
  WithdrawalJournal(..), JournalValidation(..), JournalStorage(..), readWithdrawalJournal, writeWithdrawalJournal, clearWithdrawalJournal,
  withdrawRules, buildWalletBundle, DSL(Withdraw, BuildWalletBundle, WithdrawFromWallet, ValidateJournal, ReadJournal, WriteJournal, ClearJournal)) where

import Control.Monad (unless, when)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT)
import CapabilityContext
import BmmConstants (withdrawalDestinationSize, withdrawalReferenceSize, withdrawalLegacySize)
import Data.Bits (shiftR, (.&.), (.|.))
import qualified Data.Bifunctor as Bi
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.Word (Word8, Word32, Word64)
import Control.Operation
import Control.Operation.Validation
import ParentReplay (transition)
import Workflow (NativeBytes, CommandFlow(..))

type Result = Either String B.ByteString

-- Reading composes validation directly, so no native callback re-enters the
-- FFI for admission, transaction normalization or identity comparison.
data WithdrawalJournal = WithdrawalJournal Int64 NativeBytes
class JournalValidation op where
  validateJournal :: op -> IO Bool
class JournalStorage op where
  observeJournal :: op -> Word32 -> IO Int64

journalAbort :: NativeBytes -> String -> IO a
journalAbort native message = do
  _ <- native 0 0 (C.pack message)
  ioError (userError "journal error callback returned")

journalScalar :: NativeBytes -> Word32 -> B.ByteString -> IO Int64
journalScalar native step input = do
  bytes <- native step 0 input
  let value = readLE bytes
  if B.length bytes == 8 && value <= fromIntegral (maxBound :: Word32)
    then pure (fromIntegral value)
    else journalAbort native "invalid withdrawal journal scalar"

instance JournalValidation WithdrawalJournal where
  validateJournal (WithdrawalJournal maximumMoney native) = do
    facts <- native 101 0 B.empty
    unless (B.length facts == 74) (journalAbort native "invalid withdrawal journal facts")
    case rule JournalAdmission (B.take 42 facts) of
      Left message -> reject message
      Right _ -> do
        bundle <- native 102 0 B.empty
        case rule JournalLegacy bundle of
          Left _ -> journalAbort native "Haskell withdrawal transport evaluation failed"
          Right normalized -> do
            digest <- native 103 0 normalized
            unless (B.length digest == 32) (journalAbort native "invalid withdrawal journal digest")
            either reject (const (pure True)) (rule JournalIdentity (digest <> B.drop 42 facts))
    where
      rule action = withdrawal (fromIntegral (fromEnum action)+1) maximumMoney
      reject message = do
        reply <- journalScalar native 105 (C.pack message)
        unless (reply == 1) (journalAbort native "invalid withdrawal journal rejection")
        pure False

instance JournalStorage WithdrawalJournal where
  observeJournal (WithdrawalJournal _ native) step = journalScalar native step B.empty

readWithdrawalJournal :: (JournalValidation op, JournalStorage op) => op -> IO Int32
readWithdrawalJournal value = validate (CommandFlow 10
  (\phase reply -> validate (JournalReadFlow phase reply))
  (\step -> if step == 8 then fromIntegral . fromEnum <$> validateJournal value
            else observeJournal value step))

requireJournalEffect :: JournalStorage op => op -> Word32 -> IO ()
requireJournalEffect value step = observeJournal value step >>= \reply ->
  unless (reply == 1) (ioError (userError "invalid journal persistence effect"))

writeWithdrawalJournal :: (JournalValidation op, JournalStorage op) => op -> IO Int32
writeWithdrawalJournal value = do
  accepted <- validateJournal value
  if not accepted then requireJournalEffect value 209 >> pure 0 else do
    mapM_ (requireJournalEffect value) [201,202]
    stored <- validate (CommandFlow 8
      (\phase reply -> validate (JournalPersistFlow False phase reply)) (observeJournal value))
    if stored < 0 then pure stored else do
      requireJournalEffect value 203
      if stored /= 1 then pure stored else do
        mapM_ (requireJournalEffect value) [204,205]
        pure 1

clearWithdrawalJournal :: JournalStorage op => op -> IO Int32
clearWithdrawalJournal value = validate (CommandFlow 4
  (\phase reply -> validate (JournalPersistFlow True phase reply)) (observeJournal value))

type JournalCapabilities = '[JournalValidation, JournalStorage]
instance Operation WithdrawalJournal JournalCapabilities where
  type Context WithdrawalJournal = CapabilityContext JournalCapabilities WithdrawalJournal
  type Outcome WithdrawalJournal = IO Int32
  data DSL WithdrawalJournal where
    ValidateJournal :: Context WithdrawalJournal => DSL WithdrawalJournal
    ReadJournal :: Context WithdrawalJournal => DSL WithdrawalJournal
    WriteJournal :: Context WithdrawalJournal => DSL WithdrawalJournal
    ClearJournal :: Context WithdrawalJournal => DSL WithdrawalJournal
  interpret operation request = withOperation @WithdrawalJournal operation $ \value -> case request of
    ValidateJournal -> Just (fromIntegral . fromEnum <$> validateJournal value)
    ReadJournal -> Just (readWithdrawalJournal value)
    WriteJournal -> Just (writeWithdrawalJournal value)
    ClearJournal -> Just (clearWithdrawalJournal value)

-- A single wallet session retains native wallet/transaction ownership while
-- rules and preparation-to-commit ordering stay inside Haskell.
data WalletWithdrawal = WalletWithdrawal Int64 NativeBytes
class WalletAdmission op where
  admitWithdrawalWallet :: op -> IO Bool
class WalletPreparation op where
  prepareWithdrawalWallet :: op -> IO Bool
class WalletSubmission op where
  submitWithdrawalWallet :: op -> Bool -> IO ()

walletAbort :: NativeBytes -> String -> IO a
walletAbort native message = do
  _ <- native 0 0 (C.pack message)
  ioError (userError "withdrawal error callback returned")

walletRpcError :: NativeBytes -> (Int32,String) -> IO a
walletRpcError native (code,message) = do
  _ <- native 0 1 (wordLE 4 (fromIntegral code) <> C.pack message)
  ioError (userError "withdrawal RPC error callback returned")

walletScalar :: NativeBytes -> Word32 -> B.ByteString -> IO Word64
walletScalar native step payload = do
  bytes <- native step 0 payload
  if B.length bytes == 8 then pure (readLE bytes)
    else walletAbort native "invalid wallet withdrawal scalar"

walletFlag :: NativeBytes -> Word32 -> IO Bool
walletFlag native step = walletScalar native step B.empty >>= \value -> case value of
  0 -> pure False
  1 -> pure True
  _ -> walletAbort native "invalid wallet withdrawal boolean"

walletEffect :: NativeBytes -> Word32 -> B.ByteString -> IO ()
walletEffect native step payload = walletScalar native step payload >>= \value ->
  unless (value == 1) (walletAbort native "invalid wallet withdrawal effect")

walletGuard :: NativeBytes -> Word8 -> Bool -> IO ()
walletGuard native stage flag = either (walletRpcError native) pure
  (nativeGuard (B.pack [stage,if flag then 1 else 0]))

walletRule :: WalletWithdrawal -> WithdrawalAction -> B.ByteString -> String -> IO B.ByteString
walletRule (WalletWithdrawal maximumMoney native) action input failure =
  let request = WithdrawalRequest maximumMoney input
  in if hasFrame action request then either (const (walletAbort native failure)) pure (withdrawalBody action request)
    else walletAbort native failure

walletDecoded :: NativeBytes -> [Int32] -> String -> B.ByteString -> IO B.ByteString
walletDecoded native allowed invalid bytes
  | B.length bytes < 4 = walletAbort native invalid
  | code == 0 = pure (B.drop 4 bytes)
  | code `elem` allowed = walletRpcError native (code,C.unpack (B.drop 4 bytes))
  | otherwise = walletAbort native invalid
  where code = fromIntegral (readLE (B.take 4 bytes))

instance WalletAdmission WalletWithdrawal where
  admitWithdrawalWallet (WalletWithdrawal _ native) = do
    walletFlag native 1 >>= walletGuard native 0
    activation <- walletScalar native 2 B.empty
    unless (activation <= 3) (walletAbort native "invalid withdrawal activation observation")
    walletGuard native 1 (activation == 3)
    loaded <- walletFlag native 3
    when loaded $ mapM_ (\step -> walletEffect native step B.empty) [4,5]
    pure loaded

instance WalletPreparation WalletWithdrawal where
  prepareWithdrawalWallet value@(WalletWithdrawal _ native) = do
    walletEffect native 10 B.empty
    destinationResult <- validate (CommandFlow 14 (\phase result -> validate (DestinationFlow phase result))
      (\step -> do
        reply <- walletScalar native (100+step) B.empty
        pure (if reply <= 0xffffffff then fromIntegral reply else -1)))
    unless (destinationResult == 1) (walletAbort native "Haskell parent replay store evaluation failed")
    payoutFrame <- native 20 0 B.empty
    payoutResult <- walletRule value NativePayout payoutFrame "Haskell native payout evaluation failed"
    unless (B.length payoutResult == 12) (walletAbort native "Haskell native payout evaluation failed")
    case fromIntegral (readLE (B.take 4 payoutResult)) :: Int32 of
      -3 -> walletRpcError native (-3,"Invalid withdrawal payout amount")
      -8 -> do
        minimumAmount <- native 21 0 (B.drop 4 payoutResult)
        walletRpcError native (-8,"Bitcoin withdrawal payout is dust for this destination (minimum "++C.unpack minimumAmount++")")
      0 -> pure ()
      _ -> walletAbort native "Invalid Haskell native payout result"
    omittedSubtract <- walletFlag native 22
    subtractFee <- if omittedSubtract then pure False else walletFlag native 23
    walletGuard native 2 subtractFee
    omittedVerbose <- walletFlag native 24
    verbose <- if omittedVerbose then pure False else walletFlag native 25
    omittedFee <- walletFlag native 26
    unless omittedFee (walletEffect native 27 B.empty)
    burnFrame <- native 28 0 B.empty
    burn <- walletRule value NativeBurnPlan burnFrame "Haskell native burn planning failed"
      >>= walletDecoded native [-3,-8] "Invalid Haskell native burn plan"
    unless (B.length burn >= 8) (walletAbort native "Invalid Haskell native burn plan")
    walletEffect native 29 burn
    dataCarrier <- walletFlag native 30
    when dataCarrier (walletEffect native 31 B.empty)
    walletFlag native 32 >>= walletGuard native 3
    walletEffect native 40 B.empty
    pure verbose

instance WalletSubmission WalletWithdrawal where
  submitWithdrawalWallet value@(WalletWithdrawal _ native) verbose = do
    mapM_ (\step -> walletEffect native step B.empty) [41,42]
    available <- walletFlag native 43
    hasTransaction <- if available then walletFlag native 44 else pure False
    unless hasTransaction (walletRpcError native (-4,"Committed withdrawal transaction is unavailable in the wallet"))
    frame <- native 46 0 B.empty
    output <- walletRule value NativeOutputSelection frame "Haskell native output selection failed"
      >>= walletDecoded native [-4] "Invalid Haskell native output selection"
    unless (B.length output == 4) (walletAbort native "Invalid Haskell native output selection")
    walletEffect native 47 output
    walletEffect native (if verbose then 49 else 48) B.empty

withdrawFromWallet :: (WalletAdmission op, WalletPreparation op, WalletSubmission op) => op -> IO Int32
withdrawFromWallet value = do
  present <- admitWithdrawalWallet value
  if not present then pure 0 else prepareWithdrawalWallet value >>= submitWithdrawalWallet value >> pure 1

type WalletWithdrawalCapabilities = '[WalletAdmission, WalletPreparation, WalletSubmission]
instance Operation WalletWithdrawal WalletWithdrawalCapabilities where
  type Context WalletWithdrawal = CapabilityContext WalletWithdrawalCapabilities WalletWithdrawal
  type Outcome WalletWithdrawal = IO Int32
  data DSL WalletWithdrawal where
    WithdrawFromWallet :: Context WalletWithdrawal => DSL WalletWithdrawal
  interpret operation request = withOperation @WalletWithdrawal operation $ \value -> case request of
    WithdrawFromWallet -> Just (withdrawFromWallet value)


newtype WalletBalance = WalletBalance [Int64]
instance Validation WalletBalance where
  type ValidationResult WalletBalance = Int64
  validate (WalletBalance amounts)
    | all (>=0) amounts && total <= toInteger (maxBound :: Int64) = fromInteger total
    | otherwise = -1
    where total = sum (map toInteger amounts)

data WalletCommandFlow = WalletCommandFlow Word32 Word32
instance Validation WalletCommandFlow where
  type ValidationResult WalletCommandFlow = Int32
  validate (WalletCommandFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-1)),(3,(4,8)),(4,(-1,5)),(5,(7,6)),
     (6,(-1,7)),(7,(-1,-1)),(8,(-1,9)),(9,(10,-11)),(10,(-1,-1))]

newtype WalletIssueAmount = WalletIssueAmount Double
instance Validation WalletIssueAmount where
  type ValidationResult WalletIssueAmount = Bool
  validate (WalletIssueAmount amount) = amount <= 0

data WalletIssueFlow = WalletIssueFlow Bool Word32 Word32
instance Validation WalletIssueFlow where
  type ValidationResult WalletIssueFlow = Int32
  validate (WalletIssueFlow executing phase result)
    | executing && phase==0 = 5
    | executing = transition phase result
        [(5,(8,6)),(6,(8,7)),(7,(-1,-11)),(8,(-1,-11))]
    | otherwise = transition phase result
        [(1,(-10,2)),(2,(-1,3)),(3,(-11,4)),(4,(-1,-10))]

data PreflightFlow = PreflightFlow Word32 Word32
instance Validation PreflightFlow where
  type ValidationResult PreflightFlow = Int32
  validate (PreflightFlow phase result) = transition phase result
    [(1,(2,9)),(9,(2,10)),(10,(2,3)),(3,(-1,4)),(4,(5,6)),
     (6,(5,7)),(7,(8,11)),(11,(8,12)),(12,(8,-11))]

data NativeSubmissionFlow = NativeSubmissionFlow Word32 Word32
instance Validation NativeSubmissionFlow where
  type ValidationResult NativeSubmissionFlow = Int32
  validate (NativeSubmissionFlow phase result) = transition phase result
    [(1,(-1,2)),(2,(-1,3)),(3,(5,4)),(4,(5,6)),(6,(-1,7)),(7,(-10,8)),(8,(-1,-11))]

data OutputFlow = OutputFlow Word32 Word32
instance Validation OutputFlow where
  type ValidationResult OutputFlow = Int32
  validate (OutputFlow phase result) = transition phase result
    ([(1,(-1,2)),(2,(12,3)),(8,(10,9)),(10,(-1,11)),(11,(-1,2)),(12,(13,-11))] ++
     [(n,(11,fromIntegral n+1)) | n <- [3..7]])

data SubmissionFlow = SubmissionFlow Word32 Word32
instance Validation SubmissionFlow where
  type ValidationResult SubmissionFlow = Int32
  validate (SubmissionFlow phase result) = transition phase result
    ([(5,(6,7)),(8,(11,9)),(9,(10,12)),(10,(-1,8)),(17,(-10,18)),(18,(-1,-11))] ++
     [(n,(-1,fromIntegral n+1)) | n <- [1,2,3,4,7,12,13,14,15,16]])

data EventFlow = EventFlow Word32 Word32
instance Validation EventFlow where
  type ValidationResult EventFlow = Int32
  validate (EventFlow phase result)
    | phase==11 = if result==32 then 12 else 10
    | otherwise = transition phase result
        [(1,(-10,2)),(2,(-1,3)),(3,(-10,4)),(4,(6,5)),(5,(-1,7)),(6,(-1,3)),
         (7,(6,8)),(8,(10,9)),(9,(10,11)),(10,(-1,7)),(12,(10,13)),(13,(-10,14)),
         (14,(15,-11)),(15,(16,-12)),(16,(-10,-13))]

-- Checking reports missing/failed events; clearing only acts on final events.
data BundleEventFlow = BundleEventFlow Bool Word32 Word32
instance Validation BundleEventFlow where
  type ValidationResult BundleEventFlow = Int32
  validate (BundleEventFlow clearing phase result)
    | not clearing && phase == 3 = case result of
        0 -> -11
        1 -> 4
        2 -> 5
        _ -> -1
    | otherwise = transition phase result $ if clearing
        then [(1,(-11,2)),(2,(-1,3)),(3,(-11,4)),(4,(-1,-11))]
        else [(1,(-1,2)),(2,(-1,3)),(4,(-1,-1)),(5,(-1,-1))]

data DestinationFlow = DestinationFlow Word32 Word32
instance Validation DestinationFlow where
  type ValidationResult DestinationFlow = Int32
  validate (DestinationFlow phase result) = case phase of
    2 -> if result <= 256 then 3 else 4
    9 -> if result > 0 && result <= fromIntegral withdrawalDestinationSize then 11 else 12
    13 -> if spendableParentType result then -11 else 14
    _ -> transition phase result
      [(1,(5,2)),(3,(4,6)),(5,(10,8)),(6,(-1,9)),(8,(-1,9)),(11,(12,13))]

spendableParentType :: Word32 -> Bool
spendableParentType value = value `elem` [2,3,4,5,7,8,9]

data JournalReadFlow = JournalReadFlow Word32 Word32
instance Validation JournalReadFlow where
  type ValidationResult JournalReadFlow = Int32
  validate (JournalReadFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-10)),(3,(-1,4)),(4,(5,6)),(5,(-1,-10)),
     (6,(7,8)),(7,(-1,-10)),(8,(9,10)),(9,(-1,-10)),(10,(-1,-11))]

data JournalPersistFlow = JournalPersistFlow Bool Word32 Word32
instance Validation JournalPersistFlow where
  type ValidationResult JournalPersistFlow = Int32
  validate (JournalPersistFlow clearing phase result) = transition phase result $
    if clearing then [(1,(-11,2)),(2,(3,4)),(3,(-1,-10)),(4,(-1,-11))]
    else [(1,(2,3)),(2,(-1,-10)),(3,(-1,4)),(4,(5,6)),
          (5,(-1,-10)),(6,(-1,7)),(7,(8,-11)),(8,(-1,-10))]

data RpcBurnFlow = RpcBurnFlow Word32 Word32
instance Validation RpcBurnFlow where
  type ValidationResult RpcBurnFlow = Int32
  validate (RpcBurnFlow phase result) = transition phase result
    ([(1,(7,2)),(2,(6,3)),(3,(5,4)),(5,(-1,6)),(6,(-1,1)),(7,(8,9)),
      (9,(10,11)),(11,(19,12)),(12,(18,13)),(13,(14,15)),(15,(17,16)),
      (17,(-1,18)),(18,(-1,11)),(19,(20,21)),(21,(22,23)),(23,(24,25)),(25,(26,-11))] <>
     [(step,(-1,-1)) | step <- [4,8,10,14,16,20,22,24,26]])

data RpcClaimFlow = RpcClaimFlow Word32 Word32
instance Validation RpcClaimFlow where
  type ValidationResult RpcClaimFlow = Int32
  validate (RpcClaimFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-1)),(3,(6,4)),(4,(6,5)),(5,(6,7)),(6,(-1,-1)),
     (7,(-1,8)),(8,(-1,9)),(9,(10,11)),(10,(-1,-1)),(11,(-1,-11))]

data RpcVerifyFlow = RpcVerifyFlow Word32 Word32
instance Validation RpcVerifyFlow where
  type ValidationResult RpcVerifyFlow = Int32
  validate (RpcVerifyFlow phase result) = transition phase result
    ([(1,(2,3)),(3,(4,5)),(5,(6,7)),(7,(8,9)),(9,(10,11)),(11,(8,12)),
      (12,(-1,13)),(13,(15,14)),(14,(15,16)),(16,(18,17)),(17,(-1,-11))] <>
     [(step,(-1,-1)) | step <- [2,4,6,8,10,15,18]])

data WithdrawalPayout = WithdrawalPayout Int64 Int64 Int64
instance Validation WithdrawalPayout where
  type ValidationResult WithdrawalPayout = Int64
  validate (WithdrawalPayout burn parentFee maximumMoney)
    | burn <= 0 || burn > maximumMoney = -1
    | parentFee < 0 || parentFee > maximumMoney = -2
    | burn <= parentFee = -3
    | otherwise = burn - parentFee

-- Constructor order is the version-1 C++ WithdrawalOp ABI (one-based).
data WithdrawalAction = BuildScript | ParseScript | BuildReference | ParseReference
  | LegacyFrame | DecodeFee | EncodeFee | BuildOutput | ParseOutput | BuildM6 | ParseM6
  | Reserved12 | StateAnchor | WalletBundle | WalletAnchor | StateMarker | WalletTransport
  | RpcFee | EventPolicy | BundleAdmission | NativeAmount | ParentDust | NativeGuard | NativeGuardResult | InputsCommitment | NativePayout | NativeBurnPlan | NativeOutputSelection | JournalAdmission | ParentPolicy | RpcAdmission | SubmissionPolicy | ProofBounds | JournalLegacy | JournalIdentity
  deriving (Bounded, Enum, Eq, Show)
data WithdrawalRequest = WithdrawalRequest Int64 B.ByteString
class WithdrawalRule op where
  withdrawalBody :: WithdrawalAction -> op -> Result
class WithdrawalFrame op where
  hasFrame :: WithdrawalAction -> op -> Bool
instance WithdrawalFrame WithdrawalRequest where
  hasFrame action (WithdrawalRequest _ input) = case action of
    BuildScript -> size >= 40
    ParseScript -> size >= 32
    BuildReference -> size == 69
    EncodeFee -> size == 8
    BuildOutput -> size >= 80
    ParseOutput -> size >= 108
    BuildM6 -> size >= 93
    ParseM6 -> size >= 69
    Reserved12 -> False
    StateAnchor -> size == 132
    WalletBundle -> size == 25
    WalletAnchor -> size == 132
    StateMarker -> size == 32
    WalletTransport -> size >= 4
    JournalLegacy -> size >= 7 && B.take 2 (B.drop 4 input) == B.pack [0,1]
    JournalIdentity -> size == 64
    RpcFee -> size == 16
    BundleAdmission -> size == 65
    NativeAmount -> size == 17 && B.head input <= 2
    ParentDust -> size == 5 && B.index input 4 <= 1
    NativeGuard -> size == 2 && B.head input < 5 && B.index input 1 <= 1
    NativeGuardResult -> hasFrame NativeGuard (WithdrawalRequest 0 input)
    InputsCommitment -> size == 40
    NativePayout -> size == 13 && B.index input 12 <= 1
    NativeBurnPlan -> size >= 48
    JournalAdmission -> (size == 34 && B.index input 33 < 64) ||
      (size == 42 && B.index input 33 < 32 && B.index input 34 <= 7)
    ParentPolicy -> size == 10 && B.index input 4 <= 1 && B.last input <= 1
    RpcAdmission -> size == 10 && B.head input <= 3 && B.index input 1 <= 3
    ProofBounds -> size == 17 && B.head input <= 1
    SubmissionPolicy -> (size == 14 && B.head input == 0 && B.last input <= 1) ||
      (size == 2 && B.head input == 1) ||
      (size >= 3 && B.head input == 2 && B.index input 1 < 128 && B.index input 2 <= 1)
    NativeOutputSelection -> size >= 92 && scriptSize <= fromIntegral (size-92) &&
      (size-92-fromIntegral scriptSize) `mod` 49 == 0
    _ -> True
    where
      size = B.length input
      scriptSize = readLE (B.take 4 (B.drop 88 input))

type WithdrawalCapabilities = '[WithdrawalRule, WithdrawalFrame]

applyWithdrawal :: (WithdrawalRule op, WithdrawalFrame op) => op -> WithdrawalAction -> Result
applyWithdrawal value action
  | hasFrame action value = withdrawalBody action value
  | otherwise = error "invalid withdrawal FFI request"

withdrawRules :: DSL WithdrawalRequest
withdrawRules = Withdraw

instance Operation WithdrawalRequest WithdrawalCapabilities where
  type Context WithdrawalRequest = CapabilityContext WithdrawalCapabilities WithdrawalRequest
  type Outcome WithdrawalRequest = WithdrawalAction -> Result
  data DSL WithdrawalRequest where
    Withdraw :: Context WithdrawalRequest => DSL WithdrawalRequest
  interpret operation request = withOperation @WithdrawalRequest operation $ \value -> case request of
    Withdraw -> Just (applyWithdrawal value)

-- Only successful monetary/script validation can construct a bundle plan.
data BundlePlan = BundlePlan { bundlePayout :: Word64, bundleFeeScript :: B.ByteString,
  bundleInputs :: B.ByteString, bundleMarker :: B.ByteString }
bundleLayout :: BundlePlan -> B.ByteString
bundleLayout plan = wordLE 4 2 <> B.cons (fromIntegral (B.length roles)) roles
  where roles = B.pack ([0,1,2] ++ [3 | not (B.null (bundleMarker plan))])
data BundleFailure = BundleRejection String | AnchorRejection String deriving (Eq, Show)
class BundleAnchoring op where
  prepareBundleAnchor :: op -> IO (Either String B.ByteString)
class BundlePlanning op where
  planBundle :: op -> Either String BundlePlan
class BundleConstruction op where
  constructBundle :: op -> BundlePlan -> IO B.ByteString
data WalletBundleRequest = WalletBundleRequest WithdrawalRequest (BundlePlan -> IO B.ByteString)
  | AnchoredBundleRequest WithdrawalRequest (Word32 -> B.ByteString -> IO B.ByteString) (BundlePlan -> IO B.ByteString)
bundleRequest :: WalletBundleRequest -> WithdrawalRequest
bundleRequest (WalletBundleRequest request _) = request
bundleRequest (AnchoredBundleRequest request _ _) = request
instance BundleAnchoring WalletBundleRequest where
  prepareBundleAnchor (WalletBundleRequest _ _) = pure (Right B.empty)
  prepareBundleAnchor (AnchoredBundleRequest (WithdrawalRequest maximumMoney input) digest _)
    | B.length input /= 161 = pure (Left "invalid withdrawal FFI request")
    | otherwise = do
        commitment <- checkedDigest 2 (inputsCommitment (B.take 40 (B.drop 25 input)))
        let anchorInput = B.take 4 (B.drop 61 input) <> B.take 64 (B.drop 65 input) <>
              commitment <> B.drop 129 input
        case withdrawalBody WalletAnchor (WithdrawalRequest maximumMoney anchorInput) of
          Left err -> pure (Left err)
          Right payload -> do
            let tag = C.pack "ECX/perps-m6-state/v1"
            anchor <- checkedDigest 3 (B.singleton (fromIntegral (B.length tag)) <> tag <> payload)
            pure (withdrawalBody StateMarker (WithdrawalRequest maximumMoney anchor))
    where
      checkedDigest action bytes = do
        result <- digest action bytes
        if B.length result /= 32 then ioError (userError "invalid withdrawal digest reply") else pure result
instance BundlePlanning WalletBundleRequest where
  planBundle value = do
    let WithdrawalRequest maximumMoney input = bundleRequest value
        sizes = case value of WalletBundleRequest _ _ -> [25,65]; AnchoredBundleRequest _ _ _ -> [161]
    check (B.length input `elem` sizes) "invalid withdrawal FFI request"
    encoded <- withdrawalBody WalletBundle (WithdrawalRequest maximumMoney (B.take 25 input))
    pure (BundlePlan (readLE (B.take 8 encoded)) (B.drop 8 encoded)
      (if B.length input == 25 then B.empty else inputsCommitment (B.take 40 (B.drop 25 input))) B.empty)
instance BundleConstruction WalletBundleRequest where
  constructBundle (WalletBundleRequest _ build) = build
  constructBundle (AnchoredBundleRequest _ _ build) = build

type BundleCapabilities = '[BundleAnchoring, BundlePlanning, BundleConstruction]

bundleProgram :: (BundleAnchoring op, BundlePlanning op, BundleConstruction op)
  => op -> ExceptT BundleFailure IO (B.ByteString, B.ByteString)
bundleProgram value = do
  marker <- ExceptT (Bi.first AnchorRejection <$> prepareBundleAnchor value)
  plan <- ExceptT (pure (Bi.first BundleRejection (planBundle value)))
  serialized <- lift (constructBundle value plan { bundleMarker = marker })
  if B.length serialized < 4 then lift (ioError (userError "invalid withdrawal transaction frame"))
    else pure (serialized, walletTransport serialized)

buildWalletBundle :: DSL WalletBundleRequest
buildWalletBundle = BuildWalletBundle

instance Operation WalletBundleRequest BundleCapabilities where
  type Context WalletBundleRequest = CapabilityContext BundleCapabilities WalletBundleRequest
  type Outcome WalletBundleRequest = IO (Either BundleFailure (B.ByteString, B.ByteString))
  data DSL WalletBundleRequest where
    BuildWalletBundle :: Context WalletBundleRequest => DSL WalletBundleRequest
  interpret operation request = withOperation @WalletBundleRequest operation $ \value -> case request of
    BuildWalletBundle -> Just (runExceptT (bundleProgram value))

walletTransport :: B.ByteString -> B.ByteString
walletTransport input = B.take 4 input <> B.pack [0,1] <> B.drop 4 input

inputsCommitment :: B.ByteString -> B.ByteString
inputsCommitment input = B.singleton 2 <> B.take 36 input <> B.replicate 32 0 <> B.drop 36 input

wordBE :: Int -> Word64 -> B.ByteString
wordBE n value = B.pack [fromIntegral (value `shiftR` (8*i)) | i <- reverse [0..n-1]]

wordLE :: Int -> Word64 -> B.ByteString
wordLE n = B.reverse . wordBE n

readBE, readLE :: B.ByteString -> Word64
readBE = B.foldl' (\value byte -> value * 256 + fromIntegral byte) 0
readLE = readBE . B.reverse

check :: Bool -> String -> Either String ()
check ok message = unless ok (Left message)

destination :: B.ByteString -> String -> Either String ()
destination bytes prefix = check (not (B.null bytes) && B.length bytes <= fromIntegral withdrawalDestinationSize)
  (prefix ++ " destination size is outside 1..128 bytes")

fee :: Int64 -> B.ByteString -> Either String Word64
fee maximumMoney bytes = do
  check (B.length bytes == 8) "native withdrawal parent fee is not eight bytes"
  let value = readBE bytes
  check (value <= fromIntegral maximumMoney) "native withdrawal parent fee is outside the money range"
  pure value

-- Only the bounded OP_RETURN data envelope is recognized here, not Script
-- execution. Match GetOp's acceptance of PUSHDATA1/2/4, then require exact
-- canonical re-encoding so alternate pushes never gain a consensus alias.
push :: B.ByteString -> B.ByteString
push bytes = B.pack prefix <> bytes
  where n = B.length bytes
        prefix | n < 76 = [fromIntegral n]
               | n <= 255 = [76, fromIntegral n]
               | otherwise = error "unbounded withdrawal push"

envelope :: [B.ByteString] -> B.ByteString
envelope fields = B.singleton 106 <> B.concat (map push fields)

pushes :: Int -> B.ByteString -> Maybe [B.ByteString]
pushes count script = do
  (op, rest) <- B.uncons script
  if op /= 106 then Nothing else go count rest
  where
    go 0 bytes = if B.null bytes then Just [] else Nothing
    go n bytes = do
      (op, rest) <- B.uncons bytes
      let width | op <= 75 = 0
                | op <= 78 = 2 ^ (fromIntegral op - 76 :: Int)
                | otherwise = -1
      if width < 0 || B.length rest < width then Nothing else do
        let size = if width == 0 then fromIntegral op else readLE (B.take width rest)
            body = B.drop width rest
        if size > fromIntegral (B.length body) then Nothing else do
          let (payload, remaining) = B.splitAt (fromIntegral size) body
          (payload :) <$> go (n-1) remaining

buildScript :: Int64 -> B.ByteString -> Result
buildScript maximumMoney input = do
  let genesis = B.take 32 input
      amount = B.take 8 (B.drop 32 input)
      dest = B.drop 40 input
  check (B.any (/= 0) genesis) "native withdrawal parent genesis is null"
  destination dest "native withdrawal"
  _ <- fee maximumMoney (B.reverse amount)
  pure (envelope [genesis, dest, B.reverse amount])

parseScript :: Int64 -> B.ByteString -> Result
parseScript maximumMoney input = do
  let genesis = B.take 32 input
      script = B.drop 32 input
  check (B.any (/= 0) genesis) "native withdrawal parent genesis is null"
  fields <- maybe (Left "native withdrawal script is malformed or has trailing bytes") Right (pushes 3 script)
  case fields of
    [actual, dest, amount] -> do
      check (B.length actual == 32 && actual == genesis) "native withdrawal script has the wrong parent genesis"
      destination dest "native withdrawal"
      value <- fee maximumMoney amount
      check (script == envelope fields) "native withdrawal script uses a noncanonical push encoding"
      pure (wordLE 8 value <> dest)
    _ -> error "withdrawal push count invariant"

referenceMagic :: B.ByteString
referenceMagic = B.pack [69,76,87,68,1]

parseReference :: B.ByteString -> Result
parseReference script = do
  fields <- maybe (Left canonical) Right (pushes 1 script)
  payload <- case fields of
    [bytes] | B.length bytes == fromIntegral withdrawalReferenceSize && script == envelope fields -> Right bytes
    _ -> Left canonical
  check (B.take 4 payload == B.take 4 referenceMagic) "blinded M6 burn reference has the wrong domain"
  check (B.index payload 4 == 1) "blinded M6 burn reference has an unsupported version"
  let context = B.drop 5 payload
  check (B.any (/= 0) (B.take 32 context)) "blinded M6 burn reference has a null Elements genesis"
  check (B.any (/= 0) (B.take 32 (B.drop 33 context)) && readBE (B.drop 65 context) /= 0xffffffff)
    "blinded M6 burn reference has an unknown burn outpoint"
  pure context
  where canonical = "blinded M6 burn reference is not canonical"

legacyFrame :: B.ByteString -> Result
legacyFrame bytes = do
  check (B.length bytes >= 124 && B.length bytes <= fromIntegral withdrawalLegacySize && B.index bytes 4 == 0 && B.index bytes 5 == 3)
    "blinded M6 does not have the bounded legacy zero-input/three-output frame"
  let referenceSize = fromIntegral withdrawalReferenceSize + 2
  rest <- consume 10 10 (B.drop 6 bytes) >>= consume referenceSize referenceSize >>= consume 1 (fromIntegral withdrawalDestinationSize)
  check (B.length rest == 4) malformed
  pure B.empty
  where
    malformed = "blinded M6 has noncanonical output lengths or trailing bytes"
    consume lo hi remaining = do
      check (B.length remaining >= 9) malformed
      let size = fromIntegral (B.index remaining 8)
      check (size >= lo && size <= hi && B.length remaining >= 9 + size) malformed
      pure (B.drop (9 + size) remaining)

payout :: Int64 -> Int64 -> Int64 -> Either String Int64
payout maximumMoney burn parentFee = case validate (WithdrawalPayout burn parentFee maximumMoney) of
  -1 -> Left "native withdrawal burn amount is outside the money range"
  -2 -> Left "native withdrawal parent fee is outside the money range"
  -3 -> Left "native withdrawal burn amount must exceed its parent fee"
  value -> Right value

amountAt :: Int -> B.ByteString -> Int64
amountAt offset = fromIntegral . readLE . B.take 8 . B.drop offset

buildOutput :: Int64 -> B.ByteString -> Result
buildOutput maximumMoney input = do
  check (B.any (/= 0) (B.take 32 input)) "native withdrawal pegged asset is null"
  _ <- payout maximumMoney (amountAt 64 input) (amountAt 72 input)
  buildScript maximumMoney (B.take 32 (B.drop 32 input) <> B.drop 72 input)

parseOutput :: Int64 -> B.ByteString -> Result
parseOutput maximumMoney input = do
  let asset = B.take 32 input
  check (B.any (/= 0) asset) "native withdrawal pegged asset is null"
  check (B.index input 64 == 1 && B.take 32 (B.drop 32 input) == asset) "native withdrawal asset is not the explicit pegged asset"
  check (B.index input 65 == 1) "native withdrawal value is not explicit"
  check (B.index input 66 == 1) "native withdrawal nonce is not null"
  check (B.index input 67 == 1) "native withdrawal output proofs are not empty"
  parsed <- parseScript maximumMoney (B.drop 76 input)
  value <- payout maximumMoney (amountAt 68 input) (amountAt 0 parsed)
  pure (B.take 8 parsed <> wordLE 8 (fromIntegral value) <> B.drop 8 parsed)

checkContext :: B.ByteString -> Either String ()
checkContext context = do
  check (B.any (/= 0) (B.take 32 context)) "blinded M6 Elements genesis is null"
  check (B.any (/= 0) (B.take 32 (B.drop 33 context)) && readBE (B.take 4 (B.drop 65 context)) /= 0xffffffff)
    "blinded M6 burn outpoint is unknown"

buildM6 :: Int64 -> B.ByteString -> Result
buildM6 maximumMoney input = do
  let context = B.take 69 input
      burn = amountAt 69 input
      parentFee = amountAt 77 input
      requestedPayout = amountAt 85 input
      dest = B.drop 93 input
  checkContext context
  destination dest "blinded M6"
  value <- payout maximumMoney burn parentFee
  check (requestedPayout == 0 || requestedPayout == value) "blinded M6 withdrawal has an inconsistent payout amount"
  let txout amount script = wordLE 8 (fromIntegral amount) <> B.singleton (fromIntegral (B.length script)) <> script
  pure $ B.pack [2,0,0,0,0,3] <> txout (0 :: Int64) (envelope [wordBE 8 (fromIntegral parentFee)]) <>
    txout (0 :: Int64) (envelope [referenceMagic <> context]) <> txout value dest <> B.replicate 4 0

parseM6 :: Int64 -> B.ByteString -> Result
parseM6 maximumMoney input = do
  let context = B.take 69 input
      tx = B.drop 69 input
      shape = "blinded M6 does not have canonical version, inputs, outputs, and locktime"
  checkContext context
  check (B.length tx >= 10 && B.take 6 tx == B.pack [2,0,0,0,0,3] && B.drop (B.length tx-4) tx == B.replicate 4 0) shape
  (feeValue, feeScript, rest) <- txout shape (B.drop 6 tx)
  (referenceValue, referenceScript, rest2) <- txout shape rest
  (value, dest, locktime) <- txout shape rest2
  check (B.length locktime == 4) shape
  check (feeValue == 0 && referenceValue == 0) "blinded M6 commitment outputs are not zero-valued"
  encodedFee <- case pushes 1 feeScript of
    Just [bytes] | B.length bytes == 8 && feeScript == envelope [bytes] -> Right bytes
    _ -> Left "blinded M6 fee commitment is not canonical"
  parentFee <- fee maximumMoney encodedFee
  actual <- parseReference referenceScript
  check (actual == context) "blinded M6 burn reference does not match its Elements outpoint"
  check (not (B.null dest) && B.length dest <= fromIntegral withdrawalDestinationSize && value > 0 && value <= maximumMoney &&
         toInteger parentFee + toInteger value <= toInteger maximumMoney) "blinded M6 payout is outside canonical bounds"
  pure (wordLE 8 parentFee <> wordLE 8 (parentFee + fromIntegral value))
  where
    -- Upstream serializes these objects. CompactSize is decoded only for the
    -- three output scripts; no attacker-supplied count allocates a collection.
    txout message bytes = do
      check (B.length bytes >= 9) message
      let tag = B.index bytes 8
          width | tag < 253 = 0
                | otherwise = 2 ^ (fromIntegral tag - 252 :: Int)
      check (B.length bytes >= 9 + width) message
      let size = if width == 0 then fromIntegral tag else readLE (B.take width (B.drop 9 bytes))
          body = B.drop (9 + width) bytes
      check (size <= fromIntegral (B.length body)) message
      let (script, remaining) = B.splitAt (fromIntegral size) body
      pure (amountAt 0 bytes, script, remaining)

-- Version-1 call envelopes are private ABI bytes, not new consensus encodings.
-- Context = genesis[32], slot[1], burn txid[32], vout[4, BE].
withdrawal :: Word32 -> Int64 -> B.ByteString -> Result
withdrawal op maximumMoney input
  | op >= 1 && op <= fromIntegral (fromEnum (maxBound :: WithdrawalAction) + 1) =
      execute (WithdrawalRequest maximumMoney input) withdrawRules (toEnum (fromIntegral op - 1))
  | otherwise = error "invalid withdrawal FFI request"

encodeRpcResult :: Either (Int32, String) B.ByteString -> B.ByteString
encodeRpcResult = either (\(code,message) -> wordLE 4 (fromIntegral code) <> C.pack message) (wordLE 4 0 <>)

nativeOutputSelection :: Int64 -> B.ByteString -> Either (Int32, String) B.ByteString
nativeOutputSelection maximumMoney input = go Nothing records
  where
    (script,records) = B.splitAt (fromIntegral (readLE (B.take 4 (B.drop 88 input)))) (B.drop 92 input)
    failure message = Left (-4,message)
    go found remaining
      | B.null remaining = maybe (failure "Committed transaction is missing its exact native withdrawal burn")
          Right found
      | otherwise =
          let (record,rest) = B.splitAt 49 remaining
              parsed = parseOutput maximumMoney (B.take 32 input <> B.take 44 (B.drop 4 record) <> B.take 32 (B.drop 32 input) <> script)
          in if B.index record 48 /= 1 then go found rest else case parsed of
            Right values | amountAt 40 record == amountAt 64 input &&
                amountAt 8 values == amountAt 72 input && amountAt 0 values == amountAt 80 input ->
              case found of
                Just _ -> failure "Committed transaction contains multiple native withdrawal burns"
                Nothing -> go (Just (B.take 4 record)) rest
            _ -> go found rest

nativeGuard :: B.ByteString -> Either (Int32, String) ()
nativeGuard input
  | B.index input 1 == (if stage == 2 then 0 else 1) = Right ()
  | otherwise = Left $ case stage of
      0 -> (-32601, "Native BIP300 withdrawals are not enabled on this network")
      1 -> (-32601, "Native BIP300 withdrawals are disabled on this drivechain: full M3/M4/M6 withdrawal-vote and CTIP-decrease consensus validation is not implemented")
      2 -> (-8, "subtractfeefromamount is not supported for native BIP300 withdrawals; the Elements fee must remain separate from the exact burn")
      3 -> (-8, "The resulting irreversible burn is not relayable under this Elements network's standard policy")
      _ -> (-1, "sendtomainchain is unavailable outside an Elements parent-chain configuration")
  where stage = B.head input

instance WithdrawalRule WithdrawalRequest where
  withdrawalBody action (WithdrawalRequest maximumMoney input) = case action of
    BuildScript -> buildScript maximumMoney input
    ParseScript -> parseScript maximumMoney input
    BuildReference -> Right (referenceMagic <> input)
    ParseReference -> parseReference input
    LegacyFrame -> legacyFrame input
    DecodeFee -> wordLE 8 <$> fee maximumMoney input
    EncodeFee -> Right (B.reverse input)
    BuildOutput -> buildOutput maximumMoney input
    ParseOutput -> parseOutput maximumMoney input
    BuildM6 -> buildM6 maximumMoney input
    ParseM6 -> parseM6 maximumMoney input
    Reserved12 -> error "retired withdrawal operation"
    StateAnchor -> Right (B.pack [1,24] <> B.take 32 (B.drop 4 input) <>
                         B.reverse (B.take 4 input) <> B.drop 36 input)
    WalletBundle -> do
      let value = validate (WithdrawalPayout (amountAt 0 input) (amountAt 8 input) maximumMoney)
          size = readLE (B.take 8 (B.drop 16 input))
      check (value > 0 && size > 0 && size <= 10000 && B.index input 24 == 1)
        "Invalid blinded withdrawal amount, fee, payout, or outpoint"
      pure (wordLE 8 (fromIntegral value) <> envelope [B.reverse (B.take 8 (B.drop 8 input))])
    WalletAnchor -> do
      check (all (\offset -> B.any (/=0) (B.take 32 (B.drop offset input))) [4,68,100])
        "Cannot create PXST marker with a null consensus commitment"
      withdrawalBody StateAnchor (WithdrawalRequest maximumMoney input)
    StateMarker -> Right (envelope [B.pack [80,88,83,84,1] <> input])
    WalletTransport -> Right (walletTransport input)
    JournalLegacy -> Right (B.take 4 input <> B.drop 6 input)
    RpcFee -> do
      let parentFee = amountAt 8 input
      check (parentFee > 0 && parentFee <= maximumMoney && parentFee < amountAt 0 input)
        "-drivechainpegoutmainfeesats must be positive and less than the withdrawal amount"
      pure (B.drop 8 input)
    EventPolicy ->
      let failed = input == C.pack "failed"
      in Right (B.pack [if B.null input then 1 else if failed then 2 else 0,
                        if failed || input == C.pack "succeeded" then 1 else 0])
    BundleAdmission -> do
      check (B.head input <= 1) "invalid withdrawal reservation flag"
      let current = B.take 32 (B.drop 1 input)
      pure (B.pack [if B.head input == 0 && B.all (==0) current then 1 else 0,
                    if current == B.drop 33 input then 1 else 0])
    NativeGuard -> either (Left . snd) (const (Right B.empty)) (nativeGuard input)
    SubmissionPolicy -> Right $ B.singleton $ case B.head input of
      0 -> let slot = fromIntegral (readLE (B.take 4 (B.drop 1 input))) :: Int32
               count = readLE (B.take 8 (B.drop 5 input))
           in if slot < 0 || slot > 255 then 1
              else if count == 0 || count > 1048576 then 2
              else if B.last input == 1 then 3 else 0
      _ -> let flags = B.index input 1
               has bit = flags .&. bit /= 0
               duplicate = if B.head input == 1 then has 128 else
                 B.index input 2 == 1 && C.pack "AlreadyExists"
                   `B.isInfixOf` B.drop 3 input
           in if has 1 then 4 else if not (has 2) then 5
              else if has 4 then 6 else if has 8 then 7
              else if has 16 then 8 else if not (has 32) then 9
              else if not (has 64 || duplicate) then 10 else 0
    ProofBounds -> Right $ encodeRpcResult $ do
      let index = readLE (B.take 8 (B.drop 1 input))
          count = readLE (B.drop 9 input)
      if B.head input == 0
        then unless ((fromIntegral index :: Int64) >= 0)
          (Left (-8,"Withdrawal index must not be negative"))
        else do
          unless (index < count) (Left (-8,"Withdrawal index is outside this accumulator"))
          unless (count <= 10000) (Left (-1,"Proof reconstruction exceeds the safe RPC limit; use a dedicated permissionless indexer"))
      pure B.empty
    RpcAdmission -> Right $ encodeRpcResult $ do
      let stage = B.head input
          flags = B.index input 1
          depth = fromIntegral (readLE (B.take 4 (B.drop 2 input))) :: Int32
          required = fromIntegral (readLE (B.drop 6 input)) :: Int32
          require condition code message = unless condition (Left (code,message))
      case stage of
        0 -> do
          nativeGuard (B.pack [0, flags .&. 1])
          require (required >= 1 && required <= 100000) (-8) "minconfirmations must be between 1 and 100000"
        1 -> do
          require (flags .&. 1 /= 0) (-5) "Confirming block is not in the active Elements chain"
          require (flags .&. 2 /= 0) (-1) "Confirming block data is unavailable on this pruned node"
          require (depth >= required) (-25)
            ("Native withdrawal burn has " ++ show depth ++ " confirmation(s); " ++ show required ++ " required")
        _ -> do
          require (flags .&. 1 /= 0) (-25) (if stage == 2
            then "Confirming block left the active Elements chain while the withdrawal was authenticated"
            else "Confirming block left the active Elements chain during parent withdrawal replay")
          require (depth >= required) (-25) (if stage == 2
            then "Withdrawal no longer has the required active-chain depth"
            else "Withdrawal lost the required active-chain depth during parent withdrawal replay")
      pure B.empty
    ParentPolicy -> do
      dust <- withdrawalBody ParentDust (WithdrawalRequest maximumMoney (B.drop 5 input))
      pure (B.singleton (if B.index input 4 == 1 && spendableParentType (fromIntegral (readLE (B.take 4 input)))
        then 1 else 0) <> dust)
    NativeGuardResult -> Right (encodeRpcResult (B.empty <$ nativeGuard input))
    InputsCommitment -> Right (inputsCommitment input)
    JournalAdmission -> do
      let version = readLE (B.take 4 input)
          state = B.index input 4
          amount = amountAt 5 input
          parentFee = amountAt 13 input
          slot = fromIntegral (readLE (B.take 4 (B.drop 21 input))) :: Int32
          flags = B.index input 33 .|. (if B.length input==42 &&
            (B.index input 34<7 || B.take 2 (B.drop 39 input)/=B.pack [0,1]) then 32 else 0)
      check (version == 1) ("unsupported journal version " ++ show version)
      check (state <= 4) ("unknown journal state " ++ show state)
      check (flags .&. 1 == 0) "journal contains a null M6 or sidechain transaction id"
      check (amount > 0 && amount <= maximumMoney && parentFee > 0 && parentFee < amount && parentFee <= maximumMoney)
        "journal amount or mainchain fee is out of range"
      check (slot >= 0 && slot <= 255 && flags .&. 30 == 0)
        "journal identity, destination, payout script, or bundle is invalid"
      check (amountAt 25 input > 0) "journal creation time is invalid"
      check (flags .&. 32 == 0) "journal bundle is not the expected witness-encoded M6 transaction"
      pure B.empty
    JournalIdentity -> do
      check (B.take 32 input == B.drop 32 input) "journal M6 identity does not match its serialized bundle"
      pure B.empty
    NativeOutputSelection -> Right (encodeRpcResult (nativeOutputSelection maximumMoney input))
    NativeBurnPlan -> Right $ encodeRpcResult $ do
      total <- Bi.first ((,) (-3)) $ withdrawalBody NativeAmount
        (WithdrawalRequest maximumMoney (B.singleton 1 <> B.take 16 input))
      script <- Bi.first ((,) (-8)) $ withdrawalBody BuildScript (WithdrawalRequest maximumMoney
        (B.take 32 (B.drop 16 input) <> B.take 8 (B.drop 8 input) <> B.drop 48 input))
      pure (total <> script)
    NativePayout -> do
      dust <- withdrawalBody ParentDust (WithdrawalRequest maximumMoney (B.drop 8 input))
      let netAmount = amountAt 0 input
          threshold = readLE dust
          code :: Int32
          code | netAmount <= 0 || netAmount > maximumMoney = -3
               | fromIntegral netAmount < threshold = -8
               | otherwise = 0
      pure (wordLE 4 (fromIntegral code) <> dust)
    ParentDust ->
      let outputSize = fromIntegral (readLE (B.take 4 input)) :: Word32
          spendSize = if B.index input 4 == 1 then 67 else 148
      in Right (wordLE 8 (3 * fromIntegral (outputSize+spendSize)))
    NativeAmount -> do
      let netAmount = amountAt 1 input
          parentFee = amountAt 9 input
      if B.head input /= 1 then do
        let legacy = B.head input == 2
        check (netAmount > 0 && (legacy || netAmount <= maximumMoney))
          (if legacy then "Invalid amount for send" else "Invalid withdrawal payout amount")
        pure (wordLE 8 (fromIntegral netAmount))
      else do
        check (parentFee >= 0 && parentFee <= maximumMoney && netAmount <= maximumMoney-parentFee)
          "Invalid mainchain fee or withdrawal total"
        pure (wordLE 8 (fromIntegral (netAmount+parentFee)))
