{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, GADTs, PolyKinds, ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies, ForeignFunctionInterface #-}
module OperationTests (dispatchMatrix, mismatchIsLazy, withdrawalDispatch, dispatchFaults, deferredEffects, withdrawalCapabilities, signetCapabilities, lazyWorkflows) where

import Control.Exception (ErrorCall, displayException, evaluate, try)
import Control.Monad (forM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.IORef (IORef, newIORef, readIORef, writeIORef, modifyIORef')
import Data.Int (Int32, Int64)
import Data.List (isPrefixOf)
import Data.Word (Word8)
import qualified Deposit as D
import qualified Bmm
import qualified ParentReplay
import Drivechain
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (FunPtr, castPtr, nullPtr, nullFunPtr)
import Foreign.Storable (peek, poke)
import Control.Operation
import Control.Operation.Validation
import Test.QuickCheck
import Withdrawal
import Workflow

foreign import ccall "&reference_empty_fingerprint" emptyFingerprint :: FunPtr Bmm.ReadFingerprint
foreign import ccall "&reference_empty_state_write" emptyStateWriter :: FunPtr Bmm.WriteState

foreign import ccall "&reference_live_empty" emptyLiveFields :: FunPtr D.ReadPegFields
foreign import ccall "&reference_signet_empty" emptySignetFields :: FunPtr D.ReadPegFields

-- An unrelated class extends dispatch without changing Operation or production rules.
data Probe = Probe Int32 (IORef Int)
class Counted op where
  countCall :: op -> IO Int32
instance Counted Probe where
  countCall (Probe value calls) = modifyIORef' calls (+1) >> pure value
instance Validation Probe where
  type ValidationResult Probe = IO Int32
  validate = countCall
type ProbeCapabilities = '[Counted, Labelled, Adjustable]
countProbe :: DSL Probe
countProbe = CountCall

instance Operation Probe ProbeCapabilities where
  type Context Probe = Counted Probe
  type Outcome Probe = IO Int32
  data DSL Probe where
    CountCall :: Context Probe => DSL Probe
  interpret operation request = withOperation @Probe operation $ \value -> case request of
    CountCall -> Just (countCall value)

lazyWorkflows :: Property
lazyWorkflows = conjoin $
  [ absent (undefined :: DSL WithdrawalRequest)
  , absent (undefined :: DSL WalletBundleRequest)
  , absent (undefined :: DSL Bmm.GrpcPlan)
  , absent (undefined :: DSL Bmm.ReplacementBid)
  , absent (undefined :: DSL Bmm.SubmissionRequest)
  , absent (undefined :: DSL Bmm.StateEncode)
  , absent (undefined :: DSL Bmm.StateWrite)
  , absent (undefined :: DSL Bmm.FingerprintRequest)
  , absent (undefined :: DSL Bmm.SignetRequest)
  , absent (undefined :: DSL Bmm.BodyRecovery)
  , cold (undefined :: WithdrawalRequest) withdrawRules
  , cold (undefined :: WalletBundleRequest) buildWalletBundle
  , cold (undefined :: Bmm.GrpcPlan) Bmm.planGrpc
  , cold (undefined :: Bmm.ReplacementBid) (Bmm.ReplaceBid undefined)
  , cold (undefined :: Bmm.SubmissionRequest) (Bmm.submitBmm undefined undefined)
  , cold (undefined :: Bmm.StateEncode) Bmm.encodeState
  , cold (undefined :: Bmm.StateWrite) Bmm.replaceState
  , cold (undefined :: Bmm.SignetRequest) Bmm.extractSignetRequest
  , cold (undefined :: Bmm.BodyRecovery) Bmm.RecoverBody
  ] ++ [cold (undefined :: Bmm.FingerprintRequest) (Bmm.fingerprint format)
        | format <- [Bmm.BmmFormat]]
  where
    absent :: Operation op caps => DSL op -> Property
    absent request = (() <$ interpret (SomeOperation (undefined :: Probe)) request) === Nothing
    cold :: (Operation op caps, Capabilities caps op) => op -> DSL op -> Property
    cold value request = (() <$ interpret (SomeOperation value) request) === Just ()

dispatchMatrix :: Property
dispatchMatrix = forAllShrink arbitrary shrink $ \(d,t,n,script,opcode,burn,fee,value,raw) -> ioProperty $ do
  calls <- newIORef 0
  let depth = DepositDepth d t n
      treasury = TreasuryScript script opcode
      payout = WithdrawalPayout burn fee maximumMoney
      request = WithdrawalRequest maximumMoney (B.pack raw)
      witnessRequest = D.DepositWitness maximumMoney 100 0 0 nullPtr nullPtr nullPtr nullPtr nullPtr nullFunPtr nullPtr
      recipients = D.DepositOutputs 14 value [3,0] [(7,value)]
      authenticated = D.AuthenticatedDeposit 1 0 1 127 value value 1 [(23,value)]
      evidence = D.DeterministicEvidence 100 0 nullPtr nullPtr nullPtr nullFunPtr nullFunPtr nullPtr
      inclusion = D.DepositInclusion 0 0 0 nullFunPtr nullPtr
      ctip = D.DepositCtip 3 1 20 10 10
      persisted = D.PersistedCtip 0 0 0 nullFunPtr nullPtr
      state = D.DepositStateRule 1 5
      checkpoint = D.CheckpointLookup 0 nullPtr nullPtr 0
      legacyClaim = D.LegacyClaim 3 2000 2000
      destination = D.DepositDestination 0 nullFunPtr nullPtr
      live = D.LiveEvidence 1 emptyLiveFields nullPtr
      pegEvent = D.PegEvent 0 4 4 0
      bmmState = Bmm.ParentState 1 2016 4031 1 1 2016 1 11 1
      bmmHeader = Bmm.Header 2
      bmmProof = Bmm.Proof 3 1 1 1 0
      payloads :: [SomeOperation]
      payloads = [SomeOperation (Check depth), SomeOperation (Check treasury), SomeOperation (Check payout),
                  SomeOperation request, SomeOperation (Check witnessRequest), SomeOperation (Check recipients),
                  SomeOperation (Probe 42 calls), SomeOperation (Check (Probe 42 calls)),
                  SomeOperation (Check authenticated), SomeOperation (Check evidence),
                  SomeOperation (Check inclusion), SomeOperation (Check ctip), SomeOperation (Check persisted),
                  SomeOperation (Check state), SomeOperation (Check checkpoint),
                  SomeOperation (Check legacyClaim), SomeOperation (Check destination), SomeOperation (Check live),
                  SomeOperation (Check pegEvent), SomeOperation (Check bmmState), SomeOperation (Check bmmHeader),
                  SomeOperation (Check bmmProof), SomeOperation (Check (Bmm.Commitment 0 24 0 nullFunPtr nullPtr)),
                  SomeOperation (Check (Bmm.Retarget 100 2016 1209600 100000 40000)),
                  SomeOperation (Check (Bmm.Activation 0 2 0 0)),
                  SomeOperation (Bmm.SignetRequest emptySignetFields nullPtr),
                  SomeOperation (Check (Bmm.HashPlan 1 0 0)),
                  SomeOperation (Check (Bmm.SignetValidation 0 0 0 0 0)),
                  SomeOperation (Check (Bmm.Codec 0 0 1 1)),
                  SomeOperation (Check (Bmm.Traversal 0 0 0)),
                  SomeOperation (Check (Bmm.Advance 1 0 0 (replicate 16 0))),
                  SomeOperation (Check (Bmm.StateSource 0 0)),
                  SomeOperation (Check (Bmm.Lifecycle 0 0)),
                  SomeOperation (Check (Bmm.StateFlow 0 0)),
                  SomeOperation (Bmm.FingerprintRequest emptyFingerprint nullPtr),
                  SomeOperation (Check (Bmm.TargetScale 0 1 (replicate 32 255) (replicate 32 255))),
                  SomeOperation (Bmm.StateWrite 0 emptyStateWriter nullPtr),
                  SomeOperation (Bmm.StateEncode (Bmm.StateWrite 0 emptyStateWriter nullPtr)),
                  SomeOperation (Check (Bmm.PrivateTemplate 0 0 0 24 (replicate 32 0))),
                  SomeOperation (Check (Bmm.Preimage 0)),
                  SomeOperation (Check (Bmm.SignatureBytes [42,129])),
                  SomeOperation (Check Bmm.SignetTemplate),
                  SomeOperation (Check (Bmm.SignetActions 0)),
                  SomeOperation (Check (Bmm.CommitmentBytes 1 (replicate 32 42))),
                  SomeOperation (Check (Bmm.DifficultyInterval 1209600 600)),
                  SomeOperation (Check (Bmm.ConsensusPreset 1)),
                  SomeOperation (Check (Bmm.CheckpointPreset 0)),
                  SomeOperation (Check Bmm.FixedIdentity),
                  SomeOperation (Check (D.EventIdentity 1 (C.pack "hash") 7 0)),
                  SomeOperation (Check (D.EventLayout 0 0 0)),
                  SomeOperation (Check (ParentReplay.Record 0 0 0 4 5)),
                  SomeOperation (Check (ParentReplay.Message [])), SomeOperation (Check (Bmm.HeaderLayout 0 13)),
                  SomeOperation (Check (D.ConfirmationPolicy 1 64 100 (const (pure 1))))]
      expected index target result = if index == target then Just result else Nothing
  checks <- forM (zip [0 :: Int ..] payloads) $ \(i,op) -> do
    witnessResult <- sequence (interpret op (Validate @D.DepositWitness))
    confirmationResult <- sequence (interpret op (Validate @D.ConfirmationPolicy))
    probeResult <- sequence (interpret op countProbe)
    checkedProbe <- sequence (interpret op (Validate @Probe))
    evidenceResult <- sequence (interpret op (Validate @D.DeterministicEvidence))
    inclusionResult <- sequence (interpret op (Validate @D.DepositInclusion))
    persistedResult <- sequence (interpret op (Validate @D.PersistedCtip))
    checkpointResult <- sequence (interpret op (Validate @D.CheckpointLookup))
    destinationResult <- sequence (interpret op (Validate @D.DepositDestination))
    liveResult <- sequence (interpret op (Validate @D.LiveEvidence))
    commitmentResult <- sequence (interpret op (Validate @Bmm.Commitment))
    signetResult <- sequence (interpret op Bmm.extractSignetRequest)
    fingerprintResult <- sequence (interpret op (Bmm.fingerprint Bmm.BmmFormat))
    storageResult <- sequence (interpret op Bmm.replaceState)
    encodingResult <- sequence (interpret op Bmm.encodeState)
    pure $ conjoin
      [confirmationResult === expected i 53 6,
       interpret op (Validate @DepositDepth) === expected i 0 (validate depth),
       interpret op (Validate @TreasuryScript) === expected i 1 (validate treasury),
       interpret op (Validate @WithdrawalPayout) === expected i 2 (validate payout),
       (($ LegacyFrame) <$> interpret op withdrawRules) === expected i 3 (applyWithdrawal LegacyFrame request),
       witnessResult === expected i 4 0,
       interpret op (Validate @D.DepositOutputs) === expected i 5 (validate recipients),
       probeResult === expected i 6 42, checkedProbe === expected i 7 42,
       interpret op (Validate @D.AuthenticatedDeposit) === expected i 8 (validate authenticated),
       evidenceResult === expected i 9 1, inclusionResult === expected i 10 1,
       interpret op (Validate @D.DepositCtip) === expected i 11 0, persistedResult === expected i 12 1,
       interpret op (Validate @D.DepositStateRule) === expected i 13 0,
       checkpointResult === expected i 14 B.empty,
       interpret op (Validate @D.LegacyClaim) === expected i 15 0,
       destinationResult === expected i 16 (-1), liveResult === expected i 17 10,
       interpret op (Validate @D.PegEvent) === expected i 18 2,
       interpret op (Validate @Bmm.ParentState) === expected i 19 0,
       interpret op (Validate @Bmm.Header) === expected i 20 6,
       interpret op (Validate @Bmm.Proof) === expected i 21 0,
       commitmentResult === expected i 22 (-1),
       interpret op (Validate @Bmm.Timing) === expected i 23 (-1),
       interpret op (Validate @Bmm.Activation) === expected i 24 2, signetResult === expected i 25 1,
       interpret op (Validate @Bmm.Signature) === expected i 26 7,
       interpret op (Validate @Bmm.SignetValidation) === expected i 27 1,
       interpret op (Validate @Bmm.Codec) === expected i 28 0,
       interpret op (Validate @Bmm.Traversal) === expected i 29 1,
       interpret op (Validate @Bmm.Advance) === expected i 30 ([1,0,0,1,0] ++ replicate 11 0),
       interpret op (Validate @Bmm.StateSource) === expected i 31 1,
       interpret op (Validate @Bmm.Lifecycle) === expected i 32 2,
       interpret op (Validate @Bmm.StateFlow) === expected i 33 1,
       fingerprintResult === expected i 34 ([0,0,0,4] ++ replicate 95 0),
       interpret op (Validate @Bmm.TargetScale) === expected i 35 (replicate 32 0),
       storageResult === expected i 36 (), encodingResult === expected i 37 (),
       interpret op (Validate @Bmm.PrivateTemplate) === expected i 38
         ([2,1,0x20000000,1], [0xd1,0x61,0x73,0x68,24] ++ replicate 32 0),
       interpret op (Validate @Bmm.Preimage) === expected i 39 [0..9],
       interpret op (Validate @Bmm.SignatureBytes) === expected i 40 (1,129),
       interpret op (Validate @Bmm.SignetTemplate) === expected i 41 [0,0,0,0,0,106],
       interpret op (Validate @Bmm.SignetActions) === expected i 42 [0..5],
       interpret op (Validate @Bmm.CommitmentBytes) === expected i 43 (replicate 32 42),
       interpret op (Validate @Bmm.DifficultyInterval) === expected i 44 2016,
       interpret op (Validate @Bmm.ConsensusPreset) === expected i 45
         ([1209600,600,24,128,1000000,0],replicate 31 255 ++ [127],[]),
       interpret op (Validate @Bmm.CheckpointPreset) === expected i 46
         ([6400,1784826005,0x1e0376cc,6048,1784614805] ++ [1784820005,1784820605,
           1784821205,1784821805,1784822405,1784823005,1784823605,1784824205,
           1784824805,1784825405,1784826005], [0x65,0x76,0x74,0x19,0x0b,0x9b,0xd4,0x39,0xb4,0x7f,0xff,0x98,0xfb,0x29,0xde,0x90,0xee,0x6c,0xab,0xc0,0x8c,0xd4,0xeb,0xd1,0x4e,0x84,0x9e,0xb6,0x1b,0x03,0x00,0x00]),
       fmap fst (interpret op (Validate @Bmm.FixedIdentity)) === expected i 47 [0,2069],
       interpret op (Validate @D.EventIdentity) === expected i 48 (C.pack "sidechain:deposit:hash:7"),
       interpret op (Validate @D.EventLayout) === expected i 49 (Just (C.pack "event_id",Nothing,False)),
       interpret op (Validate @ParentReplay.Record) === expected i 50 4,
       interpret op (Validate @ParentReplay.Message) === expected i 51 (0,0,[]),
       interpret op (Validate @Bmm.HeaderLayout) === expected i 52 (Just (0xc0000000,65))]
  observed <- readIORef calls
  pure (conjoin ((observed === 2) : checks))

-- A type mismatch must not force the hidden payload (including borrowed pointers).
mismatchIsLazy :: Property
mismatchIsLazy = forAll (chooseInt (0,53)) $ \index -> ioProperty $ do
  let bottom = error "mismatched payload was evaluated"
      payloads :: [SomeOperation]
      payloads = [SomeOperation (bottom :: Check DepositDepth), SomeOperation (bottom :: Check TreasuryScript),
                  SomeOperation (bottom :: Check WithdrawalPayout), SomeOperation (bottom :: WithdrawalRequest),
                  SomeOperation (bottom :: Check D.DepositWitness), SomeOperation (bottom :: Check D.DepositOutputs),
                  SomeOperation (bottom :: Probe), SomeOperation (bottom :: Check Probe),
                  SomeOperation (bottom :: Check D.AuthenticatedDeposit),
                  SomeOperation (bottom :: Check D.DeterministicEvidence),
                  SomeOperation (bottom :: Check D.DepositInclusion), SomeOperation (bottom :: Check D.DepositCtip),
                  SomeOperation (bottom :: Check D.PersistedCtip), SomeOperation (bottom :: Check D.DepositStateRule),
                  SomeOperation (bottom :: Check D.CheckpointLookup), SomeOperation (bottom :: Check D.LegacyClaim),
                  SomeOperation (bottom :: Check D.DepositDestination), SomeOperation (bottom :: Check D.LiveEvidence),
                  SomeOperation (bottom :: Check D.PegEvent), SomeOperation (bottom :: Check Bmm.ParentState),
                  SomeOperation (bottom :: Check Bmm.Header), SomeOperation (bottom :: Check Bmm.Proof),
                  SomeOperation (bottom :: Check Bmm.Commitment), SomeOperation (bottom :: Check Bmm.Timing),
                  SomeOperation (bottom :: Check Bmm.Activation), SomeOperation (bottom :: Bmm.SignetRequest),
                  SomeOperation (bottom :: Check Bmm.Signature),
                  SomeOperation (bottom :: Check Bmm.SignetValidation),
                  SomeOperation (bottom :: Check Bmm.Codec),
                  SomeOperation (bottom :: Check Bmm.Traversal),
                  SomeOperation (bottom :: Check Bmm.Advance),
                  SomeOperation (bottom :: Check Bmm.StateSource),
                  SomeOperation (bottom :: Check Bmm.Lifecycle),
                  SomeOperation (bottom :: Check Bmm.StateFlow),
                  SomeOperation (bottom :: Bmm.FingerprintRequest),
                  SomeOperation (bottom :: Check Bmm.TargetScale),
                  SomeOperation (bottom :: Bmm.StateWrite),
                  SomeOperation (bottom :: Bmm.StateEncode),
                  SomeOperation (bottom :: Check Bmm.PrivateTemplate),
                  SomeOperation (bottom :: Check Bmm.Preimage),
                  SomeOperation (bottom :: Check Bmm.SignatureBytes),
                  SomeOperation (bottom :: Check Bmm.SignetTemplate),
                  SomeOperation (bottom :: Check Bmm.SignetActions),
                  SomeOperation (bottom :: Check Bmm.CommitmentBytes),
                  SomeOperation (bottom :: Check Bmm.DifficultyInterval),
                  SomeOperation (bottom :: Check Bmm.ConsensusPreset),
                  SomeOperation (bottom :: Check Bmm.CheckpointPreset),
                  SomeOperation (bottom :: Check Bmm.FixedIdentity),
                  SomeOperation (bottom :: Check D.EventIdentity),
                  SomeOperation (bottom :: Check D.EventLayout), SomeOperation (bottom :: Check ParentReplay.Record),
                  SomeOperation (bottom :: Check ParentReplay.Message), SomeOperation (bottom :: Check Bmm.HeaderLayout),
                  SomeOperation (bottom :: Check D.ConfirmationPolicy)]
      op = payloads !! index
  fingerprintResult <- if index == 34 then pure Nothing else sequence (interpret op (Bmm.fingerprint Bmm.BmmFormat))
  storageResult <- if index == 36 then pure Nothing else sequence (interpret op Bmm.replaceState)
  encodingResult <- if index == 37 then pure Nothing else sequence (interpret op Bmm.encodeState)
  witnessResult <- if index == 4 then pure Nothing else sequence (interpret op (Validate @D.DepositWitness))
  probeResult <- if index == 6 then pure Nothing else sequence (interpret op countProbe)
  checkedProbe <- if index == 7 then pure Nothing else sequence (interpret op (Validate @Probe))
  evidenceResult <- if index == 9 then pure Nothing else sequence (interpret op (Validate @D.DeterministicEvidence))
  inclusionResult <- if index == 10 then pure Nothing else sequence (interpret op (Validate @D.DepositInclusion))
  persistedResult <- if index == 12 then pure Nothing else sequence (interpret op (Validate @D.PersistedCtip))
  checkpointResult <- if index == 14 then pure Nothing else sequence (interpret op (Validate @D.CheckpointLookup))
  destinationResult <- if index == 16 then pure Nothing else sequence (interpret op (Validate @D.DepositDestination))
  liveResult <- if index == 17 then pure Nothing else sequence (interpret op (Validate @D.LiveEvidence))
  commitmentResult <- if index == 22 then pure Nothing else sequence (interpret op (Validate @Bmm.Commitment))
  signetResult <- if index == 25 then pure Nothing else sequence (interpret op Bmm.extractSignetRequest)
  pure $ conjoin
    [if index == 0 then property True else interpret op (Validate @DepositDepth) === Nothing,
     if index == 1 then property True else interpret op (Validate @TreasuryScript) === Nothing,
     if index == 2 then property True else interpret op (Validate @WithdrawalPayout) === Nothing,
     if index == 3 then property True else (() <$ interpret op withdrawRules) === Nothing,
     witnessResult === Nothing,
     if index == 5 then property True else interpret op (Validate @D.DepositOutputs) === Nothing,
     probeResult === Nothing, checkedProbe === Nothing,
     if index == 8 then property True else interpret op (Validate @D.AuthenticatedDeposit) === Nothing,
     evidenceResult === Nothing, inclusionResult === Nothing,
     if index == 11 then property True else interpret op (Validate @D.DepositCtip) === Nothing,
     persistedResult === Nothing,
     if index == 13 then property True else interpret op (Validate @D.DepositStateRule) === Nothing,
     checkpointResult === Nothing,
     if index == 15 then property True else interpret op (Validate @D.LegacyClaim) === Nothing,
     destinationResult === Nothing, liveResult === Nothing,
     if index == 18 then property True else interpret op (Validate @D.PegEvent) === Nothing,
     if index == 19 then property True else interpret op (Validate @Bmm.ParentState) === Nothing,
     if index == 20 then property True else interpret op (Validate @Bmm.Header) === Nothing,
     if index == 21 then property True else interpret op (Validate @Bmm.Proof) === Nothing,
     commitmentResult === Nothing,
     if index == 23 then property True else interpret op (Validate @Bmm.Timing) === Nothing,
     if index == 24 then property True else interpret op (Validate @Bmm.Activation) === Nothing,
     signetResult === Nothing,
     if index == 26 then property True else interpret op (Validate @Bmm.Signature) === Nothing,
     if index == 27 then property True else interpret op (Validate @Bmm.SignetValidation) === Nothing,
     if index == 28 then property True else interpret op (Validate @Bmm.Codec) === Nothing,
     if index == 29 then property True else interpret op (Validate @Bmm.Traversal) === Nothing,
     if index == 30 then property True else interpret op (Validate @Bmm.Advance) === Nothing,
     if index == 31 then property True else interpret op (Validate @Bmm.StateSource) === Nothing,
     if index == 32 then property True else interpret op (Validate @Bmm.Lifecycle) === Nothing,
     if index == 33 then property True else interpret op (Validate @Bmm.StateFlow) === Nothing,
     fingerprintResult === Nothing,
     if index == 35 then property True else interpret op (Validate @Bmm.TargetScale) === Nothing,
     storageResult === Nothing, encodingResult === Nothing,
     if index == 38 then property True else interpret op (Validate @Bmm.PrivateTemplate) === Nothing,
     if index == 39 then property True else interpret op (Validate @Bmm.Preimage) === Nothing,
     if index == 40 then property True else interpret op (Validate @Bmm.SignatureBytes) === Nothing,
     if index == 41 then property True else interpret op (Validate @Bmm.SignetTemplate) === Nothing,
     if index == 42 then property True else interpret op (Validate @Bmm.SignetActions) === Nothing,
     if index == 43 then property True else interpret op (Validate @Bmm.CommitmentBytes) === Nothing,
     if index == 44 then property True else interpret op (Validate @Bmm.DifficultyInterval) === Nothing,
     if index == 45 then property True else interpret op (Validate @Bmm.ConsensusPreset) === Nothing,
     if index == 46 then property True else interpret op (Validate @Bmm.CheckpointPreset) === Nothing,
     if index == 47 then property True else interpret op (Validate @Bmm.FixedIdentity) === Nothing,
     if index == 48 then property True else interpret op (Validate @D.EventIdentity) === Nothing,
     if index == 49 then property True else interpret op (Validate @D.EventLayout) === Nothing,
     if index == 50 then property True else interpret op (Validate @ParentReplay.Record) === Nothing,
     if index == 51 then property True else interpret op (Validate @ParentReplay.Message) === Nothing,
     if index == 52 then property True else interpret op (Validate @Bmm.HeaderLayout) === Nothing,
     if index == 53 then property True else property (case interpret op (Validate @D.ConfirmationPolicy) of Nothing -> True; Just _ -> False)]

data ScriptProbe = ScriptProbe (IORef [Bmm.ScriptStep]) (IORef [Bmm.ScriptEdit])
instance Bmm.ScriptStream ScriptProbe where
  nextScriptStep (ScriptProbe steps _) = do
    remaining <- readIORef steps
    case remaining of
      [] -> error "script read after termination"
      step:rest -> writeIORef steps rest >> pure step
instance Bmm.ScriptRewrite ScriptProbe where
  editScript (ScriptProbe _ edits) action = modifyIORef' edits (action :)
instance Finalize ScriptProbe where
  type FinalInput ScriptProbe = Bool
  type FinalResult ScriptProbe = Int32
  finalize probe found = do
    if found then Bmm.editScript probe Bmm.PublishScript else pure ()
    pure 1

signetCapabilities :: NonNegative Int -> Bool -> Property
signetCapabilities (NonNegative n) complete = ioProperty $ do
  let count = n `mod` 10
  steps <- newIORef ([Bmm.ScriptPush 4 0xa2dac7ec, Bmm.ScriptPush 0 0] ++
    replicate count (Bmm.ScriptPush 5 0xa2dac7ec) ++ [Bmm.ScriptEnd complete])
  edits <- newIORef []
  result <- Bmm.extractSignet (ScriptProbe steps edits)
  actual <- reverse <$> readIORef edits
  let expected = [Bmm.AppendPush,Bmm.AppendOpcode] ++
        (if count == 0 then [] else Bmm.CaptureSolution : replicate count Bmm.AppendPush) ++
        [Bmm.PublishScript | count > 0 && complete]
  pure (conjoin [result === (if complete then 1 else 0), actual === expected])

maximumMoney :: Int64
maximumMoney = 21000000 * 100000000

withdrawalDispatch :: Property
withdrawalDispatch = forAll (B.pack <$> vectorOf 150 arbitrary) $ \bytes -> ioProperty $ do
  -- Explicit table freezes the existing ABI numbers, independently of Enum order.
  checks <- forM (filter ((/= Reserved12) . fst . snd) $ zip [1..] [(BuildScript,150),(ParseScript,150),(BuildReference,69),
    (ParseReference,150),(LegacyFrame,150),(DecodeFee,8),(EncodeFee,8),(BuildOutput,150),
    (ParseOutput,150),(BuildM6,150),(ParseM6,150),(Reserved12,116),(StateAnchor,132),(WalletBundle,25),
    (WalletAnchor,132),(StateMarker,32),(WalletTransport,150),(RpcFee,16),(EventPolicy,150),(BundleAdmission,65),(NativeAmount,17),(ParentDust,5),(NativeGuard,2),(NativeGuardResult,2),(InputsCommitment,40),(NativePayout,13),(NativeBurnPlan,70),(NativeOutputSelection,140)]) $ \(tag,(action,size)) -> do
      let input = if action == NativeAmount then B.singleton (B.head bytes `mod` 2) <> B.take 16 (B.drop 1 bytes)
            else if action == ParentDust then B.take 4 bytes <> B.singleton (B.index bytes 4 `mod` 2)
            else if action == NativeGuard || action == NativeGuardResult then B.pack [B.head bytes `mod` 4,B.index bytes 1 `mod` 2]
            else if action == NativePayout then B.take 12 bytes <> B.singleton (B.index bytes 12 `mod` 2)
            else if action == NativeOutputSelection then B.take 88 bytes <> wordLE 4 0 <> B.take 48 (B.drop 92 bytes) <> B.singleton 1
            else B.take size bytes
          request = WithdrawalRequest maximumMoney input
          result = applyWithdrawal action request
          expected = either ((B.singleton 1 <>) . C.pack) (B.singleton 0 <>) result
      B.useAsCString input $ \ptr -> allocaBytes 256 $ \out -> do
        count <- elements_hs_withdrawal_bytes tag maximumMoney (castPtr ptr) (fromIntegral (B.length input)) out 256
        actual <- B.packCStringLen (castPtr out, max 0 (fromIntegral count))
        pure $ conjoin [(($ action) <$> interpret (SomeOperation request) withdrawRules) === Just result,
                        withdrawal tag maximumMoney input === result, actual === expected]
  pure (conjoin checks)

-- Previous orchestration retained as a reference independent of the interpreter.
applyWithdrawal :: WithdrawalAction -> WithdrawalRequest -> Either String B.ByteString
applyWithdrawal action request
  | not (hasFrame action request) = error "invalid withdrawal FFI request"
  | otherwise = withdrawalBody action request

withdrawalCapabilities :: Property
withdrawalCapabilities = forAll (B.pack <$> listOf arbitrary) $ \bytes -> ioProperty $ do
  rejected <- try (evaluate (case interpret (SomeOperation (WithdrawalRequest maximumMoney B.empty)) withdrawRules of
    Just run -> run BuildScript
    Nothing -> error "withdrawal dispatch failed"))
    :: IO (Either ErrorCall (Either String B.ByteString))
  pure $ conjoin
    [(() <$ interpret (SomeOperation (error "deferred payload forced" :: WithdrawalRequest)) withdrawRules) === Just (),
     case interpret (SomeOperation (WithdrawalRequest maximumMoney bytes)) withdrawRules of
       Nothing -> counterexample "withdrawal dispatch failed" False
       Just run -> conjoin [run action === applyWithdrawal action (WithdrawalRequest maximumMoney bytes)
                          | action <- [LegacyFrame, ParseReference, DecodeFee]],
     case rejected of
       Left exception -> counterexample (displayException exception)
         ("invalid withdrawal FFI request" `isPrefixOf` displayException exception)
       Right result -> counterexample (show result) False]

dispatchFaults :: Property
dispatchFaults = forAll (oneof [elements [0,12,maxBound], choose (12,maxBound)]) $ \tag -> ioProperty $
  allocaBytes 256 $ \out -> do
    poke out (0xa5 :: Word8)
    invalid <- elements_hs_withdrawal_bytes tag maximumMoney nullPtr 0 out 256
    -- A matching type with an invalid envelope is also an ABI fault, not Nothing/Left.
    short <- elements_hs_withdrawal_bytes 1 maximumMoney nullPtr 0 out 256
    unchanged <- peek out
    pure $ conjoin [invalid === -1, short === -1, unchanged === 0xa5]

class Labelled op where
  operationLabel :: op -> String
class Adjustable op where
  adjust :: (Int32 -> Int32) -> op -> op
instance Labelled Probe where
  operationLabel _ = "probe"
instance Adjustable Probe where
  adjust transform (Probe value calls) = Probe (transform value) calls

deferredEffects :: Property
deferredEffects = forAll (choose (-10000,10000)) $ \value -> ioProperty $ do
  calls <- newIORef 0
  let prepared = adjust (*3) (adjust (+2) (Probe value calls))
      pending = SomeOperation prepared
  _ <- evaluate pending
  before <- readIORef calls
  result <- sequence (interpret pending countProbe)
  after <- readIORef calls
  pure $ conjoin [operationLabel prepared === "probe", before === 0,
    result === Just ((value+2)*3), after === 1]
