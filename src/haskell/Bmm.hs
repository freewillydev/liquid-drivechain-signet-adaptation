{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, GADTs, MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances, ScopedTypeVariables, TypeApplications, TypeFamilies, TypeOperators #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Bmm where

import Control.Operation.Validation
import qualified BmmConstants as Constants
import Control.Operation
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import CapabilityContext
import Workflow
import Control.Monad (when, void, guard, unless, forM, forM_)
import Control.Exception (Exception, SomeException, evaluate, finally, throwIO, try)
import Data.Bits (testBit, (.&.), (.|.), shiftL, shiftR)
import Data.Int (Int32, Int64)
import Data.List (sort)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Word (Word8, Word32, Word64)
import Deposit (ReadPegFields, readPegFields, constructionScalar, constructionWord)
import ParentReplay (transition, commitmentBytes)
import qualified ParentReplay as R
import qualified NodeRules
import Data.IORef (newIORef, readIORef, writeIORef)
import Withdrawal (readLE, wordLE)
import Foreign.Marshal.Array (allocaArray, peekArray)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable (peek, poke)
import Foreign.Ptr (FunPtr, Ptr, nullFunPtr, nullPtr)

data AnchorFlow
  = CandidateAdmissionFlow Word32 Word32
  | AnchorDisconnectFlow Word32 Word32
  | AnchorPublishFlow Word32 Word32
  | AnchorCacheFlow Word32 Word32
  | SnapshotPrepareFlow Word32 Word32
  | SnapshotBacklogFlow Word32 Word32
  | ConnectionContextFlow Word32 Word32
  | AnchorReplacementFlow Word32 Word32
  | ReconciliationGate Word32 Word32
  | AnchorOrder Word32 Word32
  | AnchorCollect Word32 Word32
  | FullBlockPreflight Word32 Word32
  | BlockAnchorAdmission Word32 Word32
  | BlockAnchorPublication Word32 Word32
instance Validation AnchorFlow where
  type ValidationResult AnchorFlow = Int32
  validate request = case request of
    -- Preflight returns continue (0), ignore unsolicited work (1), or reject (2).
    FullBlockPreflight phase reply -> transition phase reply
      [(1,(-10,2)),(2,(-10,3)),(3,(-10,4)),(4,(-11,5)),(5,(6,7)),(6,(-12,-1)),
       (7,(8,9)),(8,(-12,-1)),(9,(-12,10)),(10,(-12,11)),(11,(12,13)),(12,(-12,-1)),
       (13,(14,15)),(14,(-12,-1)),(15,(16,17)),(16,(-12,-1)),(17,(21,18)),
       (18,(20,19)),(19,(20,21)),(20,(-12,-1)),(21,(-12,22)),(22,(-1,-10))]
    BlockAnchorAdmission phase reply -> transition phase reply
      [(1,(27,2)),(2,(27,3)),(3,(5,4)),(4,(-1,8)),(5,(6,7)),(6,(-1,31)),
       (7,(-1,8)),(8,(-1,9)),(9,(10,13)),(10,(-1,11)),(11,(31,12)),(12,(-1,31)),
       (13,(14,15)),(14,(-1,31)),(15,(18,16)),(16,(17,18)),(17,(-1,31)),
       (18,(22,19)),(19,(22,20)),(20,(21,22)),(21,(-1,31)),(22,(26,23)),
       (23,(26,24)),(24,(25,26)),(25,(-1,31)),(26,(-1,27)),(27,(-11,28)),
       (28,(29,-11)),(29,(31,30)),(30,(-1,31)),(31,(-1,-10))]
    BlockAnchorPublication phase reply -> transition phase reply
      [(1,(7,2)),(2,(-1,3)),(3,(7,4)),(4,(7,5)),(5,(7,6)),(6,(-1,7)),
       (7,(-11,8)),(8,(-11,9)),(9,(11,10)),(10,(-11,11)),(11,(-1,-11))]
    AnchorCollect phase reply -> transition phase reply
      [(1,(-11,2)),(2,(-11,3)),(3,(-11,4)),(4,(6,5)),
       (5,(-1,6)),(6,(7,-11)),(7,(-1,1))]
    AnchorOrder phase reply -> transition phase reply
      [(1,(3,2)),(2,(-10,-11)),(3,(-10,-11))]
    ReconciliationGate phase reply -> transition phase reply
      [(1,(-10,2)),(2,(-1,3)),(3,(-11,4)),(4,(5,-11)),(5,(-1,-10))]
    AnchorReplacementFlow 0 _ -> 10
    AnchorReplacementFlow phase reply -> transition phase reply
      [(1,(2,3)),(2,(-1,-11)),(3,(4,7)),(4,(6,5)),(5,(-1,6)),
       (6,(-1,-11)),(7,(8,9)),(8,(-1,-11)),(9,(-1,-11)),
       (10,(-11,11)),(11,(-11,12)),(12,(15,13)),(13,(-11,14)),
       (14,(-1,15)),(15,(16,1)),(16,(-10,-10))]
    SnapshotBacklogFlow phase reply
      | phase == 1 -> if reply <= 1 then 2 else -10
      | otherwise -> transition phase reply [(2,(-1,-11))]
    CandidateAdmissionFlow 0 _ -> 20
    CandidateAdmissionFlow phase reply -> transition phase reply
      [(1,(2,3)),(2,(3,4)),(3,(-1,4)),(4,(-11,5)),
       (5,(6,7)),(6,(-11,7)),(7,(-1,-11)),(8,(9,1)),
       (9,(-1,10)),(10,(12,11)),(11,(-1,12)),(12,(14,13)),
       (13,(-1,-11)),(14,(-1,-11)),(15,(8,16)),(16,(17,18)),
       (17,(19,18)),(18,(-1,8)),(19,(-1,15)),(20,(21,22)),
       (21,(-1,-11)),(22,(23,15)),(23,(-1,-11))]
    AnchorDisconnectFlow phase reply -> transition phase reply
      [(1,(9,2)),(2,(3,9)),(3,(5,4)),(4,(-1,9)),
       (5,(-1,13)),(6,(7,8)),(7,(-10,-10)),(8,(-1,1)),
       (9,(-11,10)),(10,(-1,11)),(11,(-11,12)),(12,(-1,-11)),
       (13,(6,14)),(14,(-1,6))]
    AnchorPublishFlow phase reply -> transition phase reply
      [(1,(4,2)),(2,(3,4)),(3,(-10,-10)),(4,(-10,-11))]
    AnchorCacheFlow phase reply -> transition phase reply
      [(1,(4,2)),(2,(3,4)),(3,(-1,-11)),(4,(-11,5)),(5,(6,8)),
       (6,(7,8)),(7,(9,10)),(8,(-1,-11)),(9,(-1,-11)),
       (10,(11,8)),(11,(-1,-11))]
    SnapshotPrepareFlow phase reply -> transition phase reply
      [(1,(-11,2)),(2,(4,3)),(3,(-10,-10)),(4,(5,-11)),
       (5,(6,-11)),(6,(-10,7)),(7,(-1,-11))]
    ConnectionContextFlow phase reply -> transition phase reply
      [(1,(2,3)),(2,(-11,4)),(3,(6,5)),(4,(-10,-10)),(5,(-1,-11)),
       (6,(7,8)),(7,(-10,-10)),(8,(12,9)),(9,(10,11)),(10,(-10,-10)),
       (11,(-1,-11)),(12,(13,14)),(13,(-10,-10)),(14,(-1,-11))]

data CanonicalMatchFlow = CanonicalMatchFlow Word32 Word32
instance Validation CanonicalMatchFlow where
  type ValidationResult CanonicalMatchFlow = Int32
  validate (CanonicalMatchFlow phase reply) = transition phase reply
    [(1,(4,2)),(2,(5,3)),(3,(-1,6)),(4,(-10,-1)),(5,(-10,-1)),
     (6,(-11,7)),(7,(-1,-11))]

data MessageMatch = DefinitiveWaitError B.ByteString | DuplicateRequest B.ByteString
instance Validation MessageMatch where
  type ValidationResult MessageMatch = Bool
  validate request = case request of
    DefinitiveWaitError message -> matches message
      ["BMM successor", "not the exact successor of committed parent",
       "not the active-chain block at its declared height",
       "cached parent edge has no unique enforcer-recognized M7",
       "expected critical hash does not match the cached enforcer-recognized M7"]
    DuplicateRequest message -> matches message
      ["AlreadyExists", "same `sidechain_number` and `prev_bytes` already exists"]
    where matches message = any ((`B.isInfixOf` message) . C.pack)

data BiddingFlow
  = MinedPreflightFlow Word32 Word32
  | ConfiguredBidFlow Word32 Word32
  | ParsedBidFlow Word32 Word32
  | CommitmentProbe Word32 Word32
  | SuccessorProbe Word32 Word32
  | RewardWalletFlow Word32 Word32
  | TemplateCreationFlow Word32 Word32
  | FundedSubmissionFlow Word32 Word32
  | CacheRoutingFlow Word32 Word32
  | ProductionRoutingFlow Word32 Word32
  | BlockPreparationFlow Word32 Word32
  | BlockAcceptanceFlow Word32 Word32
instance Validation BiddingFlow where
  type ValidationResult BiddingFlow = Int32
  validate request = case request of
    MinedPreflightFlow phase result -> transition phase result
      [(1,(-10,2)),(2,(3,-11)),(3,(-10,-10))]
    ConfiguredBidFlow phase result -> transition phase result
      [(1,(3,2)),(2,(-10,-11)),(3,(-1,4)),(4,(-11,5)),(5,(-1,-11))]
    ParsedBidFlow phase result -> transition phase result
      [(1,(3,2)),(2,(-1,3)),(3,(4,6)),(4,(-10,5)),(5,(-1,-10)),(6,(-10,7)),(7,(-1,-11))]
    CommitmentProbe phase result -> transition phase result [(1,(2,-11)),(2,(-10,-12))]
    SuccessorProbe phase result -> transition phase result [(1,(-10,2)),(2,(-12,-11))]
    RewardWalletFlow phase result -> transition phase result
      [(1,(-10,2)),(2,(-1,3)),(3,(-10,4)),(4,(5,6)),(5,(6,-11)),(6,(-1,3))]
    -- Template result: unavailable (0), coinbase-only (1), transactions selected (2).
    TemplateCreationFlow 3 result -> case result of
      0 -> 4
      1 -> -10
      2 -> -11
      _ -> -1
    TemplateCreationFlow phase result -> transition phase result
      [(1,(2,3)),(2,(-1,-10)),(4,(-1,-10))]
    FundedSubmissionFlow phase result -> transition phase result
      [(1,(-10,2)),(2,(3,4)),(3,(-1,-10)),(4,(-1,-11))]
    ProductionRoutingFlow phase result -> transition phase result
      [(1,(3,2)),(2,(-10,-11)),(3,(-10,-11))]
    BlockPreparationFlow phase result -> transition phase result
      [(1,(2,3)),(2,(-10,3)),(3,(4,-11)),(4,(-11,5)),(5,(-1,-10))]
    BlockAcceptanceFlow phase result -> transition phase result
      [(1,(2,-11)),(2,(-1,-10))]
    CacheRoutingFlow phase result
      | phase `elem` [3,5,9] -> if result > 3 then -1
          else if phase == 5 && result == 0 then 6 else -11
      | otherwise -> transition phase result
          [(1,(-1,2)),(2,(4,3)),(4,(6,5)),(6,(7,-10)),(7,(-1,8)),(8,(-10,9))]

-- Slot 256 denotes an ordinary network. Reads preserve native widths; effects
-- return 1. Rejection rendering is separate from the decision that selects it.
data StartupArgs = StartupArgs Word32 Word64 Word64 (Word32 -> IO Word64)
instance Validation StartupArgs where
  type ValidationResult StartupArgs = IO Int32
  validate (StartupArgs slot moneyLimit timeoutMaximum action)
    | slot>256 || moneyLimit>fromIntegral (maxBound :: Int64) ||
      timeoutMaximum==0 || timeoutMaximum>fromIntegral (maxBound :: Int32) = pure (-1)
    | otherwise = either id (const 0) <$> runExceptT startup
    where
      flag step = do
        result <- lift (action step)
        case result of
          0 -> pure False
          1 -> pure True
          _ -> throwE (-1)
      effect step = flag step >>= \ok -> when (not ok) (throwE (-1))
      reject reason = effect (100+reason) >> throwE 1
      demand step reason = flag step >>= \ok -> when (not ok) (reject reason)
      deny step reason = flag step >>= \yes -> when yes (reject reason)
      startup = do
        reward <- flag 1
        when reward $ demand 2 1 >> demand 3 1
        effect 4
        signet <- flag 5
        if slot<256 then do
          demand 7 2
          deny 8 3
          deny 9 3
          configured <- lift (action 10)
          when (configured/=fromIntegral slot) (reject 4)
          demand 11 5
          demand 12 5
          demand 13 6
          extra <- lift (action 14)
          when (extra>moneyLimit) (reject 6)
          timeout <- lift (action 15)
          when (timeout<1 || timeout>timeoutMaximum) (reject 7)
          effect 16
          demand 17 8
        else deny 18 9 >> deny 19 10
        when signet $ do
          override <- flag 20
          when override (demand 21 11)
        credentials <- flag 22
        when credentials $ do
          deny 23 12
          deny 8 12
          deny 9 12
          demand 17 13
          demand 24 14

-- One anchor, candidate/predecessor, or uint32 status + old/candidate[/predecessor].
-- Hash/work fields are 32-byte little-endian; height addition wraps at 32 bits.
newtype AnchorRule = AnchorRule B.ByteString
instance Validation AnchorRule where
  type ValidationResult AnchorRule = Bool
  validate (AnchorRule bytes)
    | size==294 || size==439 = number 0 4==1 && check old && check candidate &&
        old/=candidate && (size==294 || check (B.drop 149 bytes))
    | otherwise = (size==145 || size==290) && sane 0 &&
        (size==145 || (sane 145 && parent>=previousHeight &&
          if parent==previousHeight then field 1==field 178 && number 65 32==number 242 32
          else number 65 32>number 242 32))
    where
      size = B.length bytes
      check = validate . AnchorRule
      old = B.take 145 (B.drop 4 bytes)
      candidate = B.take 145 (B.drop 149 bytes)
      field offset = B.take 32 (B.drop offset bytes)
      number offset width = B.foldr (\byte total -> fromIntegral byte+256*total)
        (0 :: Integer) (B.take width (B.drop offset bytes))
      parent = number 129 4
      previousHeight = number 278 4
      sane offset = B.index bytes offset==fromIntegral Constants.anchorVersion &&
        all (B.any (/=0) . field . (offset+)) [1,33,65,97] &&
        number (offset+133) 4==(number (offset+129) 4+1) `mod` 4294967296 &&
        number (offset+97) 32>number (offset+65) 32 && number (offset+137) 8<=4294967295

newtype AnchorCheckpoint = AnchorCheckpoint B.ByteString
instance Validation AnchorCheckpoint where
  type ValidationResult AnchorCheckpoint = Either Int32 B.ByteString
  validate (AnchorCheckpoint bytes)
    | B.length bytes/=145 || not (validate (AnchorRule bytes)) = Left 1
    | otherwise = Right (big 1 32<>B.replicate 4 0<>big 129 4<>big 137 8<>big 65 32)
    where big offset width = B.reverse (B.take width (B.drop offset bytes))

-- Keep BMM marking in its original order.
data TemplateCommitmentFlow = TemplateCommitmentFlow Word32 Word32
instance Validation TemplateCommitmentFlow where
  type ValidationResult TemplateCommitmentFlow = Int32
  validate (TemplateCommitmentFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-11,3)),(3,(-1,-11))]

-- Clear a prior selection before checking whether this template needs a parent.
data TemplateSelectionFlow = TemplateSelectionFlow Word32 Word32
instance Validation TemplateSelectionFlow where
  type ValidationResult TemplateSelectionFlow = Int32
  validate (TemplateSelectionFlow phase result) = transition phase result
    [(1,(-1,2)),(2,(-11,3)),(3,(5,4)),(4,(-1,-11)),(5,(-1,-10))]

-- Replay races with assembly are fenced before optional candidate validation.
data TemplateAdmissionFlow = TemplateAdmissionFlow Word32 Word32
instance Validation TemplateAdmissionFlow where
  type ValidationResult TemplateAdmissionFlow = Int32
  validate (TemplateAdmissionFlow phase result) = transition phase result
    [(1,(5,2)),(2,(3,5)),(3,(5,4)),(4,(-1,-10)),
     (5,(6,7)),(6,(-11,7)),(7,(8,-11)),(8,(-1,-10))]

-- Candidate P is authenticated before comparing or publishing its height.
-- Non-native fallback failure is optional.
data TemplateParentFlow = TemplateParentFlow Word32 Word32
instance Validation TemplateParentFlow where
  type ValidationResult TemplateParentFlow = Int32
  validate (TemplateParentFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(7,3)),(3,(12,4)),(4,(6,5)),(5,(13,6)),
     (6,(-1,11)),(7,(8,11)),(8,(11,9)),(9,(11,10)),(10,(-1,11)),
     (11,(12,-11)),(12,(-1,-10)),(13,(-1,-10))]

data HeaderAdmissionFlow = HeaderAdmissionFlow Bool Word32 Word32
instance Validation HeaderAdmissionFlow where
  type ValidationResult HeaderAdmissionFlow = Int32
  validate (HeaderAdmissionFlow context phase result) = transition phase result
    [(1,(if context then -11 else -10,2)),(2,(-11,if context then 5 else 3)),
     (3,(4,-11)),(4,(-11,if context then 6 else 5)),
     (5,(if context then 3 else 6,if context then -11 else -10)),(6,(-11,7)),(7,(-11,-10))]

data RecoveryFlow
  = RecoveryReplyFlow Bool Word32 Word32
  | RecoveryHeaderFlow Word32 Word32
  | RecoveryBodyFlow Word32 Word32
  | RecoveryPeerFlow Word32 Word32
  | RecoveryPeerReplyFlow Word32 Word32
instance Validation RecoveryFlow where
  type ValidationResult RecoveryFlow = Int32
  validate request = case request of
    RecoveryReplyFlow pruned phase result -> transition phase result
      [(step,(-11,if step==end then -10 else fromIntegral step+1)) | step <- [1..end]]
      where end = if pruned then 5 else 2
    RecoveryHeaderFlow phase result -> transition phase result $
      [(step,(65536+256+10,fromIntegral step+1)) | step <- [1..6]] ++
      [(7,(8,8)),(8,(65536+256+11,9)),(9,(65536+256+11,-10))]
    RecoveryBodyFlow phase result -> transition phase result
      [(1,(2,2)),(2,(3,6)),(3,(failure 5,4)),(4,(failure 5,-10)),
       (6,(failure 7,8)),(8,(9,9)),(9,(10,10)),(10,(11,11)),
       (11,(12,12)),(12,(14,failure 13)),(14,(15,15)),(15,(17,16)),
       (16,(11,11)),(17,(failure 19,18)),(18,(failure 19,20)),(20,(failure 21,-10))]
      where failure action = 65536+256+action
    RecoveryPeerFlow phase result -> transition phase result
      [(1,(65536+256+10,2)),(2,(9,3)),(3,(9,4)),(4,(5,5)),
       (5,(9,6)),(6,(8,7)),(7,(8,11)),(8,(5,5)),(9,(1,1)),(11,(-10,-10))]
    RecoveryPeerReplyFlow 0 _ -> 12
    RecoveryPeerReplyFlow phase result
      | phase>=12 -> transition phase result [(12,(65536+256+13,14)),(14,(1,1))]
      | otherwise -> validate (RecoveryPeerFlow phase result)

-- Compose retrieval rules here; native callbacks retain JSON, transport and clocks.
newtype BodyRecovery = BodyRecovery (Word32 -> IO Int64)
class RecoveryReplies op where
  isPrunedReply :: op -> ExceptT Int32 IO Bool
  checkRecoveryReply :: op -> ExceptT Int32 IO ()
class RecoveryHeader op where
  recoveryHeight :: op -> ExceptT Int32 IO Int64
class RecoveryPeers op where
  requestRecoveryPeer :: op -> ExceptT Int32 IO ()
class RecoveryEffects op where
  recoveryEffect :: op -> Word32 -> IO Int64

recoveryFlow :: Int32 -> (Word32 -> Word32 -> RecoveryFlow) -> (Word32 -> IO Int64) -> IO Int32
recoveryFlow limit rule = validate . CommandFlow limit (\phase result -> validate (rule phase result))

recoveryEffectChecked :: RecoveryEffects op => op -> Word32 -> ExceptT Int32 IO ()
recoveryEffectChecked value step = do
  result <- lift (recoveryEffect value step)
  unless (result == 1) (throwE (-1))

recoveryAccepted :: IO Int32 -> ExceptT Int32 IO ()
recoveryAccepted run = lift run >>= \code -> unless (code == 0) (throwE code)

instance RecoveryEffects BodyRecovery where
  recoveryEffect (BodyRecovery native) = native
instance RecoveryReplies BodyRecovery where
  isPrunedReply (BodyRecovery native) = do
    code <- lift (recoveryFlow 5 (RecoveryReplyFlow True) (native . (+100)))
    case code of
      0 -> pure True
      1 -> pure False
      _ -> throwE (-1)
  checkRecoveryReply value@(BodyRecovery native) = do
    code <- lift (recoveryFlow 2 (RecoveryReplyFlow False) (native . (+300)))
    case code of
      0 -> pure ()
      1 -> recoveryEffectChecked value 303 >> throwE (-1)
      _ -> throwE (-1)
instance RecoveryHeader BodyRecovery where
  recoveryHeight value@(BodyRecovery native) = do
    recoveryEffectChecked value 200
    checkRecoveryReply value
    recoveryEffectChecked value 212
    recoveryAccepted $ recoveryFlow 11 RecoveryHeaderFlow $ \step ->
      if step == 7 then fmap (either (const (-1)) (const 1)) $ runExceptT $ do
        recoveryEffectChecked value 207
        checkRecoveryReply value
        recoveryEffectChecked value 214
      else native (200+step)
    height <- lift (native 213)
    unless (height >= 0 && height <= 2147483647) (throwE (-1))
    pure height
instance RecoveryPeers BodyRecovery where
  requestRecoveryPeer value@(BodyRecovery native) = do
    recoveryEffectChecked value 400
    checkRecoveryReply value
    recoveryEffectChecked value 415
    recoveryAccepted $ recoveryFlow 14 RecoveryPeerReplyFlow $ \step ->
      if step == 11 then fmap (either (const (-1)) (const 1)) $ runExceptT $ do
        recoveryEffectChecked value 411
        checkRecoveryReply value
        recoveryEffectChecked value 417
      else native (400+step)

recoverParentBody :: (RecoveryReplies op, RecoveryHeader op, RecoveryPeers op, RecoveryEffects op) => op -> IO Int32
recoverParentBody value = do
  initialHeight <- newIORef 0
  recoveryFlow 21 RecoveryBodyFlow $ \step -> fmap (either (const (-1)) id) $ runExceptT $ case step of
    2 -> boolean <$> isPrunedReply value
    15 -> boolean <$> isPrunedReply value
    9 -> recoveryHeight value >>= lift . writeIORef initialHeight >> pure 1
    10 -> requestRecoveryPeer value >> pure 1
    20 -> do
      current <- recoveryHeight value
      initial <- lift (readIORef initialHeight)
      pure (boolean (current == initial))
    _ -> lift (recoveryEffect value step)
  where boolean valid = if valid then 1 else 0

type BodyRecoveryCapabilities = '[RecoveryReplies, RecoveryHeader, RecoveryPeers, RecoveryEffects]
instance Operation BodyRecovery BodyRecoveryCapabilities where
  type Context BodyRecovery = CapabilityContext BodyRecoveryCapabilities BodyRecovery
  type Outcome BodyRecovery = IO Int32
  data DSL BodyRecovery where
    RecoverBody :: Context BodyRecovery => DSL BodyRecovery
  interpret operation request = withOperation @BodyRecovery operation $ \value -> case request of
    RecoverBody -> Just (recoverParentBody value)

type WriteState = Ptr () -> Word32 -> Word32 -> IO Int32

-- Probe: 0 resets failures, 1 succeeds, 2 is definitive, 3 preserves failures.
newtype WaitForBmm = WaitForBmm (Word32 -> IO Int32)
instance Validation WaitForBmm where
  type ValidationResult WaitForBmm = IO Int32
  validate (WaitForBmm action) = loop 0 0
    where
      effect step next = action step >>= \result -> if result == 1 then next else pure (-1)
      loop :: Word32 -> Word32 -> IO Int32
      loop cadence failures = action 1 >>= \running -> case running of
        0 -> pure 0
        1 -> action 2 >>= \probe -> case probe of
          1 -> finish 4 1 cadence failures
          0 -> wait cadence 0
          2 | failures >= 2 -> finish 5 0 cadence 3
            | otherwise -> wait cadence (failures+1)
          3 -> wait cadence failures
          _ -> pure (-1)
        _ -> pure (-1)
      -- Proof logging failures are retryable; a failure reporting that error is not.
      finish step result cadence failures = action step >>= \logged -> case logged of
        1 -> pure result
        3 -> wait cadence failures
        _ -> pure (-1)
      wait cadence failures = (if cadence == 0 then report else id) $
        action 6 >>= \continued -> case continued of
          0 -> pure 0
          1 -> loop ((cadence+1) `mod` 4) failures
          _ -> pure (-1)
      report next = action 3 >>= \logged -> case logged of
        1 -> next
        3 -> effect 3 next
        _ -> pure (-1)

data ProofBuild = ProofBuild Word64 Int64 (Word32 -> Word64 -> IO Int32)
instance Validation ProofBuild where
  type ValidationResult ProofBuild = IO Int32
  validate (ProofBuild previous parent action)
    | parent < 0 || parent == maxBound || first > lastHeight ||
      lastHeight - first + 1 > toInteger Constants.proofEntries = pure 1
    | otherwise = runReportedEffects (uncurry action) rejection ([(1,previous),(2,fromIntegral parent),(3,0)] ++
        [(stage,fromInteger height) | height <- [first..lastHeight], stage <- [4,9,10,11,12]] ++ [(5,0)])
    where
      first = toInteger previous + 1
      lastHeight = toInteger parent + 1
      rejection (stage,height) = (\failure -> (failure,height)) <$> lookup stage [(1,6),(2,7),(5,8),(9,13),(10,13),(11,13)]

data ParentRpcAddress = ParentRpcIPv4 Word32 | ParentRpcIPv6 B.ByteString
instance Validation ParentRpcAddress where
  type ValidationResult ParentRpcAddress = Bool
  validate address = case address of
    ParentRpcIPv4 value -> value `shiftR` 24 == 127
    ParentRpcIPv6 bytes -> bytes == B.replicate 15 0 <> B.singleton 1

class HostAdmission op where
  admitRpcHost :: op -> IO Bool

admitHostSnapshot :: B.ByteString -> IO Bool
admitHostSnapshot bytes = case B.uncons bytes of
  Just (0, rest) | B.null rest -> pure False
  Just (4, rest) | B.length rest == 4 -> pure (validate (ParentRpcIPv4 (fromIntegral (readLE rest))))
  Just (6, rest) | B.length rest == 16 -> pure (validate (ParentRpcIPv6 rest))
  _ -> ioError (userError "invalid parent RPC host snapshot")

newtype RpcHost = RpcHost NativeBytes
instance HostAdmission RpcHost where
  admitRpcHost (RpcHost native) = do
    mode <- native 1 0 B.empty
    if mode == wordLE 8 0 then pure True
      else if mode == wordLE 8 1 then native 2 0 B.empty >>= admitHostSnapshot
      else ioError (userError "invalid parent RPC host mode")
instance Operation RpcHost '[HostAdmission] where
  type Context RpcHost = CapabilityContext '[HostAdmission] RpcHost
  type Outcome RpcHost = IO Int32
  data DSL RpcHost where
    CheckRpcHost :: Context RpcHost => DSL RpcHost
  interpret operation request = withOperation @RpcHost operation $ \value ->
    case request of
      CheckRpcHost -> Just (fromIntegral . fromEnum <$> admitRpcHost value)

data StageAdmission
  = RewardAddress (Word32 -> IO Int32)
  | NativeProduction (Word32 -> IO Int32)
  | EcxProduction (Word32 -> IO Int32)
  | SyncTick (Word32 -> IO Int32)
  | SyncHeights Int64 Int64 (Word32 -> IO Int32)
instance Validation StageAdmission where
  type ValidationResult StageAdmission = IO Int32
  validate request = case request of
    RewardAddress action -> run 5 action
    NativeProduction action -> produce action
      [(1,1),(2,2),(13,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8),(9,9),(10,10)]
      [(1,101),(2,102),(13,102),(3,103),(6,106),(7,107)]
    EcxProduction action -> produce action
      [(1,1),(19,1),(2,2),(20,2),(3,3),(15,3),(4,4),(5,5),(6,6),(16,6),
       (7,7),(8,8),(9,9),(17,9),(10,10),(18,10),(11,11),(12,12),(13,13),(14,14)]
      [(1,101),(19,101),(2,102),(20,102),(3,103),(15,115),(4,104),
       (6,106),(16,116),(7,107),(9,109),(10,110),(12,112)]
    SyncTick action -> run 5 action
    SyncHeights parent child action
      | validate (ChildBehind child parent) -> orderedFacts action [(4,4),(5,5)] 0
      | otherwise -> pure 3
    where
      run count action = orderedFacts action [(step,fromIntegral step) | step <- [1..count]] 0
      -- Reports cannot turn rejection into success; malformed replies do not log.
      produce action checks reports = orderedFacts observe checks 0
        where
          observe step = do
            reply <- action step
            when (reply == 0) $ maybe (pure ()) (void . action) (lookup step reports)
            pure reply

data SelectedBid = SelectedBid Int64 Int64 Int64
instance Validation SelectedBid where
  type ValidationResult SelectedBid = Int64
  validate (SelectedBid configured fees moneyLimit)
    | configured <= 0 || configured > moneyLimit = -1
    | fees < 0 || fees > moneyLimit = -2
    | otherwise = max configured fees

data ReplacementLimit = ReplacementLimit Int64 Int64 Int64
instance Validation ReplacementLimit where
  type ValidationResult ReplacementLimit = Int64
  validate (ReplacementLimit selected extra moneyLimit)
    | extra < 0 || extra > moneyLimit = -1
    | validate (SelectedBid selected 0 moneyLimit) < 0 = -2
    | otherwise = fromInteger (min (toInteger moneyLimit) (toInteger selected + toInteger extra))

addWork :: Word64 -> Word64 -> Maybe Word64
addWork total extra | total > maxBound - extra = Nothing
                    | otherwise = Just (total + extra)

data WorkTotal = WorkTotal Word32 Word64 Word64 (Word64 -> IO Word64)
instance Validation WorkTotal where
  type ValidationResult WorkTotal = IO (Int32, Word64)
  validate (WorkTotal mode count initial readWork)
    | mode > 1 = pure (-1,initial)
    | otherwise = scan 0 initial
    where
      scan index total
        | index >= count = pure (0,total)
        | otherwise = readWork index >>= \extra -> case addWork total extra of
            Just next -> scan (index+1) next
            Nothing | mode == 0 -> pure (1,total)
                    | otherwise -> scan (index+1) maxBound

data WorkBudget = WorkBudget Word64 (Word32 -> Word64 -> Word64 -> IO Word64)
instance Validation WorkBudget where
  type ValidationResult WorkBudget = IO Word64
  validate (WorkBudget count readField) = scan 0 0
    where
      scan index total
        | index >= count = pure total
        | otherwise = do
            size <- readField 0 index 0
            if size < 4 then next else do
              final <- readField 1 index (size-1)
              let control = size - (if final == 0x50 then 2 else 1)
              tag <- readField 1 index control
              if tag == 256 || tag .&. 0xfe /= 0xbe then next else do
                cmrSize <- readField 2 index (control-1)
                if cmrSize /= 32 then next else do
                  bytes <- readField 3 index 0
                  let budget = bytes + 50
                  if budget > maxBound `quot` 1000 then pure maxBound
                    else maybe (pure maxBound) (scan (index+1)) (addWork total (budget*1000))
        where next = scan (index+1) total

data WorkMeasurement = WorkMeasurement Word32 Word64 Word64 NativeBytes
instance Validation WorkMeasurement where
  type ValidationResult WorkMeasurement = IO (Int32,Word64,Word64)
  validate (WorkMeasurement mode count initial native)
    | mode > 1 = pure (-1,initial,0)
    | otherwise = scan 0 initial 0
    where
      scan index total lastWork
        | index == count = pure (0,total,lastWork)
        | otherwise = do
            snapshot <- native 0 index B.empty
            when (B.length snapshot `mod` 40 /= 0) (ioError (userError "invalid work snapshot"))
            let field witness column = readLE (B.take 8 (B.drop (fromIntegral witness*40+column*8) snapshot))
                readField step witness _ = case step of
                  0 -> pure (field witness 0)
                  1 -> pure (field witness (if field witness 1 == 0x50 then 2 else 1))
                  2 -> pure (field witness (if field witness 1 == 0x50 then 4 else 3))
                  3 -> do
                    bytes <- native 1 witness (wordLE 8 index)
                    if B.length bytes == 8 then pure (readLE bytes) else ioError (userError "invalid serialized work size")
                  _ -> ioError (userError "invalid work field")
                -- WorkBudget first asks for the last tag, then the selected
                -- control tag. Distinguish those reads by their stack index.
                readBudget step witness item
                  | step == 1 && item == field witness 0-1 = pure (field witness 1)
                  | otherwise = readField step witness item
            work <- validate (WorkBudget (fromIntegral (B.length snapshot `div` 40)) readBudget)
            case addWork total work of
              Just next -> scan (index+1) next work
              Nothing | mode == 0 -> pure (1,total,work)
                      | otherwise -> scan (index+1) maxBound work

data WorkQuote = WorkQuote Int64 Word64 Int64 Int64 Int64
instance Validation WorkQuote where
  type ValidationResult WorkQuote = (Bool, [Int64])
  validate (WorkQuote fees work rate reserve bound)
    | any (\value -> value < 0 || value > bound) [fees,rate,reserve] ||
      scaled > toInteger (maxBound :: Word64) || priced > toInteger bound = (False,[0,0,0])
    | cost > fees || reserve > fees - cost = (False,[cost,reserve,0])
    | otherwise = (True,[cost,reserve,fees-cost-reserve])
    where
      scaled = toInteger work * toInteger rate + 999999
      priced = scaled `quot` 1000000
      cost = fromInteger priced

newtype WorkQuoteDisplay = WorkQuoteDisplay WorkQuote
instance Validation WorkQuoteDisplay where
  type ValidationResult WorkQuoteDisplay = (Bool, [Int64])
  validate (WorkQuoteDisplay quote) = case validate quote of
    (True,fields@[_,_,bid]) -> (bid>0,fields)
    _ -> (False,[0,0,0])

data WorkBid = WorkBid Word32 Int64 Int64 Int64 Int64 Int64 Int64 (IO Int64)
instance Validation WorkBid where
  type ValidationResult WorkBid = IO (Int32,[Int64])
  validate (WorkBid flags height fees work reserve requested bound readRate)
    | flags > 3 = rejected (-1)
    | flags /= 3 = rejected 1
    | height <= 0 || toInteger height > toInteger (maxBound :: Word32) = rejected 2
    | fees <= 0 || work < 0 || reserve < 0 || requested <= 0 = rejected 3
    | otherwise = do
        rate <- readRate
        pure $ case validate (WorkQuote fees (fromIntegral work) rate reserve bound) of
          (True,[cost,_,bid]) ->
            (if requested > bid then 5 else 0,
             [cost,cost+reserve,bid,if requested > bid then 0 else bid-requested])
          _ -> (4,replicate 4 0)
    where rejected code = pure (code,replicate 4 0)

data SyncFlow = SyncPreflightFlow Word32 Word32 | SyncLoopFlow Word32 Word32 | BidParentFlow Word32 Word32
instance Validation SyncFlow where
  type ValidationResult SyncFlow = Int32
  validate (SyncPreflightFlow phase result) = transition phase result
    [(step,(-10,if step==5 then -11 else fromIntegral step+1)) | step <- [1..5]]
  validate (SyncLoopFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-1,3)),(3,(-11,1))]
  validate (BidParentFlow phase result) = transition phase result
    [(1,(-1,2)),(2,(-1,3)),(3,(5,4)),(4,(5,-11)),(5,(-1,-10))]

-- Prepare fork-specific state; inherited native activation follows this flow.
data ReverificationFlow = ReverificationFlow Word32 Word32
instance Validation ReverificationFlow where
  type ValidationResult ReverificationFlow = Int32
  validate (ReverificationFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(3,4)),(3,(-1,-11)),(4,(-1,5)),(5,(6,-11)),
     (6,(7,-11)),(7,(-1,-11))]

data ChildFlow
  = ChildDrainFlow Word32 Word32
  | ChildReapFlow Word32 Word32
  | ChildMonitorFlow Bool Word32 Word32
  | ChildPreflightFlow Word32 Word32
instance Validation ChildFlow where
  type ValidationResult ChildFlow = Int32
  validate (ChildPreflightFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-10)),(3,(4,5)),(4,(-1,-10)),(5,(-11,6)),(6,(-1,-10))]
  validate (ChildDrainFlow phase result)
    | phase == 1 = case result of
        0 -> 2 -- append bytes
        1 -> 3 -- EOF
        2 -> 1 -- interrupted; retry
        3 -> -11 -- would block
        4 -> 4 -- read error
        _ -> -1
    | otherwise = transition phase result [(2,(1,-11)),(3,(-1,-11)),(4,(-1,-10))]

  validate (ChildReapFlow phase result)
    | phase == 2 = case result of
        0 -> -11 -- reaped our child
        1 -> -11 -- still running (nonblocking wait)
        2 -> 2 -- interrupted; retry
        3 -> -11 -- no remaining child
        4 -> 4 -- record a native error
        5 -> -11 -- unexpected positive result; preserve the old no-op
        _ -> -1
    | otherwise = transition phase result [(1,(2,-11)),(4,(-1,-11))]

  validate (ChildMonitorFlow grace phase result) = transition phase result $
    if grace then [(1,(-11,2)),(2,(-1,3)),(3,(4,-11)),(4,(-1,5)),(5,(1,6)),(6,(-1,1))]
    else [(1,(2,-11)),(2,(-11,3)),(3,(-1,4)),(4,(5,-11)),(5,(7,6)),
     (6,(-1,-11)),(7,(9,8)),(8,(-1,-11)),(9,(10,-10)),(10,(-11,2))]

-- Byte strings preserve native argv contents; this planner never invokes a shell.
data CredentialRecordFlow = CredentialRecordFlow Word32 Word32
instance Validation CredentialRecordFlow where
  type ValidationResult CredentialRecordFlow = Int32
  validate (CredentialRecordFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(3,-11)),(3,(-1,-10))]

data CredentialFileFlow = CredentialFileFlow Word32 Word32
instance Validation CredentialFileFlow where
  type ValidationResult CredentialFileFlow = Int32
  validate (CredentialFileFlow phase result)
    | phase==7 = case result of 0 -> 9; 1 -> 8; 2 -> 9; _ -> -1
    | phase==9 = case result of 0 -> 11; 2 -> 10; _ -> -1
    | phase==20 = if result>4096 then 22 else 23
    | phase==23 = if result>256 then -1 else if result==10 then 24 else 25
    | phase==25 = if result>256 then -1 else if result==13 then 26 else -11
    | otherwise = transition phase result
        ([(1,(2,3)),(3,(12,4)),(4,(5,6)),(6,(-10,7)),(11,(-1,23)),
          (12,(13,15)),(13,(15,14)),(14,(15,16)),(16,(17,18)),
          (18,(-1,19)),(19,(20,22)),(24,(-1,25)),(26,(-1,-11))] ++
         [(step,(-1,-10)) | step <- [2,5,8,10,15,17,22]])

data TlsFileAdmission = TlsFileAdmission Bool (Word32 -> IO Word64)
instance Validation TlsFileAdmission where
  type ValidationResult TlsFileAdmission = IO Int32
  validate (TlsFileAdmission privateKey action) = fmap (either id (const 1)) $ runExceptT $ do
    platform <- lift (action 1)
    case platform of
      0 -> reject 2
      2 -> require (boolean 13) 14
      1 -> do
        require (boolean 3) 4
        require (same 5 15) 6
        require (allChecks [boolean 7,boolean 16,same 17 18,zero 19]) 8
        require (zero (if privateKey then 9 else 20)) 10
        opened <- lift (allChecks [boolean 11,boolean 21,same 22 23,
          zero (if privateKey then 24 else 25),same 26 27,same 28 29])
        closed <- lift (action 30)
        when (closed/=1) (throwE (-1))
        when (not opened) (reject 12)
      _ -> throwE (-1)
    where
      reject step = lift (action step) >>= \result -> throwE (if result==1 then 0 else -1)
      require check err = lift check >>= \ok -> when (not ok) (reject err)
      boolean step = action step >>= \value -> case value of
        0 -> pure False
        1 -> pure True
        _ -> ioError (userError "invalid credential boolean")
      same a b = (==) <$> action a <*> action b
      zero step = (==0) <$> action step
      allChecks = foldr (\check rest -> check >>= \ok -> if ok then rest else pure False) (pure True)

newtype PrivateFileAdmission = PrivateFileAdmission (Word32 -> IO Int64)
instance Validation PrivateFileAdmission where
  type ValidationResult PrivateFileAdmission = IO Int32
  validate (PrivateFileAdmission action) = do
    regular <- action 1
    case regular of
      0 -> reject 2
      1 -> do
        owner <- action 3
        if invalid owner then pure (-1) else do
          user <- action 4
          if invalid user then pure (-1) else if owner/=user then reject 5 else do
            permissions <- action 6
            if invalid permissions then pure (-1)
              else if permissions/=0 then reject 7 else pure 1
      _ -> pure (-1)
    where
      invalid value = value<0 || value>4294967295
      reject step = action step >>= \result -> pure (if result==1 then 0 else -1)

data CredentialRead = CredentialRead Word64 (Word64 -> Word64 -> IO Word64)
instance Validation CredentialRead where
  type ValidationResult CredentialRead = IO (Int32,Word64)
  validate (CredentialRead capacity readBytes)
    | capacity/=4097 = pure (-1,0)
    | otherwise = go 0
    where
      go used | used==capacity = pure (2,used)
              | otherwise = do
          count <- readBytes used (capacity-used)
          if count==maxBound then go used
          else if count==maxBound-1 then pure (1,used)
          else if count>capacity-used then pure (-1,used)
          else if count==0 then pure (0,used) else go (used+count)

newtype AuthFile = AuthFile NativeBytes

class CredentialMetadata op where
  inspectCredentialFile :: op -> IO Int32
class CredentialContents op where
  readCredentialFile :: op -> IO (Int32,Word64)
class CredentialFileEffects op where
  credentialFileEffect :: op -> Word32 -> Word64 -> IO Int64
class CredentialFormat op where
  validateCredentialRecord :: op -> Bool -> IO Int32

authFileScalar :: NativeBytes -> Word32 -> Word64 -> B.ByteString -> IO Word64
authFileScalar action step index input = do
  bytes <- action step index input
  if B.length bytes==8 then pure (readLE bytes)
    else ioError (userError "invalid credential workflow scalar")

instance CredentialFileEffects AuthFile where
  credentialFileEffect (AuthFile action) step index =
    fromIntegral <$> authFileScalar action step index B.empty
instance CredentialMetadata AuthFile where
  inspectCredentialFile value = validate (PrivateFileAdmission observe)
    where
      effect step = credentialFileEffect value step 0
      observe 1 = effect 31 >>= \result -> case result of
        0 -> pure 0
        1 -> effect 38
        _ -> pure (-1)
      observe step = effect (step+30)
instance CredentialContents AuthFile where
  readCredentialFile (AuthFile action) = validate (CredentialRead 4097
    (\offset available -> authFileScalar action 40 offset (wordLE 8 available)))
instance CredentialFormat AuthFile where
  validateCredentialRecord (AuthFile action) rotating = do
    bytes <- action 50 0 B.empty
    if B.length bytes>4096 then pure (-1)
    else case validate (NodeRules.ConfigurationField (if rotating then 7 else 8) bytes) of
      Right accepted | accepted==B.singleton 1 -> pure 1
      Left 1 -> do
        reported <- authFileScalar action 60 0 B.empty
        pure (if reported==1 then 0 else -1)
      _ -> pure (-1)

loadAuthFile :: (CredentialMetadata op, CredentialContents op, CredentialFileEffects op)
  => op -> IO Int32
loadAuthFile value = do
  readResult <- newIORef (0,0)
  let observe 6 = fromIntegral <$> inspectCredentialFile value
      observe 7 = do
        result@(status,_) <- readCredentialFile value
        writeIORef readResult result
        pure (fromIntegral status)
      observe 9 = do
        closed <- credentialFileEffect value 9 0
        (status,_) <- readIORef readResult
        pure (if closed==1 then fromIntegral status else -1)
      observe 11 = readIORef readResult >>= \(_,used) -> credentialFileEffect value 11 used
      observe step = credentialFileEffect value step 0
  validate (CommandFlow 26 (\phase result -> validate (CredentialFileFlow phase result)) observe)

loadAuthRecord :: (CredentialMetadata op, CredentialContents op, CredentialFileEffects op, CredentialFormat op)
  => op -> Bool -> IO Int32
loadAuthRecord value rotating = do
  loaded <- loadAuthFile value
  if loaded==1 then validateCredentialRecord value rotating else pure loaded

type AuthFileCapabilities = '[CredentialMetadata, CredentialContents, CredentialFileEffects, CredentialFormat]
instance Operation AuthFile AuthFileCapabilities where
  type Context AuthFile = CapabilityContext AuthFileCapabilities AuthFile
  type Outcome AuthFile = IO Int32
  data DSL AuthFile where
    ReadRawAuthFile :: Context AuthFile => DSL AuthFile
    ReadStaticAuthRecord :: Context AuthFile => DSL AuthFile
    ReadCookieAuthRecord :: Context AuthFile => DSL AuthFile
  interpret operation request = withOperation @AuthFile operation $ \value ->
    case request of
      ReadRawAuthFile -> Just (loadAuthFile value)
      ReadStaticAuthRecord -> Just (loadAuthRecord value False)
      ReadCookieAuthRecord -> Just (loadAuthRecord value True)

-- The transport composes the file capabilities here, without a dependency from
-- parent replay back through BMM/exchange credential validation.
newtype RpcSession = RpcSession NativeBytes
newtype RpcTransportFailure = RpcTransportFailure R.RpcAttemptResult deriving Show
instance Exception RpcTransportFailure

rpcSessionBytes :: RpcSession -> NativeBytes
rpcSessionBytes (RpcSession native) step index input = do
  bytes <- native step index input
  if step < 100 then pure bytes else case B.uncons bytes of
    Just (1,rest) -> pure rest
    Just (2,rest) | B.null rest -> throwIO (RpcTransportFailure R.RpcAuthenticationFailed)
    Just (0,rest) | B.null rest -> throwIO (RpcTransportFailure R.RpcFailed)
    _ -> ioError (userError "invalid parent RPC transport frame")

rpcSessionScalar :: RpcSession -> Word32 -> IO Int64
rpcSessionScalar value step = rpcSessionNumber value step B.empty

rpcSessionNumber :: RpcSession -> Word32 -> B.ByteString -> IO Int64
rpcSessionNumber value step input = do
  body <- rpcSessionBytes value step 0 input
  if B.length body == 8 then pure (fromIntegral (readLE body))
    else ioError (userError "invalid parent RPC scalar")

instance R.CredentialSource RpcSession where
  selectCredential = R.selectCredential . R.RpcPreparation . (\value step -> rpcSessionScalar value (400+step))
instance R.CredentialCache RpcSession where
  cachedCredential = R.cachedCredential . R.RpcPreparation . (\value step -> rpcSessionScalar value (400+step))
instance HostAdmission RpcSession where
  admitRpcHost value = rpcSessionBytes value 444 0 B.empty >>= admitHostSnapshot
instance R.CredentialLoader RpcSession where
  loadCredential value = R.checkedStore 59 observe >> pure ()
    where
      effect step = do
        status <- rpcSessionScalar value step
        unless (status == 1) (ioError (userError "invalid credential file lifecycle result"))
      file rotating = do
        ready <- if rotating then do
          chain <- rpcSessionBytes value 483 0 B.empty
          let path = if validate (NodeRules.NetworkSelection 3 0 chain) == 1 then ".cookie" else "regtest/.cookie"
          rpcSessionNumber value 447 (C.pack path)
          else rpcSessionScalar value 445
        case ready of
          0 -> pure 0
          1 -> do
            status <- loadAuthRecord (AuthFile (\step -> rpcSessionBytes value (500+step))) rotating
              `finally` effect 480
            when (rotating && status == 0) (effect 481)
            when (rotating && status == 1) (effect 482)
            pure (fromIntegral status)
          _ -> pure (-1)
      observe 4 = fromIntegral . fromEnum <$> admitRpcHost value
      observe 5 = file False
      observe 7 = file True
      observe step = rpcSessionScalar value (440+step)

instance R.RpcCircuit RpcSession where
  admitRpcCall = R.admitRpcCall . R.RpcCall . rpcSessionScalar
instance R.RpcAuthentication RpcSession where
  retryRpcCall = R.retryRpcCall . R.RpcCall . rpcSessionScalar
instance R.RpcFailure RpcSession where
  rejectRpcCall = R.rejectRpcCall . R.RpcCall . rpcSessionScalar
instance R.RpcReply RpcSession where
  verifyRpcReply = R.verifyRpcReply . R.RpcCall . rpcSessionScalar
instance R.RpcAttempt RpcSession where
  attemptRpcCall value = do
    let action = rpcSessionScalar value
        accepted run = do
          status <- lift run
          unless (status >= 0 && status <= 3) (throwE (-1))
        effect step = do
          result <- lift (action step)
          unless (result == 1) (throwE (-1))
        deadline = accepted (R.runDeadline (action . (200+)))
        request = do
          deadline
          effect 100
          accepted (R.configureTimeout (R.RpcPreparation (action . (300+))))
          effect 101
          R.prepareCredentials value
          effect 102
          deadline
          effect 103
          deadline
          effect 104
          effect 105
    -- Cleanup precedes cookie invalidation, retry and backoff even on failure.
    result <- lift (try (runExceptT request) `finally` (action 11 >> pure ()))
    case result of
      Left (RpcTransportFailure failure) -> pure failure
      Right status -> either throwE (const (pure R.RpcSucceeded)) status

type RpcSessionCapabilities =
  '[R.RpcCircuit, R.RpcAttempt, R.RpcAuthentication, R.RpcFailure, R.RpcReply,
    R.CredentialSource, R.CredentialCache, R.CredentialLoader, HostAdmission]
instance Operation RpcSession RpcSessionCapabilities where
  type Context RpcSession = CapabilityContext RpcSessionCapabilities RpcSession
  type Outcome RpcSession = IO Int32
  data DSL RpcSession where
    CallTransport :: Context RpcSession => DSL RpcSession
    CallCheckedTransport :: Context RpcSession => DSL RpcSession
  interpret operation request = withOperation @RpcSession operation $ \value ->
    let run = fmap (either id (const 1)) . runExceptT
    in case request of
      CallTransport -> Just (run (R.performRpcCall value))
      CallCheckedTransport -> Just (run (R.performRpcCall value >> R.verifyRpcReply value))

data GrpcTextAdmission = GrpcTextAdmission B.ByteString B.ByteString
instance Validation GrpcTextAdmission where
  type ValidationResult GrpcTextAdmission = Int32
  validate (GrpcTextAdmission address authority) =
    bit 1 (not (B.null address) && not (C.pack "://" `B.isInfixOf` address)) +
    bit 2 (B.length address<=512 && clean address) + bit 4 (clean authority)
    where
      clean = B.all (\byte -> byte>32 && byte/=127)
      bit flag accepted = if accepted then flag else 0

data GrpcPlan = GrpcPlan B.ByteString B.ByteString
class GrpcPolicy op where
  admitGrpc :: op -> Either String ()
instance GrpcPolicy GrpcPlan where
  admitGrpc (GrpcPlan method payload) = do
    grpcMethod method
    if B.null payload || B.length payload > 1048576
      then Left "enforcer gRPC payload must contain 1..1048576 bytes" else Right ()

grpcMethod :: B.ByteString -> Either String ()
grpcMethod method
  | method `elem` map C.pack methods = Right ()
  | otherwise = Left "refusing an unrecognized enforcer gRPC method"
  where methods =
            ["cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction",
             "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
             "cusf.mainchain.v1.BlockProducerService/ProposeWithdrawalBundle",
             "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData",
             "cusf.mainchain.v1.ValidatorService/GetChainInfo",
             "cusf.mainchain.v1.ValidatorService/GetChainTip",
             "cusf.mainchain.v1.ValidatorService/GetSidechains",
             "cusf.mainchain.v1.ValidatorService/GetCtip"]
type GrpcCapabilities = '[GrpcPolicy]

class SubmissionTransport op where
  transmitBid :: op -> Word64 -> ExceptT Int32 IO Bool
class SubmissionReplacement op where
  increaseBid :: op -> Word64 -> Word64 -> ExceptT Int32 IO (Maybe Word64)
class SubmissionReporting op where
  reportBid :: op -> Bool -> ExceptT Int32 IO ()

newtype SubmissionRequest = SubmissionRequest (Word32 -> Word64 -> IO Int64)
instance SubmissionTransport SubmissionRequest where
  transmitBid (SubmissionRequest action) bid = do
    parent <- lift (action 1 0)
    case parent of
      0 -> throwE 1
      1 -> pure ()
      _ -> throwE (-1)
    status <- lift (action 2 bid)
    case status of
      0 -> throwE 2
      1 -> pure False
      2 -> pure True
      _ -> throwE (-1)
instance SubmissionReplacement SubmissionRequest where
  increaseBid (SubmissionRequest action) bid limit = do
    replacement <- lift (action 3 bid)
    if replacement == 0 then pure Nothing
    else if replacement < 0 || fromIntegral replacement <= bid || fromIntegral replacement > limit
      then throwE (-1)
      else do
        published <- lift (action 4 (fromIntegral replacement))
        if published == 1 then pure (Just (fromIntegral replacement)) else throwE (-1)
instance SubmissionReporting SubmissionRequest where
  reportBid (SubmissionRequest action) success = do
    duplicate <- if success then pure 1 else lift (action 5 0)
    case duplicate of
      0 -> throwE 2
      1 -> do
        published <- lift (action 6 (if success then 1 else 0))
        if published == 1 then pure () else throwE (-1)
      _ -> throwE (-1)

type SubmissionCapabilities = '[SubmissionTransport, SubmissionReplacement, SubmissionReporting]
-- Publish a replacement before the next parent check; stop after three attempts.
runSubmission :: (SubmissionTransport op, SubmissionReplacement op, SubmissionReporting op)
  => op -> Int64 -> Int64 -> IO Int32
runSubmission value bid limit
  | bid <= 0 || bid > limit = pure (-1)
  | otherwise = either id (const 0) <$> runExceptT (attempt (0 :: Int) (fromIntegral bid))
  where
    attempt retries current = do
      success <- transmitBid value current
      if success then reportBid value True
      else if retries == 2 then reportBid value False
      else do
        replacement <- increaseBid value current (fromIntegral limit)
        maybe (reportBid value False) (attempt (retries+1)) replacement

instance Operation SubmissionRequest SubmissionCapabilities where
  type Context SubmissionRequest = CapabilityContext SubmissionCapabilities SubmissionRequest
  type Outcome SubmissionRequest = IO Int32
  data DSL SubmissionRequest where
    SubmitBmm :: Context SubmissionRequest => Int64 -> Int64 -> DSL SubmissionRequest
  interpret operation request = withOperation @SubmissionRequest operation $ \value -> case request of
    SubmitBmm bid limit -> Just (runSubmission value bid limit)

submitBmm :: Int64 -> Int64 -> DSL SubmissionRequest
submitBmm = SubmitBmm

data ReplacementBid = ReplacementBid Int64 Int64 Int64 B.ByteString
class BidBounds op where
  canReplaceBid :: op -> Bool
class BidReplacementRules op where
  replacementFields :: op -> Maybe (Bool,B.ByteString,B.ByteString)
  adjustedBid :: op -> Bool -> Int64 -> Int64 -> Maybe Int64
instance BidBounds ReplacementBid where
  canReplaceBid (ReplacementBid current maximumBid moneyLimit _) =
    current > 0 && current <= moneyLimit && maximumBid <= moneyLimit && current < maximumBid
instance BidReplacementRules ReplacementBid where
  replacementFields (ReplacementBid _ _ _ message) = do
    guard (C.pack "insufficient fee, rejecting replacement " `B.isInfixOf` message)
    let after marker = let suffix = snd (B.breakSubstring (C.pack marker) message)
                       in if B.null suffix then Nothing else Just (B.drop (length marker) suffix)
    values <- case after "not enough additional fees to relay; " of
      Just value -> Just value
      Nothing -> after "less fees than conflicting txs; "
    let (paid,separator) = B.breakSubstring (C.pack " < ") values
        (needed,suffix) = B.span (\c -> (c >= 48 && c <= 57) || c == 46) (B.drop 3 separator)
        negative = not (B.null paid) && B.head paid == 45
    guard (not (B.null separator) && not (B.null needed))
    guard (B.null suffix || B.head suffix `elem` [34,10])
    pure (negative,if negative then B.drop 1 paid else paid,needed)
  adjustedBid (ReplacementBid current maximumBid _ _) negative paid needed = do
    guard (paid >= 0 && needed >= 0)
    let delta = toInteger needed - (if negative then negate (toInteger paid) else toInteger paid)
    guard (delta > 0 && delta <= toInteger maximumBid - toInteger current)
    pure (fromInteger (toInteger current + delta))
type BidCapabilities = '[BidBounds, BidReplacementRules]
replacementBid :: (BidBounds op, BidReplacementRules op)
  => op -> (B.ByteString -> IO Int64) -> IO (Maybe Int64)
replacementBid value parseAmount
    | not (canReplaceBid value) = pure Nothing
    | otherwise = case replacementFields value of
        Nothing -> pure Nothing
        Just (negative,paid,needed) -> parseAmount paid >>= \paidAmount ->
          parseAmount needed >>= \neededAmount -> pure (adjustedBid value negative paidAmount neededAmount)
instance Operation ReplacementBid BidCapabilities where
  type Context ReplacementBid = CapabilityContext BidCapabilities ReplacementBid
  type Outcome ReplacementBid = IO (Maybe Int64)
  data DSL ReplacementBid where
    ReplaceBid :: Context ReplacementBid => (B.ByteString -> IO Int64) -> DSL ReplacementBid
  interpret operation request = withOperation @ReplacementBid operation $ \value -> case request of
    ReplaceBid parser -> Just (replacementBid value parser)

replaceBid :: ReplacementBid -> (B.ByteString -> IO Int64) -> IO (Maybe Int64)
replaceBid value parser = execute value (ReplaceBid parser)

planGrpc :: DSL GrpcPlan
planGrpc = PlanGrpc

instance Operation GrpcPlan GrpcCapabilities where
  type Context GrpcPlan = CapabilityContext GrpcCapabilities GrpcPlan
  type Outcome GrpcPlan = Either String ()
  data DSL GrpcPlan where
    PlanGrpc :: Context GrpcPlan => DSL GrpcPlan
  interpret operation request = withOperation @GrpcPlan operation $ \value -> case request of
    PlanGrpc -> Just (admitGrpc value)

data GrpcSetupFlow
  = GrpcRequestFlow Word32 Word32
  | GrpcRequestAdmission Word32 Word32
  | GrpcExecutableFlow Word32 Word32
  | RpcServerFlow Word32 Word32
  | CredentialFlow Word32 Word32
  | GrpcConfigFlow Word32 Word32
instance Validation GrpcSetupFlow where
  type ValidationResult GrpcSetupFlow = Int32
  validate (GrpcRequestAdmission phase result)
    | phase==0 = 11
    | phase==11 = if result<=128 then 1 else 2
    | phase==1 && result==1 = 12
    | phase==12 = if result>0 && result<=1048576 then 5 else 4
    | otherwise = validate (GrpcRequestFlow phase result)
  validate (GrpcRequestFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-10)),(3,(4,5)),(4,(-1,-10)),(5,(6,7)),
     (6,(-1,-10)),(7,(9,8)),(8,(9,10)),(9,(-1,-10)),(10,(-1,-11))]

  validate (GrpcExecutableFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-10)),(3,(4,5)),(4,(-1,-10)),
     (5,(-10,6)),(6,(7,-11)),(7,(-1,-10))]

  validate (RpcServerFlow phase result)
    | phase==7 = if result>3 then -1 else if result==3 then 10 else 8
    | otherwise = transition phase result
        [(1,(3,2)),(2,(-1,-10)),(3,(4,5)),(4,(-1,-10)),(5,(-1,6)),
         (6,(-11,7)),(8,(-1,-10)),(9,(-1,6)),(10,(8,9))]

  validate (CredentialFlow phase result)
    | phase==1 = case result of 0 -> 2; 1 -> 3; 2 -> 13; _ -> -1
    | otherwise = transition phase result
        ([(3,(4,5)),(5,(6,7)),(7,(8,9)),(9,(10,11)),(11,(12,-11)),(13,(14,-11))] ++
         [(n,(-1,-10)) | n <- [2,4..14]])

  validate (GrpcConfigFlow phase result)
    | phase==0 = 1
    | phase==5 = if result>7 then -1 else if result==7 then 7 else 6
    | phase==9 = branch 20 11
    | phase==11 = branch 21 13
    | phase==20 = branch 11 10
    | phase==21 = branch 13 12
    | phase<=16 && odd phase = branch (fromIntegral phase+2) (fromIntegral phase+1)
    | phase<=16 = if result==1 then -10 else -1
    | phase<19 = branch (fromIntegral phase+1) (-10)
    | phase==19 = branch (-11) (-10)
    | otherwise = -1
    where branch yes no = if result==1 then yes else if result==0 then no else -1

-- Modes: absent (0), checked Int32 successor (1), widened successor (2).
data NextBlockHeight = NextBlockHeight Word32 Int32
instance Validation NextBlockHeight where
  type ValidationResult NextBlockHeight = Int64
  validate (NextBlockHeight mode height)
    | mode == 0 = -1
    | mode == 2 || (mode == 1 && height < maxBound) = fromIntegral height + 1
    | otherwise = -2147483649

data ExtraNonce = ExtraNonce Word32 Word32
instance Validation ExtraNonce where
  type ValidationResult ExtraNonce = Int64
  validate (ExtraNonce sameParent current) = case sameParent of
    0 -> 1
    1 -> fromIntegral (current + 1)
    _ -> -1

data PeerStrikes = PeerStrikes Word32 Word32
instance Validation PeerStrikes where
  type ValidationResult PeerStrikes = Int64
  validate (PeerStrikes flags count)
    | flags > 3 = -1
    | not (testBit flags 0) = 0
    | testBit flags 1 && count /= 0 = min 4294967295 (fromIntegral count + 1)
    | otherwise = 1

data PeerAdmissionFlow = PeerAdmissionFlow Bool Word32 Word32
instance Validation PeerAdmissionFlow where
  type ValidationResult PeerAdmissionFlow = Int32
  validate (PeerAdmissionFlow syncing phase result) = transition phase result $
    if syncing then [(1,(-10,2)),(2,(-10,-11))]
    else [(1,(7,2)),(2,(-1,3)),(3,(4,-11)),(4,(-10,5)),
          (5,(-10,6)),(6,(-10,-11)),(7,(-10,-11))]

data PeerBlockDispatchFlow = PeerBlockDispatchFlow Word32 Word32
instance Validation PeerBlockDispatchFlow where
  type ValidationResult PeerBlockDispatchFlow = Int32
  validate (PeerBlockDispatchFlow 1 outcome) = case outcome of
    1 -> 2
    2 -> 3
    _ -> -11
  validate (PeerBlockDispatchFlow phase result) = transition phase result
    [(2,(-1,-11)),(3,(-11,4)),(4,(-1,-11))]

data PeerDispatchFlow = PeerDispatchFlow Word32 Word32
instance Validation PeerDispatchFlow where
  type ValidationResult PeerDispatchFlow = Int32
  validate (PeerDispatchFlow phase result)
    | phase==4 = case result of 0 -> -10; 1 -> 5; 2 -> 6; _ -> -1
    | otherwise = transition phase result
        [(1,(2,4)),(2,(-10,3)),(3,(-1,-10)),(5,(-1,7)),(6,(-1,-10)),(7,(-1,-10))]

data PeerHeadersFlow = PeerHeadersFlow Word32 Word32
instance Validation PeerHeadersFlow where
  type ValidationResult PeerHeadersFlow = Int32
  validate (PeerHeadersFlow phase result) = transition phase result
    [(1,(3,2)),(2,(-1,3)),(3,(5,4)),(4,(-1,-10)),(5,(9,6)),
     (6,(8,7)),(7,(-1,-12)),(8,(-1,-10)),(9,(17,10)),(10,(14,11)),
     (11,(13,12)),(12,(-1,9)),(13,(-1,17)),(14,(17,15)),(15,(-1,16)),
     (16,(-1,-11)),(17,(-10,18)),(18,(-10,19)),(19,(-1,-12))]

data PeerTimerFlow = PeerTimerFlow Word32 Word32
instance Validation PeerTimerFlow where
  type ValidationResult PeerTimerFlow = Int32
  validate (PeerTimerFlow phase result) = transition phase result
    [(1,(4,2)),(2,(4,3)),(3,(-1,4)),(4,(-10,5)),
     (5,(7,6)),(6,(-1,-10)),(7,(-10,8)),(8,(-1,-11))]

data PeerBlockFlow = PeerBlockFlow Word32 Word32
instance Validation PeerBlockFlow where
  type ValidationResult PeerBlockFlow = Int32
  validate (PeerBlockFlow phase result)
    | phase==6 = if result==0 then 8 else if fromIntegral result < Constants.peerRejectedStrikes then 10 else 9
    | otherwise = transition phase result
        [(1,(-10,2)),(2,(4,3)),(3,(-1,-11)),(4,(-1,5)),(5,(12,6)),
         (8,(-1,-10)),(9,(-1,-12)),(10,(-1,-10)),(12,(13,8)),
         (13,(-10,14)),(14,(-1,-11))]

data FixedIdentity = FixedIdentity
instance Validation FixedIdentity where
  type ValidationResult FixedIdentity = ([Word32], [Word8])
  validate FixedIdentity = ([0,2069],
    [0x43,0xe5,0xde,0x39,0x49,0x4d,0xf3,0xa6,0x59,0xe2,0xff,0xd2,0x61,0x00,0x49,0xef
    ,0x5e,0x40,0x67,0x03,0x2a,0xf4,0x4a,0x06,0x42,0x13,0x24,0x89,0xcb,0x31,0x2f,0x94
    ,0x98,0x69,0x40,0xa8,0x72,0xb3,0x7b,0x68,0x7a,0xb8,0xf3,0xdd,0x18,0x8b,0x3b,0xc2
    ,0xe3,0x3a,0xe3,0xe5,0x0e,0xda,0x24,0x26,0xe6,0xf2,0x37,0xb0,0xe3,0xdf,0x77,0xce
    ,0xf9,0x9f,0x57,0x00,0x13,0x2a,0x03,0x08,0x8c,0xb9,0xb6,0xa8,0xf5,0x5d,0xa1,0xd1
    ,0xea,0x58,0x54,0x0d,0x54,0xd5,0x74,0x6d,0xc6,0xa7,0xc8,0x88,0xca,0xf7,0xbc,0xf0
    ,0x64,0x72,0x69,0x76,0x65,0x63,0x68,0x61,0x69,0x6e,0x2d,0x62,0x6d,0x6d,0x2d,0x76
    ,0x31,0xec,0xc7,0xda,0xa2,0xd1,0x61,0x73,0x68])

newtype CheckpointPreset = CheckpointPreset Word32
instance Validation CheckpointPreset where
  type ValidationResult CheckpointPreset = ([Word32], [Word8])
  validate (CheckpointPreset mode) = case mode of
    0 -> ([6400,1784826005,0x1e0376cc,6048,1784614805] ++
          [1784820005,1784820605,1784821205,1784821805,1784822405,1784823005,
           1784823605,1784824205,1784824805,1784825405,1784826005],
          [0x65,0x76,0x74,0x19,0x0b,0x9b,0xd4,0x39,0xb4,0x7f,0xff,0x98,0xfb,0x29,0xde,0x90,0xee,0x6c,0xab,0xc0,0x8c,0xd4,0xeb,0xd1,0x4e,0x84,0x9e,0xb6,0x1b,0x03,0x00,0x00])
    1 -> ([2096,1802055061,0x207fffff,2016,1786323045] ++
          [1802055058,1802055058,1802055059,1802055058,1802055059,1802055059,
           1802055060,1802055059,1802055060,1802055060,1802055061],
          [0x9f,0x8d,0x72,0xf9,0x78,0xf7,0x1a,0x6c,0xce,0x89,0xc3,0x3f,0x50,0x23,0x57,0x43,0xa7,0x7a,0xf1,0x26,0xa6,0x51,0xee,0x4f,0xd2,0x0c,0x19,0x68,0xd4,0xe8,0x4f,0x63])
    _ -> error "invalid BMM checkpoint preset"

newtype ConsensusPreset = ConsensusPreset Word32
instance Validation ConsensusPreset where
  type ValidationResult ConsensusPreset = ([Word64], [Word8], [Word8])
  validate (ConsensusPreset mode) = case mode of
    0 -> (common ++ [Constants.requireSignet], replicate 27 0 ++ [0xae,0x77,3,0,0],
          [0,0x14,0x88,0x35,0x83,0x2e,0x28,0xc8,0x16,0xb7,0xac,0xd8,0xfd,0xb1,0x97,0x72,0xab,0x21,0x99,0x60,0x3a,0x56])
    1 -> (common ++ [0], replicate 31 255 ++ [127], [])
    _ -> error "invalid BMM consensus preset"
    where common = Constants.consensusDefaults

data ApprovingParentHeight = ApprovingParentHeight Int64
instance Validation ApprovingParentHeight where
  type ValidationResult ApprovingParentHeight = Int64
  validate (ApprovingParentHeight height)
    | height < 0 || height >= 0xffffffff = -1
    | otherwise = height + 1

data ChildBehind = ChildBehind Int64 Int64
instance Validation ChildBehind where
  type ValidationResult ChildBehind = Bool
  validate (ChildBehind child parent) = child < parent

data BoundedWait = BoundedWait Int64 Int64
instance Validation BoundedWait where
  type ValidationResult BoundedWait = Int64
  validate (BoundedWait value maximumWait)
    | maximumWait < 1 = -1
    | otherwise = max 1 (min maximumWait value)

data BoundedAppend = BoundedAppend Word64 Word64 Int64
instance Validation BoundedAppend where
  type ValidationResult BoundedAppend = Int64
  validate (BoundedAppend limit used count)
    | count < 0 = -1
    | used >= limit = 0
    | otherwise = fromIntegral (min (limit-used) (fromIntegral count))

data DifficultyInterval = DifficultyInterval Int64 Int64
instance Validation DifficultyInterval where
  type ValidationResult DifficultyInterval = Int64
  validate (DifficultyInterval timespan spacing)
    | spacing == 0 || (timespan == minBound && spacing == -1) = error "invalid difficulty interval division"
    | otherwise = timespan `quot` spacing

foreign import ccall "dynamic" writeState :: FunPtr WriteState -> WriteState

class StateReplacement op where
  replacementHeight :: op -> IO Int32
  clearStoredState :: op -> IO ()
  prepareStoredState :: op -> IO ()

replaceStoredState :: (StateReplacement op, Finalize op, FinalInput op ~ Word32, FinalResult op ~ ()) => op -> IO ()
replaceStoredState request = do
  height <- replacementHeight request
  clearStoredState request
  prepareStoredState request
  finalize request (fromIntegral (max 0 height))

data StateWrite = StateWrite Int32 (FunPtr WriteState) (Ptr ())
                | StateRestore Int32 (FunPtr WriteState) (Ptr ())
stateAction :: StateWrite -> Word32 -> Word32 -> IO ()
stateAction (StateRestore prior writer context) action height = stateAction (StateWrite prior writer context) action height
stateAction (StateWrite _ writer context) action height
  | writer == nullFunPtr = error "missing BMM state writer"
  | otherwise = do
      status <- writeState writer context action height
      when (status /= 1) (error "BMM state write failed")

class StateAssembly op where
  serializeMarker :: op -> IO ()
  serializeParent :: op -> IO ()
  pushStatePayload :: op -> IO ()

assembleStoredState :: (StateAssembly op, Finalize op, FinalInput op ~ (), FinalResult op ~ ()) => op -> IO ()
assembleStoredState request = do
  serializeMarker request
  serializeParent request
  pushStatePayload request
  finalize request ()

newtype StateEncode = StateEncode StateWrite
instance StateAssembly StateEncode where
  serializeMarker (StateEncode writer) = stateAction writer 0 0
  serializeParent (StateEncode writer) = stateAction writer 1 0
  pushStatePayload (StateEncode writer) = stateAction writer 2 0
instance Finalize StateEncode where
  type FinalInput StateEncode = ()
  type FinalResult StateEncode = ()
  finalize (StateEncode writer) () = stateAction writer 3 117 >> stateAction writer 3 0
type StateEncodeCapabilities = '[StateAssembly, Finalize]

encodeState :: DSL StateEncode
encodeState = EncodeState

instance Operation StateEncode StateEncodeCapabilities where
  type Context StateEncode = CapabilityContext StateEncodeCapabilities StateEncode
  type Outcome StateEncode = IO ()
  data DSL StateEncode where
    EncodeState :: Context StateEncode => DSL StateEncode
  interpret operation request = withOperation @StateEncode operation $ \value -> case request of
    EncodeState -> Just (assembleStoredState value)
instance StateReplacement StateWrite where
  replacementHeight (StateWrite height _ _) = pure height
  replacementHeight (StateRestore height _ _) = pure (max 1 height - 1)
  clearStoredState request = stateAction request 0 0
  prepareStoredState request = stateAction request 1 0
instance Finalize StateWrite where
  type FinalInput StateWrite = Word32
  type FinalResult StateWrite = ()
  finalize request = stateAction request 2
type StateWriteCapabilities = '[StateReplacement, Finalize]

replaceState :: DSL StateWrite
replaceState = ReplaceState

instance Operation StateWrite StateWriteCapabilities where
  type Context StateWrite = CapabilityContext StateWriteCapabilities StateWrite
  type Outcome StateWrite = IO ()
  data DSL StateWrite where
    ReplaceState :: Context StateWrite => DSL StateWrite
  interpret operation request = withOperation @StateWrite operation $ \value -> case request of
    ReplaceState -> Just (replaceStoredState value)

-- Encode and replace within one workflow; native effects never request a
-- second Haskell encoding plan. The two products reuse the existing algebras.
data PersistedOutput = PersistedOutput Bool NativeBytes
newtype OutputEncoding = OutputEncoding NativeBytes

instance StateAssembly OutputEncoding where
  serializeMarker (OutputEncoding native) = stateEffect native 11 0 B.empty
  serializeParent (OutputEncoding native) = stateEffect native 12 0 B.empty
  pushStatePayload (OutputEncoding native) = stateEffect native 13 0 B.empty
instance Finalize OutputEncoding where
  type FinalInput OutputEncoding = ()
  type FinalResult OutputEncoding = ()
  finalize (OutputEncoding native) () = do
    stateEffect native 14 117 B.empty
    stateEffect native 14 0 B.empty

instance StateReplacement PersistedOutput where
  replacementHeight (PersistedOutput restore native) = do
    values <- stateReplyWords native 0 1
    case values of
      [bits] | bits <= 0xffffffff -> do
        let height = fromIntegral bits :: Int32
        pure (if restore then max 1 height - 1 else height)
      _ -> ioError (userError "invalid persisted output height")
  clearStoredState (PersistedOutput _ native) = stateEffect native 10 0 B.empty
  prepareStoredState (PersistedOutput _ native) = do
    assembleStoredState (OutputEncoding native)
    stateEffect native 15 0 B.empty
instance Finalize PersistedOutput where
  type FinalInput PersistedOutput = Word32
  type FinalResult PersistedOutput = ()
  finalize (PersistedOutput _ native) height = stateEffect native 16 (fromIntegral height) B.empty

type PersistedOutputCapabilities = '[StateReplacement, Finalize]
instance Operation PersistedOutput PersistedOutputCapabilities where
  type Context PersistedOutput = CapabilityContext PersistedOutputCapabilities PersistedOutput
  type Outcome PersistedOutput = IO Int32
  data DSL PersistedOutput where
    PersistOutput :: Context PersistedOutput => DSL PersistedOutput
  interpret operation request = withOperation @PersistedOutput operation $ \value -> case request of
    PersistOutput -> Just (replaceStoredState value >> pure 1)

-- Field groups: scalars, blobs, public state/history, private state/history.
type ReadFingerprint = Ptr () -> Word32 -> Word32 -> Ptr Word64 -> Ptr (Ptr Word8) -> IO Int32
foreign import ccall "dynamic" readFingerprint :: FunPtr ReadFingerprint -> ReadFingerprint

class FingerprintSource op where
  fingerprintNumber :: op -> Word32 -> Word32 -> IO Word64
  fingerprintBytes :: op -> Word32 -> IO [Word8]

bigEndian :: Int -> Word64 -> [Word8]
bigEndian width value = [fromIntegral (value `shiftR` shift) | shift <- reverse [0,8..8*(width-1)]]

fingerprintPayload :: FingerprintSource op => op -> IO [Word8]
fingerprintPayload source = do
  private <- fingerprintNumber source 0 2
  if private > 1 then error "invalid BMM fingerprint mode" else pure ()
  prefix <- sequence [pure (bigEndian 4 4), number 1 0, number 4 1,
    pure [fromIntegral private], raw 0, number 8 3, number 8 4,
    sized 1, number 1 5, number 4 6, number 8 7, number 8 8]
  publicState <- state 2 8
  privateState <- if private == 1 then state 4 9 else pure []
  suffix <- sequence [raw 2, raw 3, raw 4, number 4 9, sized 5, raw 6, raw 7, number 4 10]
  pure (concat prefix ++ publicState ++ privateState ++ concat suffix)
  where
    number width index = bigEndian width <$> fingerprintNumber source 0 index
    raw = fingerprintBytes source
    sized index = do
      bytes <- raw index
      pure (bigEndian 8 (fromIntegral (length bytes)) ++ bytes)
    state group hashIndex = do
      blockHash <- raw hashIndex
      fields <- mapM (fingerprintNumber source group) [0..4]
      count <- fingerprintNumber source group 5
      when (count > fromIntegral (maxBound :: Word32)) (error "BMM fingerprint history too large")
      times <- mapM (fingerprintNumber source (group + 1)) (take (fromIntegral count) [0..])
      pure (blockHash ++ concatMap (bigEndian 4) fields ++ bigEndian 8 count ++ concatMap (bigEndian 4) times)

data FingerprintRequest = FingerprintRequest (FunPtr ReadFingerprint) (Ptr ())
fingerprintField :: FingerprintRequest -> Word32 -> Word32 -> IO (Word64, Ptr Word8)
fingerprintField (FingerprintRequest reader context) group index
  | reader == nullFunPtr = error "missing BMM fingerprint adapter"
  | otherwise = alloca $ \value -> alloca $ \bytes -> do
      poke value 0
      poke bytes nullPtr
      status <- readFingerprint reader context group index value bytes
      if status /= 1 then error "BMM fingerprint adapter fault"
      else (,) <$> peek value <*> peek bytes
instance FingerprintSource FingerprintRequest where
  fingerprintNumber request group index = fst <$> fingerprintField request group index
  fingerprintBytes request index = do
    (size, bytes) <- fingerprintField request 1 index
    if size > fromIntegral (maxBound :: Int) || (size /= 0 && bytes == nullPtr)
      then error "invalid BMM fingerprint bytes"
      else peekArray (fromIntegral size) bytes
data FingerprintFormat = BmmFormat

fingerprint :: FingerprintFormat -> DSL FingerprintRequest
fingerprint = EncodeFingerprint

encodeFingerprint :: FingerprintSource op => FingerprintFormat -> op -> IO [Word8]
encodeFingerprint format source = do
  bytes <- case format of
    BmmFormat -> fingerprintPayload source
  mapM_ evaluate bytes
  pure bytes

instance Operation FingerprintRequest '[FingerprintSource] where
  type Context FingerprintRequest = FingerprintSource FingerprintRequest
  type Outcome FingerprintRequest = IO [Word8]
  data DSL FingerprintRequest where
    EncodeFingerprint :: Context FingerprintRequest => FingerprintFormat -> DSL FingerprintRequest
  interpret operation request = withOperation @FingerprintRequest operation $ \value -> case request of
    EncodeFingerprint format -> Just (encodeFingerprint format value)

data ScriptStep = ScriptEnd Bool | ScriptPush Int64 Int64
data ScriptEdit = CaptureSolution | AppendPush | AppendOpcode | PublishScript deriving (Enum, Eq, Show)
class ScriptStream op where
  nextScriptStep :: op -> IO ScriptStep
class ScriptRewrite op where
  editScript :: op -> ScriptEdit -> IO ()

extractSignet :: (ScriptStream op, ScriptRewrite op, Finalize op, FinalInput op ~ Bool, FinalResult op ~ Int32) => op -> IO Int32
extractSignet request = go False
  where
    go found = do
      step <- nextScriptStep request
      case step of
        ScriptEnd False -> pure 0
        ScriptEnd True -> finalize request found
        ScriptPush size prefix -> do
          let capture = not found && size > 4 && prefix == 0xa2dac7ec
          when capture (editScript request CaptureSolution)
          editScript request (if size > 0 then AppendPush else AppendOpcode)
          go (found || capture)

data SignetRequest = SignetRequest (FunPtr ReadPegFields) (Ptr ())
scriptCall :: SignetRequest -> Word32 -> IO [Int64]
scriptCall (SignetRequest reader context) action
  | reader == nullFunPtr = error "missing signet script adapter"
  | otherwise = allocaArray 4 $ \out -> do
      status <- readPegFields reader context action out
      if status /= 1 then error "signet script adapter fault"
      else if action == 0 then peekArray 4 out else pure []

instance ScriptStream SignetRequest where
  nextScriptStep request = scriptCall request 0 >>= signetScriptStep

signetScriptStep :: [Int64] -> IO ScriptStep
signetScriptStep [parsed,end,size,prefix]
  | parsed >= 0 && parsed <= 1 && end >= 0 && end <= 1 &&
      size >= 0 && prefix >= 0 && prefix <= 0xffffffff =
    pure (if parsed == 0 then ScriptEnd (end == 1) else ScriptPush size prefix)
signetScriptStep _ = error "invalid signet script facts"
instance ScriptRewrite SignetRequest where
  editScript request action = void (scriptCall request (fromIntegral (fromEnum action) + 1))
instance Finalize SignetRequest where
  type FinalInput SignetRequest = Bool
  type FinalResult SignetRequest = Int32
  finalize request found = when found (editScript request PublishScript) >> pure 1
type ScriptCapabilities = '[ScriptStream, ScriptRewrite, Finalize]

extractSignetRequest :: DSL SignetRequest
extractSignetRequest = ExtractSignet

instance Operation SignetRequest ScriptCapabilities where
  type Context SignetRequest = CapabilityContext ScriptCapabilities SignetRequest
  type Outcome SignetRequest = IO Int32
  data DSL SignetRequest where
    ExtractSignet :: Context SignetRequest => DSL SignetRequest
  interpret operation request = withOperation @SignetRequest operation $ \value -> case request of
    ExtractSignet -> Just (extractSignet value)

-- Parent-header and BMM validation share construction and witness selection,
-- but retain their different native decoding and Merkle-proof contracts.
class SignetConstruction op where
  buildSignetTransactions :: op -> ExceptT Int32 IO ()
  writeSignetBlockData :: op -> ExceptT Int32 IO ()
class SignetCommitment op where
  selectSignetCommitment :: op -> ExceptT Int32 IO Bool

signetEffect :: NativeBytes -> Word32 -> Word64 -> ExceptT Int32 IO ()
signetEffect native step index = do
  value <- lift (constructionScalar native step index)
  unless (value == 1) (throwE (-1))

constructSignet :: NativeBytes -> ExceptT Int32 IO ()
constructSignet native = do
  let fields = B.concat (map (wordLE 4 . fromIntegral) (validate SignetTemplate))
  forM_ (validate (SignetActions 0)) $ \action -> do
    reply <- lift (native (200+action) 0 fields)
    unless (reply == wordLE 8 1) (throwE (-1))

writeSignetData :: NativeBytes -> ExceptT Int32 IO ()
writeSignetData native = mapM_ (\field -> signetEffect native (300+field) 0) (validate (Preimage 1))

selectSignetWitness :: NativeBytes -> ExceptT Int32 IO Bool
selectSignetWitness native = do
  count <- lift (constructionScalar native 500 0)
  unless (count <= fromIntegral (maxBound :: Word32)) (throwE (-1))
  let scan index found
        | index == count = do
            answer <- lift (constructionScalar native 502 found)
            case answer of
              0 -> pure False
              1 -> pure True
              _ -> throwE (-1)
        | otherwise = do
            facts <- lift (native 501 index B.empty)
            unless (B.length facts == 16) (throwE (-1))
            let matches = witnessCommitment (fromIntegral (readLE (B.take 8 facts)))
                  (fromIntegral (readLE (B.drop 8 facts)))
            matches `seq` scan (index+1) (if matches then index else found)
  scan 0 maxBound

newtype SignetSession = SignetSession NativeBytes
class SignetProof op where
  signetScope :: op -> IO a -> IO a
  signetFacts :: op -> Word32 -> IO [Word64]
  signetResult :: op -> Int32 -> IO Bool

instance ScriptStream SignetSession where
  nextScriptStep (SignetSession native) = map fromIntegral <$> proofWords native 10 4 >>= signetScriptStep
instance ScriptRewrite SignetSession where
  editScript (SignetSession native) action = stateEffect native (11+fromIntegral (fromEnum action)) 0 B.empty
instance Finalize SignetSession where
  type FinalInput SignetSession = Bool
  type FinalResult SignetSession = Int32
  finalize value found = when found (editScript value PublishScript) >> pure 1

instance SignetConstruction SignetSession where
  buildSignetTransactions (SignetSession native) = constructSignet (\step -> native (step-180))
  writeSignetBlockData (SignetSession native) = writeSignetData (\step -> native (step-270))
instance SignetCommitment SignetSession where
  selectSignetCommitment (SignetSession native) = selectSignetWitness (\step -> native (step-460))

signetChecked :: ExceptT Int32 IO a -> IO a
signetChecked action = runExceptT action >>= either (const (ioError (userError "invalid signet projection"))) pure

instance SignetProof SignetSession where
  signetScope (SignetSession native) action =
    stateEffect native 0 0 B.empty >> action `finally` stateEffect native 1 0 B.empty
  signetFacts (SignetSession native) step = case step of
    2 -> stateEffect native 54 0 B.empty >> pure [1,0,0,0]
    3 -> answer <$> proofBoolean native 53
    4 -> do
      -- The old BMM decoder catches all exceptions, unlike parent authentication.
      result <- try @SomeException $ do
        let required s = proofScalar native s >>= \ok -> unless (ok == 1) (ioError (userError "signet decode failure"))
        required 60
        mapM_ (required . (61+)) (validate (SignetActions 1))
        proofScalar native 63 >>= \status -> case status of
          0 -> pure 0
          1 -> pure 1
          _ -> ioError (userError "signet decode failure")
      stateEffect native 64 0 B.empty
      pure [either (const 2) id result,0,0,0]
    5 -> proofWords native 50 4
    6 -> answer <$> proofBoolean native 51
    7 -> answer <$> proofBoolean native 52
    _ -> ioError (userError "invalid signet observation")
    where answer ok = [fromIntegral (fromEnum ok),0,0,0]
  signetResult (SignetSession native) result
    | result == 0 = pure True
    | result >= -6 && result <= -1 = do
        stateEffect native 90 0 (C.pack (messages !! fromIntegral (-result-1)))
        pure False
    | otherwise = ioError (userError "invalid signet validation result")
    where messages = ["BMM parent block has no Bitcoin witness commitment",
            "BMM parent block has a malformed signet commitment script",
            "BMM parent block signet solution contains trailing data",
            "BMM parent block signet solution cannot be decoded",
            "BMM signet proof does not authenticate exactly the coinbase",
            "BMM parent block signet solution is invalid"]

verifySignetSession :: (SignetConstruction op, SignetCommitment op, SignetProof op,
    ScriptStream op, ScriptRewrite op, Finalize op, FinalInput op ~ Bool, FinalResult op ~ Int32)
  => op -> IO Bool
verifySignetSession value = signetScope value $
  validate (ProofExecution 0 0 observe) >>= signetResult value
  where
    observe 1 = do
      found <- signetChecked (selectSignetCommitment value)
      pure [fromIntegral (fromEnum found),0,0,0]
    observe 2 = signetFacts value 2 >> extractSignet value >>= \ok -> pure [fromIntegral ok,0,0,0]
    observe 3 = signetChecked (buildSignetTransactions value) >> signetFacts value 3
    observe 7 = signetChecked (writeSignetBlockData value) >> signetFacts value 7
    observe step = signetFacts value step

type SignetSessionCapabilities = '[SignetConstruction, SignetCommitment, SignetProof, ScriptStream, ScriptRewrite, Finalize]
instance Operation SignetSession SignetSessionCapabilities where
  type Context SignetSession = CapabilityContext SignetSessionCapabilities SignetSession
  type Outcome SignetSession = IO Bool
  data DSL SignetSession where
    VerifySignetSession :: Context SignetSession => DSL SignetSession
  interpret operation request = withOperation @SignetSession operation $ \value -> case request of
    VerifySignetSession -> Just (verifySignetSession value)

-- Positive results select the next action, zero accepts, negative results reject.
data SignetValidation = SignetValidation Word32 Word64 Word64 Word64 Word64
instance Validation SignetValidation where
  type ValidationResult SignetValidation = Int32
  validate (SignetValidation phase a b c d) = case phase of
    0 -> 1
    1 -> if a /= 0 then 2 else -1
    2 -> if a /= 0 then 3 else -2
    3 -> if a /= 0 then 4 else 5
    4 -> case a of
      0 -> 5
      1 -> -3
      2 -> -4
      _ -> error "invalid signet decode status"
    5 -> if a /= 0 && b == 1 && c == 1 && d == 0 then 6 else -5
    6 -> if a /= 0 then 7 else -5
    7 -> if a /= 0 then 0 else -6
    _ -> error "invalid signet validation phase"

-- Both proof protocols consume unsigned facts; publication has no later gate.
data ProofExecution = ProofExecution Word32 Word32 (Word32 -> IO [Word64])
instance Validation ProofExecution where
  type ValidationResult ProofExecution = IO Int32
  validate (ProofExecution kind start action)
    | kind > 1 = pure minBound
    | otherwise = run (nextProofStep start [0,0,0,0])
    where
      nextProofStep phase [a,b,c,d]
        | kind == 0 = validate (SignetValidation phase a b c d)
        | otherwise = validate (Traversal phase a b)
      nextProofStep _ _ = error "invalid BMM proof reply shape"
      run phase
        | phase < (if kind == 0 then -6 else -2) || phase > (if kind == 0 then 7 else 20) = pure minBound
        | phase <= 0 = pure phase
        | otherwise = do
            fields <- action (fromIntegral phase)
            if kind == 1 && phase == 19 then pure 0
              else run (nextProofStep (fromIntegral phase) fields)

-- Compose proof decisions inside the traversal; native replies contain facts,
-- not the results of another Haskell entry. Extended steps retain lazy reads.
data ProofWorkflow = ProofWorkflow Word32 (Word32 -> IO [Word64])
instance Validation ProofWorkflow where
  type ValidationResult ProofWorkflow = IO Int32
  validate (ProofWorkflow start native)
    | start `notElem` [0,11,21] = pure minBound
    | otherwise = either id id <$> runExceptT (if start == 21 then do
        _ <- readFields 22 >>= rule 13
        accepted <- boolean 23
        pure (if accepted then 0 else -1)
      else run (validate (Traversal start 0 0)))
    where
      readFields step = do
        fields <- lift (native step)
        case fields of
          [_,_,_,_] -> pure fields
          _ -> throwE minBound
      boolean step = do
        fields <- readFields step
        case head fields of
          0 -> pure False
          1 -> pure True
          _ -> throwE minBound
      rule :: Word32 -> [Word64] -> ExceptT Int32 IO [Word64]
      rule phase [flags,a,b,c]
        | flags <= fromIntegral (maxBound :: Word32) =
            case validate (Proof phase (fromIntegral flags) a b c) of
              0 -> pure [1,0,0,0]
              code | code > 0 -> throwE (100+code)
              _ -> throwE minBound
      rule _ _ = throwE minBound
      reply 1 = do
        fields <- readFields 1
        _ <- rule 0 fields
        readFields 147
      reply 20 = do
        ready <- boolean 200
        when (not ready) (throwE minBound)
        let decode step bits
              | step == 205 = pure bits
              | otherwise = do
                  accepted <- boolean step
                  if accepted then decode (step+1) (bits .|. (1 `shiftL` fromIntegral (step-201)))
                    else pure bits
        decoded <- decode 201 0
        fields <- readFields 205
        case fields of
          [coinbase,inputs,0,0] | coinbase <= 1 -> rule 2 [decoded .|. (coinbase `shiftL` 4),inputs,0,0]
          _ -> throwE minBound
      reply 5 = do
        let extend [] = pure True
            extend (step:rest) = boolean step >>= \accepted ->
              if accepted then extend rest else pure False
        accepted <- extend [150,151,152]
        _ <- rule 4 [if accepted then 7 else 0,0,0,0]
        fields <- readFields 154
        case fields of
          [flags,signet,0,0] | signet <= 1 -> do
            _ <- rule 11 [flags,0,0,0]
            _ <- readFields 155 >>= rule 12
            pure [1,signet,0,0]
          _ -> throwE minBound
      reply step
        | Just phase <- lookup step [(2,1),(3,3),(4,10),(8,5),(10,6),(12,7),(13,8),(15,9)] =
            readFields step >>= rule phase
        | otherwise = readFields step
      run phase
        | phase < -2 || phase > 20 = throwE minBound
        | phase <= 0 = pure phase
        | otherwise = do
            fields <- reply (fromIntegral phase)
            case fields of
              a:b:_ | phase == 19 -> pure 0
                    | otherwise -> run (validate (Traversal (fromIntegral phase) a b))
              _ -> throwE minBound

-- A proof session composes codecs and traversal without a native callback
-- re-entering the ABI for the next workflow. Native objects remain borrowed.
newtype ProofSession = ProofSession NativeBytes
class ProofCoding op where
  encodeProofBytes :: op -> IO Bool
  decodeProofBytes :: op -> IO Bool
class ProofEnvelopeAccess op where
  resetProofError :: op -> IO ()
  proofFacts :: op -> Word32 -> IO [Word64]
  proofHeaderEnabled :: op -> IO Bool
  publishProofCommitment :: op -> IO ()
  proofResult :: op -> Int32 -> IO Bool
class ProofSequence op where
  verifyProofSequence :: op -> IO Bool

class ProofHeaderEvolution op where
  type ProofHeaderState op
  inspectProofState :: op -> IO (Maybe (ProofHeaderState op))
  beginProofHeaders :: op -> ProofHeaderState op -> IO (ProofHeaderState op)
  matchesProofParent :: op -> ProofHeaderState op -> IO Bool
  matchesProofBits :: op -> ProofHeaderState op -> IO Bool
  exceedsProofMedian :: op -> ProofHeaderState op -> IO Bool
  advanceProofHeader :: op -> ProofHeaderState op -> IO (ProofHeaderState op, [Word64])
  publishProofState :: op -> ProofHeaderState op -> IO ()

data ProofHeaderProgress = ProofHeaderProgress
  { proofStateHash :: B.ByteString, proofStateFields :: [Word32]
  , proofStateInterval :: Int64, proofStateTimespan :: Int64
  , proofEntryCount :: Word64, proofEntryPosition :: Word64 }

proofWords :: NativeBytes -> Word32 -> Int -> IO [Word64]
proofWords native step count = do
  bytes <- native step 0 B.empty
  unless (B.length bytes == count*8) (ioError (userError "invalid proof session reply"))
  pure [readLE (B.take 8 (B.drop (8*i) bytes)) | i <- [0..count-1]]

proofScalar :: NativeBytes -> Word32 -> IO Word64
proofScalar native step = head <$> proofWords native step 1

proofBoolean :: NativeBytes -> Word32 -> IO Bool
proofBoolean native step = proofScalar native step >>= \value -> case value of
  0 -> pure False
  1 -> pure True
  _ -> ioError (userError "invalid proof session boolean")

rejectProof :: NativeBytes -> String -> IO Bool
rejectProof native message = stateEffect native 390 0 (C.pack message) >> pure False

proofBytes :: NativeBytes -> Word32 -> Int -> B.ByteString -> IO B.ByteString
proofBytes native step size input = do
  bytes <- native step 0 input
  unless (B.length bytes == size) (ioError (userError "invalid proof header projection"))
  pure bytes

proofEvaluation :: NativeBytes -> String -> IO a -> IO a
proofEvaluation native message action = do
  result <- try @SomeException action
  case result of
    Right value -> pure value
    Left _ -> native 409 0 (C.pack message) >> ioError (userError message)

headerDWords :: B.ByteString -> [Word32]
headerDWords bytes = [fromIntegral (readLE (B.take 4 (B.drop offset bytes))) | offset <- [0,4..B.length bytes-4]]

instance ProofHeaderEvolution ProofSession where
  type ProofHeaderState ProofSession = ProofHeaderProgress
  inspectProofState (ProofSession native) = do
    fields <- proofWords native 400 11
    case fields of
      [hash,timespan,spacing,height,time,bits,start,startTime,count,latest,entries]
        | hash <= 1 && all (<= 0xffffffff) [height,time,bits,start,startTime,latest] -> do
          interval <- proofEvaluation native "Haskell difficulty interval failed" $
            evaluate (validate (DifficultyInterval (fromIntegral timespan) (fromIntegral spacing)))
          let valid = validate (ParentState (fromIntegral hash) interval (fromIntegral height) (fromIntegral time)
                (fromIntegral bits) (fromIntegral start) (fromIntegral startTime) count (fromIntegral latest)) == 0
          if not valid then rejectProof native "BMM parent-chain state is malformed" >> pure Nothing
            else pure (Just (ProofHeaderProgress B.empty (map fromIntegral [height,time,bits,start,startTime])
              interval (fromIntegral timespan) entries 0))
      _ -> ioError (userError "invalid proof state projection")
  beginProofHeaders (ProofSession native) state = do
    bytes <- proofBytes native 401 97 B.empty
    unless (B.index bytes 52 == 11) (ioError (userError "invalid proof state history"))
    let fields = headerDWords (B.take 20 (B.drop 32 bytes) <> B.drop 53 bytes)
    unless (take 5 fields == proofStateFields state) (ioError (userError "inconsistent proof state projection"))
    pure state {proofStateHash = B.take 32 bytes, proofStateFields = fields}
  matchesProofParent (ProofSession native) state =
    (== proofStateHash state) <$> proofBytes native 402 32 B.empty
  matchesProofBits (ProofSession native) state = do
    (height,time,bits,startTime) <- case take 5 (proofStateFields state) of
      [height,time,bits,_,startTime] -> pure (height,time,bits,startTime)
      _ -> ioError (userError "invalid proof header state")
    timing <- proofEvaluation native "Haskell BMM retarget evaluation failed" $
      evaluate (validate (Retarget height (proofStateInterval state) (proofStateTimespan state) time startTime))
    expected <- if timing == -1 then pure bits else do
      targets <- proofBytes native 405 64 (wordLE 4 (fromIntegral bits))
      scaled <- proofEvaluation native "Haskell BMM target scaling failed" $
        mapM evaluate (validate (TargetScale (fromIntegral timing) (fromIntegral (proofStateTimespan state))
          (B.unpack (B.take 32 targets)) (B.unpack (B.drop 32 targets))))
      fromIntegral . readLE <$> proofBytes native 406 4 (B.pack scaled)
    actual <- headerDWords <$> proofBytes native 403 8 B.empty
    pure (actual !! 1 == expected)
  exceedsProofMedian (ProofSession native) state = do
    actual <- headerDWords <$> proofBytes native 403 8 B.empty
    let median = validate (Median (drop 5 (proofStateFields state)))
    pure (fromIntegral (head actual) > median)
  advanceProofHeader (ProofSession native) state = do
    [time,bits] <- headerDWords <$> proofBytes native 403 8 B.empty
    fields <- proofEvaluation native "Haskell BMM advancement failed" $
      mapM evaluate (validate (Advance (proofStateInterval state) time bits (proofStateFields state)))
    hash <- proofBytes native 404 32 B.empty
    stateEffect native 408 0 B.empty
    pure (state {proofStateHash = hash, proofStateFields = fields, proofEntryPosition = proofEntryPosition state + 1},
      [proofEntryPosition state,proofEntryCount state,0,0])
  publishProofState (ProofSession native) state = do
    let fields = map (wordLE 4 . fromIntegral) (proofStateFields state)
    stateEffect native 407 0 (proofStateHash state <> B.concat (take 5 fields) <> B.singleton 11 <> B.concat (drop 5 fields))

proofCodecRule :: NativeBytes -> Word32 -> Word32 -> Word64 -> Word64 -> IO Bool
proofCodecRule native phase facts a b = case validate (Codec phase facts a b) of
  0 -> pure True
  code | code >= 1 && code <= 4 -> rejectProof native (messages !! (fromIntegral code-1))
  _ -> ioError (userError "invalid proof session codec result")
  where
    messages = ["serialized BMM proof exceeds its consensus size bound",
      "BMM proof is empty or exceeds its consensus size bound",
      "BMM proof is malformed or non-canonical",
      "cannot attach BMM proof without the header version bit"]

instance ProofCoding ProofSession where
  encodeProofBytes value@(ProofSession native) = do
    resetProofError value
    reply <- native 300 0 B.empty
    case B.uncons reply of
      Just (0,message) -> rejectProof native (C.unpack message)
      Just (1,bytes) | B.length bytes == 8 -> proofCodecRule native 0 0 (readLE bytes) Constants.proofBytes
      _ -> ioError (userError "invalid proof serialization reply")
  decodeProofBytes value@(ProofSession native) = do
    resetProofError value
    size <- proofScalar native 301
    bounded <- proofCodecRule native 1 0 size Constants.proofBytes
    if not bounded then pure False else do
      decoded <- proofBoolean native 302
      version <- if decoded then (== Constants.schemaVersion) <$> proofScalar native 303 else pure False
      count <- if version then proofScalar native 304 else pure 0
      shape <- proofCodecRule native 2 (fromIntegral (fromEnum decoded + 2*fromEnum version)) count Constants.proofEntries
      if not shape then pure False else do
        canonical <- proofBoolean native 305
        proofCodecRule native 3 (if canonical then 1 else 0) 0 0

instance ProofEnvelopeAccess ProofSession where
  resetProofError (ProofSession native) = stateEffect native 392 0 B.empty
  proofFacts (ProofSession native) step
    | step == 6 = do
        accepted <- verifySignetSession (SignetSession (\s -> native (700+s)))
        pure [fromIntegral (fromEnum accepted),0,0,0]
    | Just offset <- lookup step [(9,500),(23,600)] = do
        accepted <- extractSelectedCommitment (CommitmentSession (\s -> native (offset+s)))
        pure [fromIntegral (fromEnum accepted),0,0,0]
    | otherwise = proofWords native step 4
  proofHeaderEnabled (ProofSession native) = do
    present <- proofBoolean native 306
    proofCodecRule native 4 (if present then 1 else 0) 0 0
  publishProofCommitment (ProofSession native) = stateEffect native 307 0 B.empty
  proofResult (ProofSession native) result
    | result >= 101 && result <= 111 = rejectProof native (messages !! (fromIntegral result-101))
    | result < -2 || result > 20 = ioError (userError "invalid proof traversal result")
    | result == -2 = do
        empty <- proofBoolean native 391
        if empty then rejectProof native "BMM parent header does not extend the authenticated state" else pure False
    | otherwise = pure (result == 0)
    where
      messages = ["BMM proof envelope is invalid",
        "BMM proof entry exceeds its transaction or Merkle proof bound",
        "BMM proof entry has a malformed or non-canonical coinbase proof",
        "BMM Merkle proof does not authenticate exactly the parent coinbase",
        "BMM parent header does not extend the authenticated state",
        "BMM proof final header is not the successor of the committed L1 parent",
        "BMM successor commitment does not match the sidechain critical hash",
        "sidechain block does not commit its exact BMM proof bytes",
        "BMM proof does not extend the locally authenticated parent-chain state",
        "BMM proof contains an invalid parent-chain proof-of-work header",
        "sidechain block has no coinbase transaction"]

instance ProofSequence ProofSession where
  verifyProofSequence = evolveProofHeaders

-- The validated parent state stays in Haskell for the entire header sequence.
-- Native adapters expose immutable facts and crypto, and publish only at success.
evolveProofHeaders :: (ProofHeaderEvolution op, ProofEnvelopeAccess op) => op -> IO Bool
evolveProofHeaders value = do
  resetProofError value
  current <- newIORef Nothing
  let withState action = readIORef current >>= maybe (ioError (userError "missing proof header state")) action
      answer accepted = [if accepted then 1 else 0,0,0,0]
      observe 147 = do
        state <- inspectProofState value
        writeIORef current state
        pure (answer (maybe False (const True) state))
      observe 18 = withState $ \state -> do
        next <- beginProofHeaders value state
        writeIORef current (Just next)
        pure (answer True)
      observe 150 = withState (fmap answer . matchesProofParent value)
      observe 151 = withState (fmap answer . matchesProofBits value)
      observe 152 = withState (fmap answer . exceedsProofMedian value)
      observe 7 = withState $ \state -> do
        (next,position) <- advanceProofHeader value state
        writeIORef current (Just next)
        pure position
      observe 19 = withState $ \state -> publishProofState value state >> pure (answer True)
      observe step = proofFacts value step
  validate (ProofWorkflow 0 observe) >>= proofResult value

attachProofEnvelope :: (ProofCoding op, ProofEnvelopeAccess op) => op -> IO Bool
attachProofEnvelope value = do
  resetProofError value
  enabled <- proofHeaderEnabled value
  if not enabled then pure False else do
    encoded <- encodeProofBytes value
    if encoded then publishProofCommitment value >> pure True else pure False

verifyProofParent :: ProofEnvelopeAccess op => op -> IO Bool
verifyProofParent value = validate (ProofWorkflow 21 (proofFacts value)) >>= proofResult value

verifyProofEnvelope :: (ProofCoding op, ProofEnvelopeAccess op, ProofSequence op) => op -> IO Bool
verifyProofEnvelope value = do
  resetProofError value
  let result accepted = [if accepted then 1 else 0,0,0,0]
      observe 14 = result <$> decodeProofBytes value
      observe 16 = result <$> verifyProofParent value
      observe 17 = do
        ready <- proofFacts value 17
        unless (ready == [1,0,0,0]) (ioError (userError "invalid proof sequence preparation"))
        result <$> verifyProofSequence value
      observe step = proofFacts value step
  validate (ProofWorkflow 11 observe) >>= proofResult value

type ProofSessionCapabilities = '[ProofCoding, ProofEnvelopeAccess, ProofHeaderEvolution, ProofSequence]
instance Operation ProofSession ProofSessionCapabilities where
  type Context ProofSession = CapabilityContext ProofSessionCapabilities ProofSession
  type Outcome ProofSession = IO Int32
  data DSL ProofSession where
    EncodeProof :: Context ProofSession => DSL ProofSession
    DecodeProof :: Context ProofSession => DSL ProofSession
    AttachProof :: Context ProofSession => DSL ProofSession
    VerifyProofEntries :: Context ProofSession => DSL ProofSession
    VerifyProofBlock :: Context ProofSession => DSL ProofSession
    VerifyProofParent :: Context ProofSession => DSL ProofSession
  interpret operation request = withOperation @ProofSession operation $ \value ->
    let reply = Just . fmap (fromIntegral . fromEnum) in case request of
      EncodeProof -> reply (encodeProofBytes value)
      DecodeProof -> reply (decodeProofBytes value)
      AttachProof -> reply (attachProofEnvelope value)
      VerifyProofEntries -> reply (verifyProofSequence value)
      VerifyProofBlock -> reply (verifyProofEnvelope value)
      VerifyProofParent -> reply (verifyProofParent value)

data HeaderLayout = HeaderLayout Word32 Word32
instance Validation HeaderLayout where
  type ValidationResult HeaderLayout = Maybe (Word32,Word32)
  validate (HeaderLayout version flags)
    | flags > 47 || (flags > 16 && flags < 32) = Nothing
    | flags == 16 = Just (version,rawFields)
    | not (testBit flags 0) = Just (version,0)
    | otherwise = Just (normalized,fields)
    where
      reading = testBit flags 1
      withdrawal = if reading then testBit version Constants.withdrawalHeaderBit else testBit flags 2
      dynamic = if reading then testBit version 31 else testBit flags 3
      present yes bit = if yes then 1 `shiftL` bit else 0
      normalized = (version .&. (present True Constants.withdrawalHeaderBit - 1)) .|.
        (if reading then 0 else present withdrawal Constants.withdrawalHeaderBit .|. present dynamic 31)
      fields = present withdrawal 0 .|. present dynamic 6 .|. extensions .|. present (testBit flags 5) 8
      rawFields = present (testBit version Constants.withdrawalHeaderBit) 0 .|. present (testBit version 31) 6 .|. extensions
      extensions = present (testBit version 20) 1

data CommitmentBytes = CommitmentBytes Word32 [Word8]
instance Validation CommitmentBytes where
  type ValidationResult CommitmentBytes = [Word8]
  validate (CommitmentBytes mode bytes) = commitmentBytes mode bytes

newtype SignetActions = SignetActions Word32
instance Validation SignetActions where
  type ValidationResult SignetActions = [Word32]
  validate (SignetActions 0) = [0..5]
  validate (SignetActions 1) = [0,1]
  validate _ = error "invalid signet action mode"

data SignetTemplate = SignetTemplate
instance Validation SignetTemplate where
  type ValidationResult SignetTemplate = [Word32]
  -- Version, locktime, sequence, amount, spend input opcode, spending output opcode.
  validate SignetTemplate = [0,0,0,0,0,106]

newtype SignatureBytes = SignatureBytes [Word8]
instance Validation SignatureBytes where
  type ValidationResult SignatureBytes = (Word64, Word8)
  validate (SignatureBytes []) = error "empty BMM signature"
  validate (SignatureBytes bytes) = (fromIntegral (length bytes - 1), last bytes)

data Preimage = Preimage Word32 | SignatureActions Word32
instance Validation Preimage where
  type ValidationResult Preimage = [Word32]
  validate (Preimage 0) = [0..9]
  validate (Preimage 1) = [0..3]
  validate (SignatureActions plan) | plan <= 15 =
    [0 | testBit plan 0] ++ [1 | testBit plan 1] ++
    (if testBit plan 2 then [2] else [3 | testBit plan 3])
  validate _ = error "invalid BMM preimage kind"

data Signature = HashPlan Int32 Word32 Word64 | SignatureGate Word32 Word64 Word32 Word64
instance Validation Signature where
  type ValidationResult Signature = Int32
  validate (HashPlan hashType index outputs) =
    (if not anyone then 1 else 0) + (if not anyone && allOutputs then 2 else 0) +
    (if allOutputs then 4 else 0) + (if base == 3 && fromIntegral index < outputs then 8 else 0)
    where
      base = hashType .&. 31
      anyone = testBit hashType 7
      allOutputs = base /= 3 && base /= 2
  validate (SignatureGate witness size index inputs) =
    if witness /= 0 && size /= 0 && fromIntegral index < inputs then 1 else 0

-- Native effects hash/serialize existing Bitcoin objects. Mode selection,
-- short-circuiting and all signature planning stay inside this one invocation.
data SignatureWorkflow
  = SignatureHashWorkflow Int32 Word32 Word64 NativeBytes
  | SignatureVerifyWorkflow Word32 Word32 Word32 Word64 Word64 B.ByteString NativeBytes
data SignaturePlan = SignaturePlan Int32 Word32 Word64
class SignaturePreparation op where
  prepareSignature :: op -> ExceptT Int32 IO SignaturePlan
class SignatureHashing op where
  hashSignature :: op -> SignaturePlan -> ExceptT Int32 IO ()
class SignatureVerification op where
  verifySignature :: op -> ExceptT Int32 IO ()

signatureNative :: SignatureWorkflow -> NativeBytes
signatureNative (SignatureHashWorkflow _ _ _ native) = native
signatureNative (SignatureVerifyWorkflow _ _ _ _ _ _ native) = native

signatureEffect :: NativeBytes -> Word32 -> Word64 -> B.ByteString -> ExceptT Int32 IO ()
signatureEffect native step index input = do
  reply <- lift (native step index input)
  when (not (B.null reply)) (throwE (-1))

signatureRequired :: NativeBytes -> Word32 -> ExceptT Int32 IO ()
signatureRequired native step = do
  reply <- lift (native step 0 B.empty)
  case B.unpack reply of
    [1] -> pure ()
    [0] -> throwE 0
    _ -> throwE (-1)

instance SignaturePreparation SignatureWorkflow where
  prepareSignature (SignatureHashWorkflow hashType index outputs _) = pure (SignaturePlan hashType index outputs)
  prepareSignature (SignatureVerifyWorkflow mode witness index inputs outputs signature native) = do
      when (mode > 1) (throwE (-1))
      let (gateIndex, gateInputs) = if mode == 1 then (0,1) else (index,inputs)
      when (validate (SignatureGate witness (fromIntegral (B.length signature)) gateIndex gateInputs) /= 1) (throwE 0)
      when (mode == 1) (signatureRequired native 0)
      signatureRequired native 1
      let (prefix, hashType) = validate (SignatureBytes (B.unpack signature))
      signatureEffect native 2 (fromIntegral hashType) (B.take (fromIntegral prefix) signature)
      pure (SignaturePlan (fromIntegral hashType) index outputs)
instance SignatureHashing SignatureWorkflow where
  hashSignature request (SignaturePlan hashType index outputs) = do
    let native = signatureNative request
        plan = fromIntegral (validate (HashPlan hashType index outputs))
        actions = map (100+) (validate (SignatureActions plan)) ++
          map (200+) (validate (Preimage 0)) ++ [210]
    signatureEffect native 4 0 (B.pack (map fromIntegral actions))
instance SignatureVerification SignatureWorkflow where
  verifySignature (SignatureHashWorkflow _ _ _ _) = pure ()
  verifySignature request = signatureRequired (signatureNative request) 3

runSignature :: (SignaturePreparation op, SignatureHashing op, SignatureVerification op) => op -> IO Int32
runSignature value = either id (const 1) <$> runExceptT (do
  plan <- prepareSignature value
  hashSignature value plan
  verifySignature value)

type SignatureCapabilities = '[SignaturePreparation, SignatureHashing, SignatureVerification]
instance Operation SignatureWorkflow SignatureCapabilities where
  type Context SignatureWorkflow = CapabilityContext SignatureCapabilities SignatureWorkflow
  type Outcome SignatureWorkflow = IO Int32
  data DSL SignatureWorkflow where
    RunSignature :: Context SignatureWorkflow => DSL SignatureWorkflow
  interpret operation request = withOperation @SignatureWorkflow operation $ \value -> case request of
    RunSignature -> Just (runSignature value)

data TargetScale = TargetScale Word64 Word64 [Word8] [Word8]
instance Validation TargetScale where
  type ValidationResult TargetScale = [Word8]
  validate (TargetScale factor divisor target limit)
    | divisor == 0 || length target /= 32 || length limit /= 32 = error "invalid BMM target scaling input"
    | otherwise = [fromIntegral (result `shiftR` shift) | shift <- [0,8..248]]
    where
      decode = foldr (\byte value -> fromIntegral byte + 256 * value) (0 :: Integer)
      -- Native multiplication chooses uint32_t, and wraps before division.
      multiplied = (decode target * fromIntegral (fromIntegral factor :: Word32)) `mod` (2 ^ (256 :: Int))
      result = min (decode limit) (multiplied `quot` fromIntegral divisor)

data PrivateTemplate = PrivateTemplate Word32 Word32 Word32 Word32 [Word8]
instance Validation PrivateTemplate where
  type ValidationResult PrivateTemplate = ([Word32], [Word8])
  validate (PrivateTemplate height time median slot critical)
    | length critical /= 32 = error "invalid private BMM critical hash"
    | otherwise = ([2,height + 1,0x20000000,max (time + 1) (median + 1)],
        [0xd1,0x61,0x73,0x68,fromIntegral slot] ++ reverse critical)

data Timing = Retarget Word32 Int64 Int64 Word32 Word32 | Median [Word32] | ParentMedian [Word32]
instance Validation Timing where
  type ValidationResult Timing = Int64
  validate (Retarget height interval target time start)
    | interval <= 0 = error "invalid BMM adjustment interval"
    | (fromIntegral height + 1) `mod` interval /= 0 = -1
    | target <= 0 || target > maxBound `quot` 4 = error "invalid BMM target timespan"
    | otherwise = min (target * 4) (max (target `quot` 4) (fromIntegral time - fromIntegral start))
  validate (Median []) = error "empty BMM median time history"
  validate (Median times) = fromIntegral (sort times !! (length times `quot` 2))
  validate (ParentMedian times) = case validate (Median times) of
    0 -> -1
    time -> time

data RetargetWorkflow = RetargetWorkflow Word32 Int64 Int64 Word32 Word32 NativeBytes
instance Validation RetargetWorkflow where
  type ValidationResult RetargetWorkflow = IO Int32
  validate (RetargetWorkflow height interval target time start native) = do
    timing <- try @SomeException (evaluate (validate (Retarget height interval target time start)))
    case timing of
      Left _ -> pure (-2)
      Right (-1) -> pure 0
      Right spanTime -> do
        bytes <- native 0 0 B.empty
        if B.length bytes /= 64 then pure (-1) else do
          scaled <- try @SomeException $ mapM evaluate (validate (TargetScale
            (fromIntegral spanTime) (fromIntegral target)
            (B.unpack (B.take 32 bytes)) (B.unpack (B.drop 32 bytes))))
          case scaled of
            Left _ -> pure (-3)
            Right result -> native 1 0 (B.pack result) >> pure 0

-- Upstream GetOp projects two nine-bit opcodes (256 = failure), consumed,
-- payload size, first four bytes little-endian, and the fifth byte.
-- Kind 2 instead supplies raw script size and its first six bytes little-endian.
type ReadScript = Ptr () -> Word32 -> Word32 -> Ptr Int64 -> IO Int32
foreign import ccall "dynamic" readScript :: FunPtr ReadScript -> ReadScript

data Commitment = Commitment Word32 Int32 Word32 (FunPtr ReadScript) (Ptr ())

class CommitmentScripts op where
  inspectCommitmentScript :: op -> Word32 -> Word32 -> IO [Int64]

instance CommitmentScripts Commitment where
  inspectCommitmentScript (Commitment _ _ _ reader context) index action =
    allocaArray 4 $ \out -> do
      status <- readScript reader context index action out
      if status /= 1 then error "BMM script adapter fault" else peekArray 4 out

witnessCommitment :: Int64 -> Int64 -> Bool
witnessCommitment size prefix
  | size < 0 || prefix < 0 || prefix > 0xffffffffffff = error "BMM witness facts out of range"
  | otherwise = size >= 38 && prefix == 0xeda921aa246a

instance Validation Commitment where
  type ValidationResult Commitment = IO Int64
  validate value@(Commitment kind slot count reader _)
    | kind > 3 = error "invalid BMM commitment kind"
    | count /= 0 && reader == nullFunPtr = error "missing BMM script adapter"
    | otherwise = selectCommitment value kind slot count

selectCommitment :: CommitmentScripts op => op -> Word32 -> Int32 -> Word32 -> IO Int64
selectCommitment value kind slot count
    | kind > 3 = error "invalid BMM commitment kind"
    | otherwise = go 0 Nothing
    where
      inspect = inspectCommitmentScript value
      scriptFields index
        | kind == 2 = inspect index 0
        | otherwise = do
            first <- head <$> inspect index 1
            second <- if first == 106 then head <$> inspect index 2 else pure 256
            metadata <- inspect index 3
            case metadata of
              [ended,size,magic,actualSlot]
                | first >= 0 && first <= 511 && second >= 0 && second <= 511 && ended >= 0 && ended <= 1 ->
                    pure [first + second * 512 + ended * 262144,size,magic,actualSlot]
              _ -> error "BMM script metadata count"
      go index found
        | index == count = pure (maybe (-1) fromIntegral found)
        | otherwise = do
            fields <- scriptFields index
            case fields of
              [size,prefix,_,_] | kind == 2 ->
                let matches = witnessCommitment size prefix
                in matches `seq` go (index+1) (if matches then Just index else found)
              [script,size,magic,actualSlot]
                | script < 0 || script > 524287 || size < 0 -> error "BMM script facts out of range"
                | kind == 3 ->
                    if script .&. 511 /= 106 || (script `shiftR` 9) .&. 511 > 78 ||
                       size < 5 || magic /= 0x544d4c45 || actualSlot /= 0x50
                      then go (index+1) found
                    else if size /= 37 || (script `shiftR` 9) .&. 511 /= 37 || not (testBit script 18)
                      then pure (-4)
                    else case found of
                      Just _ -> pure (-2)
                      Nothing -> inspect index 4 >> go (index+1) (Just index)
                | script .&. 511 == 106 && (script `shiftR` 9) .&. 511 <= 78 && testBit script 18 &&
                  (if kind == 0 then size == 37 && magic == 0x687361d1 && actualSlot == fromIntegral slot
                   else size == 32) ->
                    case found of
                      Nothing -> go (index+1) (Just index)
                      Just _ -> pure (-2)
                | otherwise -> go (index+1) found
              _ -> error "BMM script field count"

-- Selection and extraction share one borrowed script cursor. Failed selections
-- never reparse/publish; tagged parents retain their earlier scan-time effect.
newtype CommitmentSession = CommitmentSession NativeBytes
class CommitmentPublication op where
  commitmentSpecification :: op -> IO (Word32,Int32,Word32)
  readCommitmentPayload :: op -> Word32 -> IO B.ByteString
  publishCommitment :: op -> B.ByteString -> IO ()
  rejectCommitment :: op -> String -> IO ()

instance CommitmentScripts CommitmentSession where
  inspectCommitmentScript (CommitmentSession native) index action = do
    bytes <- native (10+action) (fromIntegral index) B.empty
    unless (B.length bytes == 32) (ioError (userError "invalid BMM script projection"))
    pure [fromIntegral (readLE (B.take 8 (B.drop offset bytes))) | offset <- [0,8,16,24]]

instance CommitmentPublication CommitmentSession where
  commitmentSpecification (CommitmentSession native) = do
    fields <- proofWords native 0 3
    case fields of
      [kind,slot,count] | kind <= 3 && count <= 0xffffffff &&
          let signed = fromIntegral slot :: Int64 in signed >= -2147483648 && signed <= 2147483647 ->
        pure (fromIntegral kind,fromIntegral slot,fromIntegral count)
      _ -> ioError (userError "invalid BMM commitment specification")
  readCommitmentPayload (CommitmentSession native) index = do
    stateEffect native 20 (fromIntegral index) B.empty
    stateEffect native 21 (fromIntegral index) B.empty
    native 22 (fromIntegral index) B.empty
  publishCommitment (CommitmentSession native) = stateEffect native 23 0
  rejectCommitment (CommitmentSession native) = stateEffect native 90 0 . C.pack

commitmentSelectionError :: Word32 -> Int64 -> Maybe String
commitmentSelectionError kind result = lookup (kind,result)
  [((0,-1),"BMM successor coinbase has no M8 commitment for slot 24"),
   ((0,-2),"BMM successor coinbase contains multiple M8 commitments for slot 24"),
   ((1,-1),"sidechain block has no L1 parent commitment"),
   ((1,-2),"sidechain block has multiple L1 parent commitments"),
   ((3,-4),"block coinbase contains a noncanonical ELMTP parent commitment"),
   ((3,-2),"block coinbase contains multiple canonical drivechain parent commitments"),
   ((3,-1),"block coinbase does not contain one canonical ELMTP drivechain parent commitment")]

extractSelectedCommitment :: (CommitmentScripts op, CommitmentPublication op) => op -> IO Bool
extractSelectedCommitment value = do
  (kind,slot,count) <- commitmentSpecification value
  selected <- selectCommitment value kind slot count
  case commitmentSelectionError kind selected of
    Just message -> rejectCommitment value message >> pure False
    Nothing | selected < 0 -> pure False
    Nothing -> do
      when (kind <= 1) $ do
        payload <- readCommitmentPayload value (fromIntegral selected)
        bytes <- evaluate (B.pack (commitmentBytes kind (B.unpack payload)))
        publishCommitment value bytes
      pure True

type CommitmentCapabilities = '[CommitmentScripts, CommitmentPublication]
instance Operation CommitmentSession CommitmentCapabilities where
  type Context CommitmentSession = CapabilityContext CommitmentCapabilities CommitmentSession
  type Outcome CommitmentSession = IO Int32
  data DSL CommitmentSession where
    ExtractSelectedCommitment :: Context CommitmentSession => DSL CommitmentSession
  interpret operation request = withOperation @CommitmentSession operation $ \value -> case request of
    ExtractSelectedCommitment -> Just (fromIntegral . fromEnum <$> extractSelectedCommitment value)

data ParentState = ParentState Word32 Int64 Word32 Word32 Word32 Word32 Word32 Word64 Word32
instance Validation ParentState where
  type ValidationResult ParentState = Int32
  validate (ParentState hash interval height time bits start startTime count latest) =
    if hash /= 0 && height /= 0 && time /= 0 && bits /= 0 && interval > 0 &&
       start <= height && fromIntegral start `mod` interval == 0 &&
       height - start < (fromIntegral interval :: Word32) && startTime /= 0 &&
       count == 11 && latest == time then 0 else 1

-- Bits: native, previous, checkpoint1, checkpoint2, proof, commitment,
-- required, incomplete candidate, final phase. Result 6 requests the lazy phase.
newtype Header = Header Word32
instance Validation Header where
  type ValidationResult Header = Int32
  validate (Header facts)
    | facts > 511 = -1
    | not (flag 8) = if flag 0 then (if flag 4 || flag 5 then 1 else 0)
                    else if not (flag 1) then 0
                    else if flag 2 && not (flag 3) then 2 else 6
    | flag 6 && not (flag 4) = 3
    | flag 6 && not (flag 5) && not (flag 7) = 4
    | not (flag 6) && flag 4 = 5
    | otherwise = 0
    where flag = testBit facts

-- Preflight returns 2 only when configuration or public ancestry is needed.
data Activation = Activation Word32 Word32 Int64 Int64
instance Validation Activation where
  type ValidationResult Activation = Int32
  validate (Activation phase facts height activation) = case phase of
    0 | facts <= 3 -> if facts == 2 then 2 else 0
    1 | facts <= 1 -> if facts == 0 then -2
                     else if activation <= 0 || activation >= 2147483647 then -3
                     else if toInteger height + 1 >= toInteger activation then 1 else 0
    2 | facts <= 3 -> if facts /= 0 then 1 else 0
    3 | facts == 0 -> if activation /= 2147483647 && height >= activation then 1 else 0
    4 | facts <= 1 -> if toInteger height + toInteger facts >= toInteger activation then 1 else 0
    _ -> -1

-- Header admission owns the lazy activation query. The native side only reads
-- chain/configuration facts and publishes the original rejection text.
newtype HeaderPolicy = HeaderPolicy NativeBytes
class ProofRequirement op where
  requiresProof :: op -> IO Bool
class HeaderObservation op where
  headerFacts :: op -> IO Word32
  rejectHeader :: op -> Int32 -> IO ()

headerPolicyAbort :: NativeBytes -> String -> IO a
headerPolicyAbort native message = do
  void (native 0 0 (C.pack message))
  ioError (userError message)

headerPolicyWords :: NativeBytes -> Word32 -> Int -> IO [Word64]
headerPolicyWords native step count = do
  bytes <- native step 0 B.empty
  unless (B.length bytes == count*8) (headerPolicyAbort native "invalid BMM header policy reply")
  pure [readLE (B.take 8 (B.drop (8*i) bytes)) | i <- [0..count-1]]

headerPolicyScalar :: NativeBytes -> Word32 -> Word64 -> IO Word32
headerPolicyScalar native step limit = do
  values <- headerPolicyWords native step 1
  case values of
    [value] | value <= limit -> pure (fromIntegral value)
    _ -> headerPolicyAbort native "invalid BMM header policy scalar"

instance ProofRequirement HeaderPolicy where
  requiresProof (HeaderPolicy native) = do
    flags <- headerPolicyScalar native 1 3
    if validate (Activation 0 flags 0 0) /= 2 then pure False else do
      private <- headerPolicyScalar native 2 1
      result <- if private == 0 then do
        ancestry <- headerPolicyScalar native 4 3
        pure (validate (Activation 2 ancestry 0 0))
        else do
          fields <- headerPolicyWords native 3 3
          case fields of
            [present,height,activation] | present <= 1 ->
              pure (validate (Activation 1 (fromIntegral present) (fromIntegral height) (fromIntegral activation)))
            _ -> headerPolicyAbort native "invalid BMM activation reply"
      case result of
        -2 -> headerPolicyAbort native "-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight"
        -3 -> headerPolicyAbort native "invalid -ecxprivatebmmactivationheight"
        0 -> pure False
        1 -> pure True
        _ -> headerPolicyAbort native "Haskell BMM activation evaluation failed"

instance HeaderObservation HeaderPolicy where
  headerFacts (HeaderPolicy native) = do
    facts <- headerPolicyScalar native 10 255
    when (testBit facts 6) (headerPolicyAbort native "invalid BMM header preflight")
    pure facts
  rejectHeader (HeaderPolicy native) code = do
    let messages = ["historical signet BMM proof is not valid on native Elements",
          "public-signet height 2 does not match its immutable checkpoint",
          "public-signet descendant does not signal deterministic BMM proof",
          "deterministic BMM header has no proof commitment",
          "deterministic BMM proof cannot activate outside the public-signet checkpoint"]
    unless (code >= 1 && code <= 5) (headerPolicyAbort native "Haskell BMM header evaluation failed")
    reply <- native 11 0 (C.pack (messages !! (fromIntegral code-1)))
    unless (reply == wordLE 8 1) (headerPolicyAbort native "invalid BMM header rejection reply")

checkHeaderPolicy :: (ProofRequirement op, HeaderObservation op) => op -> IO Int32
checkHeaderPolicy value = do
  facts <- headerFacts value
  let preflight = validate (Header facts)
  result <- if preflight /= 6 then pure preflight else do
    required <- requiresProof value
    pure (validate (Header (facts .|. (if required then 64 else 0) .|. 256)))
  if result == 0 then pure 1 else rejectHeader value result >> pure 0

type HeaderPolicyCapabilities = '[ProofRequirement, HeaderObservation]
instance Operation HeaderPolicy HeaderPolicyCapabilities where
  type Context HeaderPolicy = CapabilityContext HeaderPolicyCapabilities HeaderPolicy
  type Outcome HeaderPolicy = IO Int32
  data DSL HeaderPolicy where
    ProofIsRequired :: Context HeaderPolicy => DSL HeaderPolicy
    CheckHeaderPolicy :: Context HeaderPolicy => DSL HeaderPolicy
  interpret operation request = withOperation @HeaderPolicy operation $ \value -> case request of
    ProofIsRequired -> Just (fromIntegral . fromEnum <$> requiresProof value)
    CheckHeaderPolicy -> Just (checkHeaderPolicy value)

newtype StoredBmmState = StoredBmmState NativeBytes
class StateLoading op where
  loadParentState :: op -> IO (Either String Bool)
class CheckpointSelection op where
  checkpointFact :: op -> Word32 -> IO Bool
  publishCheckpoint :: op -> Bool -> IO ()
class ParentContextAccess op where
  validParentContext :: op -> IO Bool
  parentContextMedian :: op -> IO Int64
  publishParentContext :: op -> Int64 -> IO ()
class StateReporting op where
  reportParentState :: op -> Either String Bool -> IO Int32

-- Only the old payload-decoding region catches native exceptions. Its native
-- replies carry a success byte so recovery does not poison the FFI session.
stateReplyWords :: NativeBytes -> Word32 -> Int -> IO [Word64]
stateReplyWords native step count = do
  reply <- native step 0 B.empty
  let owned = step >= 20 && step <= 25
      bytes = if owned then B.drop 1 reply else reply
  unless ((not owned || B.take 1 reply == B.singleton 1) && B.length bytes == count*8)
    (ioError (userError "invalid BMM state observation"))
  pure [readLE (B.take 8 (B.drop (8*i) bytes)) | i <- [0..count-1]]

stateFlag :: NativeBytes -> Word32 -> IO Bool
stateFlag native step = do
  values <- stateReplyWords native step 1
  case values of
    [value] | value <= 1 -> pure (value == 1)
    _ -> ioError (userError "invalid BMM state flag")

stateEffect :: NativeBytes -> Word32 -> Word64 -> B.ByteString -> IO ()
stateEffect native step index input = do
  reply <- native step index input
  unless (reply == wordLE 8 1) (ioError (userError "invalid BMM state effect"))

instance ParentContextAccess StoredBmmState where
  validParentContext (StoredBmmState native) = do
    private <- stateFlag native 24
    fields <- stateReplyWords native 23 8
    let (preset,_,_) = validate (ConsensusPreset (if private then 1 else 0))
        interval = case preset of
          timespan:spacing:_ -> validate (DifficultyInterval (fromIntegral timespan) (fromIntegral spacing))
          _ -> error "invalid BMM consensus preset fields"
    case fields of
      [hash,height,time,bits,start,startTime,count,latest]
        | hash <= 1 && all (<= 0xffffffff) [height,time,bits,start,startTime,latest] ->
          pure (validate (ParentState (fromIntegral hash) interval (fromIntegral height) (fromIntegral time)
            (fromIntegral bits) (fromIntegral start) (fromIntegral startTime) count (fromIntegral latest)) == 0)
      _ -> ioError (userError "invalid BMM state fields")
  parentContextMedian (StoredBmmState native) = do
    history <- stateReplyWords native 25 11
    unless (all (<= 0xffffffff) history) (ioError (userError "invalid BMM history"))
    evaluate (validate (ParentMedian (map fromIntegral history)))
  publishParentContext (StoredBmmState native) median = stateEffect native 26 0 (wordLE 8 (fromIntegral median))

instance StateLoading StoredBmmState where
  loadParentState value@(StoredBmmState native) = runExceptT $ do
    present <- lift (stateFlag native 1)
    if not present then pure False else do
      forM_ [2..6] $ \step -> do
        accepted <- lift (stateFlag native step)
        unless accepted (throwE "persisted BMM state has invalid asset or value encoding")
      forM_ [(10,6),(11,7),(12,8)] $ \(step,phase) -> do
        fields <- lift (stateReplyWords native step 2)
        let result = case fields of
              [facts,opcode] | facts <= 3 && opcode <= 255 -> validate (Codec phase (fromIntegral facts) opcode 0)
              _ -> -1
        when (result < 0) (lift (ioError (userError "invalid BMM script observation")))
        unless (result == 0) (throwE "persisted BMM state script is malformed")
      decoded <- lift $ try @SomeException $ runExceptT $ do
        forM_ [20,21] $ \step -> do
          fields <- lift (stateReplyWords native step 0)
          unless (null fields) (lift (ioError (userError "invalid BMM decode effect")))
        flags <- lift (stateReplyWords native 22 1)
        unless (flags == [3]) (throwE "persisted BMM state payload is invalid")
        valid <- lift (validParentContext value)
        unless valid (throwE "BMM parent-chain state is malformed")
        pure True
      either (const (throwE "persisted BMM state payload cannot be decoded")) (either throwE pure) decoded

instance CheckpointSelection StoredBmmState where
  checkpointFact (StoredBmmState native) = stateFlag native
  publishCheckpoint (StoredBmmState native) private = do
    let mode = if private then 1 else 0
        (fields,hash) = validate (CheckpointPreset mode)
    stateEffect native 33 (fromIntegral mode) (B.pack hash <> B.concat (map (wordLE 4 . fromIntegral) fields))
instance StateReporting StoredBmmState where
  reportParentState (StoredBmmState native) = either
    (\message -> stateEffect native 90 0 (C.pack message) >> pure 0)
    (pure . fromIntegral . fromEnum)

effectiveParentState :: (StateLoading op, CheckpointSelection op) => op -> IO (Either String Bool)
effectiveParentState value = do
  native <- checkpointFact value 30
  if native then pure (Left "native Elements requires its authenticated parent replay, not signet BMM state") else do
    loaded <- loadParentState value
    case loaded of
      Right False -> do
        public <- checkpointFact value 31
        if public then publishCheckpoint value False >> pure (Right True) else do
          private <- checkpointFact value 32
          if private then publishCheckpoint value True >> pure (Right True)
            else pure (Left "authenticated BMM parent-chain state is missing")
      _ -> pure loaded

prepareParentContext :: ParentContextAccess op => op -> IO (Either String Bool)
prepareParentContext value = do
  valid <- validParentContext value
  if not valid then pure (Left "BMM parent-chain state is malformed") else do
    median <- parentContextMedian value
    if median < 0 then pure (Left "authenticated BMM parent median time past is zero")
      else publishParentContext value median >> pure (Right True)

type StoredBmmCapabilities = '[StateLoading, CheckpointSelection, ParentContextAccess, StateReporting]
instance Operation StoredBmmState StoredBmmCapabilities where
  type Context StoredBmmState = CapabilityContext StoredBmmCapabilities StoredBmmState
  type Outcome StoredBmmState = IO Int32
  data DSL StoredBmmState where
    ReadParentState :: Context StoredBmmState => DSL StoredBmmState
    EffectiveParentState :: Context StoredBmmState => DSL StoredBmmState
    PrepareParentContext :: Context StoredBmmState => DSL StoredBmmState
  interpret operation request = withOperation @StoredBmmState operation $ \value -> case request of
    ReadParentState -> Just (loadParentState value >>= reportParentState value)
    EffectiveParentState -> Just (effectiveParentState value >>= reportParentState value)
    PrepareParentContext -> Just (prepareParentContext value >>= reportParentState value)

-- Chain sessions keep the state, proof and storage subworkflows inside Haskell.
-- Routes select borrowed native object adapters, never another FFI entry.
newtype ChainSession = ChainSession NativeBytes
data ChainOutput = InitialOutput | NextOutput | PriorOutput deriving (Eq, Enum)
class ChainObservations op where
  chainFact :: op -> Word32 -> IO Bool
  chainFailure :: op -> String -> IO ()
  chainError :: op -> IO String
class ChainStateAccess op where
  loadChainState :: op -> IO (Either String Bool)
  effectiveChainState :: op -> IO Bool
  matchesChainCheckpoint :: op -> IO Bool
  storeChainState :: op -> ChainOutput -> IO ()
class ChainProofAccess op where
  checkChainHeader :: op -> IO Bool
  chainProofRequired :: op -> IO Bool
  decodeChainProof :: op -> IO Bool
  extractChainParent :: op -> IO Bool
  verifyChainProof :: op -> Bool -> IO Bool

chainRoute :: Word32 -> NativeBytes -> NativeBytes
chainRoute base native step = native (base+step)

instance ChainObservations ChainSession where
  chainFact (ChainSession native) = stateFlag native
  chainFailure (ChainSession native) message = stateEffect native 90 0 (C.pack message)
  chainError (ChainSession native) = C.unpack <$> native 92 0 B.empty
instance ChainStateAccess ChainSession where
  loadChainState (ChainSession native) = loadParentState (StoredBmmState (chainRoute 2000 native))
  effectiveChainState (ChainSession native) = do
    let state = StoredBmmState (chainRoute 2000 native)
    (==1) <$> (effectiveParentState state >>= reportParentState state)
  matchesChainCheckpoint (ChainSession native) = do
    current <- native 8 0 B.empty
    let (fields,hash) = validate (CheckpointPreset 0)
        encoded = map (wordLE 4 . fromIntegral) fields
    pure (current == B.pack hash <> B.concat (take 5 encoded) <> B.singleton 11 <> B.concat (drop 5 encoded))
  storeChainState (ChainSession native) output = do
    when (output == InitialOutput) (publishCheckpoint (StoredBmmState (chainRoute 2000 native)) False)
    stateEffect native 5000 (fromIntegral (fromEnum output)) B.empty
    replaceStoredState (PersistedOutput (output == PriorOutput) (chainRoute 4000 native))
instance ChainProofAccess ChainSession where
  checkChainHeader value@(ChainSession native) = do
    chainFailure value ""
    (==1) <$> checkHeaderPolicy (HeaderPolicy (chainRoute 1000 native))
  chainProofRequired (ChainSession native) = requiresProof (HeaderPolicy (chainRoute 1000 native))
  decodeChainProof (ChainSession native) = decodeProofBytes (ProofSession (chainRoute 3000 native))
  extractChainParent (ChainSession native) = verifyProofParent (ProofSession (chainRoute 3000 native))
  verifyChainProof (ChainSession native) entriesOnly = do
    private <- stateFlag (chainRoute 1000 native) 2
    let (fields,limit,challenge) = validate (ConsensusPreset (if private then 1 else 0))
    stateEffect native 2999 0 (B.concat (map (wordLE 8) fields) <> B.pack limit <> B.pack challenge)
    let proof = ProofSession (chainRoute 3000 native)
    if entriesOnly then stateEffect native 2998 0 B.empty >> verifyProofSequence proof
      else verifyProofEnvelope proof

runChainLifecycle :: (ChainObservations op, ChainStateAccess op, ChainProofAccess op) => Bool -> op -> IO Int32
runChainLifecycle disconnect value = do
  stateError <- newIORef ""
  let number = fromIntegral . fromEnum
      fact step = number <$> chainFact value step
      checkpoint = andM (map (chainFact value) [10,11,12])
      load = do
        result <- loadChainState value
        case result of
          Left message -> writeIORef stateError message >> pure (False,not (null message))
          Right found -> pure (found,False)
      observe 1 = fact 0
      observe 2 = number <$> checkChainHeader value
      observe 4 = number <$> checkpoint
      observe 5 = do (found,bad) <- load; pure (number found + 2*number bad)
      observe 6 = storeChainState value InitialOutput >> pure 1
      observe 7 = do
        required <- chainProofRequired value
        present <- if required then pure False else chainFact value 1
        pure (number required + 2*number present)
      observe 8 = do
        allow <- chainFact value 4
        present <- chainFact value 1
        uncommitted <- chainFact value 3
        nonempty <- chainFact value 2
        pure (number allow + 2*number present + 4*number uncommitted + 8*number (not nonempty))
      observe 9 = number <$> effectiveChainState value
      observe 10 = number <$> verifyChainProof value False
      observe 11 = storeChainState value NextOutput >> pure 1
      observe 13 = number <$> checkpoint
      observe 14 = do
        (found,bad) <- load
        same <- if found then matchesChainCheckpoint value else pure False
        pure (number found + 2*number same + 4*number bad)
      observe 15 = fact 6
      observe 16 = fact 1
      observe 17 = number <$> decodeChainProof value
      observe 18 = do (found,bad) <- load; pure (number found + 2*number bad)
      observe 19 = number <$> extractChainParent value
      observe 20 = storeChainState value PriorOutput >> pure 1
      observe 21 = number <$> verifyChainProof value True
      observe 22 = fact 7
      observe 23 = pure 0
      observe 108 = fact 2
      observe 109 = fact 5
      observe _ = ioError (userError "invalid BMM chain observation")
  result <- validate (StateWorkflow (if disconnect then 12 else 0) observe)
  let messages = ["historical signet BMM state is not valid on native Elements",
        "public BMM checkpoint cannot overwrite existing parent-chain state", "",
        "public BMM checkpoint state is inconsistent during disconnect",
        "public BMM checkpoint state could not be removed",
        "cannot disconnect BMM proof without authenticated state",
        "BMM state is inconsistent during disconnect"]
  if result == 0 then pure 1 else if result == 1 then pure 0 else
    if result >= 101 && result <= 107 then do
      message <- if result == 103 then readIORef stateError else pure (messages !! (fromIntegral result-101))
      preserve <- if result == 107 then not . null <$> chainError value else pure False
      unless preserve (chainFailure value message)
      pure 0
    else ioError (userError "invalid BMM chain result")
  where
    andM [] = pure True
    andM (test:rest) = test >>= \accepted -> if accepted then andM rest else pure False

type ChainCapabilities = '[ChainObservations, ChainStateAccess, ChainProofAccess]
instance Operation ChainSession ChainCapabilities where
  type Context ChainSession = CapabilityContext ChainCapabilities ChainSession
  type Outcome ChainSession = IO Int32
  data DSL ChainSession where
    ConnectChainState :: Context ChainSession => DSL ChainSession
    DisconnectChainState :: Context ChainSession => DSL ChainSession
  interpret operation request = withOperation @ChainSession operation $ \value -> case request of
    ConnectChainState -> Just (runChainLifecycle False value)
    DisconnectChainState -> Just (runChainLifecycle True value)

data StateExecution = StateExecution Word32 (Word32 -> IO Int64)
instance Validation StateExecution where
  type ValidationResult StateExecution = IO Int32
  validate (StateExecution start action) = run (validate (StateFlow start 0))
    where
      run phase
        | phase < -1 || phase > 114 = pure (-1)
        | phase <= 0 = pure (-phase)
        | otherwise = do
            reply <- action (fromIntegral phase)
            if reply < fromIntegral (minBound :: Int32) || reply > fromIntegral (maxBound :: Int32)
              then pure (-1)
              else run (validate (StateFlow (fromIntegral phase) (fromIntegral reply)))

-- Lifecycle and source decisions run inside the traversal. Native callbacks
-- return facts or perform effects; they do not re-enter these decision rules.
data StateWorkflow = StateWorkflow Word32 (Word32 -> IO Int64)
instance Validation StateWorkflow where
  type ValidationResult StateWorkflow = IO Int32
  validate (StateWorkflow start native)
    | start `notElem` [0,12,68] = pure (-1)
    | otherwise = either id id <$> runExceptT (run (validate (StateFlow start 0)))
    where
      facts step = do
        value <- lift (native step)
        when (value < 0 || value > fromIntegral (maxBound :: Word32)) (throwE (-1))
        pure (fromIntegral value)
      decision base value = if value < 0 then throwE (base-value) else pure value
      lifecycle phase value = decision 100 (validate (Lifecycle phase value))
      reply step
        | step == 3 = do
            present <- facts 108
            when (present > 1) (throwE (-1))
            stored <- if present == 1 then pure 1 else facts 109
            lifecycle 1 stored
        | Just phase <- lookup step [(1,0),(4,2),(5,3),(7,4),(8,5),(13,6),(14,7),
            (15,8),(16,9),(18,10),(22,11),(23,11)] = facts step >>= lifecycle phase
        | Just phase <- lookup step [(69,0),(70,1),(71,2),(73,3)] =
            facts step >>= decision 200 . validate . StateSource phase
        | otherwise = do
            value <- lift (native step)
            when (value < fromIntegral (minBound :: Int32) || value > fromIntegral (maxBound :: Int32)) (throwE (-1))
            pure (fromIntegral value)
      run phase
        | phase == 0 = pure 0
        | phase == -1 = pure 1
        | phase < 0 || phase > 114 = throwE (-1)
        | otherwise = reply (fromIntegral phase) >>= run . validate . StateFlow (fromIntegral phase)

data StateFlow = StateFlow Word32 Int32
instance Validation StateFlow where
  type ValidationResult StateFlow = Int32
  validate (StateFlow phase reply) = case phase of
    0 -> 1
    1 -> choose [(1,2),(2,4)]
    2 -> advance 1 3
    3 -> advance 0 0
    4 -> choose [(3,5),(4,7)]
    5 -> advance 5 6
    6 -> advance 1 0
    7 -> choose [(0,0),(6,8)]
    8 -> choose [(0,0),(7,9)]
    9 -> advance 1 10
    10 -> advance 1 11
    11 -> advance 1 0
    12 -> 13
    13 -> choose [(1,14),(2,16)]
    14 -> advance 3 15
    15 -> advance 0 0
    16 -> choose [(0,0),(4,17)]
    17 -> advance 1 18
    18 -> advance 5 19
    19 -> choose [(0,23),(1,21)]
    20 -> advance 1 0
    21 -> choose [(0,23),(1,22)]
    22 -> advance 6 20
    23 -> choose [(-7,-1)]
    24 -> 25
    25 -> advance 1 26
    26 -> advance 1 27
    27 -> advance 1 28
    28 -> advance 1 29
    29 -> choose [(0,30),(1,31)]
    30 -> advance 1 29
    31 -> advance 1 32
    32 -> advance 1 0
    33 -> 34
    34 -> advance 1 35
    35 -> advance 1 36
    36 -> advance 1 37
    37 -> advance 1 38
    38 -> advance 1 39
    39 -> advance 1 40
    40 -> advance 1 0
    41 -> 42
    42 -> advance 1 43
    43 -> advance 1 44
    44 -> advance 1 45
    45 -> advance 1 0
    46 -> 47
    47 -> advance 1 48
    48 -> advance 1 0
    49 -> 50
    50 -> choose [(0,53),(1,51)]
    51 -> choose [(0,53),(1,52)]
    52 -> choose [(0,53),(1,53)]
    53 -> advance 1 54
    54 -> advance 1 0
    55 -> 56
    56 -> advance 1 57
    57 -> advance 1 58
    58 -> advance 1 0
    59 -> 60
    60 -> advance 1 61
    61 -> advance 1 62
    62 -> advance 1 0
    63 -> 64
    64 -> advance 1 65
    65 -> choose [(0,66),(1,66)]
    66 -> advance 1 67
    67 -> advance 1 0
    68 -> 69
    69 -> advance 1 70
    70 -> choose [(0,0),(2,71),(-2,-1)]
    71 -> choose [(3,72),(4,73)]
    72 -> advance 1 0
    73 -> choose [(5,74),(-3,-1)]
    74 -> advance 1 0
    75 -> 76
    76 -> choose [(0,0),(2,77)]
    77 -> choose [(0,79),(1,78)]
    78 -> advance 1 0
    79 -> advance 1 0
    80 -> 77
    81 -> 82
    82 -> choose [(0,0),(1,83)]
    83 -> advance 1 0
    84 -> 85
    85 -> advance 1 86
    86 -> advance 1 0
    87 -> 88
    88 -> advance 1 89
    89 -> advance 1 90
    90 -> advance 1 91
    91 -> advance 1 0
    92 -> 93
    93 -> advance 1 94
    94 -> advance 1 0
    95 -> 96
    96 -> advance 1 97
    97 -> advance 1 98
    98 -> advance 1 99
    99 -> advance 1 100
    100 -> advance 1 0
    101 -> 102
    102 -> advance 1 103
    103 -> advance 1 104
    104 -> advance 1 105
    105 -> advance 1 106
    106 -> advance 1 0
    107 -> 108
    108 -> choose [(0,109),(1,110)]
    109 -> choose [(0,110),(1,110)]
    110 -> advance 0 0
    111 -> 112
    112 -> advance 1 113
    113 -> advance 1 97
    114 -> choose [(0,95),(1,111)]
    _ -> error "invalid BMM state-flow phase"
    where
      choose options = maybe (error "invalid BMM state-flow reply") id (lookup reply options)
      advance expected next
        | reply == expected = next
        | reply <= 0 = -1
        | otherwise = error "invalid BMM state-flow reply"

data Lifecycle = Lifecycle Word32 Word32
instance Validation Lifecycle where
  type ValidationResult Lifecycle = Int32
  validate (Lifecycle phase facts) = case phase of
    0 | facts <= 1 -> if facts /= 0 then 1 else 2
    1 | facts <= 1 -> if facts /= 0 then -1 else 0
    2 | facts <= 1 -> if facts /= 0 then 3 else 4
    3 | facts <= 3 -> if bit 0 then -2 else if bit 1 then -3 else 5
    4 | facts <= 3 -> if facts == 0 then 0 else 6
    5 | facts <= 15 -> if facts == 15 then 0 else 7
    6 | facts <= 1 -> if facts /= 0 then 1 else 2
    7 | facts <= 7 -> if bit 0 && bit 1 then 3 else if bit 2 then -3 else -4
    8 | facts <= 1 -> if facts /= 0 then 0 else -5
    9 | facts <= 1 -> if facts /= 0 then 4 else 0
    10 | facts <= 3 -> if bit 0 then 5 else if bit 1 then -3 else -6
    11 | facts <= 1 -> if facts /= 0 then 6 else -7
    _ -> error "invalid BMM lifecycle facts"
    where bit = testBit facts

data StateSource = StateSource Word32 Word32
instance Validation StateSource where
  type ValidationResult StateSource = Int32
  validate (StateSource phase facts) = case phase of
    0 | facts <= 1 -> if facts == 0 then 1 else -1
    1 | facts <= 3 -> if testBit facts 0 then 0 else if testBit facts 1 then -2 else 2
    2 | facts <= 1 -> if facts /= 0 then 3 else 4
    3 | facts <= 1 -> if facts /= 0 then 5 else -3
    4 | facts <= 1 -> fromIntegral facts
    5 | facts <= 1 -> if facts /= 0 then 0 else -2
    _ -> error "invalid BMM state source facts"

data Advance = Advance Int64 Word32 Word32 [Word32]
instance Validation Advance where
  type ValidationResult Advance = [Word32]
  validate (Advance interval time bits fields)
    | interval <= 0 = error "invalid BMM advancement interval"
    | otherwise = case fields of
        height:_:_:start:startTime:history@(_:rest) | length history == 11 ->
          let next = height + 1
              boundary = fromIntegral next `mod` interval == 0
          in [next,time,bits,if boundary then next else start,if boundary then time else startTime] ++ rest ++ [time]
        _ -> error "invalid BMM advancement fields"

data Traversal = Traversal Word32 Word64 Word64
instance Validation Traversal where
  type ValidationResult Traversal = Int32
  validate (Traversal phase a b) = case phase of
    0 -> 1
    1 -> proceed 18
    2 -> proceed 20
    3 -> proceed 4
    4 -> proceed 5
    5 -> if a == 0 then -2 else if b /= 0 then 6 else 7
    6 -> if a == 0 then -2 else 7
    7 | a < b -> if a + 1 == b then 8 else 2
      | otherwise -> error "invalid BMM traversal position"
    8 -> proceed 9
    9 -> proceed 10
    10 -> proceed 19
    11 -> 12
    12 -> proceed 13
    13 -> proceed 14
    14 -> proceed 15
    15 -> proceed 16
    16 -> proceed 17
    17 -> proceed 0
    18 -> proceed 2
    19 -> proceed 0
    20 -> proceed 3
    _ -> error "invalid BMM traversal phase"
    where proceed next = if a == 0 then -1 else next

data Codec = Codec Word32 Word32 Word64 Word64
instance Validation Codec where
  type ValidationResult Codec = Int32
  validate (Codec phase facts a b) = case phase of
    0 -> check (a > 0 && a <= b) 1
    1 -> check (a > 0 && a <= b) 2
    2 -> check (facts == 3 && a > 0 && a <= b) 3
    3 -> check (facts /= 0) 3
    4 -> check (facts /= 0) 4
    5 -> check (facts == 31) 5
    6 -> check (facts /= 0 && a <= 78) 6
    7 -> check (facts /= 0 && a == 117) 6
    8 -> check (facts == 3 && a == 0) 6
    9 -> check (facts == 3) 7
    10 -> 8
    _ -> -1
    where check valid failure = if valid then 0 else failure

-- One caller-thread entry owns journal recovery, funding, signing and publication.
-- Native effects keep Bitcoin codecs and RPC objects, never select the next stage.
data LocalBidWallet = LocalBidWallet Word64 NativeBytes
data BidLimits = BidLimits { bidHeight :: Integer, bidFee :: Integer,
  bidMaximum :: Integer, bidMoneyLimit :: Integer } deriving (Eq, Show)
data BidPlan = RetrySignedBid | FundLocalBid Bool Integer deriving (Eq, Show)

class BidPreparation op where
  prepareLocalBid :: op -> IO (Maybe (BidLimits, BidPlan))
class BidFunding op where
  fundLocalBid :: op -> BidLimits -> BidPlan -> IO ()
class BidPublication op where
  publishLocalBid :: op -> BidLimits -> IO ()

bidScalar :: NativeBytes -> Word32 -> Word64 -> IO Integer
bidScalar native step index = toInteger . (fromIntegral :: Word64 -> Int64) <$>
  constructionScalar native step index

bidReject :: NativeBytes -> String -> IO a
bidReject native message = native 0 0 (C.pack message) >> ioError (userError "native bid rejection returned")

bidRequire :: NativeBytes -> String -> Bool -> IO ()
bidRequire native message valid = unless valid (bidReject native message)

bidEffect :: NativeBytes -> Word32 -> Integer -> IO ()
bidEffect native step index = do
  result <- bidScalar native step (fromInteger index)
  unless (result == 1) (ioError (userError "invalid local bid effect reply"))

bidCheck :: NativeBytes -> String -> [Word32] -> IO ()
bidCheck native message = mapM_ (\step -> bidScalar native step 0 >>= bidRequire native message . (== 1))

bidFlag :: NativeBytes -> Word32 -> IO Bool
bidFlag native step = do
  result <- bidScalar native step 0
  unless (result == 0 || result == 1) (ioError (userError "invalid local bid flag"))
  pure (result == 1)

bidCurrent :: NativeBytes -> BidLimits -> IO ()
bidCurrent native limits = do
  bidCheck native "BMM submission cancelled" [2]
  bidCheck native "BMM parent changed before broadcast" [3]
  height <- bidScalar native 4 0
  bidRequire native "BMM parent height mismatch" (height == bidHeight limits)
  bidCheck native "BMM submission cancelled" [2]

bidInputTotal :: NativeBytes -> BidLimits -> IO Integer
bidInputTotal native limits = do
  count <- bidScalar native 16 0
  bidRequire native "Invalid BMM funding input count" (count > 0 && count <= 100)
  bidEffect native 34 0
  let loop total index
        | index == count = pure total
        | otherwise = do
            bidCheck native "BMM submission cancelled" [2]
            unique <- bidScalar native 20 (fromInteger index)
            bidRequire native "Duplicate BMM funding input" (unique == 1)
            shape <- bidScalar native 17 (fromInteger index)
            bidRequire native "BMM funding input is not confirmed and unspent on L1" (shape == 1)
            confirmations <- bidScalar native 18 0
            bidRequire native "BMM funding input is not confirmed and unspent on L1" (confirmations > 0)
            amount <- bidScalar native 19 0
            bidRequire native "BMM input amount overflow" (amount >= 0 && amount <= bidMoneyLimit limits - total)
            loop (total+amount) (index+1)
  loop 0 0

instance BidPreparation LocalBidWallet where
  prepareLocalBid (LocalBidWallet maximumMoney native) = do
    unless (maximumMoney > 0 && maximumMoney <= fromIntegral (maxBound :: Int64))
      (ioError (userError "invalid local bid money limit"))
    bytes <- native 1 0 B.empty
    unless (B.length bytes == 112) (ioError (userError "invalid local bid frame"))
    let field offset = toInteger (fromIntegral (readLE (B.take 8 (B.drop offset bytes)) :: Word64) :: Int64)
        slot = field 0
        height = field 8
        fee = field 16
        extra = field 24
        parent = field 32
        critical = field 40
        money = toInteger maximumMoney
        limits = BidLimits height fee (fee+extra) money
    bidRequire native "Invalid local BMM bid" (slot >= 0 && slot <= 255 && height > 0 && height < 500000000 &&
      parent == 1 && critical == 1 && fee > 0 && fee <= money && extra >= 0 && extra <= money-fee)
    bidCurrent native limits
    bidCheck native "BMM requires a signing parent wallet" [5]
    -- M8 h* is display order, followed by the parent's internal hash bytes.
    let request = B.pack [0x6a,68,0,0xbf,0,fromInteger slot] <>
          B.reverse (B.drop 80 bytes) <> B.take 32 (B.drop 48 bytes)
    saved <- constructionWord =<< native 6 0 request
    unless (saved == 0 || saved == 1) (ioError (userError "invalid saved bid flag"))
    plan <- if saved == 0 then pure (Just (FundLocalBid False fee)) else do
      bidEffect native 7 0
      version <- bidScalar native 30 0
      bidRequire native "Corrupt saved BMM bid" (version == 2)
      inputs <- bidScalar native 16 0
      bidRequire native "Corrupt saved BMM bid" (inputs > 0 && inputs <= 100)
      outputs <- bidScalar native 27 0
      bidRequire native "Corrupt saved BMM bid" (outputs == 2)
      value <- bidScalar native 31 0
      bidRequire native "Corrupt saved BMM bid" (value == 0)
      script <- native 8 0 B.empty
      bidRequire native "Corrupt saved BMM bid" (B.length script == 70 &&
        B.take 6 script == B.pack [0x6a,68,0,0xbf,0,fromInteger slot])
      sameParent <- bidFlag native 10
      if sameParent then do
        lock <- bidScalar native 32 0
        bidRequire native "A different candidate is already recorded for this parent; refusing another bid" (lock == height)
        bidCheck native "A different candidate is already recorded for this parent; refusing another bid" [11]
        pending <- bidFlag native 12
        if pending then bidEffect native 55 0 >> pure Nothing else pure (Just RetrySignedBid)
      else do
        pending <- bidFlag native 12
        nextFee <- if not pending then pure fee else do
          oldFee <- bidScalar native 13 0
          rate <- bidScalar native 14 0
          size <- bidScalar native 15 0
          bidRequire native "Invalid replacement fee data" (oldFee >= 0 && oldFee <= money &&
            rate > 0 && rate <= money `div` 100032 && size > 0 && size <= 100000)
          let increment = (rate*(size+32)+999) `div` 1000
              selected = max fee (oldFee+increment)
          bidRequire native "Replacement fee overflow" (oldFee <= money-increment)
          bidRequire native "BMM replacement exceeds configured fee allowance" (selected <= bidMaximum limits)
          pure selected
        -- Inspect every previous input, even after one is absent, as before.
        present <- forM [0..inputs-1] $ \index -> do
          bidCheck native "BMM submission cancelled" [2]
          (/= 0) <$> bidScalar native 17 (fromInteger index)
        let reuse = and present
        bidRequire native "Pending BMM bid inputs no longer exist" (not pending || reuse)
        pure (Just (FundLocalBid reuse nextFee))
    pure (fmap (\selected -> (limits,selected)) plan)

instance BidFunding LocalBidWallet where
  fundLocalBid _ _ RetrySignedBid = pure ()
  fundLocalBid (LocalBidWallet _ native) limits (FundLocalBid reuse fee) = do
    unless reuse $ do
      bidEffect native 21 0
      bidEffect native 22 0
      bidCheck native "BMM change address is not wallet-owned" [23]
      bidCheck native "Invalid BMM funding target" [24]
      bidRequire native "Invalid BMM funding target" (fee <= bidMoneyLimit limits-1000)
      bidEffect native 25 (fee+1000)
      position <- bidScalar native 26 0
      outputs <- bidScalar native 27 0
      bidRequire native "Unexpected BMM funding outputs" ((outputs == 2 && position == -1) || (outputs == 3 && position == 1))
      forM_ [1..outputs-1] $ \index -> bidScalar native 28 (fromInteger index) >>=
        bidRequire native "Wallet changed BMM change script" . (== 1)
      bidEffect native 29 0
    version <- bidScalar native 30 0
    bidRequire native "Unexpected BMM funding transaction" (version == 2)
    outputs <- bidScalar native 27 0
    bidRequire native "Unexpected BMM funding transaction" (outputs == 2)
    amount <- bidScalar native 31 0
    bidRequire native "Unexpected BMM funding transaction" (amount == 0)
    unless reuse $ do
      bidCheck native "Wallet changed BMM request" [11]
      lock <- bidScalar native 32 0
      bidRequire native "Wallet changed BMM request" (lock == bidHeight limits)
    bidEffect native 33 0
    total <- bidInputTotal native limits
    bidRequire native "Insufficient BMM funds or dust change" (total > fee && total-fee >= 1000)
    bidEffect native 35 (total-fee)
    inputs <- bidScalar native 16 0
    forM_ [0..inputs-1] (bidEffect native 36)
    bidCurrent native limits
    bidEffect native 37 0
    bidCheck native "Incomplete BMM signature" [38]
    bidEffect native 39 0
    bidCheck native "Signer changed BMM transaction" [40,41,42,43]
    forM_ [0..inputs-1] $ \index -> forM_ [44,45] $ \step ->
      bidScalar native step (fromInteger index) >>= bidRequire native "Signer changed BMM inputs" . (== 1)
    bidEffect native 46 0

instance BidPublication LocalBidWallet where
  publishLocalBid (LocalBidWallet _ native) limits = do
    total <- bidInputTotal native limits
    change <- bidScalar native 47 0
    bidRequire native "Saved BMM fee exceeds current budget" (change >= 0 && change <= bidMoneyLimit limits &&
      total > change && total-change <= bidMaximum limits)
    bidEffect native 48 0
    bidCurrent native limits
    bidCheck native "Malformed parent mempool response" [49,50]
    accepted <- bidScalar native 51 0
    unless (accepted == 1) $ do
      reason <- native 52 0 B.empty
      bidReject native ("Parent mempool rejected BMM bid: " ++ C.unpack reason)
    bidEffect native 53 0
    bidCurrent native limits
    bidCheck native "Parent returned a different BMM transaction ID" [54]

submitLocalBid :: (BidPreparation op, BidFunding op, BidPublication op) => op -> IO Int32
submitLocalBid value = do
  planned <- prepareLocalBid value
  forM_ planned $ \(limits,plan) -> fundLocalBid value limits plan >> publishLocalBid value limits
  pure 1

type LocalBidCapabilities = '[BidPreparation, BidFunding, BidPublication]
instance Operation LocalBidWallet LocalBidCapabilities where
  type Context LocalBidWallet = CapabilityContext LocalBidCapabilities LocalBidWallet
  type Outcome LocalBidWallet = IO Int32
  data DSL LocalBidWallet where
    SubmitLocalBid :: Context LocalBidWallet => DSL LocalBidWallet
  interpret operation request = withOperation @LocalBidWallet operation $ \value -> case request of
    SubmitLocalBid -> Just (submitLocalBid value)

data Proof = Proof Word32 Word32 Word64 Word64 Word64
instance Validation Proof where
  type ValidationResult Proof = Int32
  validate (Proof phase facts a b c) = case phase of
    0 -> check (facts /= 0 && a > 0 && a <= b) 1
    1 -> check (a > 0 && a <= c && b > 0 && b <= c) 2
    2 -> check (facts == 31 && a == 1) 3
    3 -> check (facts /= 0 && a == 1 && b == 1 && c == 0) 4
    4 -> check (facts == 7) 5
    5 -> check (facts /= 0) 6
    6 -> check (facts /= 0) 7
    7 -> check (facts == 3 && a > 0 && a <= b) 8
    8 -> check (facts /= 0) 8
    9 -> check (facts /= 0) 9
    10 -> check (facts /= 0) 4
    11 -> check (facts == 0) 10
    12 -> check (facts /= 0) 10
    13 -> check (facts /= 0) 11
    _ -> -1
    where check valid failure = if valid then 0 else failure
