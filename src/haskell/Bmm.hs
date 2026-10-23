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
import Control.Monad (when, void, guard)
import Control.Exception (evaluate)
import Data.Bits (testBit, (.&.), (.|.), shiftL, shiftR)
import Data.Int (Int32, Int64)
import Data.List (sort)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Word (Word8, Word32, Word64)
import Deposit (ReadPegFields, readPegFields)
import ParentReplay (transition, Message(..))
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

-- Keep BMM marking and withdrawal-envelope reads in their original order.
data TemplateCommitmentFlow = TemplateCommitmentFlow Bool Word32 Word32
instance Validation TemplateCommitmentFlow where
  type ValidationResult TemplateCommitmentFlow = Int32
  validate (TemplateCommitmentFlow envelope phase result) = transition phase result $
    if envelope then
      [(1,(4,2)),(2,(4,3)),(3,(-1,4)),(4,(-11,5)),(5,(-11,6)),
       (6,(7,8)),(7,(8,-11)),(8,(11,9)),(9,(11,10)),(10,(-1,-11)),(11,(-1,-10))]
    else [(1,(-11,2)),(2,(-11,3)),(3,(-1,-11))]

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
-- Non-native fallback failure is optional; exchange-header failure is not.
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

data StageAdmission
  = RewardAddress (Word32 -> IO Int32)
  | NativeProduction (Word32 -> IO Int32)
  | EcxProduction (Word32 -> IO Int32)
  | SyncTick (Word32 -> IO Int32)
instance Validation StageAdmission where
  type ValidationResult StageAdmission = IO Int32
  validate request = case request of
    RewardAddress action -> run 5 action
    NativeProduction action -> produce action
      [(1,1),(2,2),(13,2),(3,3),(4,4),(5,5),(6,6),(11,6),(12,6),(7,7),(8,8),(9,9),(10,10)]
      [(1,101),(2,102),(13,102),(3,103),(6,106),(11,111),(12,112),(7,107)]
    EcxProduction action -> produce action
      [(1,1),(19,1),(2,2),(20,2),(3,3),(15,3),(4,4),(5,5),(6,6),(16,6),
       (7,7),(8,8),(9,9),(17,9),(10,10),(18,10),(11,11),(12,12),(13,13),(14,14)]
      [(1,101),(19,101),(2,102),(20,102),(3,103),(15,115),(4,104),
       (6,106),(16,116),(7,107),(9,109),(10,110),(12,112)]
    SyncTick action -> run 5 action
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

data AnnexAccountingFlow = AnnexAccountingFlow Word32 Word32
instance Validation AnnexAccountingFlow where
  type ValidationResult AnnexAccountingFlow = Int32
  validate (AnnexAccountingFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-1,-11))]

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
  replacementHeight :: op -> Int32
  clearStoredState :: op -> IO ()
  prepareStoredState :: op -> IO ()

replaceStoredState :: (StateReplacement op, Finalize op, FinalInput op ~ Word32, FinalResult op ~ ()) => op -> IO ()
replaceStoredState request = do
  clearStoredState request
  prepareStoredState request
  finalize request (fromIntegral (max 0 (replacementHeight request)))

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
  replacementHeight (StateWrite height _ _) = height
  replacementHeight (StateRestore height _ _) = max 1 height - 1
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
-- Exchange v9 field ordering. Native adapters expose values, not encoded layout.
exchangeFingerprintPayload :: FingerprintSource op => op -> IO [Word8]
exchangeFingerprintPayload source = do
  private <- fingerprintNumber source 0 37
  when (private > 1) (error "invalid exchange fingerprint mode")
  parts <- sequence $
    [number 4 i | i <- [0..9]] ++ [number 8 i | i <- [10..20]] ++
    concat [[raw i, number 4 (21+i)] | i <- [0..2]] ++
    [sized 8 i | i <- [3..8]] ++ [number 1 i | i <- [24..26]] ++
    [raw 9, sized 4 10] ++ [raw i | i <- [11..13]] ++
    [number 4 27, raw 14, number 4 28] ++ [raw i | i <- [15..18]] ++
    [sized 4 19, raw 20, number 1 29, number 1 30, number 4 31,
     sized 8 21, sized 8 22] ++ [number 4 i | i <- [32..35]] ++
    [sized 8 23] ++ [raw i | i <- [24..62]] ++
    [number 8 36, pure [fromIntegral private],
     if private == 1 then number 4 38 else pure (bigEndian 4 0)]
  pure (concat parts)
  where
    number width index = bigEndian width <$> fingerprintNumber source 0 index
    raw = fingerprintBytes source
    sized width index = do
      bytes <- raw index
      pure (bigEndian width (fromIntegral (length bytes)) ++ bytes)

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
activationFingerprintPayload :: FingerprintSource op => op -> IO [Word8]
activationFingerprintPayload source = concat <$> sequence (
  [raw 0,raw 1] ++ [number 4 i | i <- [0..3]] ++ [raw 2] ++
  [fixed i | i <- [3..45]] ++ [number 8 4,number 1 5,number 4 6,fixed 46,number 8 7])
  where
    raw = fingerprintBytes source
    fixed index = do
      bytes <- raw index
      when (length bytes/=32) (error "invalid activation fingerprint identity")
      pure bytes
    number width index = do
      value <- fingerprintNumber source 0 index
      when (width<8 && value>=2^(8*width)) (error "invalid activation fingerprint number")
      pure (bigEndian width value)

data FingerprintFormat = BmmFormat | ExchangeFormat | ActivationFormat

fingerprint :: FingerprintFormat -> DSL FingerprintRequest
fingerprint = EncodeFingerprint

encodeFingerprint :: FingerprintSource op => FingerprintFormat -> op -> IO [Word8]
encodeFingerprint format source = do
  bytes <- case format of
    BmmFormat -> fingerprintPayload source
    ExchangeFormat -> exchangeFingerprintPayload source
    ActivationFormat -> activationFingerprintPayload source
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
  nextScriptStep request = do
    fields <- scriptCall request 0
    case fields of
      [parsed,end,size,prefix] | parsed >= 0 && parsed <= 1 && end >= 0 && end <= 1 &&
          size >= 0 && prefix >= 0 && prefix <= 0xffffffff ->
        pure (if parsed == 0 then ScriptEnd (end == 1) else ScriptPush size prefix)
      _ -> error "invalid signet script facts"
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
      extensions = extensionFields .|. present (extensionFields .&. 24 == 24) 7
      extensionFields = sum [present (testBit version bit) position | (bit,position) <- zip Constants.headerExtensionBits [1..5]]

data CommitmentBytes = CommitmentBytes Word32 [Word8]
instance Validation CommitmentBytes where
  type ValidationResult CommitmentBytes = [Word8]
  validate (CommitmentBytes 0 bytes) | length bytes == 37 = reverse (drop 5 bytes)
  validate (CommitmentBytes 1 bytes) | length bytes == 32 = bytes
  validate (CommitmentBytes 2 bytes) = case validate (Message bytes) of
    (5,_,_) -> validate (CommitmentBytes 0 bytes)
    (kind,_,_) | kind == 2 || kind == 3 -> validate (CommitmentBytes 1 (drop 5 bytes))
    _ -> error "parent message has no commitment hash"
  validate _ = error "invalid commitment payload"

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

-- Upstream GetOp projects two nine-bit opcodes (256 = failure), consumed,
-- payload size, first four bytes little-endian, and the fifth byte.
-- Kind 2 instead supplies raw script size and its first six bytes little-endian.
type ReadScript = Ptr () -> Word32 -> Word32 -> Ptr Int64 -> IO Int32
foreign import ccall "dynamic" readScript :: FunPtr ReadScript -> ReadScript

data Commitment = Commitment Word32 Int32 Word32 (FunPtr ReadScript) (Ptr ())
instance Validation Commitment where
  type ValidationResult Commitment = IO Int64
  validate (Commitment kind slot count reader context)
    | kind > 3 = error "invalid BMM commitment kind"
    | count /= 0 && reader == nullFunPtr = error "missing BMM script adapter"
    | otherwise = go 0 Nothing
    where
      inspect index action = allocaArray 4 $ \out -> do
        status <- readScript reader context index action out
        if status /= 1 then error "BMM script adapter fault" else peekArray 4 out
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
                if size < 0 || prefix < 0 || prefix > 0xffffffffffff then error "BMM witness facts out of range"
                else go (index+1) (if size >= 38 && prefix == 0xeda921aa246a then Just index else found)
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
