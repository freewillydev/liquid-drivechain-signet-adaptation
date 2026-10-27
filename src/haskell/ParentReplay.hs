{-# LANGUAGE TypeFamilies, BangPatterns, ConstraintKinds, DataKinds, FlexibleContexts #-}
{-# LANGUAGE GADTs, MultiParamTypeClasses, TypeApplications, FlexibleInstances #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ParentReplay where

import Control.Operation.Validation
import Control.Operation
import CapabilityContext (CapabilityContext)
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int32, Int64)
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.Binary.Get as G
import qualified ReplayStore as RS
import Data.List (findIndex, foldl', sort)
import Control.Monad (forM_, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Workflow (NativeBytes, CommandFlow(..), runRequiredEffects)
import BmmConstants (depositAddressLimit, parentMessageTags)
import Numeric (showHex)

runStore :: Word32 -> (Word32 -> IO Int64) -> IO Int32
runStore kind = validate . CommandFlow (storeMaximum kind)
  (\phase result -> validate (StoreFlow kind phase result))

runDeadline :: (Word32 -> IO Int64) -> IO Int32
runDeadline = runStore 25

newtype RpcPreparation = RpcPreparation (Word32 -> IO Int64)

class CredentialSource op where
  selectCredential :: op -> ExceptT Int32 IO Bool
class CredentialCache op where
  cachedCredential :: op -> ExceptT Int32 IO Bool
class CredentialLoader op where
  loadCredential :: op -> ExceptT Int32 IO ()
class RequestTimeout op where
  configureTimeout :: op -> IO Int32

checkedStore :: Word32 -> (Word32 -> IO Int64) -> ExceptT Int32 IO Bool
checkedStore kind action = do
  result <- liftIO (runStore kind action)
  when (result < 0) (throwE result)
  pure (result /= 0)

instance CredentialSource RpcPreparation where
  selectCredential (RpcPreparation action) = checkedStore 58 action
instance CredentialCache RpcPreparation where
  cachedCredential (RpcPreparation action) = do
    let effect step = do
          result <- liftIO (action step)
          unless (result == 1) (throwE (-1))
    effect 20
    found <- checkedStore 57 (action . (20+))
    effect 27
    pure found
instance CredentialLoader RpcPreparation where
  loadCredential (RpcPreparation action) = checkedStore 59 (action . (40+)) >> pure ()

prepareCredentials :: (CredentialSource op, CredentialCache op, CredentialLoader op)
  => op -> ExceptT Int32 IO ()
prepareCredentials value = do
  selected <- selectCredential value
  unless selected $ do
    cached <- cachedCredential value
    unless cached (loadCredential value)

instance RequestTimeout RpcPreparation where
  configureTimeout (RpcPreparation action) = do
    configured <- newIORef 0
    let positive value = fromIntegral (validate (Record 15 0 value 0 0))
        observe step = case step of
          3 -> positive <$> action step
          8 -> positive <$> action step
          11 -> do
            value <- action step
            writeIORef configured value
            pure (positive value)
          12 -> do
            seconds <- readIORef configured
            remainingSeconds <- action step
            pure (fromIntegral (validate (Record 11 0 0 (fromIntegral seconds) (fromIntegral remainingSeconds))))
          _ -> action step
    runStore 56 observe

type RpcPreparationCapabilities = '[CredentialSource, CredentialCache, CredentialLoader, RequestTimeout]
instance Operation RpcPreparation RpcPreparationCapabilities where
  type Context RpcPreparation = CapabilityContext RpcPreparationCapabilities RpcPreparation
  type Outcome RpcPreparation = IO Int32
  data DSL RpcPreparation where
    PrepareCredentials :: Context RpcPreparation => DSL RpcPreparation
    ConfigureTimeout :: Context RpcPreparation => DSL RpcPreparation
  interpret operation request = withOperation @RpcPreparation operation $ \value ->
    case request of
      PrepareCredentials -> Just (either id (const 1) <$> runExceptT (prepareCredentials value))
      ConfigureTimeout -> Just (configureTimeout value)

newtype RpcCall = RpcCall (Word32 -> IO Int64)
data RpcAttemptResult = RpcSucceeded | RpcAuthenticationFailed | RpcFailed deriving (Eq, Show)

class RpcCircuit op where
  admitRpcCall :: op -> ExceptT Int32 IO ()
class RpcAttempt op where
  attemptRpcCall :: op -> ExceptT Int32 IO RpcAttemptResult
class RpcAuthentication op where
  retryRpcCall :: op -> ExceptT Int32 IO Bool
class RpcFailure op where
  rejectRpcCall :: op -> ExceptT Int32 IO ()
class RpcReply op where
  verifyRpcReply :: op -> ExceptT Int32 IO ()

instance RpcCircuit RpcCall where
  admitRpcCall (RpcCall action) = checkedStore 26 action >> pure ()
instance RpcAttempt RpcCall where
  attemptRpcCall (RpcCall action) = liftIO (action 10) >>= \result -> case result of
    0 -> pure RpcSucceeded
    1 -> pure RpcAuthenticationFailed
    2 -> pure RpcFailed
    _ -> throwE (-1)
instance RpcAuthentication RpcCall where
  retryRpcCall (RpcCall action) = checkedStore 55 (action . (20+))
instance RpcFailure RpcCall where
  rejectRpcCall (RpcCall action) = do
    result <- liftIO (runRequiredEffects action [12,13])
    -- Native action 13 rethrows the retained exception; returning cannot succeed.
    throwE (if result == 0 then -1 else result)
instance RpcReply RpcCall where
  verifyRpcReply (RpcCall action) = checkedStore 54 (action . (30+)) >> pure ()

performRpcCall :: (RpcCircuit op, RpcAttempt op, RpcAuthentication op, RpcFailure op)
  => op -> ExceptT Int32 IO ()
performRpcCall value = do
  admitRpcCall value
  result <- attemptRpcCall value
  case result of
    RpcSucceeded -> pure ()
    RpcFailed -> rejectRpcCall value
    RpcAuthenticationFailed -> do
      retry <- retryRpcCall value
      if retry then do
        second <- attemptRpcCall value
        unless (second == RpcSucceeded) (rejectRpcCall value)
      else rejectRpcCall value

type RpcCallCapabilities = '[RpcCircuit, RpcAttempt, RpcAuthentication, RpcFailure, RpcReply]
instance Operation RpcCall RpcCallCapabilities where
  type Context RpcCall = CapabilityContext RpcCallCapabilities RpcCall
  type Outcome RpcCall = IO Int32
  data DSL RpcCall where
    CallRpc :: Context RpcCall => DSL RpcCall
    CallCheckedRpc :: Context RpcCall => DSL RpcCall
  interpret operation request = withOperation @RpcCall operation $ \value ->
    let run = fmap (either id (const 1)) . runExceptT
    in case request of
      CallRpc -> Just (run (performRpcCall value))
      CallCheckedRpc -> Just (run (performRpcCall value >> verifyRpcReply value))

-- The same milestone workflow is callable on its own or directly from cache
-- advancement, without returning to C++ to dispatch Haskell subrules.
newtype Milestone = Milestone NativeBytes
data MilestoneInput = MilestoneInput
  { milestoneHeight :: Word32, milestoneDescription :: B.ByteString
  , milestoneSlot :: Maybe Word8, milestoneProposal :: Maybe RS.Hash
  , milestoneProposed :: (Word32,RS.Hash), milestoneActivated :: (Word32,RS.Hash)
  , milestoneCheckpoint :: (Word32,RS.Hash), milestoneTreasury :: (RS.Hash,Word32,Int64)
  } deriving (Eq, Show)

milestoneInput :: G.Get MilestoneInput
milestoneInput = MilestoneInput <$> G.getWord32le <*> (B.pack <$> RS.counted 1 G.getWord8)
  <*> present G.getWord8 <*> present RS.hash <*> point <*> point <*> point
  <*> ((,,) <$> RS.hash <*> G.getWord32le <*> G.getInt64le)
  where
    point = (,) <$> G.getWord32le <*> RS.hash
    present parser = do
      exists <- RS.flag
      value <- parser
      pure (if exists then Just value else Nothing)

readReplayReply :: NativeBytes -> Word32 -> Word64 -> G.Get a -> ExceptT Int32 IO a
readReplayReply native step index parser = do
  bytes <- liftIO (native step index B.empty)
  either throwE pure (RS.decode parser bytes)
milestoneRead :: Milestone -> Word32 -> Word64 -> G.Get a -> ExceptT Int32 IO a
milestoneRead (Milestone native) = readReplayReply native
milestoneFail :: Milestone -> String -> ExceptT Int32 IO a
milestoneFail (Milestone native) message = do
  reply <- liftIO (native 8 0 (C.pack message))
  throwE (if B.null reply then 0 else -1)
milestoneHash :: Milestone -> Word32 -> RS.Hash -> ExceptT Int32 IO ()
milestoneHash value height expected = do
  actual <- milestoneRead value 1 0 RS.hash
  unless (actual == expected) $ milestoneFail value
    ("authenticated parent milestone height " ++ show height ++ " hashes to " ++ hashHex actual ++ ", expected " ++ hashHex expected)

hashHex :: RS.Hash -> String
hashHex = concatMap (\byte -> if byte < 16 then '0':showHex byte "" else showHex byte "") . B.unpack . B.reverse

-- The native reader projects upstream GetOp, not a second Script parser.
coinbasePush :: NativeBytes -> Word64 -> ExceptT Int32 IO (Maybe B.ByteString)
coinbasePush native index = do
  first <- readReplayReply native 1 index G.getWord16le
  if first /= 106 then pure Nothing else do
    (op,ended,payload) <- readReplayReply native 2 index
      ((,,) <$> G.getWord16le <*> RS.flag <*> (B.pack <$> RS.counted 1 G.getWord8))
    pure (if op <= 78 && ended then Just payload else Nothing)

milestoneMessage :: Milestone -> B.ByteString -> ExceptT Int32 IO ()
milestoneMessage value@(Milestone native) expected = do
  count <- milestoneRead value 2 0 (RS.optional G.getWord64le) >>=
    maybe (milestoneFail value "pinned parent identity block has no coinbase transaction") pure
  let scan index matches
        | index == count = pure matches
        | otherwise = do
            payload <- coinbasePush (\step -> native (step+2)) index
            scan (index+1) (if payload == Just expected then matches+1 else matches)
  found <- scan 0 (0 :: Word64)
  unless (found == 1) $ milestoneFail value
    ("pinned parent identity block contains " ++ show found ++ " copies of its expected drivechain message")

milestoneIdentity :: MilestoneInput -> ExceptT Int32 IO (Word8,RS.Hash)
milestoneIdentity input = case (milestoneSlot input,milestoneProposal input) of
  (Just slot,Just proposal) -> pure (slot,proposal)
  _ -> throwE (-1)
milestoneTag :: String -> B.ByteString
milestoneTag key = B.pack (map fromIntegral (maybe (error "unknown parent message tag") id (lookup key parentMessageTags)))
milestonePending :: Milestone -> ExceptT Int32 IO (Maybe (Word32,Word32))
milestonePending value = milestoneRead value 5 0 (RS.optional ((,) <$> G.getWord32le <*> G.getWord32le))

class MilestoneSource op where
  readMilestone :: op -> ExceptT Int32 IO MilestoneInput
class ProposalMilestone op where
  checkProposalMilestone :: op -> MilestoneInput -> ExceptT Int32 IO ()
class ActivationMilestone op where
  checkActivationMilestone :: op -> MilestoneInput -> ExceptT Int32 IO ()
class CheckpointMilestone op where
  checkCheckpointMilestone :: op -> MilestoneInput -> ExceptT Int32 IO ()

instance MilestoneSource Milestone where
  readMilestone value = milestoneRead value 0 0 milestoneInput
instance ProposalMilestone Milestone where
  checkProposalMilestone value input =
    when (not (B.null (milestoneDescription input)) && milestoneHeight input == fst (milestoneProposed input)) $ do
      milestoneHash value (milestoneHeight input) (snd (milestoneProposed input))
      (slot,_) <- milestoneIdentity input
      milestoneMessage value (milestoneTag "PARENT_M1_TAG" <> B.singleton slot <> milestoneDescription input)
      pending <- milestonePending value
      unless (pending == Just (milestoneHeight input,0)) $ milestoneFail value
        "authenticated parent proposal milestone did not derive the expected pending proposal state"
instance ActivationMilestone Milestone where
  checkActivationMilestone value input =
    when (not (B.null (milestoneDescription input)) && milestoneHeight input == fst (milestoneActivated input)) $ do
      milestoneHash value (milestoneHeight input) (snd (milestoneActivated input))
      (slot,proposal) <- milestoneIdentity input
      milestoneMessage value (milestoneTag "PARENT_M2_TAG" <> B.singleton slot <> proposal)
      active <- milestoneRead value 6 0 RS.hash
      matches <- if active == proposal then (== Nothing) <$> milestonePending value else pure False
      unless matches $ milestoneFail value
        "authenticated parent activation milestone did not derive the expected active proposal state"
instance CheckpointMilestone Milestone where
  checkCheckpointMilestone value input = when (milestoneHeight input == fst (milestoneCheckpoint input)) $ do
    milestoneHash value (milestoneHeight input) (snd (milestoneCheckpoint input))
    (ctip,amount) <- milestoneRead value 7 0
      ((,) <$> RS.optional ((,) <$> RS.hash <*> G.getWord32le) <*> G.getInt64le)
    let (expectedHash,expectedIndex,expectedAmount) = milestoneTreasury input
        ctipMatches = if RS.nonzero expectedHash then ctip == Just (expectedHash,expectedIndex) && amount == expectedAmount
                      else ctip == Nothing && amount == 0
    active <- milestoneRead value 6 0 RS.hash
    proposalMatches <- if B.null (milestoneDescription input) then pure (not (RS.nonzero active))
      else maybe (throwE (-1)) (pure . (active ==)) (milestoneProposal input)
    unless (proposalMatches && ctipMatches) $ milestoneFail value
      "authenticated parent checkpoint milestone did not derive the asserted active proposal and CTIP"

validateMilestones :: (MilestoneSource op, ProposalMilestone op, ActivationMilestone op, CheckpointMilestone op)
  => op -> ExceptT Int32 IO ()
validateMilestones value = do
  input <- readMilestone value
  checkProposalMilestone value input
  checkActivationMilestone value input
  checkCheckpointMilestone value input

type MilestoneCapabilities = '[MilestoneSource, ProposalMilestone, ActivationMilestone, CheckpointMilestone]
instance Operation Milestone MilestoneCapabilities where
  type Context Milestone = CapabilityContext MilestoneCapabilities Milestone
  type Outcome Milestone = IO Int32
  data DSL Milestone where
    ValidateMilestones :: Context Milestone => DSL Milestone
  interpret operation request = withOperation @Milestone operation $ \value -> case request of
    ValidateMilestones -> Just (either id (const 1) <$> runExceptT (validateMilestones value))


newtype BmmScan = BmmScan NativeBytes
data BmmScanPlan = BmmScanPlan Word8 Word64 (Maybe RS.Hash) deriving (Eq, Show)
data BmmCommitment = BmmCommitment RS.Hash Word32 deriving (Eq, Show)

bmmScanEffect :: BmmScan -> Word32 -> Word64 -> B.ByteString -> ExceptT Int32 IO ()
bmmScanEffect (BmmScan native) step index input = do
  reply <- liftIO (native step index input)
  unless (B.null reply) (throwE (-1))
bmmScanFail :: BmmScan -> String -> ExceptT Int32 IO a
bmmScanFail value message = bmmScanEffect value 6 0 (C.pack message) >> throwE 0

class BmmScanAdmission op where
  prepareBmmScan :: op -> ExceptT Int32 IO BmmScanPlan
class BmmCollection op where
  collectBmmCommitment :: op -> BmmScanPlan -> ExceptT Int32 IO BmmCommitment
class BmmPublication op where
  publishBmmCommitment :: op -> BmmScanPlan -> BmmCommitment -> ExceptT Int32 IO ()

instance BmmScanAdmission BmmScan where
  prepareBmmScan value@(BmmScan native) = do
    (slot,match,expected) <- readReplayReply native 1 0 ((,,) <$> G.getInt32le <*> RS.flag <*> RS.hash)
    unless (slot >= 0 && slot <= 255) (bmmScanFail value "BIP301 M7 sidechain slot is outside the uint8 range")
    count <- readReplayReply native 2 0 (RS.optional G.getWord64le) >>=
      maybe (bmmScanFail value "raw BMM block has no coinbase transaction") pure
    pure (BmmScanPlan (fromIntegral slot) count (if match then Just expected else Nothing))
instance BmmCollection BmmScan where
  collectBmmCommitment value@(BmmScan native) (BmmScanPlan slot count _) = scan 0 (0 :: Word64) Nothing
    where
      scan index !matches selected
        | index == count = case (matches,selected) of
            (1,Just commitment) -> pure commitment
            _ -> bmmScanFail value ("BMM successor has " ++
              (if matches == 0 then "no enforcer-recognized M7 for" else show matches ++ " enforcer-recognized M7 outputs for") ++
              " sidechain slot " ++ show slot)
        | otherwise = do
            payload <- coinbasePush (\step -> native (step+2)) index
            case payload >>= recognized of
              Just commitment -> scan (index+1) (matches+1) (Just (BmmCommitment commitment (fromIntegral index)))
              Nothing -> scan (index+1) matches selected
      recognized bytes
        | B.length bytes /= 37 = Nothing
        | otherwise = case validate (Message (B.unpack bytes)) of
            (5,_,_) | B.index bytes 4 == slot -> Just (B.pack (commitmentBytes 0 (B.unpack bytes)))
            _ -> Nothing
instance BmmPublication BmmScan where
  publishBmmCommitment value (BmmScanPlan _ _ expected) (BmmCommitment hash index) = do
    -- Match callers historically observe the output index even on hash mismatch.
    bmmScanEffect value 5 (fromIntegral index) hash
    case expected of
      Just wanted | hash /= wanted -> bmmScanFail value
        ("BMM successor commits to critical hash " ++ hashHex hash ++ ", expected " ++ hashHex wanted)
      _ -> pure ()

scanBmmCommitment :: (BmmScanAdmission op, BmmCollection op, BmmPublication op)
  => op -> ExceptT Int32 IO BmmCommitment
scanBmmCommitment value = do
  plan <- prepareBmmScan value
  commitment <- collectBmmCommitment value plan
  publishBmmCommitment value plan commitment
  pure commitment

type BmmScanCapabilities = '[BmmScanAdmission, BmmCollection, BmmPublication]
instance Operation BmmScan BmmScanCapabilities where
  type Context BmmScan = CapabilityContext BmmScanCapabilities BmmScan
  type Outcome BmmScan = IO Int32
  data DSL BmmScan where
    ScanBmmCommitment :: Context BmmScan => DSL BmmScan
  interpret operation request = withOperation @BmmScan operation $ \value -> case request of
    ScanBmmCommitment -> Just (either id (const 1) <$> runExceptT (scanBmmCommitment value))


exceedsLane :: Word64 -> Word64 -> Word64 -> Bool
exceedsLane lane current additional = current>lane || additional>lane-current

treasurySlot :: Word32 -> Word32 -> Int32
treasurySlot script opcode
  | (opcode == 0xb4 || opcode == 0xb7) && script .&. 0xff == opcode
    && (script `shiftR` 8) .&. 0xff == 1 && script `shiftR` 24 == 0x51 =
      fromIntegral ((script `shiftR` 16) .&. 0xff)
  | otherwise = -1

data Distance = Distance Word32 Word32
instance Validation Distance where
  type ValidationResult Distance = Int64
  validate (Distance upper lower)
    | lower <= upper = fromIntegral upper - fromIntegral lower
    | otherwise = -1

-- Entry workflows return zero to continue and preserve any nonzero failure code.
repeatEntries :: Word64 -> IO Int32 -> IO Int32
repeatEntries 0 _ = pure 0
repeatEntries count entry = entry >>= \result ->
  if result == 0 then repeatEntries (count-1) entry else pure result

completeEntry :: (Eq status, Num status) => IO status -> IO Int32
completeEntry = fmap (\result -> if result == 1 then 0 else -1)

data CoinbaseMessages = CoinbaseMessages Word64 (Word32 -> Word64 -> IO Int64)
instance Validation CoinbaseMessages where
  type ValidationResult CoinbaseMessages = IO Int32
  validate (CoinbaseMessages count action) = visit 0 False
    where
      visit index sawM4
        | index == count = pure 0
        | otherwise = (if index `mod` 256 == 0 then action 1 index else pure 1) >>= \ready ->
            if ready /= 1 then pure (-1)
            else action 2 index >>= \kind -> case kind of
              0 -> finish index sawM4 []
              1 -> unique index sawM4 3 1 []
              2 -> unique index sawM4 4 2 []
              3 -> finish index sawM4 [7]
              4 | sawM4 -> pure 3
                | otherwise -> finish index True [7]
              5 -> unique index sawM4 5 4 [6]
              _ -> pure (-1)
      unique index sawM4 step rejection before = action step index >>= \inserted -> case inserted of
        0 -> pure rejection
        1 -> finish index sawM4 (before ++ [7])
        _ -> pure (-1)
      finish index sawM4 effects = runRequiredEffects (\step -> action step index) (effects ++ [8]) >>= \result ->
        if result == 0 then visit (index+1) sawM4 else pure result

-- One entry owns the ordered message traversal. Native callbacks select the
-- current message and perform effects; nested rule calls stay in Haskell.
data MessageWorkflow = MessageWorkflow Word64 Word32 Word64 NativeBytes
instance Validation MessageWorkflow where
  type ValidationResult MessageWorkflow = IO Int32
  validate (MessageWorkflow count height settings native) = either id id <$> runExceptT (visit 0)
    where
      parameter offset = fromIntegral ((settings `shiftR` offset) `mod` 65536)
      scalar base step value = do
        result <- native (base+step) value B.empty
        if B.length result /= 8 then ioError (userError "invalid replay scalar reply")
        else pure (fromIntegral (B.foldr (\byte rest -> fromIntegral byte+256*rest) (0 :: Word64) result))
      effect step = do
        reply <- liftIO (native step 0 B.empty)
        unless (B.null reply) (throwE (-1))
      checked group failure action = do
        result <- liftIO action
        when (result < 0) (throwE failure)
        when (result /= 0) (throwE (group+result))
      visit index
        | index == count = effect 40 >> pure 0
        | otherwise = do
            message <- liftIO (native 0 index B.empty)
            when (B.length message < 2 || odd (B.length message)) (throwE (-1))
            let kind = B.index message 0
                flags = fromIntegral (B.index message 1)
                votes = [fromIntegral (B.index message i) + 256*fromIntegral (B.index message (i+1))
                  | i <- [2,4..B.length message-2]]
            case kind of
              1 -> effect 2
              2 -> do
                effect 3
                checked 0x100 (-2) (validate (M2Proposal height
                  (parameter 0) (parameter 16) (parameter 32) (parameter 48) (scalar 10)))
              3 -> checked 0x200 (-3) (validate (M3Proposal (scalar 20)))
              5 -> pure () -- M7 was authenticated before replay mutations.
              _ -> checked 0x300 (-4) (validate (M4Workflow flags votes
                (\step slot input -> native (30+step) slot input)))
            visit (index+1)

data M4Repeat = M4Repeat Word32 (Word32 -> IO Int64)
instance Validation M4Repeat where
  type ValidationResult M4Repeat = IO Int32
  validate (M4Repeat upvote action)
    | upvote > 1 = pure (-1)
    | otherwise = action 1 >>= \active -> case active of
        0 -> pure 1
        1 -> action (if upvote == 1 then 2 else 3) >>= \result -> case result of
          0 | upvote == 1 -> pure 2
          1 -> completeEntry (action 4)
          2 -> pure 0
          _ -> pure (-1)
        _ -> pure (-1)

-- One entry owns mode selection, ordered slots, vote arithmetic and publication.
-- Reads are lazy: abstentions never load pending withdrawals, and a bad slot
-- prevents reads/publication for all later slots.
data M4Workflow = M4Workflow Word32 [Word16] NativeBytes
instance Validation M4Workflow where
  type ValidationResult M4Workflow = IO Int32
  validate (M4Workflow flags explicit native) = either id (const 0) <$> runExceptT (do
    when (flags > 15) (throwE (-1))
    unless (testBit flags 0) (throwE 1)
    when (testBit flags 1) (throwE 2)
    entries <- readBytes 0 0
    when (B.length entries > 514 || odd (B.length entries) ||
      any ((>1) . B.index entries) [1,3..B.length entries-1]) (throwE (-1))
    let active = B.unpack (validate (ActiveSlots entries))
    if testBit flags 2 then do
      unless (length explicit == length active) (throwE 3)
      forM_ (zip active explicit) $ \(slot,vote) -> when (vote /= 65535) $ do
        (hashes,votes) <- pending slot
        case validate (ExplicitVote vote hashes votes) of
          (0,_) -> pure ()
          (1,updated) -> publish slot 1 (B.take 32 (B.drop (32*fromIntegral vote) hashes)) updated
          (2,updated) -> publish slot 0 (B.replicate 32 0) updated
          _ -> throwE 4
    else if testBit flags 3 then forM_ active $ \slot -> do
      (hashes,votes) <- pending slot
      case validate (LeadingVote hashes votes) of
        Nothing -> pure ()
        Just (leader,updated) -> publish slot 1 (B.take 32 (B.drop (32*fromIntegral leader) hashes)) updated
    else do
      previous <- readBytes 1 0
      unless (B.length previous `mod` 34 == 0 && B.length previous <= 256*34) (throwE (-1))
      forM_ [0,34..B.length previous-1] $ \offset -> do
        let slot = B.index previous offset
            upvote = B.index previous (offset+1)
            target = B.take 32 (B.drop (offset+2) previous)
        when (upvote > 1) (throwE (-1))
        (hashes,votes) <- pending slot
        case validate (if upvote == 1 then VoteUpdate target hashes votes else VoteAlarm votes) of
          Nothing -> throwE 6
          Just (False,_) -> pure ()
          Just (True,updated) -> publish slot upvote target updated)
    where
      readBytes step slot = liftIO (native step (fromIntegral slot) B.empty)
      pending slot = do
        bytes <- readBytes 2 slot
        when (B.null bytes || B.head bytes > 1) (throwE (-1))
        when (B.head bytes == 0) (throwE 5)
        let rows = B.tail bytes
        unless (B.length rows `mod` 34 == 0) (throwE (-1))
        pure (B.concat [B.take 32 (B.drop i rows) | i <- [0,34..B.length rows-1]],
          [fromIntegral (B.index rows (i+32)) + 256*fromIntegral (B.index rows (i+33)) | i <- [0,34..B.length rows-1]])
      publish slot kind target votes = do
        result <- liftIO (native 3 (fromIntegral slot) (B.cons kind target <>
          B.pack (concatMap (\v -> [fromIntegral v,fromIntegral (v `div` 256)]) votes)))
        unless (B.null result) (throwE (-1))

data M8Acceptance = M8Acceptance Word64 (Word32 -> Word64 -> IO Int64)
instance Validation M8Acceptance where
  type ValidationResult M8Acceptance = IO Int32
  validate (M8Acceptance count action) = visit 1
    where
      visit index
        | index >= count = pure 0
        | otherwise = action 1 index >>= \ready ->
            if ready /= 1 then pure (-1)
            else action 2 index >>= \recognized -> case recognized of
              0 -> visit (index+1)
              1 -> action 3 index >>= \accepted -> case accepted of
                0 -> pure 1
                1 -> action 4 index >>= \current -> case current of
                  0 -> pure 2
                  1 -> visit (index+1)
                  _ -> pure (-1)
                _ -> pure (-1)
              _ -> pure (-1)

data M2Proposal = M2Proposal Word32 Word32 Word32 Word32 Word32 (Word32 -> Word64 -> IO Int64)
instance Validation M2Proposal where
  type ValidationResult M2Proposal = IO Int32
  validate (M2Proposal height unusedAge unusedThreshold usedAge usedThreshold action)
    | any (>65535) [unusedAge,unusedThreshold,usedAge,usedThreshold] = pure (-1)
    | otherwise = action 1 0 >>= \proposed ->
        if proposed == -2 then pure 0
        else if proposed < 0 || proposed > 0xffffffff then pure (-1)
        else if proposed == fromIntegral height then pure 0
        else if proposed > fromIntegral height then pure 1
        else action 2 0 >>= \votes ->
          if votes < 0 || votes > 0xffffffff then pure (-1)
          else let incremented = (votes+1) `mod` 0x100000000 in
            action 3 (fromIntegral incremented) >>= \used ->
              if used /= 0 && used /= 1 then pure (-1)
              else let (age,threshold) = if used == 1 then (usedAge,usedThreshold) else (unusedAge,unusedThreshold)
                   in if incremented <= fromIntegral threshold || fromIntegral height-proposed > fromIntegral age
                      then pure 0
                      else action 4 0 >>= \published ->
                        if published /= 1 then pure (-1)
                        else action 5 0 >>= \flags ->
                          if flags < 0 || flags > 7 then pure (-1)
                          else if not (testBit flags 0) then pure 0
                          else if testBit flags 1 && not (testBit flags 2) then pure 2
                          else if not (testBit flags 1) && testBit flags 2
                               then completeEntry (action 6 0) else pure 0

data M4Mode = M4Mode Word32 Word64 (Word32 -> IO Int64)
instance Validation M4Mode where
  type ValidationResult M4Mode = IO Int32
  validate (M4Mode flags votes action)
    | flags > 15 = pure (-1)
    | not (testBit flags 0) = pure 4
    | testBit flags 1 = pure 5
    | otherwise = action 1 >>= \active -> pure $
        if active < 0 then -1
        else if testBit flags 2 then if toInteger votes == toInteger active then 1 else 6
        else if testBit flags 3 then 2 else 3

newtype M3Proposal = M3Proposal (Word32 -> Word64 -> IO Int64)
instance Validation M3Proposal where
  type ValidationResult M3Proposal = IO Int32
  validate (M3Proposal action) = action 1 0 >>= \active -> case active of
    0 -> pure 1
    1 -> action 2 0 >>= \count ->
      if count < 0 then pure (-1)
      else scanParentEntries (fromIntegral count) (const (pure (1 :: Int32))) (\index ->
        action 3 index >>= \matched -> pure $ case matched of 0 -> 0; 1 -> 2; _ -> -1) >>= \result ->
          if result /= 0 then pure result else runRequiredEffects (uncurry action) [(4,0),(5,0)]
    _ -> pure (-1)

data M6Id = M6Id Word64 Word64 Int64 Int64 Word32 (Word32 -> Word64 -> IO Int64)
instance Validation M6Id where
  type ValidationResult M6Id = IO Int32
  validate (M6Id outputs inputs previous maximumValue hasSlot action)
    | maximumValue < 0 || hasSlot > 1 = pure (-1)
    | otherwise = action 1 0 >>= \cleared ->
        if cleared /= 1 then pure (-1)
        else if outputs == 0 then pure 1
        else action 2 0 >>= \parsed -> case parsed of
          0 -> pure 2
          1 | inputs /= 1 -> pure 3
            | not (amount previous) -> pure 4
            | otherwise -> action 3 0 >>= \replacement ->
                if not (amount replacement) then pure 4 else total replacement 1 0
          _ -> pure (-1)
    where
      amount value = value >= 0 && value <= maximumValue
      total replacement index payout
        | index == outputs =
            if replacement > previous || payout > previous-replacement then pure 6
            else runRequiredEffects (uncurry action)
              ([(5,fromIntegral (previous-replacement-payout))] ++ [(6,0) | hasSlot == 1])
        | otherwise = action 4 index >>= \value ->
            if not (amount value) || value > maximumValue-payout then pure 5
            else total replacement (index+1) (payout+value)

newtype ActiveSlots = ActiveSlots B.ByteString
instance Validation ActiveSlots where
  type ValidationResult ActiveSlots = B.ByteString
  validate (ActiveSlots entries)
    | B.length entries > 514 || odd (B.length entries) || any ((>1) . snd) rows = error "invalid active slot entries"
    | otherwise = B.pack (sort [slot | (slot,active) <- rows, active == 1])
    where rows = [(B.index entries i,B.index entries (i+1)) | i <- [0,2..B.length entries-1]]

data BlockPublish = BlockPublish Word32 (Word32 -> IO Int32)
instance Validation BlockPublish where
  type ValidationResult BlockPublish = IO Int32
  validate (BlockPublish flags action)
    | flags > 15 = pure (-1)
    | testBit flags 0 && not (testBit flags 1) = pure 1
    | otherwise = runRequiredEffects action ([1 | testBit flags 2] ++ [2 | testBit flags 3] ++ [3])

data PruneSlots = PruneSlots Word64 (Word32 -> IO Int64)
instance Validation PruneSlots where
  type ValidationResult PruneSlots = IO Int32
  validate (PruneSlots count action) = repeatEntries count $
    action 1 >>= \occupied ->
      if occupied < 0 || occupied > 63 then pure (-1)
      else completeEntry (action (if occupied == 0 then 2 else 3))

data M6Withdrawal = M6Withdrawal Word64 Word64 Word64 Word32 Word32 (Word32 -> IO Int64)
instance Validation M6Withdrawal where
  type ValidationResult M6Withdrawal = IO Int32
  validate (M6Withdrawal decreases changes inputs threshold single action)
    | single > 1 = pure (-1)
    | decreases /= 1 || changes /= 1 = pure 1
    | otherwise = action 1 >>= \output ->
        if output < 0 || output > 0xffffffff then pure (-1)
        else if inputs /= 1 || output /= 0 then pure 2
        else check 2 3 $ check 3 4 $ check 4 5 $
          action 5 >>= \votes ->
            if votes < 0 || votes > 65535 then pure (-1)
            else if votes <= fromIntegral threshold then pure 6
            else action 6 >>= \configured -> case configured of
              0 -> publish False
              1 | single == 0 -> publish True
                | otherwise -> action 7 >>= \applied -> case applied of
                    0 -> publish True
                    1 -> pure 7
                    _ -> pure (-1)
              _ -> pure (-1)
    where
      check stage rejected next = action stage >>= \result -> case result of
        0 -> pure rejected
        1 -> next
        _ -> pure (-1)
      publish configured = runRequiredEffects action ([8 | configured] ++ [9..12])

data M5Deposit = M5Deposit Int64 Int64 Word64 Word64 Word64 Word32 (Word32 -> Word64 -> IO Int64)
instance Validation M5Deposit where
  type ValidationResult M5Deposit = IO Int32
  validate (M5Deposit old new maximumValue output outputs flags action)
    | flags > 7 = pure (-1)
    | toInteger output + 1 >= toInteger outputs = pure 1
    | otherwise = action 1 0 >>= \parsed -> case parsed of
        0 -> pure 1
        1 | delta <= 0 || delta > toInteger maximumValue || delta > toInteger (maxBound :: Int64) -> pure 2
          | otherwise -> effect 2 (effect 3 publish)
        _ -> pure (-1)
    where
      delta = toInteger new - toInteger old
      effect stage next = action stage 0 >>= \result -> if result == 1 then next else pure (-1)
      publish
        | flags /= 7 = pure 0
        | otherwise = action 4 0 >>= \size ->
            if size < 0 then pure (-1)
            else if not (nonEmptyBounded size (fromIntegral depositAddressLimit)) then pure 0
            else completeEntry (action 5 (fromInteger delta))

data CtipChanges = CtipChanges Word64 (Word32 -> IO Int64)
instance Validation CtipChanges where
  type ValidationResult CtipChanges = IO Int32
  validate (CtipChanges count action) = repeatEntries count $
    action 1 >>= \present -> case present of
      0 -> action 4 >>= \cleared -> if cleared == 1 then prepare 0 else pure (-1)
      1 -> action 2 >>= \spent -> case spent of
        0 -> pure 1
        1 -> action 3 >>= prepare
        _ -> pure (-1)
      _ -> pure (-1)
    where
      prepare old = action 5 >>= \new ->
        if new == old then pure 2
        else if (fromIntegral new :: Word64) < fromIntegral old
          then action 6 >>= \counted -> if counted == 1 then publish else pure (-1)
          else publish
      publish = completeEntry (action 7)

-- One treasury transaction, with native effects scoped to its caller. Groups
-- 1-7 reuse the existing rules; group 9 retains native M6 serialization/hash.
-- A positive result identifies the rejecting group and its unchanged error.
data TransactionReplay = TransactionReplay Word64 Word64 Word64 Word64 Word32 Word32
  (Word32 -> Word64 -> IO Int64)
instance Validation TransactionReplay where
  type ValidationResult TransactionReplay = IO Int32
  validate (TransactionReplay slots inputs outputs maximumValue threshold single native) =
    either id (const 0) <$> runExceptT (do
      when (maximumValue > fromIntegral (maxBound :: Int64) || single > 1) (throwE (-1))
      check 1 =<< liftIO (validate (CtipOwners slots maximumValue (one 1)))
      check 2 =<< liftIO (validate (CtipSpends inputs (\step index -> narrow <$> call 2 step index)))
      check 3 =<< liftIO (validate (CtipOutputs outputs maximumValue (call 3)))
      owners <- count 0
      check 4 =<< liftIO (validate (CtipReplacements owners (fmap narrow . one 4)))
      replacements <- count 1
      check 5 =<< liftIO (validate (CtipChanges replacements (one 5)))
      changes <- count 2
      when (changes /= 0) $ do
        decreases <- count 3
        if decreases /= 0 then do
          idResult <- liftIO (newIORef 0)
          result <- liftIO (validate (M6Withdrawal decreases changes inputs threshold single $ \step ->
            if step /= 2 then one 6 step else do
              previous <- native 0 4
              status <- validate (M6Id outputs inputs previous (fromIntegral maximumValue) 1 (call 9))
              writeIORef idResult status
              pure (if status == 0 then 1 else 0)))
          check 9 =<< liftIO (readIORef idResult)
          check 6 result
        else deposits changes 0)
    where
      call group step = native (group * 100 + step)
      one group step = call group step 0
      narrow value
        | value < fromIntegral (minBound :: Int32) || value > fromIntegral (maxBound :: Int32) = -1
        | otherwise = fromIntegral value
      check group result
        | result < 0 = throwE (-1)
        | result == 0 = pure ()
        | otherwise = throwE (group * 256 + result)
      count field = do
        value <- liftIO (native 0 field)
        when (value < 0) (throwE (-1))
        pure (fromIntegral value)
      deposits remaining index = when (remaining /= 0) $ do
        selected <- liftIO (native 800 index)
        unless (selected == 1) (throwE (-1))
        old <- liftIO (native 0 4)
        new <- liftIO (native 0 5)
        output <- count 6
        flags <- liftIO (native 0 7)
        when (flags < 0 || flags > 7) (throwE (-1))
        check 7 =<< liftIO (validate (M5Deposit old new maximumValue output outputs
          (fromIntegral flags) (call 7)))
        deposits (remaining-1) (index+1)

data CtipReplacements = CtipReplacements Word64 (Word32 -> IO Int32)
instance Validation CtipReplacements where
  type ValidationResult CtipReplacements = IO Int32
  validate (CtipReplacements count action) = repeatEntries count $
    action 1 >>= \spent -> case spent of
      0 -> completeEntry (action 3)
      1 -> action 2 >>= \replacement -> case replacement of
        0 -> pure 1
        1 -> completeEntry (action 3)
        _ -> pure (-1)
      _ -> pure (-1)

data CtipSpends = CtipSpends Word64 (Word32 -> Word64 -> IO Int32)
instance Validation CtipSpends where
  type ValidationResult CtipSpends = IO Int32
  validate (CtipSpends count action) = scanParentEntries count (action 1) $ \index ->
    action 2 index >>= \owned -> case owned of
      0 -> pure 0
      1 -> action 3 index >>= \spent -> pure $ case spent of
        1 -> 0
        2 -> 1
        _ -> -1
      _ -> pure (-1)

scanParentEntries :: Integral ready => Word64 -> (Word64 -> IO ready) -> (Word64 -> IO Int32) -> IO Int32
scanParentEntries count deadline visit = go 0
  where
    go index
      | index == count = pure 0
      | index `mod` 256 == 0 = deadline index >>= \ready ->
          if ready == 1 then inspect index else pure (-1)
      | otherwise = inspect index
    inspect index = visit index >>= \result ->
      if result == 0 then go (index+1) else pure result

data CtipOutputs = CtipOutputs Word64 Word64 (Word32 -> Word64 -> IO Int64)
instance Validation CtipOutputs where
  type ValidationResult CtipOutputs = IO Int32
  validate (CtipOutputs count maximumValue action)
    | count > 0xffffffff = pure (-1)
    | otherwise = scanParentEntries count (action 1) $ \index ->
        action 2 index >>= \treasury -> case treasury of
          0 -> pure 0
          1 -> action 3 index >>= \active -> case active of
            0 -> pure 0
            1 -> action 4 index >>= \value ->
              if validate (Record 7 0 value 0 maximumValue) /= 1 then pure 1
              else action 5 index >>= \inserted -> pure $ case inserted of
                0 -> 2
                1 -> 0
                _ -> -1
            _ -> pure (-1)
          _ -> pure (-1)

data CtipOwners = CtipOwners Word64 Word64 (Word32 -> IO Int64)
instance Validation CtipOwners where
  type ValidationResult CtipOwners = IO Int32
  validate (CtipOwners count maximumValue action) = repeatEntries count $
    action 1 >>= \present ->
      if present /= 0 && present /= 1 then pure (-1)
      else action 2 >>= \value ->
        if validate (Record 18 (fromIntegral present) value 0 maximumValue) /= 1 then pure 1
        else if present == 0 then completeEntry (action 4)
        else action 3 >>= \inserted -> case inserted of
          0 -> pure 2
          1 -> completeEntry (action 4)
          _ -> pure (-1)

data ExpireProposals = ExpireProposals Word64 Word32 Word32 Word32 (Word32 -> IO Int64)
instance Validation ExpireProposals where
  type ValidationResult ExpireProposals = IO Int32
  validate (ExpireProposals count height threshold maxAge action) = expireEntries count height action $ \age ->
    proposalExpiry threshold maxAge age <$> action 2

proposalExpiry :: Word32 -> Word32 -> Int64 -> Int64 -> Either Int32 Bool
proposalExpiry threshold maxAge age votes
  | votes < 0 || votes > 65535 = Left (-1)
  | votes > age = Left 2
  | otherwise = case validate (Record 19 threshold votes (fromIntegral age) (fromIntegral maxAge)) of
      0 -> Right False
      1 -> Right True
      _ -> Left (-1)

data ExpireWithdrawals = ExpireWithdrawals Word64 Word32 Word32 (Word32 -> IO Int64)
instance Validation ExpireWithdrawals where
  type ValidationResult ExpireWithdrawals = IO Int32
  validate (ExpireWithdrawals count height maxAge action) =
    expireEntries count height action (pure . Right . (> fromIntegral maxAge))

expireEntries :: Word64 -> Word32 -> (Word32 -> IO Int64) -> (Int64 -> IO (Either Int32 Bool)) -> IO Int32
expireEntries count height action decide = repeatEntries count $
  action 1 >>= \proposed ->
    if proposed < 0 || proposed > 0xffffffff then pure (-1)
    else if proposed > fromIntegral height then pure 1
    else decide (fromIntegral height-proposed) >>= \decision -> case decision of
      Left code -> pure code
      Right expired -> completeEntry (action (if expired then 3 else 4))

-- Snapshots contain only total native getters. Publish the valid prefix before
-- reporting a later rejection, preserving the original in-place replay effects.
data Maintenance = Maintenance Word32 Word64 Word32 Word32 NativeBytes
class ProposalMaintenance op where
  expireProposalSlots :: op -> ExceptT Int32 IO [Word8]
class WithdrawalMaintenance op where
  expireWithdrawalSlots :: op -> [Word8] -> ExceptT Int32 IO ()
class ReplayPublication op where
  pruneReplaySlots :: op -> ExceptT Int32 IO ()
  publishReplayBlock :: op -> ExceptT Int32 IO ()

replayWord :: B.ByteString -> Word64
replayWord = B.foldr (\byte rest -> fromIntegral byte + 256*rest) 0

maintenanceEffect :: NativeBytes -> Word32 -> Word64 -> B.ByteString -> ExceptT Int32 IO ()
maintenanceEffect native step slot payload = do
  reply <- liftIO (native step slot payload)
  unless (B.null reply) (throwE (-1))

expirySnapshot :: Word32 -> Int -> (Int64 -> B.ByteString -> Either Int32 Bool)
  -> B.ByteString -> (Int32, [Word64])
expirySnapshot height width decide rows
  | width < 4 || B.length rows `mod` width /= 0 = (-1,[])
  | otherwise = visit 0 [] rows
  where
    visit !index selected remaining
      | B.null remaining = (0,reverse selected)
      | proposed > fromIntegral height = (1,reverse selected)
      | otherwise = case decide (fromIntegral height-fromIntegral proposed) (B.take width remaining) of
          Left code -> (code,reverse selected)
          Right expired -> visit (index+1) (if expired then index:selected else selected) (B.drop width remaining)
      where proposed = replayWord (B.take 4 remaining)

applyExpiry :: NativeBytes -> Word32 -> Word8 -> (Int32 -> Int32) -> (Int32,[Word64]) -> ExceptT Int32 IO ()
applyExpiry native step slot diagnostic (status,indices) = do
  unless (null indices) $ maintenanceEffect native step (fromIntegral slot)
    (B.pack [fromIntegral (index `shiftR` shift) | index <- indices, shift <- [0,8..56]])
  when (status /= 0) (throwE (if status < 0 then status else diagnostic status))

instance ProposalMaintenance Maintenance where
  expireProposalSlots (Maintenance height settings _ _ native) = do
    slots <- liftIO (native 0 0 B.empty)
    when (B.length slots > 514 || odd (B.length slots) ||
      any ((>1) . B.index slots) [1,3..B.length slots-1]) (throwE (-1))
    forM_ [0,2..B.length slots-1] $ \offset -> do
      let slot = B.index slots offset
          window = if B.index slots (offset+1) == 1 then 32 else 0
          parameter bit = fromIntegral ((settings `shiftR` bit) `mod` 65536)
      rows <- liftIO (native 1 (fromIntegral slot) B.empty)
      applyExpiry native 2 slot (\code -> code*256+fromIntegral slot) $
        expirySnapshot height 8 (\age row -> proposalExpiry (parameter (window+16)) (parameter window)
          age (fromIntegral (replayWord (B.drop 4 row)))) rows
    pure (B.unpack (validate (ActiveSlots slots)))

instance WithdrawalMaintenance Maintenance where
  expireWithdrawalSlots (Maintenance height _ maxAge _ native) slots = forM_ slots $ \slot -> do
    rows <- liftIO (native 3 (fromIntegral slot) B.empty)
    applyExpiry native 4 slot (const 0x300) $
      expirySnapshot height 4 (\age _ -> Right (age > fromIntegral maxAge)) rows

instance ReplayPublication Maintenance where
  pruneReplaySlots (Maintenance _ _ _ _ native) = do
    slots <- liftIO (native 10 0 B.empty)
    when (B.length slots > 512 || odd (B.length slots) ||
      any ((>63) . B.index slots) [1,3..B.length slots-1]) (throwE (-1))
    let retired = B.pack [B.index slots i | i <- [0,2..B.length slots-1], B.index slots (i+1) == 0]
    unless (B.null retired) (maintenanceEffect native 11 0 retired)
  publishReplayBlock (Maintenance _ _ _ flags native) = do
    let deadline = validate (CommandFlow (storeMaximum 25)
          (\phase result -> validate (StoreFlow 25 phase result)) (\step -> do
            reply <- native (20+step) 0 B.empty
            pure $ case B.unpack reply of
              [0] -> 0
              [1] -> 1
              _ -> -1))
        action 3 = do
          result <- deadline
          pure (if result == 0 then 1 else -1)
        action step = do
          reply <- native (11+step) 0 B.empty
          pure (if B.null reply then 1 else -1)
    status <- liftIO $ validate (BlockPublish flags action)
    when (status /= 0) (throwE status)

maintainBeforeTreasury :: (ProposalMaintenance op, WithdrawalMaintenance op) => op -> ExceptT Int32 IO ()
maintainBeforeTreasury value = expireProposalSlots value >>= expireWithdrawalSlots value
maintainAfterTreasury :: ReplayPublication op => op -> ExceptT Int32 IO ()
maintainAfterTreasury value = pruneReplaySlots value >> publishReplayBlock value

type MaintenanceCapabilities = '[ProposalMaintenance, WithdrawalMaintenance, ReplayPublication]
instance Operation Maintenance MaintenanceCapabilities where
  type Context Maintenance = CapabilityContext MaintenanceCapabilities Maintenance
  type Outcome Maintenance = IO Int32
  data DSL Maintenance where
    BeforeTreasury :: Context Maintenance => DSL Maintenance
    AfterTreasury :: Context Maintenance => DSL Maintenance
  interpret operation request = withOperation @Maintenance operation $ \value ->
    let run = fmap (either id (const 0)) . runExceptT
    in case request of
      BeforeTreasury -> Just (run (maintainBeforeTreasury value))
      AfterTreasury -> Just (run (maintainAfterTreasury value))

newtype VoteLeader = VoteLeader [Word16]
instance Validation VoteLeader where
  type ValidationResult VoteLeader = Int64
  validate (VoteLeader []) = -1
  validate (VoteLeader (first:rest)) =
    if best < maxBound && best >= second && best-second >= 50 then selected else -1
    where
      (selected,best,second) = foldl' rank (0,first,0) (zip [1..] rest)
      rank (!index,!highest,!runner) (candidate,value)
        | value > highest = (candidate,value,max runner highest)
        | otherwise = (index,highest,max runner value)

data LeadingVote = LeadingVote B.ByteString [Word16]
instance Validation LeadingVote where
  type ValidationResult LeadingVote = Maybe (Int64,[Word16])
  validate (LeadingVote hashes votes)
    | B.length hashes /= 32 * length votes = error "invalid leading vote shape"
    | leader < 0 = Nothing
    | otherwise = validate (VoteUpdate target hashes votes) >>= \result -> case result of
        (False,_) -> Nothing
        (True,updated) -> Just (leader,updated)
    where
      leader = validate (VoteLeader votes)
      target = B.take 32 (B.drop (32 * fromIntegral leader) hashes)

data ExplicitVoteFlow = ExplicitVoteFlow Word32 Word32
instance Validation ExplicitVoteFlow where
  type ValidationResult ExplicitVoteFlow = Int32
  validate (ExplicitVoteFlow 2 result) = case result of
    0 -> -11
    1 -> 3
    2 -> 4
    3 -> 5
    _ -> -1
  validate (ExplicitVoteFlow phase result) = transition phase result
    [(1,(2,-11)),(3,(-1,-11)),(4,(-1,-11)),(5,(-10,-1))]

data ExplicitVote = ExplicitVote Word16 B.ByteString [Word16]
instance Validation ExplicitVote where
  type ValidationResult ExplicitVote = (Int32,[Word16])
  validate (ExplicitVote vote hashes votes)
    | vote == 65535 = (0,votes)
    | B.length hashes /= 32 * length votes = error "invalid explicit vote shape"
    | vote == 65534 = finish 2 (VoteAlarm votes)
    | fromIntegral vote >= length votes = (3,votes)
    | otherwise = finish 1 (VoteUpdate (B.take 32 (B.drop (32 * fromIntegral vote) hashes)) hashes votes)
    where
      finish code operation = case validate operation of
        Just (True,updated) -> (code,updated)
        Just (False,_) -> (0,votes)
        Nothing -> error "explicit vote target missing"

data VoteUpdate = VoteUpdate B.ByteString B.ByteString [Word16] | VoteAlarm [Word16]
decrementVote :: Word16 -> Word16
decrementVote value = if value == 0 then 0 else value-1
instance Validation VoteUpdate where
  type ValidationResult VoteUpdate = Maybe (Bool, [Word16])
  validate (VoteAlarm votes) = Just (any (>0) votes,map decrementVote votes)
  validate (VoteUpdate target hashes votes)
    | B.length target /= 32 || B.length hashes /= 32 * length votes = error "invalid vote update shape"
    | otherwise = do
        selected <- findIndex (==target) [B.take 32 (B.drop (32*i) hashes) | i <- [0..length votes-1]]
        pure $ if votes !! selected == maxBound then (False,votes) else
          (True,[if i == selected then value+1 else decrementVote value
                 | (i,value) <- zip [0..] votes])

-- Entries contain the next action for false/true; effects reject false with -1.
transition :: Word32 -> Word32 -> [(Word32,(Int32,Int32))] -> Int32
transition 0 _ _ = 1
transition phase result table = case lookup phase table of
  Just (no,yes) | result==0 -> no
                | result==1 -> yes
  _ -> -1

-- Ordered checks with distinct terminal error actions; never run the second
-- check after the first rejects, or accept an error callback that returns.
data RequiredPairFlow = RequiredPairFlow Word32 Word32
instance Validation RequiredPairFlow where
  type ValidationResult RequiredPairFlow = Int32
  validate (RequiredPairFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-1)),(3,(4,-11)),(4,(-1,-1))]

-- Ordered by the ReplayStoreFlow ABI; invalid kinds never authorize actions.
storeMaximum :: Word32 -> Int32
storeMaximum kind
  | retiredStoreKind kind = -1
  | kind == 183 = -1 -- Superseded by the typed BMM submission workflow.
  | kind >= 198 && kind <= 200 = -1 -- Retired LWK dialog.
  | kind >= fromIntegral (length storeBounds) = -1
  | otherwise = storeBounds !! fromIntegral kind

-- Keep native workflow numbers stable, but never dispatch removed feature slots.
retiredStoreKind :: Word32 -> Bool
retiredStoreKind kind = kind `elem`
  ([129..131] ++ [149..176] ++ [188,189,209,212,217,246,247] ++ [249..255] ++
   [259,261,262,263,266,269,271,272,274,276,289,290,292,293,295,323,326])

storeBounds :: [Int32]
storeBounds =
  [ 9,9,9,9,9,9,9,9,9,9,9,66,38,14,14,26,24,18
  , 49,28,16,33,9,9,9,9,9,9,44,15,9,9,9,9,9,9
  , 9,9,9,9,9,9,9,14,18,26,33,28,9,9,9,9,17,9
  , 9,9,14,9,12,9,18,15,9,9,9,9,11,19,22,9,9,12
  , 9,16,10,9,9,9,9,9,10,9,13,15,25,9,9,27,9,9
  , 9,9,9,43,23,31,18,18,9,9,9,9,19,9,9,9,9,9
  , 9,9,9,9,9,9,23,9,12,11,9,24,9,17,11,23,9,9,22,9,9,11,8,7,14,-1,16,18,13,5,7,11,10,6,5,12,21,10,7,10,14,12,11,8,17,29,19
  ] ++ [10,17,17,11,8,6,12,74,45,15,64,10,15,15,13,9,12,12,10,12,7,5,10,8,4,26,11,18,46,10,6,4,4,13,22,11,21,5,2,11,14,26,12,15,5,11,4,8,14,8,19,7,13,12,12]
  ++ [7,7,14,13,8,5,3,11,16,19,8,6,4,4,6,7,4,7,6,7,5,3,5,10,3,4,9,4,3,5,7,4,2,2,4,6,8,8,5,17,16,11,6,6,30,20,5,5,4,11,14,9]

  ++ [10,8,7,2,7,8,14,3,8,17,28,3,2,4,13,14,-1,7,5,7,19,22,13,8,13,11,12,6,6,8,5,3,4,7,14,7,11,4,14,23,2,16,5,3,7,3,5,2]
  ++ [6,6,22,31,11,8,7,6,3,4,9,3,6,6,8,5,6,8,8]

data MempoolSweepPreflight = MempoolSweepPreflight Word32 Word32
instance Validation MempoolSweepPreflight where
  type ValidationResult MempoolSweepPreflight = Int32
  validate (MempoolSweepPreflight phase result) = transition phase result
    [(1,(-11,2)),(2,(4,3)),(3,(4,5)),(4,(-10,-1)),(5,(6,-12)),(6,(-1,-11))]

data ParentRpcHostFlow = ParentRpcHostFlow Word32 Word32
instance Validation ParentRpcHostFlow where
  type ValidationResult ParentRpcHostFlow = Int32
  validate (ParentRpcHostFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-10,3)),(3,(5,4)),(4,(-10,-11)),(5,(-10,6)),(6,(-10,-11))]

data StartupParentStage = ParentLoad | ParentVerify | ParentServe deriving (Eq, Show)
data StartupParentFlow = StartupParentFlow StartupParentStage Word32 Word32
instance Validation StartupParentFlow where
  type ValidationResult StartupParentFlow = Int32
  validate (StartupParentFlow _ 0 _) = 7
  validate (StartupParentFlow stage phase result) = transition phase result $
    [(7,(-10,if stage == ParentVerify then 1 else 8))] ++
    [(8,(-1,1)) | stage /= ParentVerify] ++ case stage of
      ParentLoad -> [(1,(-11,2)),(2,(-11,-10))]
      ParentVerify -> [(1,(-11,5)),(5,(-13,-10))]
      ParentServe -> [(1,(-11,2)),(2,(-12,3)),(3,(4,5)),(4,(-1,5)),(5,(-13,6)),(6,(-13,-10))]

data StartupBundleFlow = StartupBundleFlow Word32 Word32
instance Validation StartupBundleFlow where
  type ValidationResult StartupBundleFlow = Int32
  validate (StartupBundleFlow phase result) = transition phase result
    [(1,(6,2)),(2,(4,3)),(3,(-1,4)),(4,(-1,5)),(5,(-1,-10)),(6,(-1,-10))]

data BlockValidationStage = ContextualHeader | ContextualOutputs | CandidateSelfCheck
  | BranchChoice | StartupReconcile | FinalBmm | BmmFailure deriving (Eq, Show)
data BlockValidationFlow = BlockValidationFlow BlockValidationStage Word32 Word32
instance Validation BlockValidationFlow where
  type ValidationResult BlockValidationFlow = Int32
  validate (BlockValidationFlow stage phase result) = transition phase result $ case stage of
    ContextualHeader -> [(1,(-11,2)),(2,(-10,3)),(3,(-10,-11))]
    ContextualOutputs -> [(1,(3,2)),(2,(-10,3)),(3,(-11,4)),(4,(-10,-11))]
    CandidateSelfCheck -> [(1,(-10,2)),(2,(-10,3)),(3,(-10,4)),(4,(-1,5)),
      (5,(6,9)),(6,(9,7)),(7,(-10,8)),(8,(-1,9)),(9,(-10,-11))]
    BranchChoice -> [(1,(3,2)),(2,(-10,-11)),(3,(-10,-11))]
    StartupReconcile -> [(1,(2,3)),(2,(-10,-1)),(3,(-1,4)),(4,(-10,5)),(5,(-11,6)),(6,(-10,-1))]
    FinalBmm -> [(1,(-11,2)),(2,(-11,3)),(3,(4,5)),(4,(-10,-1)),
      (5,(7,6)),(6,(-10,-1)),(7,(8,-11)),(8,(-1,-12))]
    BmmFailure -> [(1,(3,2)),(2,(-10,-1)),(3,(5,4)),(4,(-10,-1)),(5,(-10,-1))]

data ConnectionStateFlow = ConnectionStateFlow Word32 Word32
instance Validation ConnectionStateFlow where
  type ValidationResult ConnectionStateFlow = Int32
  validate (ConnectionStateFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(4,3)),(3,(-1,4)),(4,(7,5)),(5,(7,6)),(6,(-1,7)),
     (7,(8,9)),(8,(-10,-10)),(9,(10,11)),(10,(-10,-10)),(11,(12,-11)),(12,(-10,-10))]

data ConnectionAnchorFlow = ConnectionAnchorFlow Word32 Word32
instance Validation ConnectionAnchorFlow where
  type ValidationResult ConnectionAnchorFlow = Int32
  validate (ConnectionAnchorFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-10,-10)),(3,(4,6)),(4,(5,-11)),(5,(-10,-10)),
     (6,(7,8)),(7,(-10,-10)),(8,(10,9)),(9,(-10,-10)),(10,(-11,11)),(11,(-10,-10))]

data EphemeralHeaderFlow = EphemeralHeaderFlow Word32 Word32
instance Validation EphemeralHeaderFlow where
  type ValidationResult EphemeralHeaderFlow = Int32
  validate (EphemeralHeaderFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-10,-10)),(3,(5,4)),(4,(-10,-10)),(5,(-10,6)),
     (6,(7,8)),(7,(-10,-10)),(8,(10,9)),(9,(-10,-10)),(10,(11,12)),
     (11,(-10,-10)),(12,(-10,13)),(13,(-1,-11))]

data RecoveryAncestorFlow = RecoveryAncestorFlow Word32 Word32
instance Validation RecoveryAncestorFlow where
  type ValidationResult RecoveryAncestorFlow = Int32
  validate (RecoveryAncestorFlow phase result) = transition phase result
    [(1,(5,2)),(2,(5,3)),(3,(5,4)),(4,(-1,1)),
     (5,(9,6)),(6,(9,7)),(7,(9,8)),(8,(-1,5)),
     (9,(13,10)),(10,(13,11)),(11,(13,12)),(12,(-1,9)),(13,(-10,-11))]

data RecoveryAdmissionFlow = RecoveryAdmissionFlow Word32 Word32
instance Validation RecoveryAdmissionFlow where
  type ValidationResult RecoveryAdmissionFlow = Int32
  validate (RecoveryAdmissionFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(-10,3)),(3,(6,4)),(4,(5,8)),
     (5,(6,8)),(6,(7,8)),(7,(-11,8)),(8,(-10,-10))]

data BranchReplayFlow = BranchReplayFlow Word32 Word32
instance Validation BranchReplayFlow where
  type ValidationResult BranchReplayFlow = Int32
  validate (BranchReplayFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-11,3)),(3,(4,5)),(4,(-10,-10)),
     (5,(11,6)),(6,(7,10)),(7,(8,10)),(8,(9,10)),(9,(11,10)),
     (10,(-1,-11)),(11,(-1,12)),(12,(22,13)),(13,(-1,14)),
     (14,(21,15)),(15,(16,10)),(16,(20,17)),(17,(18,10)),
     (18,(19,10)),(19,(20,10)),(20,(-1,14)),(21,(-1,12)),(22,(-1,1))]

data ParentRequestFlow = ParentRequestFlow Word32 Word32
instance Validation ParentRequestFlow where
  type ValidationResult ParentRequestFlow = Int32
  validate (ParentRequestFlow phase result) = transition phase result
    [(1,(-1,2)),(2,(4,3)),(3,(-1,4)),(4,(-10,5)),(5,(-10,-11))]

data RequiredFactsFlow = RequiredFactsFlow Word32 Word32 Word32
instance Validation RequiredFactsFlow where
  type ValidationResult RequiredFactsFlow = Int32
  validate (RequiredFactsFlow count phase result)
    | count == 0 || count > 254 = -1
    | otherwise = transition phase result
        ([(step,(fromIntegral count+1,if step==count then -11 else fromIntegral step+1)) | step <- [1..count]] ++
         [(count+1,(-10,-10))])

data ConfiguredSlotFlow = ConfiguredSlotFlow Word32 Word32
instance Validation ConfiguredSlotFlow where
  type ValidationResult ConfiguredSlotFlow = Int32
  validate (ConfiguredSlotFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-10,-10)),(3,(4,-11)),(4,(-10,-10))]

data IndexDerivedFlow = IndexDerivedFlow Word32 Word32
instance Validation IndexDerivedFlow where
  type ValidationResult IndexDerivedFlow = Int32
  validate (IndexDerivedFlow phase result) = transition phase result
    [(1,(5,2)),(2,(3,4)),(3,(-1,-11)),(4,(-1,5)),(5,(10,6)),
     (6,(8,7)),(7,(8,9)),(8,(-1,-11)),(9,(-1,-10)),(10,(12,11)),
     (11,(-1,-10)),(12,(-10,13)),(13,(-1,-11))]

data IndexContinuityFlow = IndexContinuityFlow Word32 Word32
instance Validation IndexContinuityFlow where
  type ValidationResult IndexContinuityFlow = Int32
  validate (IndexContinuityFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(3,6)),(3,(5,4)),(4,(5,12)),(5,(-1,-11)),
     (6,(9,7)),(7,(9,8)),(8,(12,10)),(9,(-1,-11)),(10,(11,12)),
     (11,(-1,-11)),(12,(-1,1))]

commitmentBytes :: Word32 -> [Word8] -> [Word8]
commitmentBytes 0 bytes | length bytes == 37 = reverse (drop 5 bytes)
commitmentBytes 1 bytes | length bytes == 32 = bytes
commitmentBytes 2 bytes = case validate (Message bytes) of
  (5,_,_) -> commitmentBytes 0 bytes
  (kind,_,_) | kind == 2 || kind == 3 -> commitmentBytes 1 (drop 5 bytes)
  _ -> error "parent message has no commitment hash"
commitmentBytes _ _ = error "invalid commitment payload"

newtype Message = Message [Word8]
instance Validation Message where
  type ValidationResult Message = (Word32, Word32, [Word16])
  validate (Message bytes) = case splitAt 4 bytes of
    (tag, mode:body)
      | tag == [0xd5,0xe0,0xc4,0xaf] -> (1,0,[])
      | tag == [0xd6,0xe1,0xc5,0xdf], length body == 32 -> (2,0,[])
      | tag == [0xd4,0x5a,0xa9,0x43], length body == 32 -> (3,0,[])
      | tag == [0xd7,0x7d,0x17,0x76] -> case mode of
          0 | null body -> (4,1,[])
          1 -> (4,2,map oneByte body)
          2 | even (length body) ->
            let votes = pairs body
            in (4,if all (<= 253) votes then 0 else 2,votes)
          3 | null body -> (4,3,[])
          _ -> none
      | tag == [0xd1,0x61,0x73,0x68], length body == 32 -> (5,0,[])
    _ -> none
    where
      none = (0,0,[])
      oneByte 255 = 65535
      oneByte 254 = 65534
      oneByte n = fromIntegral n
      pairs (lo:hi:rest) = (fromIntegral lo + 256 * fromIntegral hi) : pairs rest
      pairs _ = []

-- Native projections contain no serialized state or pointers.
nonEmptyBounded :: (Ord a, Num a) => a -> a -> Bool
nonEmptyBounded size limit = size > 0 && size <= limit

currentEpoch :: Word64 -> Word64 -> Bool
currentEpoch authenticated observed = authenticated /= 0 && authenticated == observed

data Record = Record Word32 Word32 Int64 Word64 Word64 | TipFlow Word32 Word32
            | StoreFlow Word32 Word32 Word32
instance Validation Record where
  type ValidationResult Record = Int32
  validate (StoreFlow kind phase result) = case (kind,phase) of
    _ | retiredStoreKind kind -> -1
    (328,_) -> transition phase result
      [(1,(-10,4)),(4,(-10,5)),(5,(-10,7)),(7,(-10,8)),(8,(-10,-11))]
    (327,_) -> transition phase result
      [(1,(-10,2)),(2,(-10,3)),(3,(-10,4)),(4,(-10,5)),(5,(-10,7)),(7,(-10,8)),(8,(-10,-11))]
    (227,_) -> transition phase result
      [(1,(-10,2)),(2,(-1,3)),(3,(-11,4)),(4,(-12,5)),(5,(7,6)),(6,(-1,7)),(7,(-1,1))]
    (226,_) -> transition phase result
      [(1,(-11,2)),(2,(4,3)),(3,(-12,4)),(4,(-13,-10))]
    (225,_) -> transition phase result
      [(1,(-11,2)),(2,(-1,3)),(3,(6,4)),(4,(-12,5)),(5,(-1,-10)),(6,(-13,7)),(7,(-13,-10))]
    (224,_) -> transition phase result
      [(1,(-10,2)),(2,(-11,3)),(3,(-12,4)),(4,(-12,5)),(5,(-13,6)),(6,(-1,-10))]
    (223,_) -> transition phase result
      [(1,(-10,2)),(2,(-1,3)),(3,(-12,4)),(4,(-12,-11))]
    -- Both key spaces stop at a neighboring prefix; only claims read a value.
    (k,_) | k == 221 || k == 222 -> transition phase result
      ([(1,(-10,2)),(2,(-12,3)),(3,(-10,4))] ++
       [(p,(-13,if p == end then -11 else fromIntegral p+1)) | p <- [4..end]])
      where end = if k == 221 then 6 else 4
    -- Snapshot metadata: reject an unfinished transition before reading its tip.
    -- Outcomes 1/2 distinguish transition/metadata rejection; zero accepts.
    (220,_) -> transition phase result
      [(1,(4,2)),(2,(-11,3)),(3,(-11,4)),(4,(-12,5)),
       (5,(-12,6)),(6,(-12,7)),(7,(-12,8)),(8,(-12,-10))]
    (219,_) -> transition phase result
      [(1,(16,2)),(2,(16,3)),(3,(7,4)),(4,(16,7)),
       (7,(-1,8)),(8,(18,9)),(9,(-1,10)),(10,(-1,11)),(11,(19,12)),
       (12,(19,13)),(13,(19,14)),(14,(19,15)),(15,(19,-10))]
    (k,0) | k<=128 -> if k==61 then 2 else 1
    (0,1) -> branch 2 (-11)
    (0,2) -> branch (-10) (terminal 2 3)
    (1,1) -> case result of 0 -> 3; 1 -> 2; 2 -> -12; _ -> -1
    (1,2) -> branch (terminal 2 4) (-10)
    (1,3) -> branch 5 (terminal 3 6)
    (1,5) -> branch 7 (terminal 3 6)
    (1,7) -> case result of 0 -> 8; 1 -> terminal 2 9; 2 -> -12; _ -> -1
    (1,8) -> branch (-11) (terminal 2 9)
    (2,1) -> branch 2 3
    (2,2) -> branch 3 (-1)
    (2,3) -> branch (-10) (terminal 2 4)
    (3,1) -> branch (terminal 1 3) (terminal 0 2)
    (4,1) -> branch 2 (-1)
    (4,2) -> branch 3 (-1)
    (4,3) -> branch (committing 4) (-1)
    (4,4) -> branch (-11) (terminal 0 5)
    (5,1) -> branch (-10) (terminal 2 3)
    (6,1) -> branch 2 (terminal 2 3)
    (6,2) -> branch (-10) (terminal 2 3)
    (k,1) | k >= 7 && k <= 10 -> case result of 0 -> 2; 1 -> -11; 2 -> -12; _ -> -1
    (k,p) | k >= 7 && k <= 10 && p >= 2 && p <= lastCheck k ->
      branch (if p == lastCheck k then -10 else fromIntegral p + 1) (terminal 2 6)
    (12,p) | p >= 1 && p <= 37 -> next (if p == 37 then terminal 1 38 else fromIntegral p + 1)
    (13,p) | p >= 1 && p <= 13 -> next (if p == 13 then terminal 1 14 else fromIntegral p + 1)
    (14,p) | p >= 1 && p <= 14 -> branch (if p == 14 then -11 else fromIntegral p + 1) (-10)
    (15,1) -> branch 2 (-10)
    (15,p) | p >= 2 && p <= 18 -> branch (if p == 18 then 20 else fromIntegral p + 1) (terminal 2 19)
    (15,20) -> branch 21 (-12)
    (15,21) -> branch 23 (terminal 2 22)
    (15,23) -> branch 24 (-12)
    (15,24) -> branch 25 (terminal 2 26)
    (15,25) -> branch (-11) (terminal 2 26)
    (16,1) -> branch 3 2
    (16,2) -> next 3
    (16,3) -> next 4
    (16,4) -> branch (-10) 5
    (16,5) -> branch (-10) 6
    (16,6) -> case result of 1 -> 7; 0 -> 22; 2 -> 22; 3 -> 22; _ -> -1
    (16,7) -> next 8
    (16,8) -> next 9
    (16,9) -> branch 10 18
    (16,10) -> branch 11 12
    (16,11) -> branch 21 12
    (16,12) -> branch 13 16
    (16,13) -> branch 21 14
    (16,14) -> branch 21 15
    (16,15) -> branch 21 16
    (16,16) -> branch 17 18
    (16,17) -> branch 21 18
    (16,18) -> next 19
    (16,19) -> next (terminal 1 20)
    (16,21) -> next 22
    (16,22) -> branch (terminal 0 24) 23
    (16,23) -> branch (terminal 0 24) (-10)
    (39,p) | p == 1 || p == 2 -> branch (if p == 1 then 2 else terminal 1 4) (terminal 0 3)
    (40,p) | p == 1 || p == 2 -> next (fromIntegral p + 1)
    (40,3) -> branch (terminal 0 4) (-11)
    (41,1) -> next 2
    (41,2) -> branch 3 (terminal 0 4)
    (41,3) -> branch (-11) (-10)
    (42,p) | p >= 1 && p <= 4 -> next (fromIntegral p + 1)
    (42,5) -> branch (-11) (-10)
    (43,4) -> branch 5 12
    (43,7) -> branch 8 (-10)
    (43,11) -> next 4
    (43,13) -> next (terminal 1 14)
    (43,p) | p >= 1 && p <= 12 -> next (fromIntegral p + 1)
    (44,1) -> branch 3 (terminal 0 2)
    (44,3) -> branch 4 (terminal 0 5)
    (44,4) -> branch 6 (terminal 0 5)
    (44,p) | p >= 6 && p <= 8 -> next (fromIntegral p + 1)
    (44,p) | p == 9 || p == 10 -> branch (fromIntegral p + 1) (terminal 0 12)
    (44,11) -> branch 13 (terminal 0 12)
    (44,p) | p == 13 || p == 14 -> next (fromIntegral p + 1)
    (44,p) | p >= 15 && p <= 17 -> branch (terminal 0 18) (if p == 17 then -11 else fromIntegral p + 1)
    (45,1) -> branch 2 7
    (45,2) -> branch 3 (terminal 0 5)
    (45,3) -> branch 4 (terminal 0 5)
    (45,4) -> branch (-11) (terminal 0 6)
    (45,7) -> branch 8 (terminal 0 9)
    (45,8) -> branch 10 (terminal 0 9)
    (45,p) | p >= 10 && p <= 13 -> next (fromIntegral p + 1)
    (45,14) -> branch 16 (terminal 0 15)
    (45,16) -> next 17
    (45,p) | p >= 17 && p <= 21 -> branch (if p == 21 then 23 else fromIntegral p + 1) (terminal 0 22)
    (45,23) -> next 24
    (45,24) -> branch (terminal 0 26) 25
    (45,25) -> branch (-11) (terminal 0 26)
    (46,1) -> branch 3 (terminal 0 2)
    (46,6) -> branch 7 (terminal 0 8)
    (46,7) -> branch 9 (terminal 0 8)
    (46,p) | p == 13 || p == 21 || p == 23 || p == 25 -> branch (fromIntegral p + 1) (-10)
    (46,17) -> branch 18 (terminal 0 19)
    (46,18) -> branch 20 (terminal 0 19)
    (46,32) -> branch (terminal 0 33) (-11)
    (46,p) | p >= 3 && p <= 31 && p /= 8 && p /= 19 -> next (fromIntegral p + 1)
    (47,1) -> branch (terminal 0 4) 2
    (47,2) -> branch 3 (terminal 0 4)
    (47,3) -> branch 5 (terminal 0 4)
    (47,5) -> next 6
    (47,6) -> branch 7 14
    (47,7) -> branch 8 9
    (47,8) -> next 9
    (47,9) -> branch 10 (terminal 0 11)
    (47,10) -> branch (terminal 0 11) 12
    (47,12) -> next 6
    (47,p) | p >= 14 && p <= 17 -> next (fromIntegral p + 1)
    (47,18) -> branch 19 24
    (47,19) -> branch 20 21
    (47,p) | p == 20 || p == 21 -> next (fromIntegral p + 1)
    (47,22) -> next 18
    (47,24) -> next 25
    (47,25) -> branch (terminal 0 27) 26
    (47,26) -> branch (terminal 0 27) (terminal 1 28)
    (48,1) -> next 2
    (48,2) -> branch (-11) 3
    (48,3) -> next 4
    (48,4) -> branch (terminal 1 5) (-10)
    (49,1) -> branch 2 (-10)
    (49,2) -> branch 3 (-10)
    (49,3) -> branch (-11) (terminal 0 4)
    (50,1) -> next 2
    (50,2) -> branch 3 (terminal 1 4)
    (50,3) -> branch (terminal 1 4) (-11)
    (51,p) | p >= 1 && p <= 3 -> next (fromIntegral p + 1)
    (51,4) -> branch 5 (terminal 1 7)
    (51,5) -> next 6
    (51,6) -> next 4
    (52,1) -> branch (-11) 2
    (52,2) -> branch (terminal 0 4) 3
    (52,3) -> branch 5 (terminal 0 4)
    (52,5) -> branch 7 (terminal 0 6)
    (52,p) | p >= 7 && p <= 9 -> next (fromIntegral p + 1)
    (52,10) -> branch 12 11
    (52,11) -> branch 12 (-10)
    (52,p) | p >= 12 && p <= 15 -> next (fromIntegral p + 1)
    (52,16) -> branch (-11) (terminal 0 17)
    (53,1) -> next 2
    (53,2) -> branch 4 (terminal 0 3)
    (53,4) -> branch 5 (-10)
    (53,5) -> next 6
    (53,6) -> branch 8 (terminal 0 7)
    (53,8) -> branch (-11) (-10)
    (54,1) -> branch 3 (terminal 0 2)
    (54,3) -> branch (terminal 0 4) (-11)
    (55,1) -> branch 2 (-10)
    (55,2) -> next 3
    (55,3) -> branch (-10) (-11)
    (56,1) -> branch 2 6
    (56,2) -> next 3
    (56,3) -> branch (terminal 1 5) (terminal 0 4)
    (56,6) -> branch 7 (terminal 1 14)
    (56,7) -> next 8
    (56,8) -> branch 10 (terminal 0 9)
    (56,10) -> next 11
    (56,11) -> branch 12 (terminal 1 5)
    (56,12) -> branch 13 (terminal 1 5)
    (56,13) -> next (terminal 1 5)
    (57,1) -> branch 2 4
    (57,2) -> branch 5 (terminal 0 3)
    (57,4) -> next 5
    (57,5) -> branch (terminal 1 6) (-10)
    (58,1) -> branch 2 6
    (58,p) | p >= 2 && p <= 4 -> branch (terminal 0 5) (if p == 4 then 6 else fromIntegral p + 1)
    (58,6) -> branch 7 10
    (58,7) -> branch (terminal 0 9) 8
    (58,8) -> branch (terminal 0 9) 10
    (58,10) -> next 11
    (58,11) -> branch (terminal 1 12) (-10)
    (59,1) -> branch (terminal 0 2) 3
    (59,3) -> branch 4 7
    (59,4) -> branch 5 (terminal 0 6)
    (59,5) -> branch (terminal 1 9) (terminal 0 6)
    (59,7) -> branch (terminal 1 9) (terminal 0 8)
    (60,1) -> branch 2 (-10)
    (60,2) -> branch 3 11
    (60,3) -> branch 4 5
    (60,p) | p >= 4 && p <= 8 -> branch (fromIntegral p + 1) 11
    (60,9) -> branch (-11) (-10)
    (60,11) -> branch (-10) 12
    (60,12) -> branch 13 (-10)
    (60,13) -> branch (-10) 14
    (60,14) -> branch 15 (-10)
    (60,p) | p == 15 || p == 16 -> branch (-10) (fromIntegral p + 1)
    (60,17) -> branch 18 (-10)
    (60,18) -> branch (-11) (-10)
    (61,2) -> branch 4 (terminal 0 3)
    (61,4) -> next 5
    (61,p) | p >= 5 && p <= 7 -> branch (if p == 7 then 9 else fromIntegral p + 1) (terminal 0 8)
    (61,p) | p == 9 || p == 10 -> branch (if p == 10 then 12 else 10) (terminal 0 11)
    (61,12) -> next 13
    (61,13) -> branch 15 (terminal 0 14)
    (61,15) -> branch (-11) (-10)
    (62,_) -> transition phase result
      [(1,(3,2)),(2,(3,-10)),(3,(-11,4)),(4,(-11,-10))]
    (63,_) -> transition phase result
      [(1,(2,-10)),(2,(4,3)),(3,(4,-10)),(4,(-10,-11))]
    (64,_) -> transition phase result
      [(1,(2,3)),(2,(-10,3)),(3,(-11,4)),(4,(-10,-11))]
    (65,_) -> transition phase result
      [(1,(2,-10)),(2,(-10,3)),(3,(-10,-11))]
    (66,1) -> branch 2 (-11)
    (66,2) -> next 3
    (66,3) -> branch 4 11
    (66,4) -> next 5
    (66,5) -> branch 6 (terminal 0 7)
    (66,6) -> branch 8 (terminal 0 7)
    (66,8) -> branch 11 (terminal 0 9)
    (66,11) -> next 1
    (67,1) -> branch 2 (-11)
    (67,2) -> branch 3 4
    (67,3) -> next 4
    (67,4) -> next 5
    (67,5) -> case result of 0 -> 19; 1 -> 6; 2 -> 8; 3 -> 18; 4 -> 10; 5 -> 14; _ -> -1
    (67,6) -> branch 18 (terminal 0 7)
    (67,8) -> branch 18 (terminal 0 9)
    (67,10) -> branch (terminal 0 11) 12
    (67,12) -> next 18
    (67,14) -> branch 16 (terminal 0 15)
    (67,16) -> next 18
    (67,18) -> next 19
    (67,19) -> next 1
    (68,1) -> branch 2 (-11)
    (68,2) -> branch (-11) 3
    (68,3) -> branch (terminal 0 4) 5
    (68,5) -> next 6
    (68,6) -> next 7
    (68,7) -> branch 8 9
    (68,p) | p == 8 || p == 9 -> next 10
    (68,10) -> branch 11 (-11)
    (68,11) -> branch 12 (-11)
    (68,12) -> next 13
    (68,13) -> next 14
    (68,14) -> branch 15 (-11)
    (68,15) -> branch 16 18
    (68,16) -> branch (terminal 0 17) 18
    (68,18) -> branch 19 (-11)
    (68,19) -> branch 20 (-11)
    (68,20) -> next 21
    (68,21) -> next (terminal 1 22)
    (69,1) -> branch (terminal 1 2) (-11)
    (70,1) -> branch (terminal 0 2) 3
    (70,3) -> next 4
    (70,4) -> branch 5 8
    (70,5) -> branch (terminal 0 6) 7
    (70,7) -> next 4
    (70,8) -> next (terminal 1 9)
    (71,1) -> branch 2 (terminal 0 4)
    (71,2) -> branch 5 3
    (71,3) -> next 1
    (71,5) -> branch 6 (-11)
    (71,6) -> next 7
    (71,7) -> branch 8 (terminal 1 12)
    (71,8) -> branch 9 11
    (71,9) -> branch 10 11
    (71,10) -> next 11
    (71,11) -> next 7
    (72,1) -> branch 2 5
    (72,2) -> branch 3 4
    (72,3) -> next 4
    (72,4) -> next 1
    (72,5) -> branch (terminal 1 6) (-10)
    (73,1) -> branch (-11) 2
    (73,2) -> branch 3 9
    (73,3) -> branch 4 6
    (73,4) -> branch 5 7
    (73,5) -> next 7
    (73,6) -> branch 10 8
    (73,7) -> next 8
    (73,8) -> next 2
    (73,9) -> next 11
    (73,10) -> next 8
    (73,11) -> branch 12 (-11)
    (73,12) -> branch 13 (-11)
    (73,13) -> branch 14 (-11)
    (73,14) -> next 15
    (73,15) -> branch (terminal 1 16) (-10)
    (74,1) -> branch (-11) 2
    (74,2) -> next 3
    (74,3) -> branch 4 5
    (74,p) | p == 4 || p == 8 -> branch (terminal 1 10) (-11)
    (74,5) -> branch 6 (terminal 0 7)
    (74,6) -> branch 8 (-10)
    (75,1) -> branch (terminal 0 2) 3
    (75,3) -> next 4
    (75,4) -> branch 5 6
    (75,5) -> branch 7 (-10)
    (75,p) | p == 6 || p == 7 -> branch (terminal 1 8) (-11)
    (k,1) | k == 76 || k == 77 -> branch 2 (-11)
    (k,2) | k == 76 || k == 77 -> branch (if k == 76 then 4 else 6) (terminal 0 3)
    (76,4) -> branch 6 (terminal 0 5)
    (k,6) | k == 76 || k == 77 -> branch 7 8
    (k,p) | (k == 76 || k == 77) && (p == 7 || p == 8) -> next 1
    (k,1) | k == 78 || k == 79 -> branch 2 (-11)
    (78,2) -> next 3
    (78,3) -> branch 5 (terminal 0 4)
    (78,5) -> branch 6 8
    (78,6) -> branch 8 (terminal 0 7)
    (79,2) -> branch 3 4
    (79,3) -> next 4
    (79,4) -> next 5
    (79,5) -> branch 6 8
    (79,6) -> branch (terminal 0 7) 8
    (k,8) | k == 78 || k == 79 -> next 1
    (80,1) -> branch 2 (-11)
    (80,2) -> branch 3 4
    (80,3) -> next 4
    (80,4) -> branch 5 10
    (80,5) -> branch 6 10
    (80,6) -> branch 8 (terminal 0 7)
    (80,8) -> branch 10 (terminal 0 9)
    (80,10) -> next 1
    (81,1) -> branch 2 (-11)
    (81,2) -> branch 3 5
    (81,3) -> branch 5 (terminal 0 4)
    (81,5) -> next 1
    (82,1) -> branch 2 (-11)
    (82,2) -> next 3
    (82,3) -> branch 4 7
    (82,4) -> branch 6 (terminal 0 5)
    (82,p) | p == 6 || p == 7 -> next 8
    (82,8) -> next 9
    (82,9) -> branch (terminal 0 10) 11
    (82,11) -> branch 12 13
    (82,12) -> next 13
    (82,13) -> next 1
    (83,1) -> branch 2 (terminal 0 3)
    (83,2) -> branch 4 (terminal 0 3)
    (83,4) -> next 5
    (83,5) -> branch 6 (terminal 0 7)
    (83,6) -> branch 8 (terminal 0 7)
    (83,8) -> next 9
    (83,9) -> next 10
    (83,p) | p >= 10 && p <= 14 -> branch (if p == 14 then terminal 1 15 else fromIntegral p + 1) (-11)
    (84,1) -> branch 2 (terminal 0 3)
    (84,2) -> branch 4 (terminal 0 3)
    (84,4) -> next 5
    (84,5) -> branch 6 (terminal 0 7)
    (84,6) -> branch 8 (terminal 0 7)
    (84,8) -> branch 9 (-10)
    (84,9) -> branch 11 (terminal 0 10)
    (84,11) -> next 12
    (84,12) -> branch 14 (terminal 0 13)
    (84,14) -> branch 16 (terminal 0 15)
    (84,16) -> branch 17 20
    (84,17) -> branch 18 20
    (84,18) -> branch (terminal 0 19) 20
    (84,20) -> branch 21 22
    (84,p) | p >= 21 && p <= 24 -> next (if p == 24 then terminal 1 25 else fromIntegral p + 1)
    (85,1) -> branch 2 (-11)
    (85,p) | p >= 2 && p <= 7 -> branch (fromIntegral p + 1) 9
    (85,p) | p == 8 || p == 9 -> next 1
    (86,1) -> branch 2 4
    (86,2) -> branch (terminal 0 3) 4
    (86,4) -> branch 5 6
    (86,5) -> next 6
    (86,6) -> branch 7 (terminal 1 8)
    (86,7) -> next (terminal 1 8)
    (87,1) -> next 2
    (87,2) -> branch (terminal 0 3) 4
    (87,4) -> branch 6 (terminal 0 5)
    (87,6) -> branch 8 (terminal 0 7)
    (87,8) -> branch 9 (terminal 0 10)
    (87,9) -> branch 11 (terminal 0 10)
    (87,11) -> branch 12 17
    (87,12) -> next 13
    (87,13) -> branch 14 (terminal 0 15)
    (87,14) -> branch 16 (terminal 0 15)
    (87,16) -> next 11
    (87,17) -> branch 18 (terminal 0 19)
    (87,18) -> branch 20 (terminal 0 19)
    (87,p) | p >= 20 && p <= 25 -> next (fromIntegral p + 1)
    (87,26) -> branch (terminal 1 27) (-11)
    (88,1) -> branch 3 (terminal 0 2)
    (88,3) -> branch (terminal 0 4) 5
    (88,5) -> next 6
    (88,6) -> branch 7 9
    (88,7) -> branch (-11) (terminal 0 8)
    (88,9) -> branch (-12) (-13)
    (89,1) -> branch 2 3
    (89,2) -> next 3
    (89,3) -> branch 4 (terminal 1 7)
    (89,4) -> branch 5 6
    (89,5) -> next 6
    (89,6) -> next 3
    (90,1) -> branch 2 (-11)
    (90,2) -> branch 3 (-10)
    (90,3) -> next 1
    (91,1) -> next 2
    (91,2) -> case result of
      1 -> 3
      2 -> 4
      3 -> 5
      5 -> -11
      _ -> 6
    (91,p) | p >= 3 && p <= 6 -> branch (-11) (-10)
    (92,1) -> branch 2 (-10)
    (92,2) -> next 3
    (92,p) | p >= 3 && p <= 6 -> branch (fromIntegral p + 1) (-10)
    (92,7) -> next 8
    (92,8) -> next (terminal 1 9)
    (93,1) -> branch 2 4
    (93,2) -> branch 5 (terminal 2 3)
    (93,4) -> next 5
    (93,5) -> branch 7 (terminal 2 6)
    (93,7) -> next 8
    (93,8) -> branch 9 13
    (93,9) -> branch 10 13
    (93,10) -> next 11
    (93,11) -> branch 13 (terminal 2 12)
    (93,13) -> branch 14 (-12)
    (93,14) -> branch 16 (terminal 2 15)
    (93,16) -> next 17
    (93,17) -> branch 18 21
    (93,18) -> next 19
    (93,19) -> next (terminal 2 20)
    (93,21) -> branch 22 23
    (93,p) | p == 22 || p == 26 || p == 28 || p == 31 -> next 43
    (93,p) | p >= 23 && p <= 25 -> branch (if p == 25 then 27 else fromIntegral p + 1) 26
    (93,27) -> branch 29 28
    (93,29) -> next 30
    (93,30) -> branch 32 31
    (93,32) -> branch 33 (terminal 0 39)
    (93,33) -> branch 34 (-12)
    (93,34) -> branch 37 35
    (93,35) -> next (terminal 2 36)
    (93,37) -> branch 38 (terminal 0 39)
    (93,38) -> next (terminal 0 39)
    (93,43) -> branch (-11) (-12)
    (94,1) -> branch 2 3
    (94,2) -> next 3
    (94,3) -> branch 4 5
    (94,4) -> branch 8 5
    (94,5) -> branch 6 (-11)
    (94,6) -> branch (terminal 1 7) (-11)
    (94,8) -> next 9
    (94,p) | p >= 9 && p <= 22 -> branch (if p == 22 then -10 else fromIntegral p + 1) (terminal 2 23)
    (95,1) -> branch 2 (-10)
    (95,2) -> branch 3 (-10)
    (95,3) -> next 4
    (95,4) -> branch 5 (-10)
    (95,5) -> branch 7 (terminal 0 6)
    (95,7) -> next 8
    (95,8) -> branch 11 9
    (95,9) -> branch 10 16
    (95,10) -> branch 11 16
    (95,p) | p >= 11 && p <= 13 -> next (fromIntegral p + 1)
    (95,14) -> branch 15 (-10)
    (95,15) -> branch (terminal 0 30) (-10)
    (95,16) -> branch 17 23
    (95,17) -> branch 18 (-10)
    (95,18) -> branch 23 19
    (95,19) -> next 20
    (95,20) -> next 21
    (95,21) -> next (terminal 0 22)
    (95,23) -> branch 24 (-10)
    (95,24) -> branch 29 25
    (95,25) -> next 26
    (95,26) -> next 27
    (95,27) -> next (terminal 0 28)
    (95,29) -> branch (terminal 1 31) (-11)
    (k,1) | k == 96 || k == 97 -> branch 3 (terminal 0 2)
    (k,3) | k == 96 || k == 97 -> branch (if k == 96 then 4 else 15) (-10)
    (96,4) -> branch 5 (-10)
    (96,p) | p >= 5 && p <= 9 -> branch (if p == 9 then 11 else fromIntegral p + 1) (terminal 0 10)
    (96,p) | p == 11 || p == 12 -> branch (fromIntegral p + 1) (-10)
    (96,p) | p == 13 || p == 14 -> branch (fromIntegral p + 1) (terminal 0 17)
    (k,15) | k == 96 || k == 97 -> branch 16 (terminal 0 17)
    (k,16) | k == 96 || k == 97 -> branch (terminal 1 18) (terminal 0 17)
    (98,1) -> next 2
    (98,2) -> branch 3 (-10)
    (98,3) -> branch 4 (-10)
    (98,4) -> branch (-11) (-10)
    (99,1) -> next 2
    (99,2) -> branch (terminal 1 3) (-10)
    (100,1) -> next 2
    (100,2) -> branch 3 4
    (100,3) -> next 4
    (100,4) -> branch 5 (-13)
    (100,5) -> branch 7 (terminal 1 6)
    (100,7) -> branch (-10) (-11)
    (101,1) -> branch (-11) (terminal 0 2)
    (102,1) -> branch 2 (-12)
    (102,2) -> branch 4 (terminal 1 3)
    (102,4) -> branch 5 (-12)
    (102,5) -> branch 7 (terminal 1 6)
    (102,p) | p >= 7 && p <= 9 -> branch (fromIntegral p + 1) (-12)
    (102,p) | p >= 10 && p <= 16 -> branch (if p == 16 then -10 else fromIntegral p + 1) 17
    (102,17) -> branch 18 (-12)
    (102,18) -> branch (terminal 2 19) (-12)
    (103,p) | p >= 1 && p <= 3 -> branch (if p == 3 then -11 else fromIntegral p + 1) (-10)
    (104,p) | p >= 1 && p <= 4 -> branch (fromIntegral p + 1) (-10)
    (104,5) -> next 6
    (104,6) -> next 7
    (104,7) -> branch (-11) 8
    (104,8) -> branch (-11) (-10)
    (105,p) | p == 1 || p == 2 -> branch (fromIntegral p + 1) (-10)
    (105,3) -> next 4
    (105,4) -> branch 5 (-10)
    (105,5) -> next 6
    (105,6) -> branch (-11) (-10)
    (106,1) -> next 2
    (107,1) -> branch 2 (-10)
    (106,2) -> branch (-11) (terminal 0 3)
    (107,2) -> branch 4 (terminal 0 3)
    (107,4) -> branch (-11) (-10)
    (108,1) -> next 2
    (108,2) -> branch 4 (terminal 0 3)
    (108,4) -> branch (-11) 5
    (108,5) -> case result of 0 -> 6; 2 -> terminal 0 7; _ -> -11
    (108,6) -> branch (-11) (terminal 0 8)
    (109,p) | p == 1 || p == 2 -> next (fromIntegral p + 1)
    (109,3) -> branch 5 (terminal 0 4)
    (109,5) -> branch 6 (-10)
    (109,6) -> next 7
    (109,7) -> branch 8 (-10)
    (109,8) -> branch (terminal 1 9) (-10)
    (110,1) -> branch 2 3
    (110,2) -> next 3
    (110,3) -> branch 4 (-12)
    (110,4) -> branch (-10) (terminal 2 5)
    (111,1) -> next 2
    (111,2) -> branch 3 4
    (111,3) -> next 4
    (111,p) | p == 4 || p == 5 -> branch (terminal 0 6) (if p == 4 then 5 else 7)
    (111,7) -> branch (terminal 0 8) 9
    (111,9) -> branch (-11) (-10)
    (112,p) | p == 1 || p == 2 -> next (fromIntegral p + 1)
    (112,3) -> branch 4 (-10)
    (112,4) -> branch (terminal 1 5) (-10)
    (113,1) -> branch (-10) 2
    (113,p) | p >= 2 && p <= 4 -> branch (fromIntegral p + 1) 7
    (113,5) -> branch (terminal 1 6) (-11)
    (113,7) -> branch (terminal 2 8) (-12)
    (114,1) -> branch 4 2
    (114,p) | p == 2 || p == 9 || p == 14 -> branch (terminal 2 (fromIntegral p + 1)) (-12)
    (114,p) | p == 18 || p == 22 -> branch (terminal 1 (fromIntegral p + 1)) (-11)
    (114,4) -> next 5
    (114,p) | p >= 5 && p <= 8 -> branch (if p == 8 then 11 else fromIntegral p + 1) 9
    (114,p) | p == 11 || p == 12 -> next (fromIntegral p + 1)
    (114,13) -> branch 16 14
    (114,16) -> next 17
    (114,17) -> branch 20 18
    (114,20) -> branch 21 (-12)
    (114,21) -> branch (-10) 22
    (115,1) -> branch 2 (-10)
    (115,2) -> branch 5 3
    (115,3) -> next (terminal 0 4)
    (115,5) -> branch 6 (-10)
    (115,6) -> branch (-11) 7
    (115,7) -> next (terminal 0 8)
    (116,p) | p == 1 || p == 2 -> next (fromIntegral p + 1)
    (116,3) -> branch 4 6
    (116,4) -> branch 7 (terminal 3 5)
    (116,6) -> next 7
    (116,7) -> next 8
    (116,8) -> branch 12 9
    (116,9) -> next 10
    (116,10) -> next (terminal 3 11)
    (116,12) -> next (-10)
    (117,1) -> branch 3 (terminal 3 2)
    (117,3) -> branch 5 (terminal 3 4)
    (117,5) -> branch 6 (-13)
    (117,6) -> next 7
    (117,7) -> branch 8 (terminal 3 9)
    (117,8) -> branch 10 (terminal 3 9)
    (117,10) -> next (terminal 0 11)
    (118,1) -> branch 2 (-10)
    (118,2) -> branch (-11) (-10)
    (119,1) -> branch 3 (terminal 3 2)
    (119,3) -> branch 4 (terminal 3 5)
    (119,4) -> branch 6 (terminal 3 5)
    (119,6) -> branch 8 (terminal 3 7)
    (119,8) -> next 9
    (119,9) -> branch 10 13
    (119,10) -> next 11
    (119,11) -> next (terminal 3 12)
    (119,13) -> branch (terminal 3 14) 15
    (119,15) -> branch 16 18
    (119,16) -> branch 22 18
    (119,18) -> next 19
    (119,19) -> next 20
    (119,20) -> next (terminal 3 21)
    (119,22) -> branch 23 (terminal 3 24)
    (119,23) -> branch (-10) (terminal 3 24)
    (120,1) -> branch (-13) 2
    (120,2) -> branch 3 5
    (120,3) -> next (terminal 2 4)
    (120,5) -> branch 6 (-10)
    (120,6) -> next 7
    (120,7) -> next (terminal 2 8)
    (121,1) -> branch 2 (-13)
    (121,2) -> next 3
    (121,3) -> branch 4 5
    (121,4) -> next 6
    (121,5) -> next 6
    (121,6) -> next 7
    (121,7) -> next 8
    (121,8) -> branch 9 (terminal 3 10)
    (121,9) -> branch 11 (terminal 3 10)
    (121,11) -> next 12
    (121,12) -> branch 13 14
    (121,13) -> next 14
    (121,14) -> branch 16 (terminal 2 15)
    (121,16) -> branch (-10) (terminal 2 17)
    (122,1) -> branch 2 (-13)
    (122,2) -> branch 4 (terminal 3 3)
    (122,4) -> branch 5 (-13)
    (122,5) -> branch 6 (-13)
    (122,6) -> branch 7 (-13)
    (122,7) -> branch 8 (terminal 3 9)
    (122,8) -> branch 10 (terminal 3 9)
    (122,10) -> next 11
    (122,11) -> branch (-10) (-13)
    (123,1) -> next 2
    (123,2) -> branch 3 4
    (123,3) -> next 4
    (123,4) -> branch 7 5
    (123,5) -> branch (terminal 0 6) (-10)
    (123,7) -> next 8
    (123,p) | p >= 8 && p <= 14 -> branch (if p == 14 then 17 else fromIntegral p + 1) 15
    (123,15) -> branch 22 (-10)
    (123,22) -> branch (terminal 0 16) (terminal 0 23)
    (123,17) -> branch 18 19
    (123,18) -> branch (-11) 19
    (123,19) -> next 20
    (123,20) -> branch (terminal 0 21) (-10)
    (124,1) -> branch 3 (terminal 0 2)
    (124,3) -> branch 4 (terminal 0 5)
    (124,4) -> branch 6 (terminal 0 5)
    (124,6) -> branch 7 (terminal 0 9)
    (124,7) -> branch 8 (terminal 0 9)
    (124,8) -> branch (-11) (terminal 0 9)
    (125,1) -> next 2
    (125,2) -> branch 4 (terminal 0 3)
    (125,4) -> next 5
    (125,5) -> branch 6 (terminal 0 8)
    (125,6) -> branch 7 (terminal 0 8)
    (125,7) -> branch (terminal 1 9) (terminal 0 8)
    (126,1) -> branch 3 (terminal 0 2)
    (126,p) | p >= 3 && p <= 7 -> branch (if p == 7 then 9 else fromIntegral p + 1) (terminal 0 8)
    (126,9) -> branch 11 (terminal 0 10)
    (126,11) -> branch 13 (terminal 0 12)
    (126,13) -> branch 15 (terminal 0 14)
    (126,15) -> branch 16 19
    (126,16) -> branch 18 (terminal 0 17)
    (126,18) -> next 15
    (126,19) -> branch 20 (-11)
    (126,20) -> branch 22 (terminal 0 21)
    (126,22) -> next 19
    (127,p) | p>=1 && p<=5 -> branch (fromIntegral p+1) (-10)
    (127,6) -> branch (-11) 7
    (127,7) -> branch 8 9
    (127,p) | p==8 || p==9 -> branch (-11) (-10)
    (128,p) | p>=1 && p<=9 -> branch (if p==9 then -11 else fromIntegral p+1) (-10)
    (36,1) -> next 2
    (36,p) | p >= 2 && p <= 5 -> branch (terminal 0 6) (if p == 5 then 7 else fromIntegral p + 1)
    (36,7) -> branch (terminal 0 8) (-11)
    (37,1) -> next 2
    (37,p) | p >= 2 && p <= 4 -> branch (terminal 0 5) (if p == 4 then terminal 1 6 else fromIntegral p + 1)
    (38,1) -> next 2
    (38,2) -> branch (terminal 0 5) 3
    (38,3) -> branch (terminal 0 5) (-11)
    (32,p) | p >= 1 && p <= 2 -> next (fromIntegral p + 1)
    (32,p) | p >= 3 && p <= 8 -> branch (if p == 8 then -11 else fromIntegral p + 1) (-10)
    (33,p) | p >= 1 && p <= 3 -> branch (fromIntegral p + 1) (-10)
    (33,4) -> next 5
    (33,5) -> branch (-11) (-10)
    (34,1) -> branch (-11) (terminal 0 2)
    (35,1) -> next 2
    (35,2) -> branch (terminal 1 4) (terminal 0 3)
    (29,p) -> case p of
      n | n >= 1 && n <= 3 -> branch (if n == 3 then 5 else fromIntegral n + 1) (terminal 0 4)
      5 -> next 6
      6 -> next 7
      7 -> branch 8 14
      8 -> next 9
      9 -> branch 10 12
      10 -> branch 11 12
      11 -> next 12
      12 -> next 13
      13 -> next 7
      14 -> branch (-11) (terminal 0 15)
      _ -> -1
    (30,p) | p >= 1 && p <= 3 -> branch (if p == 3 then -11 else fromIntegral p + 1) (-10)
    (31,p) | p >= 1 && p <= 3 -> next (fromIntegral p + 1)
    (31,p) | p >= 4 && p <= 8 -> branch (if p == 8 then terminal 1 9 else fromIntegral p + 1) (-10)
    (27,1) -> branch (-11) (terminal 0 2)
    (28,p) -> case p of
      1 -> next 2
      2 -> branch 3 15
      3 -> branch 4 15
      4 -> branch 5 (-10)
      n | n >= 5 && n <= 7 -> next (fromIntegral n + 1)
      8 -> branch 9 (-10)
      9 -> next 10
      10 -> branch 11 (terminal 0 14)
      11 -> branch 12 (terminal 0 14)
      12 -> branch 13 (terminal 0 14)
      13 -> next 15
      15 -> branch 16 27
      16 -> branch 17 27
      17 -> branch 18 (-10)
      n | n >= 18 && n <= 20 -> next (fromIntegral n + 1)
      21 -> branch 22 (-10)
      22 -> branch 23 (terminal 0 26)
      23 -> branch 24 (terminal 0 26)
      24 -> next 27
      27 -> branch 28 (-11)
      28 -> branch 29 (-10)
      29 -> next 30
      30 -> branch 31 35
      31 -> branch 32 38
      32 -> branch 33 38
      33 -> branch 34 38
      34 -> branch 37 38
      35 -> branch 36 38
      36 -> branch 37 38
      37 -> next 39
      38 -> next 39
      39 -> branch 40 41
      40 -> next 42
      41 -> next 42
      42 -> branch 43 (terminal 0 44)
      43 -> branch (-11) (terminal 0 44)
      _ -> -1
    (25,1) -> branch 2 7
    (25,2) -> branch 3 5
    (25,3) -> branch (terminal 0 4) 5
    (25,5) -> branch (terminal 0 6) 7
    (25,7) -> branch 8 (-10)
    (25,8) -> branch (terminal 0 9) (-10)
    (26,1) -> branch 2 (-10)
    (26,2) -> branch (terminal 0 3) (-10)
    (22,1) -> branch 2 (-11)
    (22,2) -> next 3
    (22,3) -> branch (terminal 1 6) 4
    (22,4) -> branch (terminal 0 5) (-10)
    (23,1) -> branch 2 (-10)
    (23,2) -> branch 3 (-10)
    (23,p) | p >= 3 && p <= 6 -> next (if p == 6 then terminal 0 7 else fromIntegral p + 1)
    (24,1) -> branch 2 4
    (24,2) -> branch 5 (terminal 0 3)
    (24,4) -> next 5
    (24,5) -> branch (terminal 1 6) (-10)
    (21,p) -> case p of
      1 -> branch 2 (-11)
      2 -> next 3
      3 -> branch 4 (-10)
      4 -> next 5
      5 -> branch 6 (-11)
      6 -> next 7
      7 -> next 8
      8 -> next 9
      9 -> branch 10 (-10)
      10 -> next 11
      11 -> branch 12 (-10)
      12 -> branch 15 13
      13 -> next (terminal 0 14)
      n | n >= 15 && n <= 18 -> next (fromIntegral n + 1)
      19 -> branch 20 (terminal 0 21)
      20 -> branch 22 (terminal 0 21)
      22 -> next 23
      23 -> next 24
      24 -> branch 25 28
      n | n >= 25 && n <= 27 -> next (fromIntegral n + 1)
      28 -> branch 29 (terminal 0 21)
      29 -> branch 30 (terminal 0 21)
      30 -> next 31
      31 -> next 32
      32 -> next 33
      33 -> next 5
      _ -> -1
    (19,p) -> case p of
      1 -> branch 2 (-10)
      2 -> branch 4 (terminal 2 3)
      4 -> branch 10 5
      5 -> branch (terminal 2 6) 7
      7 -> next 8
      8 -> next 9
      9 -> branch 10 (-12)
      10 -> branch 11 (-12)
      11 -> branch 14 12
      12 -> next (terminal 2 13)
      14 -> branch 15 17
      15 -> branch 16 (-12)
      16 -> next 17
      17 -> branch 20 18
      18 -> branch 19 (-12)
      19 -> next 20
      20 -> branch 21 26
      21 -> next 22
      22 -> branch (terminal 2 23) 24
      24 -> next 25
      25 -> branch 26 (-12)
      26 -> branch 27 (-12)
      27 -> branch (-11) (terminal 2 28)
      _ -> -1
    (20,p) -> case p of
      1 -> branch 2 (-10)
      2 -> branch 5 3
      3 -> next (terminal 0 4)
      5 -> branch 6 (-10)
      6 -> branch 9 7
      7 -> next (terminal 0 8)
      9 -> branch 10 (-10)
      10 -> branch 13 11
      11 -> next (terminal 0 12)
      13 -> branch 14 15
      14 -> branch 15 (-10)
      15 -> next (terminal 1 16)
      _ -> -1
    (17,p) | p >= 1 && p <= 6 -> next (fromIntegral p + 1)
    (17,7) -> branch 8 (-11)
    (17,p) | p >= 8 && p <= 13 -> next (fromIntegral p + 1)
    (17,14) -> branch 15 18
    (17,p) | p >= 15 && p <= 17 -> next (fromIntegral p + 1)
    (17,18) -> next 7
    (18,p) -> case p of
      1 -> branch 2 40
      2 -> next 3
      3 -> next 4
      4 -> next 5
      5 -> branch 6 7
      6 -> branch 9 7
      7 -> next (terminal 0 8)
      9 -> next 10
      10 -> next 11
      11 -> branch 12 32
      12 -> branch 13 15
      13 -> branch 14 15
      14 -> branch 17 15
      15 -> next (terminal 0 16)
      17 -> next 18
      18 -> next 19
      19 -> branch 22 20
      20 -> next (terminal 0 21)
      22 -> next 23
      23 -> branch 24 26
      24 -> next 25
      25 -> next 30
      26 -> branch 27 28
      27 -> branch 30 28
      28 -> next (terminal 0 29)
      30 -> branch 31 38
      31 -> next 11
      32 -> next 33
      33 -> next 34
      34 -> next 35
      35 -> branch (terminal 1 37) (terminal 0 36)
      38 -> next (terminal 0 39)
      40 -> next 41
      41 -> branch 42 (terminal 0 36)
      42 -> branch 45 43
      43 -> next (terminal 0 44)
      45 -> next 46
      46 -> branch 47 (terminal 0 36)
      47 -> next 48
      48 -> next 49
      49 -> next 35
      _ -> -1
    (11,p) -> case p of
      0 -> 1
      _ | p >= 1 && p <= 4 -> branch (if p == 4 then 6 else fromIntegral p + 1) (terminal 0 5)
      6 -> found 7 8
      7 -> branch 9 (terminal 0 8)
      9 -> found 10 13
      _ | p >= 10 && p <= 12 -> branch (if p == 12 then 14 else fromIntegral p + 1) (terminal 0 13)
      14 -> next 15
      15 -> branch 16 23
      _ | p >= 16 && p <= 19 -> branch (fromIntegral p + 1) (terminal 0 21)
      20 -> branch (terminal 0 21) 22
      22 -> next 15
      23 -> branch 24 31
      _ | p >= 24 && p <= 28 -> branch (fromIntegral p + 1) (terminal 0 30)
      29 -> branch (terminal 0 30) 31
      31 -> next 32
      32 -> branch 33 42
      _ | p >= 33 && p <= 36 -> branch (fromIntegral p + 1) (terminal 0 40)
      37 -> branch 38 39
      38 -> branch (terminal 0 40) 39
      39 -> branch (terminal 0 40) 41
      41 -> next 32
      42 -> next 43
      43 -> branch 44 50
      44 -> branch 46 (terminal 0 45)
      46 -> branch 47 49
      47 -> branch (terminal 0 48) 49
      49 -> next 43
      50 -> next 51
      51 -> next 52
      52 -> branch 53 55
      53 -> next 54
      54 -> next 52
      55 -> branch 56 57
      56 -> next 57
      57 -> next 58
      58 -> branch 59 64
      59 -> branch 61 60
      60 -> next 61
      61 -> branch 62 63
      62 -> next 63
      63 -> next 58
      64 -> next (committing 65)
      65 -> branch (-11) (terminal 0 66)
      _ -> -1
    _ -> -1
    where
      branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next yes = branch yes (-1)
      found yes diagnostic = case result of 0 -> yes; 1 -> terminal 0 diagnostic; 2 -> terminal 0 diagnostic; _ -> -1
      terminal status action = 65536 + status * 256 + action
      committing action = 131072 + 256 + action
      lastCheck k = case k of 7 -> 3; 8 -> 2; 9 -> 4; _ -> 5
  validate (TipFlow phase result)
    | result > 1 = -2
    | otherwise = case phase of
        0 -> 1
        1 -> next 2
        2 -> branch 3 6
        3 -> next 4
        4 -> next 5
        5 -> next 8
        6 -> next 7
        7 -> next 8
        8 -> branch 10 9
        9 -> next 11
        10 -> next 11
        11 -> next 12
        12 -> next 13
        13 -> branch 14 18
        14 -> next 15
        15 -> next 16
        16 -> next 17
        17 -> next 13
        18 -> next 19
        19 -> branch 20 24
        20 -> next 21
        21 -> next 22
        22 -> next 23
        23 -> next 19
        24 -> branch 26 25
        25 -> next 26
        26 -> branch 27 36
        27 -> branch 28 29
        28 -> next 29
        29 -> next 30
        30 -> branch 31 40
        31 -> next 32
        32 -> branch 34 33
        33 -> next 34
        34 -> branch 38 35
        35 -> next 38
        36 -> next 30
        38 -> next 39
        39 -> branch 41 12
        40 -> next 42
        41 -> next 12
        42 -> branch 43 0
        43 -> branch 46 44
        44 -> next 45
        45 -> next 46
        46 -> branch 47 48
        47 -> next 51
        48 -> branch (-1) 49
        49 -> next 50
        50 -> next 51
        51 -> next 42
        _ -> -2
    where
      branch yes no = if result == 1 then yes else no
      next yes = branch yes (-1)
  validate (Record kind flags value first second) = case kind of
    0 | flags <= 1 -> let version = if flags == 0 then first else second
                     in if version <= fromIntegral (maxBound :: Int32) then fromIntegral version else -1
    1 | flags <= 7 -> yes (flags == 7 && value > 0 && toInteger value <= toInteger second && nonEmptyBounded first (fromIntegral depositAddressLimit))
    2 | flags <= 15 -> yes (bit 0 && bit 1 && successor && (not (bit 2) || bit 3))
    3 | flags <= 1 -> yes (bit 0)
    4 -> yes (first <= 0xffffffff && second <= 0xffffffff && first <= second)
    5 -> votes 0
    6 -> votes 2
    7 -> yes amount
    8 -> yes (first < 0xffffffff)
    9 -> yes successor
    10 -> yes (first > 0)
    11 -> yes (first < second)
    12 | flags <= 7 -> yes (first <= 0xffffffff && second <= 0xffffffff &&
      (not (bit 0) || bit 2 || (not (bit 1) && second >= first)))
    13 -> yes (first < 11 && first <= second && second <= 0xffffffff)
    14 -> yes (first `mod` 256 == 0)
    15 -> yes (value > 0)
    16 -> yes (flags <= 1 && first <= 0xffffffff &&
      (if flags == 1 then first == 0xffffffff && value == 0
       else first < 0xffffffff && value > 0 && amount))
    17 -> yes (first > 0 && first < second)
    18 -> yes (flags <= 1 && if flags == 1 then amount else value == 0)
    19 | flags > 0 && fromIntegral flags < second && second <= 65535 &&
         first <= 0xffffffff && value >= 0 && fromIntegral value <= first ->
      let maxFails = second - fromIntegral flags
      in yes (first > second || (first > maxFails && first - fromIntegral value >= maxFails))
    20 -> yes (flags == 1 && value >= 0 && value <= 255 && currentEpoch first second)
    21 -> yes (first /= second)
    22 -> yes (value >= 0 && first <= fromIntegral value && fromIntegral value - first <= second)
    23 -> yes (flags==1 && value>=0 && value<=255 && first<=255 && fromIntegral value==first)
    24 -> yes (value >= 0 && first <= second && toInteger value + toInteger first <= toInteger second)
    25 | flags <= 7 -> if bit 0 then 0 else if not (bit 1) then 1 else if bit 2 then 2 else 3
    26 | flags <= 3 -> yes (bit 0 && not (bit 1))
    27 | flags <= 1 -> yes (first /= second || bit 0)
    28 -> yes (exceedsLane (fromIntegral flags) first second)
    29 -> yes (nonEmptyBounded first second)
    30 | flags <= 7 -> if (first == 6 && bit 0) || (first == 11 && bit 1)
                      then fromIntegral first * 256 + if bit 2 then 3 else 2
                      else if bit 1 then 8 * 256 + 1 else 6 * 256 + if bit 2 then 4 else 0
    31 -> yes (currentEpoch first second)
    32 -> yes (toInteger value == toInteger (fromIntegral first :: Int64) - 1)
    _ -> -1
    where
      yes accepted = if accepted then 1 else 0
      amount = value >= 0 && toInteger value <= toInteger second
      bit = testBit flags
      successor = first < 0xffffffff && second == first + 1
      votes allowance = yes (first <= 0xffffffff && second <= first && value >= 0 &&
        toInteger value <= toInteger first - toInteger second + allowance)
