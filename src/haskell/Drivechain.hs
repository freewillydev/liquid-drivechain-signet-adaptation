{-# LANGUAGE ForeignFunctionInterface, TypeFamilies, RankNTypes, FlexibleContexts, TypeOperators #-}
{-# LANGUAGE TypeApplications #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Drivechain where

import Control.Exception (SomeException, catch, evaluate)
import Control.Monad (when, unless)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Bits (testBit)
import Data.Int (Int32, Int64)
import Data.Typeable (Typeable)
import Data.Word (Word8, Word16, Word32, Word64)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (peekArray, pokeArray, withArrayLen, allocaArray, advancePtr)
import Foreign.Ptr (Ptr, FunPtr, castPtr, nullPtr, nullFunPtr)
import Foreign.Storable (poke, peek, peekElemOff)
import Withdrawal (withdrawal, wordLE, PreflightFlow(..), DestinationFlow(..), EventFlow(..), SubmissionFlow(..), OutputFlow(..), JournalReadFlow(..), JournalPersistFlow(..), RpcBurnFlow(..), RpcClaimFlow(..), RpcVerifyFlow(..))
import qualified Withdrawal
import qualified Deposit
import qualified NativeDeposit
import qualified Bmm
import qualified ParentReplay
import qualified ParentCache
import qualified ReplayStore
import qualified ParentBlock
import qualified ParentHeader
import qualified NodeRules
import qualified ScriptPolicy
import Control.Operation
import Control.Operation.Validation
import Workflow (CommandFlow(..), PredicateFlow(..), NativeBytes, countMatches, Continue(..))

type NativeBytesEffect = Ptr () -> Word32 -> Word64 -> Word64 -> Ptr Word8 -> Ptr Word64 -> Ptr (Ptr Word8) -> IO Int32
foreign import ccall safe "dynamic" invokeNativeBytes :: FunPtr NativeBytesEffect -> NativeBytesEffect

nativeBytes :: FunPtr NativeBytesEffect -> Ptr () -> NativeBytes
nativeBytes effect context step index input
  | effect == nullFunPtr = ioError (userError "missing native workflow callback")
  | otherwise = B.useAsCStringLen input $ \(bytes,size) -> alloca $ \lengthOut -> alloca $ \dataOut -> do
      poke lengthOut 0
      poke dataOut nullPtr
      status <- invokeNativeBytes effect context step index (fromIntegral size) (castPtr bytes) lengthOut dataOut
      count <- peek lengthOut
      result <- peek dataOut
      if status /= 1 || count > fromIntegral (maxBound :: Int) || (count /= 0 && result == nullPtr)
        then ioError (userError "invalid native workflow reply")
        else if count == 0 then pure B.empty else B.packCStringLen (castPtr result,fromIntegral count)

elements_hs_parent_block :: Word32 -> Word64 -> Word32 -> Word32 -> Word32 -> Word32 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_parent_block height settings maxAge threshold opcode single effect context =
  execute (ParentBlock.Block height settings maxAge threshold opcode single (nativeBytes effect context)) ParentBlock.ReplayBlock
    `catch` handleFailure (-1)

elements_hs_auth_file :: Word32 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_auth_file mode effect context = run `catch` handleFailure (-1)
  where
    value = Bmm.AuthFile (nativeBytes effect context)
    run = case mode of
      0 -> execute value Bmm.ReadRawAuthFile
      1 -> execute value Bmm.ReadStaticAuthRecord
      2 -> execute value Bmm.ReadCookieAuthRecord
      _ -> pure (-1)

elements_hs_replay_store :: Word32 -> Word64 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_replay_store mode maximumMoney callback context = run `catch` handleFailure (-1)
  where
    value = ReplayStore.Store maximumMoney (nativeBytes callback context)
    run = case mode of
      0 -> execute value ReplayStore.CheckTip
      1 -> execute value ReplayStore.AppendBlock
      2 -> execute value (ReplayStore.LookupRecord ReplayStore.DepositRecord)
      3 -> execute value (ReplayStore.LookupRecord ReplayStore.EdgeRecord)
      4 -> execute value (ReplayStore.LookupRecord ReplayStore.WithdrawalRecord)
      5 -> execute value (ReplayStore.LookupRecord ReplayStore.OccurrenceRecord)
      6 -> execute value ReplayStore.ListDeposits
      7 -> execute value ReplayStore.LoadStore
      8 -> execute value ReplayStore.ResetStore
      9 -> execute (ParentCache.CacheProgress (nativeBytes callback context)) ParentCache.ProgressReplayCache
      10 -> execute (ParentReplay.Milestone (nativeBytes callback context)) ParentReplay.ValidateMilestones
      11 -> execute (ParentReplay.BmmScan (nativeBytes callback context)) ParentReplay.ScanBmmCommitment
      12 -> execute value (ReplayStore.RunSession ReplayStore.LoadSession)
      13 -> execute value (ReplayStore.RunSession ReplayStore.ResetSession)
      14 -> execute value (ReplayStore.RunSession ReplayStore.AppendSession)
      15 -> execute (ParentCache.DepositAdmission maximumMoney (nativeBytes callback context)) ParentCache.AdmitDeposit
      16 -> continue @(ParentCache.ConfirmedDeposit ()) ParentCache.ConfirmationReply $
        execute (ParentCache.ConfirmedDeposit maximumMoney (nativeBytes callback context))
          (ParentCache.AuthenticateConfirmation (ParentCache.MatchConfirmation ParentCache.ReadConfirmation))
      17 -> execute value (ReplayStore.RunSession (ReplayStore.LookupSession ReplayStore.DepositRecord))
      18 -> execute value (ReplayStore.RunSession ReplayStore.ScanSession)
      19 -> continue @(ParentCache.DepositCandidates ()) ParentCache.CandidateReply $
        execute (ParentCache.DepositCandidates (nativeBytes callback context))
          (ParentCache.FilterCandidates (ParentCache.ScanCandidates ParentCache.ReadCandidateSnapshot))
      20 -> execute (ParentHeader.networkHeader (nativeBytes callback context)) ParentHeader.CheckParentNetwork
      21 -> execute (ParentHeader.networkHeader (nativeBytes callback context)) ParentHeader.ReadActiveHash
      22 -> execute (Check (Deposit.ConfirmationWorkflow False (nativeBytes callback context))) Validate
      23 -> execute (Check (Deposit.ConfirmationWorkflow True (nativeBytes callback context))) Validate
      24 -> execute (Bmm.RpcSession (nativeBytes callback context)) Bmm.CallTransport
      25 -> execute (Bmm.RpcSession (nativeBytes callback context)) Bmm.CallCheckedTransport
      26 -> execute (Bmm.RpcHost (nativeBytes callback context)) Bmm.CheckRpcHost
      27 -> execute (Bmm.LocalBidWallet maximumMoney (nativeBytes callback context)) Bmm.SubmitLocalBid
      28 -> execute (ParentHeader.BmmBidSubmission maximumMoney (nativeBytes callback context)) ParentHeader.SubmitBmmBid
      29 -> execute (ParentCache.BmmContext (nativeBytes callback context)) ParentCache.AuthenticateBmmContext
      30 -> execute (Withdrawal.WalletWithdrawal (fromIntegral maximumMoney) (nativeBytes callback context)) Withdrawal.WithdrawFromWallet
      31 -> execute (Withdrawal.WithdrawalJournal (fromIntegral maximumMoney) (nativeBytes callback context)) Withdrawal.ValidateJournal
      32 -> execute (Withdrawal.WithdrawalJournal (fromIntegral maximumMoney) (nativeBytes callback context)) Withdrawal.ReadJournal
      33 -> execute (Withdrawal.WithdrawalJournal (fromIntegral maximumMoney) (nativeBytes callback context)) Withdrawal.WriteJournal
      34 -> execute (Withdrawal.WithdrawalJournal (fromIntegral maximumMoney) (nativeBytes callback context)) Withdrawal.ClearJournal
      35 -> execute (Bmm.HeaderPolicy (nativeBytes callback context)) Bmm.ProofIsRequired
      36 -> execute (Bmm.HeaderPolicy (nativeBytes callback context)) Bmm.CheckHeaderPolicy
      37 -> execute (Bmm.StoredBmmState (nativeBytes callback context)) Bmm.ReadParentState
      38 -> execute (Bmm.StoredBmmState (nativeBytes callback context)) Bmm.EffectiveParentState
      39 -> execute (Bmm.StoredBmmState (nativeBytes callback context)) Bmm.PrepareParentContext
      40 -> execute (Bmm.PersistedOutput False (nativeBytes callback context)) Bmm.PersistOutput
      41 -> execute (Bmm.PersistedOutput True (nativeBytes callback context)) Bmm.PersistOutput
      42 -> execute (Bmm.ProofSession (nativeBytes callback context)) Bmm.EncodeProof
      43 -> execute (Bmm.ProofSession (nativeBytes callback context)) Bmm.DecodeProof
      44 -> execute (Bmm.ProofSession (nativeBytes callback context)) Bmm.AttachProof
      45 -> execute (Bmm.ProofSession (nativeBytes callback context)) Bmm.VerifyProofEntries
      46 -> execute (Bmm.ProofSession (nativeBytes callback context)) Bmm.VerifyProofBlock
      47 -> execute (Bmm.ProofSession (nativeBytes callback context)) Bmm.VerifyProofParent
      48 -> execute (Bmm.ChainSession (nativeBytes callback context)) Bmm.ConnectChainState
      49 -> execute (Bmm.ChainSession (nativeBytes callback context)) Bmm.DisconnectChainState
      50 -> execute (Bmm.CommitmentSession (nativeBytes callback context)) Bmm.ExtractSelectedCommitment
      _ -> pure (-1)

elements_hs_parent_prelude :: FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_parent_prelude effect context =
  execute (ParentBlock.Prelude (nativeBytes effect context)) ParentBlock.CheckPrelude
    `catch` handleFailure (-1)

elements_hs_parent_header :: Word32 -> Word32 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_parent_header mode height effect context = run `catch` handleFailure (-1)
  where
    value = ParentHeader.Header height (mode `elem` [5,10,12,13])
      (if mode `elem` [11,12,13,17] then ParentHeader.NativeDeadline else ParentHeader.HookDeadline)
      (nativeBytes effect context)
    run = case mode of
      0 -> execute value ParentHeader.CheckProof
      1 -> execute value ParentHeader.CalculateWork
      2 -> execute value ParentHeader.CheckChainwork
      3 -> execute value ParentHeader.AuthenticateRaw
      4 -> execute value ParentHeader.AncestorMedian
      5 -> execute value ParentHeader.AncestorMedian
      6 -> execute value ParentHeader.CanonicalHash
      7 -> execute value ParentHeader.ReadMetadata
      8 -> execute value ParentHeader.CheckPredecessor
      9 -> execute value ParentHeader.AuthenticateHeader
      10 -> execute value ParentHeader.AuthenticateHeader
      11 -> execute value ParentHeader.AuthenticateRaw
      12 -> execute value ParentHeader.AncestorMedian
      13 -> execute value ParentHeader.AuthenticateHeader
      14 -> execute value ParentHeader.CheckBlockTransactions
      15 -> execute value ParentHeader.CheckBlockSignet
      16 -> execute value ParentHeader.AuthenticateBlock
      17 -> execute value ParentHeader.AuthenticateBlock
      18 -> execute value ParentHeader.AuthenticateSignet
      19 -> execute value ParentHeader.ModifiedSignetMerkle
      20 -> execute value ParentHeader.BuildSignetTransactions
      21 -> execute value ParentHeader.WriteSignetBlockData
      22 -> execute value ParentHeader.SelectSignetCommitment
      23 -> execute (ParentHeader.NetworkHeader (nativeBytes effect context)) ParentHeader.AuthenticateNetworkHeader
      24 -> execute (ParentHeader.ParentBlockReader (nativeBytes effect context)) ParentHeader.ReadAuthenticatedBody
      25 -> execute (ParentHeader.ParentBlockReader (nativeBytes effect context)) ParentHeader.AuthenticateParentBlock
      _ -> pure (-1)

elements_hs_replay_maintenance :: Word32 -> Word32 -> Word64 -> Word32 -> Word32 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_replay_maintenance mode height settings maxAge flags effect context =
  run `catch` handleFailure (-1)
  where
    value = ParentReplay.Maintenance height settings maxAge flags (nativeBytes effect context)
    run = case mode of
      0 -> execute value ParentReplay.BeforeTreasury
      1 -> execute value ParentReplay.AfterTreasury
      _ -> pure (-1)

elements_hs_replay_messages :: Word64 -> Word32 -> Word64 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_replay_messages count height settings effect context =
  execute (Check (ParentReplay.MessageWorkflow count height settings (nativeBytes effect context))) Validate
    `catch` handleFailure (-1)

elements_hs_replay_m4_workflow :: Word32 -> Word64 -> Ptr Word16 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_replay_m4_workflow flags count votes effect context = run `catch` handleFailure (-1)
  where
    run | count > fromIntegral (maxBound :: Int) || (count /= 0 && votes == nullPtr) = pure (-1)
        | otherwise = do
            values <- if count == 0 then pure [] else peekArray (fromIntegral count) votes
            execute (Check (ParentReplay.M4Workflow flags values (nativeBytes effect context))) Validate

elements_hs_bmm_work_measurement :: Word32 -> Word64 -> Word64 -> Ptr Word64 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_bmm_work_measurement mode count initial output effect context = run `catch` handleFailure (-1)
  where
    run | output == nullPtr = pure (-1)
        | otherwise = do
            (status,total,lastWork) <- execute (Check (Bmm.WorkMeasurement mode count initial (nativeBytes effect context))) Validate
            if status < 0 then pure status else pokeArray output [total,lastWork] >> pure status

-- Fresh candidate byte codecs.
elements_hs_script_cache_encode :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_script_cache_encode mode size input capacity output = run `catch` handleFailure (-1)
  where
    shape = case mode of
      1 -> size `elem` [1,81] && capacity == 115
      _ -> False
    run | not shape || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,fromIntegral size)
            case execute (Check (NodeRules.ScriptCacheEncoding (mode == 1) bytes)) Validate of
              Just encoded | B.length encoded == fromIntegral capacity -> do
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (fromIntegral capacity))
                pure 0
              _ -> pure (-1)

elements_hs_merkle_replacement :: Word32 -> Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_merkle_replacement mode index position flags = guardResult (-1) $
  execute (Check (ScriptPolicy.MerkleReplacement mode index position flags)) Validate

elements_hs_parameter_gate :: Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_parameter_gate mode first second = guardResult (-1) $
  execute (Check (ScriptPolicy.ParameterGate mode first second)) Validate

elements_hs_optional_environment :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_optional_environment kind present fields = guardResult (-1) $
  execute (Check (ScriptPolicy.OptionalEnvironment kind present fields)) Validate

elements_hs_optional_checkpoint :: Word32 -> Ptr Word8 -> IO Int32
elements_hs_optional_checkpoint present input
  | present>1 = pure (-1)
  | otherwise = (do
      bytes <- if input==nullPtr then pure B.empty else B.packCStringLen (castPtr input,80)
      let fields = sum [if B.any (/=0) (B.take width (B.drop offset bytes)) then flag else 0 |
            (flag,offset,width) <- [(1,0,32),(2,32,8),(4,40,8),(8,48,32)]]
      evaluate (execute (Check (ScriptPolicy.OptionalEnvironment 5 present fields)) Validate))
      `catch` handleFailure (-1)

elements_hs_wallet_issue_amount :: Ptr Double -> IO Int32
elements_hs_wallet_issue_amount input
  | input==nullPtr = pure (-1)
  | otherwise = (do
      amount <- peek input
      evaluate (if execute (Check (Withdrawal.WalletIssueAmount amount)) Validate then 1 else 0))
      `catch` handleFailure (-1)

elements_hs_jet_height :: Word32 -> Word64 -> IO Int32
elements_hs_jet_height present height
  | present>1 = pure (-1)
  | otherwise = guardResult (-1) (if execute (Check (NodeRules.JetHeight (present==1) height)) Validate then 1 else 0)

elements_hs_bmm_wait_error :: Word64 -> Ptr Word8 -> IO Int32
elements_hs_bmm_wait_error = elements_hs_bmm_message 0

elements_hs_bmm_message :: Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_bmm_message kind size input
  | kind > 1 || size > fromIntegral (maxBound :: Int) || (size /= 0 && input == nullPtr) = pure (-1)
  | otherwise = (do
      message <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
      pure (if validate ((if kind==0 then Bmm.DefinitiveWaitError else Bmm.DuplicateRequest) message)
            then 1 else 0)) `catch` handleFailure (-1)

elements_hs_anchor_rule :: Word32 -> Ptr Word8 -> IO Int32
elements_hs_anchor_rule size input
  | size `notElem` [145,290,294,439] || input==nullPtr = pure (-1)
  | otherwise = (do
      bytes <- B.packCStringLen (castPtr input,fromIntegral size)
      evaluate (if execute (Check (Bmm.AnchorRule bytes)) Validate then 1 else 0)) `catch` handleFailure (-1)

elements_hs_anchor_checkpoint :: Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_anchor_checkpoint size input output
  | size/=145 || input==nullPtr || output==nullPtr = pure (-1)
  | otherwise = (do
      bytes <- B.packCStringLen (castPtr input,145)
      publishBytes 80 output (execute (Check (Bmm.AnchorCheckpoint bytes)) Validate)) `catch` handleFailure (-1)

type WalletBundleEffect = Ptr () -> Word32 -> Word64 -> Ptr Word8 -> Word32 -> Ptr (Ptr Word8) -> IO Int64
type MoneyParser = Ptr Word8 -> Word32 -> IO Int64
type PolicyEffect = Ptr () -> Word32 -> IO Int32
elements_hs_production_identity :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_production_identity = callbackCall runPolicyEffect $ \readFact ->
  fromIntegral <$> execute (Check (NodeRules.ProductionIdentity (\step -> do
    result <- readFact (fromIntegral step)
    if result == 0 || result == 1 then pure (result == 1)
      else error "invalid production identity predicate"))) Validate

type ProofBuildEffect = Ptr () -> Word32 -> Word64 -> IO Int32
type MatchFact = Ptr () -> Word32 -> IO Int64
type ProofFacts = Ptr () -> Word32 -> Ptr Word64 -> IO Int32
foreign import ccall safe "dynamic" callProofFacts :: FunPtr ProofFacts -> ProofFacts
foreign import ccall safe "dynamic" callMatchFact :: FunPtr MatchFact -> MatchFact
foreign import ccall "dynamic" callProofBuildEffect :: FunPtr ProofBuildEffect -> ProofBuildEffect
callbackCall :: Num result => (FunPtr native -> Ptr () -> action) -> (action -> IO result) -> FunPtr native -> Ptr () -> IO result
callbackCall convert run callback context
  | callback == nullFunPtr = pure (-1)
  | otherwise = run (convert callback context) `catch` handleFailure (-1)

proofCall :: ((Word32 -> Word64 -> IO Int32) -> IO Int32) -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
proofCall = callbackCall callProofBuildEffect

elements_hs_bmm_proof_build :: Word64 -> Int64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_bmm_proof_build previous parent = proofCall (\action -> execute (Check (Bmm.ProofBuild previous parent action)) Validate)

elements_hs_deposit_ctip_search :: Word64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_deposit_ctip_search count = proofCall (\action -> execute (Check (Deposit.CtipSearch count action)) Validate)

elements_hs_deposit_headers :: Word64 -> Int64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_deposit_headers first tip = proofCall (\action -> execute (Check (Deposit.HeaderBuild first tip action)) Validate)

elements_hs_deposit_previous_sequence :: Int64 -> IO Int64
elements_hs_deposit_previous_sequence current = guardResult (-1) $
  execute (Check (Deposit.PreviousSequence current)) Validate

elements_hs_deposit_construction :: Int64 -> Int64 -> Word32 -> Int32 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_deposit_construction sequenceNumber height flags slot effect context =
  execute (Deposit.Construction sequenceNumber height flags slot (nativeBytes effect context)) Deposit.ReconstructEvidence
    `catch` handleFailure (-1)

elements_hs_deposit_parsing :: Word64 -> Word64 -> Word64 -> Int64 -> Word32 -> Word32
  -> Ptr Word32 -> Ptr (Ptr Word8) -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
  -> FunPtr Deposit.HashTransaction -> FunPtr Deposit.DecodeEvidence -> Ptr ()
  -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_deposit_parsing inputs index witnesses maximumMoney maximumTx count sizes fields asset genesis prevout hasher decoder decoded effect context =
  execute (Deposit.Parsing inputs index witnesses
    (Deposit.DeterministicEvidence maximumTx count sizes fields prevout hasher decoder decoded)
    (Deposit.DepositWitness maximumMoney maximumTx 1 count sizes fields asset genesis prevout hasher)
    (nativeBytes effect context)) Deposit.ParseDeposit `catch` handleFailure (-1)

elements_hs_deposit_claim :: Word32 -> Word64 -> Word64 -> Word64 -> Word64 -> Int64 -> Word32 -> Word32
  -> Ptr Word32 -> Ptr (Ptr Word8) -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
  -> FunPtr Deposit.HashTransaction -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_deposit_claim mode inputs index witnesses outputs maximumMoney maximumTx count sizes fields asset genesis prevout hasher effect context =
  let value = Deposit.Claim inputs index witnesses outputs
        (\kind -> Deposit.DepositWitness maximumMoney maximumTx kind count sizes fields asset genesis prevout hasher)
        (nativeBytes effect context)
      run = case mode of
        0 -> execute value Deposit.DiscoverCheckpoint
        1 -> execute value Deposit.AuthenticateLegacy
        2 -> execute value Deposit.VerifyClaimTransaction
        _ -> pure (-1)
  in run `catch` handleFailure (-1)

elements_hs_native_recipient :: Word32 -> Int64 -> Int64 -> Word64 -> Ptr Word8
  -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_native_recipient mode maximumMoney amount size bytes effect context =
  let source = if size > 128 then ioError (userError "unbounded native recipient read")
        else Deposit.copyBytes bytes (fromIntegral size)
      value = NativeDeposit.Recipient maximumMoney amount size source (nativeBytes effect context)
      run = case mode of
        0 -> execute value NativeDeposit.DecodeRecipient
        1 -> execute value NativeDeposit.EncodeRecipient
        2 -> execute value NativeDeposit.ConstructNative
        _ -> pure (-1)
  in run `catch` handleFailure (-1)

elements_hs_native_outputs :: Word32 -> Word64 -> Word64 -> Word64 -> Word64 -> Int64 -> Word32
  -> Ptr Word64 -> Ptr Word32 -> Ptr (Ptr Word8) -> Ptr (Ptr Word8) -> Ptr Word8 -> Ptr Word8
  -> FunPtr Deposit.HashTransaction -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_native_outputs mode inputs index witnesses outputs maximumMoney maximumTx offsets sizes fields prevouts asset genesis hasher effect context =
  let stack i = do
        start <- peekElemOff offsets (fromIntegral i)
        end <- peekElemOff offsets (fromIntegral i+1)
        when (end < start || end-start > fromIntegral (maxBound :: Word32) ||
          end > fromIntegral (maxBound :: Int) `div` 8) (ioError (userError "invalid borrowed witness offsets"))
        pure (fromIntegral start,fromIntegral (end-start))
      witness i kind amount = do
        (start,count) <- stack i
        previous <- peekElemOff prevouts (fromIntegral i)
        pure (Deposit.DepositWitness maximumMoney maximumTx kind count (advancePtr sizes start)
          (advancePtr fields start) asset genesis previous hasher amount)
      field i item = do
        (start,count) <- stack i
        unless (count == 8 && item `elem` [3,7]) (ioError (userError "invalid native witness field"))
        lengthBytes <- peekElemOff sizes (start+item)
        unless (lengthBytes <= if item == 3 then 100 else 128) (ioError (userError "unbounded native witness field"))
        pointer <- peekElemOff fields (start+item)
        Deposit.copyBytes pointer lengthBytes
      value = NativeDeposit.Outputs inputs index witnesses outputs maximumMoney witness field (nativeBytes effect context)
      run = case mode of
        0 -> execute value NativeDeposit.CheckOutputs
        1 -> execute value NativeDeposit.CanonicalFeeFree
        _ -> pure (-1)
  in run `catch` handleFailure (-1)

elements_hs_deposit_build :: Int64 -> Int64 -> Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_deposit_build sequenceNumber height flags = policyCall (\action ->
  execute (Check (Deposit.EvidenceBuild sequenceNumber height flags action)) Validate)

publishVotes :: Ptr Word16 -> Maybe (Bool,[Word16]) -> IO Int32
publishVotes votes result = case result of
  Nothing -> pure 0
  Just (False,_) -> pure 2
  Just (True,updated) -> pokeArray votes updated >> pure 1

elements_hs_replay_leader :: Word32 -> Ptr Word16 -> IO Int64
elements_hs_replay_leader count votes = run `catch` handleFailure (-2)
  where
    run | (count /= 0 && votes == nullPtr) || toInteger count * 2 > toInteger (maxBound :: Int) = pure (-2)
        | otherwise = do
            values <- peekArray (fromIntegral count) votes
            evaluate (execute (Check (ParentReplay.VoteLeader values)) Validate)

withReplayVotes :: Word32 -> Ptr Word8 -> Ptr Word16 -> (B.ByteString -> [Word16] -> IO a) -> IO a
withReplayVotes count hashes votes action
  | (count /= 0 && (hashes == nullPtr || votes == nullPtr)) ||
      toInteger count * 32 > toInteger (maxBound :: Int) = ioError (userError "invalid replay vote buffers")
  | otherwise = do
      keys <- B.pack <$> peekArray (fromIntegral count*32) hashes
      values <- peekArray (fromIntegral count) votes
      action keys values

elements_hs_replay_leading :: Word32 -> Ptr Word8 -> Ptr Word16 -> IO Int64
elements_hs_replay_leading count hashes votes = (`catch` handleFailure (-2)) $
  withReplayVotes count hashes votes $ \keys values ->
    case execute (Check (ParentReplay.LeadingVote keys values)) Validate of
      Nothing -> pure (-1)
      Just (leader,updated) -> pokeArray votes updated >> pure leader

elements_hs_replay_explicit :: Word32 -> Word32 -> Ptr Word8 -> Ptr Word16 -> IO Int32
elements_hs_replay_explicit vote count hashes votes = run `catch` handleFailure (-1)
  where
    run | vote > 65535 = pure (-1)
        | vote == 65535 = pure 0
        | otherwise = withReplayVotes count hashes votes $ \keys values -> do
            let (code,updated) = execute (Check (ParentReplay.ExplicitVote (fromIntegral vote) keys values)) Validate
            if code == 1 || code == 2 then pokeArray votes updated else pure ()
            pure code

elements_hs_replay_alarm :: Word32 -> Ptr Word16 -> IO Int32
elements_hs_replay_alarm count votes = run `catch` handleFailure (-1)
  where
    run | (count /= 0 && votes == nullPtr) || toInteger count * 2 > toInteger (maxBound :: Int) = pure (-1)
        | otherwise = do
            values <- peekArray (fromIntegral count) votes
            publishVotes votes (execute (Check (ParentReplay.VoteAlarm values)) Validate)

elements_hs_replay_upvote :: Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word16 -> IO Int32
elements_hs_replay_upvote count hashes target votes = run `catch` handleFailure (-1)
  where
    run
      | target == nullPtr = pure (-1)
      | otherwise = withReplayVotes count hashes votes $ \keys values -> do
          key <- B.pack <$> peekArray 32 target
          publishVotes votes (execute (Check (ParentReplay.VoteUpdate key keys values)) Validate)

elements_hs_count_matches :: Word64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int64
elements_hs_count_matches count = callbackCall callProofBuildEffect (\action -> countMatches count (action 1))

elements_hs_coinbase_messages :: Word64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_coinbase_messages count = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.CoinbaseMessages count action)) Validate)

elements_hs_m4_repeat :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_m4_repeat upvote = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.M4Repeat upvote action)) Validate)

elements_hs_m8_acceptance :: Word64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m8_acceptance count = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M8Acceptance count action)) Validate)

elements_hs_m2_proposal :: Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m2_proposal height unusedAge unusedThreshold usedAge usedThreshold = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M2Proposal height unusedAge unusedThreshold usedAge usedThreshold action)) Validate)

elements_hs_m4_mode :: Word32 -> Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_m4_mode flags votes = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.M4Mode flags votes action)) Validate)

elements_hs_m3_proposal :: FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m3_proposal = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M3Proposal action)) Validate)

elements_hs_m6_id :: Word64 -> Word64 -> Int64 -> Int64 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m6_id outputs inputs previous maximumValue hasSlot = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M6Id outputs inputs previous maximumValue hasSlot action)) Validate)

elements_hs_active_slots :: Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_active_slots count input output = run `catch` handleFailure (-1)
  where
    run | count > 257 || (count /= 0 && (input == nullPtr || output == nullPtr)) = pure (-1)
        | otherwise = do
            entries <- B.pack <$> peekArray (fromIntegral count*2) input
            writeReply (execute (Check (ParentReplay.ActiveSlots entries)) Validate) output count

elements_hs_block_publish :: Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_block_publish flags = policyCall (\action ->
  execute (Check (ParentReplay.BlockPublish flags action)) Validate)

elements_hs_prune_slots :: Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_prune_slots count = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.PruneSlots count action)) Validate)

elements_hs_m6_withdrawal :: Word64 -> Word64 -> Word64 -> Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_m6_withdrawal decreases changes inputs threshold single = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.M6Withdrawal decreases changes inputs threshold single action)) Validate)

elements_hs_ctip_changes :: Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_ctip_changes count = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.CtipChanges count action)) Validate)

elements_hs_ctip_replacements :: Word64 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_ctip_replacements count = policyCall (\action ->
  execute (Check (ParentReplay.CtipReplacements count action)) Validate)

type IndexedFact = Ptr () -> Word32 -> Word64 -> IO Int64
foreign import ccall safe "dynamic" callIndexedFact :: FunPtr IndexedFact -> IndexedFact

type InboxEffect = Ptr () -> Word32 -> Word64 -> Word64 -> IO Int64
foreign import ccall safe "dynamic" callInboxEffect :: FunPtr InboxEffect -> InboxEffect
type CursorEffect = Ptr () -> Word32 -> Word64 -> Word64 -> Ptr Word64 -> IO Int32
foreign import ccall safe "dynamic" callCursorEffect :: FunPtr CursorEffect -> CursorEffect
elements_hs_credential_read :: Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_credential_read capacity = workCall (\readField ->
  execute (Check (Bmm.CredentialRead capacity (readField 0))) Validate)

elements_hs_tls_file_admission :: Word32 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_tls_file_admission privateKey callback context
  | privateKey>1 = pure (-1)
  | otherwise = cursorCall (\readField ->
      execute (Check (Bmm.TlsFileAdmission (privateKey/=0) (\step -> readField step 0 0))) Validate) callback context

elements_hs_startup_args :: Word32 -> Word64 -> Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_startup_args slot moneyLimit timeoutMaximum = cursorCall (\readField ->
  execute (Check (Bmm.StartupArgs slot moneyLimit timeoutMaximum (\step -> readField step 0 0))) Validate)

elements_hs_bmm_work_budget :: Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_bmm_work_budget count = workCall (\readField -> do
  result <- execute (Check (Bmm.WorkBudget count readField)) Validate
  pure (0,result))

elements_hs_deposit_input_limit :: Word32 -> Word64 -> Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_deposit_input_limit enabled count limit callback context
  | enabled > 1 = pure (-1)
  | otherwise = cursorCall (\readField -> do
      accepted <- execute (Check (Deposit.InputLimit (enabled/=0) count limit readField)) Validate
      pure (if accepted then 1 else 0)) callback context

elements_hs_fee_free_selection :: Int64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_fee_free_selection age = cursorCall (\readField ->
  execute (Check (Deposit.FeeFreeSelection age (\step -> readField step 0 0))) Validate)

elements_hs_bmm_work_total :: Word32 -> Word64 -> Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_bmm_work_total mode count initial = workCall (\readField ->
  execute (Check (Bmm.WorkTotal mode count initial (\index -> readField 0 index 0))) Validate)

workCall :: ((Word32 -> Word64 -> Word64 -> IO Word64) -> IO (Int32,Word64))
  -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
workCall run output callback context
  | output == nullPtr = pure (-1)
  | otherwise = cursorCall (\readField -> do
      (code,result) <- run readField
      if code < 0 then pure code else poke output result >> pure code) callback context

cursorCall :: ((Word32 -> Word64 -> Word64 -> IO Word64) -> IO Int32)
  -> FunPtr CursorEffect -> Ptr () -> IO Int32
cursorCall run = callbackCall callCursorEffect (\action -> allocaArray 1 $ \field ->
  run (\step witness index -> do
    poke field 0
    status <- action step witness index field
    if status == 1 then peekElemOff field 0 else ioError (userError "work budget read failed")))

type StateTransitionEffect = Ptr () -> Word32 -> Word64 -> IO Word64
foreign import ccall safe "dynamic" callStateTransitionEffect :: FunPtr StateTransitionEffect -> StateTransitionEffect
elements_hs_ctip_outputs :: Word64 -> Word64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_ctip_outputs count maximumValue = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.CtipOutputs count maximumValue action)) Validate)

elements_hs_m5_deposit :: Int64 -> Int64 -> Word64 -> Word64 -> Word64 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m5_deposit old new maximumValue output outputs flags = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M5Deposit old new maximumValue output outputs flags action)) Validate)

elements_hs_transaction_replay :: Word64 -> Word64 -> Word64 -> Word64 -> Word32 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_transaction_replay slots inputs outputs maximumValue threshold single = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.TransactionReplay slots inputs outputs maximumValue threshold single action)) Validate)

elements_hs_ctip_spends :: Word64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_ctip_spends count = proofCall (\action ->
  execute (Check (ParentReplay.CtipSpends count action)) Validate)

elements_hs_ctip_owners :: Word64 -> Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_ctip_owners count maximumValue = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.CtipOwners count maximumValue action)) Validate)

elements_hs_expire_proposals :: Word64 -> Word32 -> Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_expire_proposals count height threshold maxAge = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.ExpireProposals count height threshold maxAge action)) Validate)

elements_hs_expire_withdrawals :: Word64 -> Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_expire_withdrawals count height maxAge = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.ExpireWithdrawals count height maxAge action)) Validate)

elements_hs_deposit_match :: Int64 -> Int64 -> Int64 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_deposit_match slot amount bound hasAddress = callbackCall callMatchFact (\action ->
  execute (Check (Deposit.RawMatch slot amount bound hasAddress action)) Validate)

elements_hs_deposit_verify :: Word64 -> Word64 -> Word64 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_deposit_verify index inputs witnesses = policyCall (\action ->
  execute (Check (Deposit.LiveVerify index inputs witnesses action)) Validate)

publishResult :: Integral code => (value -> IO ()) -> Either code value -> IO Int32
publishResult publish = either (pure . fromIntegral) (\value -> publish value >> pure 0)

publishBytes :: Integral code => Int -> Ptr Word8 -> Either code B.ByteString -> IO Int32
publishBytes size output = publishResult (\value -> B.useAsCString value (\ptr -> copyBytes output (castPtr ptr) size))

foreign import ccall "dynamic" runPolicyEffect :: FunPtr PolicyEffect -> PolicyEffect
policyCall :: ((Word32 -> IO Int32) -> IO Int32) -> FunPtr PolicyEffect -> Ptr () -> IO Int32
policyCall = callbackCall runPolicyEffect

elements_hs_bmm_wait :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_wait = policyCall (\action -> execute (Check (Bmm.WaitForBmm action)) Validate)

elements_hs_bmm_submit :: Int64 -> Int64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_bmm_submit bid limit = callbackCall callIndexedFact (\action ->
  execute (Bmm.SubmissionRequest action) (Bmm.submitBmm bid limit))

elements_hs_bmm_reward_address :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_reward_address = policyCall (\action -> execute (Check (Bmm.RewardAddress action)) Validate)

elements_hs_bmm_native_production :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_native_production = policyCall (\action -> execute (Check (Bmm.NativeProduction action)) Validate)

elements_hs_bmm_ecx_production :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_ecx_production = policyCall (\action -> execute (Check (Bmm.EcxProduction action)) Validate)

elements_hs_bmm_sync_tick :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_sync_tick = policyCall (\action -> execute (Check (Bmm.SyncTick action)) Validate)

elements_hs_bmm_sync_heights :: Int64 -> Int64 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_sync_heights parent child = policyCall (\action ->
  execute (Check (Bmm.SyncHeights parent child action)) Validate)

elements_hs_parent_rpc_address :: Word32 -> Word32 -> Word32 -> Ptr Word8 -> IO Int32
elements_hs_parent_rpc_address family ipv4 size input = run `catch` handleFailure (-1)
  where
    check address = evaluate (if execute (Check address) Validate then 1 else 0)
    run = case family of
      4 | size == 0 -> check (Bmm.ParentRpcIPv4 ipv4)
      6 | size == 16 && input /= nullPtr ->
        B.packCStringLen (castPtr input,16) >>= check . Bmm.ParentRpcIPv6
      _ -> pure (-1)

elements_hs_bmm_work_quote :: Int64 -> Word64 -> Int64 -> Int64 -> Int64 -> Ptr Int64 -> IO Int32
elements_hs_bmm_work_quote fees work rate reserve bound = publishWorkQuote $
  execute (Check (Bmm.WorkQuote fees work rate reserve bound)) Validate

elements_hs_bmm_work_quote_display :: Int64 -> Word64 -> Int64 -> Int64 -> Int64 -> Ptr Int64 -> IO Int32
elements_hs_bmm_work_quote_display fees work rate reserve bound = publishWorkQuote $
  execute (Check (Bmm.WorkQuoteDisplay (Bmm.WorkQuote fees work rate reserve bound))) Validate

publishWorkQuote :: (Bool,[Int64]) -> Ptr Int64 -> IO Int32
publishWorkQuote quote output
  | output == nullPtr = pure (-1)
  | otherwise = (`catch` handleFailure (-1)) $ do
      let (accepted,fields) = quote
      pokeArray output fields
      pure (if accepted then 1 else 0)

elements_hs_bmm_work_bid :: Word32 -> Int64 -> Int64 -> Int64 -> Int64 -> Int64 -> Int64 -> Ptr Int64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_bmm_work_bid flags height fees work reserve requested bound output reader context
  | output == nullPtr || reader == nullFunPtr = pure (-1)
  | otherwise = (`catch` handleFailure (-1)) $ do
      (code,fields) <- execute (Check (Bmm.WorkBid flags height fees work reserve requested bound
        (callMatchFact reader context 0))) Validate
      pokeArray output fields
      pure code

elements_hs_bmm_selected_bid :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_bmm_selected_bid configured fees moneyLimit =
  evaluate (execute (Check (Bmm.SelectedBid configured fees moneyLimit)) Validate) `catch` handleFailure (-3)

elements_hs_bmm_replacement_limit :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_bmm_replacement_limit selected extra moneyLimit =
  evaluate (execute (Check (Bmm.ReplacementLimit selected extra moneyLimit)) Validate) `catch` handleFailure (-3)

elements_hs_next_block_height :: Word32 -> Int32 -> IO Int64
elements_hs_next_block_height present height =
  evaluate (execute (Check (Bmm.NextBlockHeight present height)) Validate) `catch` handleFailure (-2147483649)

elements_hs_replay_distance :: Word32 -> Word32 -> IO Int64
elements_hs_replay_distance upper lower =
  evaluate (execute (Check (ParentReplay.Distance upper lower)) Validate) `catch` handleFailure (-1)

elements_hs_extra_nonce :: Word32 -> Word32 -> IO Int64
elements_hs_extra_nonce sameParent current =
  evaluate (execute (Check (Bmm.ExtraNonce sameParent current)) Validate) `catch` handleFailure (-1)

elements_hs_peer_strikes :: Word32 -> Word32 -> IO Int64
elements_hs_peer_strikes flags count =
  evaluate (execute (Check (Bmm.PeerStrikes flags count)) Validate) `catch` handleFailure (-1)

foreign import ccall "dynamic" callMoneyParser :: FunPtr MoneyParser -> MoneyParser
elements_hs_bmm_replacement :: Int64 -> Int64 -> Int64 -> Ptr Word8 -> Word32 -> FunPtr MoneyParser -> IO Int64
elements_hs_bmm_replacement current maximumBid moneyLimit input size parser = run `catch` handleFailure (-2)
  where
    run | input == nullPtr || parser == nullFunPtr = pure (-2)
        | otherwise = do
            message <- B.packCStringLen (castPtr input,fromIntegral size)
            result <- Bmm.replaceBid (Bmm.ReplacementBid current maximumBid moneyLimit message) $ \amount ->
              B.useAsCStringLen amount $ \(ptr,len) -> callMoneyParser parser (castPtr ptr) (fromIntegral len)
            pure (maybe (-1) id result)

foreign import ccall "dynamic" callWalletBundleEffect :: FunPtr WalletBundleEffect -> WalletBundleEffect
elements_hs_wallet_bundle :: Int64 -> Ptr Word8 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
elements_hs_wallet_bundle maximumMoney input = walletBundle 25 maximumMoney input

elements_hs_wallet_bundle_context :: Int64 -> Ptr Word8 -> Word32 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
elements_hs_wallet_bundle_context maximumMoney input size callback context
  | size /= 65 = pure (-1)
  | otherwise = walletBundle 65 maximumMoney input callback context

elements_hs_wallet_bundle_anchor :: Int64 -> Ptr Word8 -> Word32 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
elements_hs_wallet_bundle_anchor maximumMoney input size callback context
  | size /= 161 = pure (-1)
  | otherwise = walletBundle 161 maximumMoney input callback context

walletBundle :: Int -> Int64 -> Ptr Word8 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
walletBundle inputSize maximumMoney input callback context
  | input == nullPtr || callback == nullFunPtr = pure (-1)
  | otherwise = catch (do
      request <- B.packCStringLen (castPtr input,inputSize)
      let effect action payout bytes = B.useAsCStringLen bytes $ \(inputPtr,inputLength) ->
            allocaArray 1 $ \reply -> do
              poke reply nullPtr
              size <- callWalletBundleEffect callback context action payout
                (castPtr inputPtr) (fromIntegral inputLength) reply
              ptr <- peekElemOff reply 0
              if ptr==nullPtr || (if action==0 then size<4 || size>2147483644 else size/=32)
                then ioError (userError "invalid bundle effect reply")
                else B.packCStringLen (castPtr ptr,fromIntegral size)
          build plan = effect 0 (Withdrawal.bundlePayout plan)
            (Withdrawal.bundleLayout plan <> Withdrawal.bundleFeeScript plan <> Withdrawal.bundleInputs plan <> Withdrawal.bundleMarker plan)
          inputRequest = Withdrawal.WithdrawalRequest maximumMoney request
          operation = if inputSize==161 then Withdrawal.AnchoredBundleRequest inputRequest (\action -> effect action 0) build
            else Withdrawal.WalletBundleRequest inputRequest build
      result <- execute operation Withdrawal.buildWalletBundle
      case result of
        Left (Withdrawal.BundleRejection _) -> pure 1
        Left (Withdrawal.AnchorRejection message) -> B.useAsCStringLen (C.pack message) $ \(ptr,size) -> do
          code <- callWalletBundleEffect callback context 4 0 (castPtr ptr) (fromIntegral size) nullPtr
          if code==0 then pure 2 else ioError (userError "bundle error publication failed")
        Right (_,transport) -> B.useAsCStringLen transport $ \(ptr,size) -> do
          code <- callWalletBundleEffect callback context 1 0 (castPtr ptr) (fromIntegral size) nullPtr
          if code==0 then pure 0 else ioError (userError "bundle publication failed")) (handleFailure (-1))

type ClaimBlockEffect = Ptr () -> Word32 -> Word64 -> Word64 -> Word64 -> Ptr Word8 -> IO Int64

elements_hs_grpc_text :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_grpc_text addressSize address authoritySize authority
  | any (> fromIntegral (maxBound :: Int)) [addressSize,authoritySize] ||
      (addressSize/=0 && address==nullPtr) || (authoritySize/=0 && authority==nullPtr) = pure (-1)
  | otherwise = (do
      a <- bytes address addressSize
      b <- bytes authority authoritySize
      pure (validate (Bmm.GrpcTextAdmission a b))) `catch` handleFailure (-1)
  where bytes ptr size = if size==0 then pure B.empty else B.packCStringLen (castPtr ptr,fromIntegral size)

elements_hs_grpc_plan :: Word32 -> Ptr (Ptr Word8) -> Ptr Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_grpc_plan count inputs lengths output capacity = run `catch` handleFailure (-1)
  where
    run | count `notElem` [1,2] || inputs==nullPtr || lengths==nullPtr = pure (-1)
        | otherwise = do
            pointers <- peekArray (fromIntegral count) inputs
            sizes <- peekArray (fromIntegral count) lengths
            if or (zipWith (\ptr size -> ptr==nullPtr && size/=0) pointers sizes) then pure (-1) else do
              fields <- sequence [if size==0 then pure B.empty else B.packCStringLen (castPtr ptr,fromIntegral size)
                                 | (ptr,size) <- zip pointers sizes]
              let plan = case fields of
                    [method] -> fmap (const []) (Bmm.grpcMethod method)
                    [method,payload] -> fmap (const []) (execute (Bmm.GrpcPlan method payload) Bmm.planGrpc)
                    _ -> error "invalid gRPC planner field count"
                  reply = either ((B.singleton 1 <>) . C.pack)
                    (\args -> B.singleton 0 <> B.concat [wordLE 4 (fromIntegral (B.length arg)) <> arg | arg <- args]) plan
              writeReply reply output capacity

foreign import ccall "dynamic" callClaimBlockEffect :: FunPtr ClaimBlockEffect -> ClaimBlockEffect
type ConfigurationHashEffect = Ptr () -> Word32 -> Ptr Word8 -> IO Int32
foreign import ccall "dynamic" callConfigurationHashEffect :: FunPtr ConfigurationHashEffect -> ConfigurationHashEffect
elements_hs_fee_asset :: Word32 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_fee_asset flags size input pegged output = run `catch` handleFailure (-1)
  where
    run | flags > 3 || pegged == nullPtr || output == nullPtr = pure (-1)
        | not (testBit flags 0) && size /= 0 = pure (-1)
        | testBit flags 0 && size /= 64 = pure 1
        | testBit flags 0 && input == nullPtr = pure (-1)
        | otherwise = do
            configured <- if testBit flags 0 then Just <$> B.packCStringLen (castPtr input,64) else pure Nothing
            asset <- B.packCStringLen (castPtr pegged,32)
            publishBytes 32 output (execute (Check (NodeRules.FeeAsset configured asset (testBit flags 1))) Validate)

elements_hs_ctv_admission :: Word32 -> Word64 -> IO Int32
elements_hs_ctv_admission flags size =
  evaluate (execute (Check (ScriptPolicy.TemplateAdmission flags size)) Validate) `catch` handleFailure (-1)

elements_hs_payment_uri :: Word32 -> Word32 -> IO Int32
elements_hs_payment_uri flags scheme =
  evaluate (execute (Check (NodeRules.PaymentUri flags scheme)) Validate) `catch` handleFailure (-1)

elements_hs_address_alias :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_address_alias flags networkSize network prefixSize prefix
  | flags>3 || any (> fromIntegral (maxBound :: Int)) [networkSize,prefixSize] ||
      (networkSize/=0 && network==nullPtr) || (prefixSize/=0 && prefix==nullPtr) = pure (-1)
  | otherwise = (do
      n <- bytes network networkSize
      p <- bytes prefix prefixSize
      evaluate (execute (Check (NodeRules.AddressAlias flags n p)) Validate)) `catch` handleFailure (-1)
  where bytes ptr size = if size==0 then pure B.empty else B.packCStringLen (castPtr ptr,fromIntegral size)

elements_hs_network_selection :: Word32 -> Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_network_selection mode flags size input = run `catch` handleFailure (-1)
  where
    run | mode>3 || flags>1 || (mode/=2 && flags/=0) || size>fromIntegral (maxBound::Int) ||
          (size/=0 && input==nullPtr) = pure (-1)
        | otherwise = do
            bytes <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
            pure (execute (Check (NodeRules.NetworkSelection mode flags bytes)) Validate)

elements_hs_bounded_wait :: Int64 -> Int64 -> IO Int64
elements_hs_bounded_wait value maximumWait =
  evaluate (execute (Check (Bmm.BoundedWait value maximumWait)) Validate) `catch` handleFailure (-1)

elements_hs_bounded_append :: Word64 -> Word64 -> Int64 -> IO Int64
elements_hs_bounded_append limit used count =
  evaluate (execute (Check (Bmm.BoundedAppend limit used count)) Validate) `catch` handleFailure (-1)

elements_hs_approving_parent_height :: Int64 -> IO Int64
elements_hs_approving_parent_height height =
  evaluate (execute (Check (Bmm.ApprovingParentHeight height)) Validate) `catch` handleFailure (-2)

elements_hs_child_behind :: Int64 -> Int64 -> IO Int32
elements_hs_child_behind child parent = guardResult (-1)
  (if execute (Check (Bmm.ChildBehind child parent)) Validate then 1 else 0)

elements_hs_unsigned32_fields :: Word64 -> Ptr Word64 -> IO Int32
elements_hs_unsigned32_fields count input = run `catch` handleFailure (-1)
  where
    run | count > fromIntegral (maxBound :: Int) `div` 8 || (count /= 0 && input == nullPtr) = pure (-1)
        | otherwise = do
            fields <- peekArray (fromIntegral count) input
            evaluate (if execute (Check (NodeRules.Unsigned32Fields fields)) Validate then 1 else 0)

elements_hs_export_range :: Word32 -> Int32 -> Int32 -> Int32 -> Int32 -> Ptr Int32 -> IO Int32
elements_hs_export_range mode start count activation tip output = run `catch` handleFailure (-1)
  where
    run | mode < 2 || mode > 3 || output == nullPtr || activation /= 0 ||
          (mode == 3 && (start /= 0 || count /= 0)) = pure (-1)
        | otherwise = case execute (Check (if mode == 3 then NodeRules.PegEventStart tip
            else NodeRules.PegEventRange start count tip)) Validate of
            Left code -> pure code
            Right end -> poke output end >> pure 0

elements_hs_configuration_field :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_configuration_field mode size input capacity output = run `catch` handleFailure (-1)
  where
    run | mode>9 || size>fromIntegral (maxBound::Int) || output==nullPtr || (size/=0 && input==nullPtr) = pure (-1)
        | mode==9 && (size<52 || size>65526) = pure (-2)
        | (mode==7 && size/=75) || (mode==8 && size>1024) = pure (-2)
        | mode==6 && size/=650 = pure (-2)
        | mode==5 && size>131072 = pure (-2)
        | otherwise = do
            bytes <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
            case execute (Check (NodeRules.ConfigurationField mode bytes)) Validate of
              Left code -> pure (fromIntegral (-1-code))
              Right encoded | fromIntegral (B.length encoded)<=capacity -> do
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (B.length encoded))
                pure (fromIntegral (B.length encoded))
              _ -> pure (-1)

elements_hs_pegin_confirmation_policy :: Word32 -> Int64 -> Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int64
elements_hs_pegin_confirmation_policy mode height configured = callbackCall runPolicyEffect (\readFact ->
  execute (Check (Deposit.ConfirmationPolicy mode height configured readFact)) Validate)

elements_hs_parent_message :: Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr Word16 -> IO Int32
elements_hs_parent_message count input fields output = run `catch` handleFailure (-1)
  where
    run | count > 0x7fffffff || (count /= 0 && input == nullPtr) || fields == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- peekArray (fromIntegral count) input
            (kind,encoding,votes) <- evaluate $ execute (Check (ParentReplay.Message bytes)) Validate
            mapM_ evaluate votes
            mapM_ evaluate [kind,encoding]
            pokeArray fields [kind,encoding]
            pokeArray output votes
            pure (fromIntegral (length votes))

elements_hs_parent_replay_record :: Word32 -> Word32 -> Int64 -> Word64 -> Word64 -> IO Int32
elements_hs_parent_replay_record kind flags value first second = guardResult (-1) $
  execute (Check (ParentReplay.Record kind flags value first second)) Validate

elements_hs_parent_replay_tip :: Word32 -> Word32 -> IO Int32
elements_hs_parent_replay_tip phase result = guardResult (-2) $
  execute (Check (ParentReplay.TipFlow phase result)) Validate

elements_hs_wallet_balance :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_wallet_balance trusted pending immature = guardResult (-1) $
  execute (Check (Withdrawal.WalletBalance [trusted,pending,immature])) Validate

elements_hs_parent_replay_store_checked :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_parent_replay_store_checked kind phase result
  | phase == maxBound = pure (if result==0 then ParentReplay.storeMaximum kind else -1)
  | otherwise = elements_hs_parent_replay_store kind phase result
elements_hs_parent_replay_store :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_parent_replay_store kind phase result = guardResult (-1) $
  replayStoreRule (\rule -> execute (Check rule) Validate) kind phase result

elements_hs_parent_replay_run :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_parent_replay_run kind = callbackCall callMatchFact (\action -> case kind of
  329 -> execute (ParentReplay.RpcPreparation action) ParentReplay.PrepareCredentials
  330 -> execute (ParentReplay.RpcPreparation action) ParentReplay.ConfigureTimeout
  331 -> execute (ParentReplay.RpcCall action) ParentReplay.CallRpc
  332 -> execute (ParentReplay.RpcCall action) ParentReplay.CallCheckedRpc
  333 -> execute (ParentCache.CacheInitialization action) ParentCache.InitializeReplayCache
  334 -> execute (Bmm.BodyRecovery action) Bmm.RecoverBody
  _ -> execute (Check (CommandFlow (ParentReplay.storeMaximum kind) (replayStoreRule validate kind) action)) Validate)

elements_hs_private_file_admission :: FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_private_file_admission = callbackCall callMatchFact (\action ->
  execute (Check (Bmm.PrivateFileAdmission action)) Validate)

predicateCall :: Bool -> Word32 -> Int64 -> (Word32 -> Word32 -> Int64) -> FunPtr MatchFact -> Ptr () -> IO Int32
predicateCall acceptZero start maximumStep transition = callbackCall callMatchFact (\action ->
  execute (Check (PredicateFlow acceptZero start maximumStep transition action)) Validate)

elements_hs_parent_replay_tip_run :: FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_parent_replay_tip_run = predicateCall True 0 51 (\phase result -> fromIntegral (validate (ParentReplay.TipFlow phase result)))

elements_hs_deposit_run :: Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_deposit_run kind start callback context
  | kind /= 0 && kind /= 5 && start /= 0 = pure (-1)
  | otherwise = case kind of
      0 -> run True 82 (\phase result -> fromIntegral (validate (Deposit.DepositVerification phase result)))
      1 -> run False 17 (\phase result -> validate (Deposit.WithdrawalStatusFlow phase result))
      2 -> run False 34 (\phase result -> validate (Deposit.L1Normalization phase result))
      3 -> run False 27 (\phase result -> validate (Deposit.SidechainEvents phase result))
      4 -> run False 6 (\phase result -> validate (Deposit.L1Location phase result))
      5 -> callbackCall callMatchFact (\action -> execute (Check (Deposit.DepositStateWorkflow start action)) Validate) callback context
      _ -> pure (-1)
  where run acceptZero maximumStep transition = predicateCall acceptZero start maximumStep transition callback context

replayStoreRule :: (forall rule. (Typeable rule, Validation rule, ValidationResult rule ~ Int32) => rule -> Int32)
  -> Word32 -> Word32 -> Word32 -> Int32
replayStoreRule apply kind phase result =
  if ParentReplay.retiredStoreKind kind then -1
  else if kind == 132 then apply (DestinationFlow phase result)
  else if kind == 133 then -1 -- Retired wallet bundle flow; preserve later ABI IDs.
  else if kind == 134 then apply (EventFlow phase result)
  else if kind == 135 then apply (SubmissionFlow phase result)
  else if kind == 136 then apply (OutputFlow phase result)
  else if kind == 137 then apply (Deposit.BroadcastFlow phase result)
  else if kind == 138 then apply (Deposit.SatoshiFlow phase result)
  else if kind == 139 then apply (Deposit.SponsorshipFlow phase result)
  else if kind == 140 then apply (Deposit.ImportFlow phase result)
  else if kind == 141 then apply (Deposit.NativeImportFlow phase result)
  else if kind == 142 then apply (Deposit.DefaultWalletFlow phase result)
  else if kind == 143 then apply (PreflightFlow phase result)
  else if kind == 144 then apply (Bmm.GrpcConfigFlow phase result)
  else if kind == 145 then apply (Bmm.GrpcRequestFlow phase result)
  else if kind == 146 then apply (Bmm.GrpcExecutableFlow phase result)
  else if kind == 147 then apply (Bmm.RpcServerFlow phase result)
  else if kind == 148 then apply (Bmm.CredentialFlow phase result)
  else if kind == 177 then apply (JournalReadFlow phase result)
  else if kind == 178 || kind == 179 then apply (JournalPersistFlow (kind==179) phase result)
  else if kind == 180 then apply (RpcBurnFlow phase result)
  else if kind == 181 then apply (RpcClaimFlow phase result)
  else if kind == 182 then apply (RpcVerifyFlow phase result)
  else if kind == 184 || kind == 185 then apply (Bmm.ChildMonitorFlow (kind == 185) phase result)
  else if kind == 186 then apply (Bmm.ChildReapFlow phase result)
  else if kind == 187 then apply (Bmm.ChildDrainFlow phase result)
  else if kind == 190 then apply (Bmm.RecoveryPeerFlow phase result)
  else if kind == 191 then apply (Bmm.RecoveryBodyFlow phase result)
  else if kind == 192 || kind == 193 then apply (Bmm.RecoveryReplyFlow (kind==192) phase result)
  else if kind == 194 then apply (Bmm.RecoveryHeaderFlow phase result)
  else if kind == 195 then apply (Bmm.RecoveryPeerReplyFlow phase result)
  else if kind == 196 then apply (Bmm.CredentialFileFlow phase result)
  else if kind == 197 then apply (Bmm.GrpcRequestAdmission phase result)
  else if kind >= 198 && kind <= 200 then -1 -- Retired LWK dialog; reserve ABI IDs.
  else if kind == 201 then apply (Withdrawal.WalletIssueFlow False phase result)
  else if kind == 202 then apply (Withdrawal.WalletIssueFlow True phase result)
  else if kind == 203 then apply (Bmm.PeerBlockFlow phase result)
  else if kind == 204 then apply (Bmm.PeerTimerFlow phase result)
  else if kind == 205 then apply (Bmm.PeerHeadersFlow phase result)
  else if kind == 206 then apply (Bmm.PeerDispatchFlow phase result)
  else if kind == 207 then apply (ParentReplay.IndexDerivedFlow phase result)
  else if kind == 208 then apply (ParentReplay.IndexContinuityFlow phase result)
  else if kind == 210 || kind == 211 then apply (Bmm.HeaderAdmissionFlow (kind==211) phase result)
  else if kind == 213 then apply (Bmm.TemplateParentFlow phase result)
  else if kind == 214 then apply (Bmm.TemplateAdmissionFlow phase result)
  else if kind == 215 then apply (Bmm.TemplateSelectionFlow phase result)
  else if kind == 216 then apply (Bmm.TemplateCommitmentFlow phase result)
  else if kind == 218 then apply (Deposit.FeeFreeSelectionFlow phase result)
  else if kind == 228 then apply (Bmm.ChildPreflightFlow phase result)
  else if kind == 229 then apply (Bmm.ReverificationFlow phase result)
  else if kind == 230 then apply (Bmm.SyncPreflightFlow phase result)
  else if kind == 231 then apply (Bmm.SyncLoopFlow phase result)
  else if kind == 232 then apply (Bmm.BidParentFlow phase result)
  else if kind == 233 then apply (Withdrawal.WalletCommandFlow phase result)
  else if kind == 234 then apply (Bmm.MinedPreflightFlow phase result)
  else if kind == 235 then apply (ParentReplay.ConfiguredSlotFlow phase result)
  else if kind == 236 then apply (Bmm.CacheRoutingFlow phase result)
  else if kind == 237 || kind == 238 then apply (ParentReplay.RequiredFactsFlow (if kind==237 then 3 else 2) phase result)
  else if kind == 239 then apply (Bmm.ConfiguredBidFlow phase result)
  else if kind == 240 then apply (Bmm.ParsedBidFlow phase result)
  else if kind == 241 then apply (Bmm.FundedSubmissionFlow phase result)
  else if kind == 242 then apply (Bmm.CommitmentProbe phase result)
  else if kind == 243 then apply (Bmm.SuccessorProbe phase result)
  else if kind == 244 then apply (Bmm.TemplateCreationFlow phase result)
  else if kind == 245 then apply (Bmm.RewardWalletFlow phase result)
  else if kind == 248 then apply (ParentReplay.RequiredFactsFlow 4 phase result)
  else if kind == 256 then apply (ParentReplay.ParentRequestFlow phase result)
  else if kind == 257 then apply (Withdrawal.BundleEventFlow False phase result)
  else if kind == 258 then apply (Withdrawal.BundleEventFlow True phase result)
  else if kind == 260 then apply (NodeRules.ParentReportFlow phase result)
  else if kind == 264 || kind == 265 then apply (Bmm.PeerAdmissionFlow (kind==265) phase result)
  else if kind == 267 then apply (ParentReplay.RequiredFactsFlow 7 phase result)
  else if kind == 268 then apply (Deposit.NativeAdmissionFlow phase result)
  else if kind == 270 then apply (Withdrawal.NativeSubmissionFlow phase result)
  else if kind == 273 then apply (Bmm.CredentialRecordFlow phase result)
  else if kind == 275 then apply (Bmm.PeerBlockDispatchFlow phase result)
  else if kind == 277 then apply (Deposit.MempoolWitnessFlow phase result)
  else if kind == 278 then -1 -- Retired: inherited witness checks remain native.
  else if kind == 279 then apply (Bmm.CanonicalMatchFlow phase result)
  else if kind == 280 then apply (ParentReplay.ExplicitVoteFlow phase result)
  else if kind == 282 then apply (Deposit.BlockPreflightFlow phase result)
  else if kind == 283 then apply (ParentReplay.BranchReplayFlow phase result)
  else if kind == 284 then apply (ParentReplay.RecoveryAncestorFlow phase result)
  else if kind == 285 then apply (ParentReplay.RecoveryAdmissionFlow phase result)
  else if kind == 286 then apply (ParentReplay.EphemeralHeaderFlow phase result)
  else if kind == 287 then apply (ParentReplay.ConnectionAnchorFlow phase result)
  else if kind == 288 then apply (ParentReplay.ConnectionStateFlow phase result)
  else if kind == 291 then apply (ParentReplay.StartupParentFlow ParentReplay.ParentServe phase result)
  else if kind == 294 then apply (ParentReplay.RequiredPairFlow phase result)
  else if kind == 296 then apply (Bmm.ConnectionContextFlow phase result)
  else if kind == 297 then apply (Bmm.SnapshotPrepareFlow phase result)
  else if kind == 298 then apply (Bmm.AnchorCacheFlow phase result)
  else if kind == 299 then apply (Bmm.AnchorPublishFlow phase result)
  else if kind == 300 then apply (Bmm.AnchorDisconnectFlow phase result)
  else if kind == 301 then apply (Bmm.CandidateAdmissionFlow phase result)
  else if kind == 302 then apply (Bmm.SnapshotBacklogFlow phase result)
  else if kind == 303 then apply (Bmm.AnchorReplacementFlow phase result)
  else if kind == 304 then apply (Bmm.ReconciliationGate phase result)
  else if kind == 305 then apply (Bmm.AnchorOrder phase result)
  else if kind == 306 then apply (Bmm.AnchorCollect phase result)
  else if kind == 307 then apply (Bmm.ProductionRoutingFlow phase result)
  else if kind == 308 then apply (Bmm.BlockPreparationFlow phase result)
  else if kind == 309 then apply (Bmm.BlockAcceptanceFlow phase result)
  else if kind == 310 then apply (ParentReplay.MempoolSweepPreflight phase result)
  else if kind == 311 then apply (ParentReplay.ParentRpcHostFlow phase result)
  else if kind == 312 then apply (Bmm.FullBlockPreflight phase result)
  else if kind == 313 then apply (Bmm.BlockAnchorAdmission phase result)
  else if kind == 314 then apply (Bmm.BlockAnchorPublication phase result)
  else if kind == 315 || kind == 316 then apply (ParentReplay.StartupParentFlow
    (if kind == 315 then ParentReplay.ParentLoad else ParentReplay.ParentVerify) phase result)
  else if kind == 317 then apply (ParentReplay.StartupBundleFlow phase result)
  else if kind >= 318 && kind <= 320 then apply (ParentReplay.BlockValidationFlow
    (case kind of 318 -> ParentReplay.ContextualHeader; 319 -> ParentReplay.ContextualOutputs; _ -> ParentReplay.CandidateSelfCheck) phase result)
  else if kind == 321 || kind == 322 then apply (ParentReplay.BlockValidationFlow
    (if kind == 321 then ParentReplay.BranchChoice else ParentReplay.StartupReconcile) phase result)
  else if kind == 324 || kind == 325 then apply (ParentReplay.BlockValidationFlow
    (if kind == 324 then ParentReplay.FinalBmm else ParentReplay.BmmFailure) phase result)
  else apply (ParentReplay.StoreFlow kind phase result)

elements_hs_bmm_identity :: Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_bmm_identity fields payload = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || payload == nullPtr = pure (-1)
        | otherwise = do
            (numbers,bytes) <- evaluate $ execute (Check Bmm.FixedIdentity) Validate
            mapM_ evaluate numbers
            mapM_ evaluate bytes
            pokeArray fields numbers
            pokeArray payload bytes
            pure 0

elements_hs_bmm_checkpoint :: Word32 -> Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_bmm_checkpoint mode fields blockHash = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || blockHash == nullPtr = pure (-1)
        | otherwise = do
            (numbers,bytes) <- evaluate $ execute (Check (Bmm.CheckpointPreset mode)) Validate
            mapM_ evaluate numbers
            mapM_ evaluate bytes
            pokeArray fields numbers
            pokeArray blockHash bytes
            pure 0

elements_hs_bmm_preset :: Word32 -> Ptr Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bmm_preset mode fields powLimit challenge = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || powLimit == nullPtr || challenge == nullPtr = pure (-1)
        | otherwise = do
            (numbers,limit,script) <- evaluate $ execute (Check (Bmm.ConsensusPreset mode)) Validate
            mapM_ evaluate numbers
            mapM_ evaluate limit
            mapM_ evaluate script
            pokeArray fields numbers
            pokeArray powLimit limit
            pokeArray challenge script
            pure (fromIntegral (length script))

elements_hs_bmm_interval :: Int64 -> Int64 -> Ptr Int64 -> IO Int32
elements_hs_bmm_interval timespan spacing output = run `catch` handleFailure (-1)
  where
    run | output == nullPtr = pure (-1)
        | otherwise = do
            interval <- evaluate $ execute (Check (Bmm.DifficultyInterval timespan spacing)) Validate
            poke output interval
            pure 0

elements_hs_bmm_header_layout :: Word32 -> Word32 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_bmm_header_layout version flags count output
  | count /= 2 || output == nullPtr = pure (-1)
  | otherwise = run `catch` handleFailure (-1)
  where
    run = case execute (Check (Bmm.HeaderLayout version flags)) Validate of
      Nothing -> pure (-1)
      Just (encoded,fields) -> do
        values <- mapM evaluate [encoded,fields]
        pokeArray output values
        pure 0

elements_hs_bmm_commitment_bytes :: Word32 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bmm_commitment_bytes kind count input output = run `catch` handleFailure (-1)
  where
    run | count > 37 || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- peekArray (fromIntegral count) input
            payload <- evaluate $ execute (Check (Bmm.CommitmentBytes kind bytes)) Validate
            mapM_ evaluate payload
            pokeArray output payload
            pure 0

elements_hs_bmm_signet_template :: Word32 -> Ptr Word32 -> IO Int32
elements_hs_bmm_signet_template count fields = run `catch` handleFailure (-1)
  where
    run | count /= 6 || fields == nullPtr = pure (-1)
        | otherwise = do
            values <- evaluate $ execute (Check Bmm.SignetTemplate) Validate
            mapM_ evaluate values
            pokeArray fields values
            pure 0

elements_hs_bmm_split_signature :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_bmm_split_signature count bytes prefixSize = run `catch` handleFailure (-1)
  where
    run | count == 0 || count > fromIntegral (maxBound :: Int) || bytes == nullPtr || prefixSize == nullPtr = pure (-1)
        | otherwise = do
            signature <- peekArray (fromIntegral count) bytes
            (size, hashType) <- evaluate $ execute (Check (Bmm.SignatureBytes signature)) Validate
            result <- evaluate (fromIntegral hashType)
            poke prefixSize size
            pure result

elements_hs_bmm_preimage :: Word32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_preimage kind = bmmActions (execute (Check (Bmm.Preimage kind)) Validate)

elements_hs_bmm_signature_actions :: Word32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_signature_actions plan = bmmActions (execute (Check (Bmm.SignatureActions plan)) Validate)

elements_hs_bmm_signet_actions :: Word32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_signet_actions mode = bmmActions (execute (Check (Bmm.SignetActions mode)) Validate)

bmmActions :: [Word32] -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
bmmActions plan writer context = run `catch` handleFailure (-1)
  where
    run = do
      fields <- evaluate plan
      mapM_ (\field -> Bmm.stateAction (Bmm.StateWrite 0 writer context) field 0) fields
      pure 1

elements_hs_bmm_private_template :: Word32 -> Word32 -> Word32 -> Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_bmm_private_template height time median slot critical fields commitment = run `catch` handleFailure (-1)
  where
    run | critical == nullPtr || fields == nullPtr || commitment == nullPtr = pure (-1)
        | otherwise = do
            bytes <- peekArray 32 critical
            (values, payload) <- evaluate $ execute (Check (Bmm.PrivateTemplate height time median slot bytes)) Validate
            mapM_ evaluate values
            mapM_ evaluate payload
            pokeArray fields values
            pokeArray commitment payload
            pure 0

elements_hs_bmm_encode_state :: FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_encode_state writer context =
  (execute (Bmm.StateEncode (Bmm.StateWrite 0 writer context)) Bmm.encodeState >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_store_state :: Int32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_store_state height writer context =
  (execute (Bmm.StateWrite height writer context) Bmm.replaceState >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_restore_state :: Int32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_restore_state height writer context =
  (execute (Bmm.StateRestore height writer context) Bmm.replaceState >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_scale_target :: Word32 -> Word64 -> Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bmm_scale_target count factor divisor target limit = run `catch` handleFailure (-1)
  where
    run | count /= 32 || target == nullPtr || limit == nullPtr = pure (-1)
        | otherwise = do
            old <- peekArray 32 target
            bound <- peekArray 32 limit
            result <- evaluate $ execute (Check (Bmm.TargetScale factor divisor old bound)) Validate
            mapM_ evaluate result
            pokeArray target result
            pure 0

type WriteFingerprint = Ptr () -> Ptr Word8 -> Word64 -> IO Int32
foreign import ccall "dynamic" writeFingerprint :: FunPtr WriteFingerprint -> WriteFingerprint
elements_hs_bmm_fingerprint :: Word32 -> FunPtr Bmm.ReadFingerprint -> FunPtr WriteFingerprint -> Ptr () -> IO Int32
elements_hs_bmm_fingerprint profile reader writer context = run `catch` handleFailure (-1)
  where
    run | profile /= 0 || writer == nullFunPtr = pure (-1)
        | otherwise = do
            bytes <- execute (Bmm.FingerprintRequest reader context)
              (Bmm.fingerprint Bmm.BmmFormat)
            withArrayLen bytes $ \size ptr -> writeFingerprint writer context ptr (fromIntegral size)

data DepositDepth = DepositDepth Word32 Word32 Word32
instance Validation DepositDepth where
  type ValidationResult DepositDepth = Int32
  validate (DepositDepth deposit tip required) =
    if Deposit.hasDepositDepth deposit tip required then 1 else 0

data TreasuryMatch = TreasuryMatch Int32 (IO Int32)
instance Validation TreasuryMatch where
  type ValidationResult TreasuryMatch = IO Bool
  validate (TreasuryMatch expected readSlot)
    | expected < 0 || expected > 255 = pure False
    | otherwise = (==expected) <$> readSlot

elements_hs_treasury_match :: Int32 -> Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_treasury_match expected opcode size input = (do
    matches <- execute (Check (TreasuryMatch expected readSlot)) Validate
    pure (if matches then 1 else 0)) `catch` handleFailure (-1)
  where
    readSlot
      | size/=4 || input==nullPtr = pure (-1)
      | otherwise = do
          bytes <- B.packCStringLen (castPtr input,4)
          evaluate (execute (Check (TreasuryScript (fromIntegral (Withdrawal.readLE bytes)) opcode)) Validate)

data TreasuryScript = TreasuryScript Word32 Word32
instance Validation TreasuryScript where
  type ValidationResult TreasuryScript = Int32
  validate (TreasuryScript script opcode) =
    ParentReplay.treasurySlot script opcode

-- Negative fault sentinels are distinct from every consensus rejection.
-- Never allow a Haskell exception to unwind through a C++ stack frame.
guardResult :: a -> a -> IO a
guardResult failure result = evaluate result `catch` handleFailure failure

handleFailure :: a -> SomeException -> IO a
handleFailure failure _ = pure failure

elements_hs_bmm_state :: Word32 -> Int64 -> Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> Word64 -> Word32 -> IO Int32
elements_hs_bmm_state hash interval height time bits start startTime count latest = guardResult (-1) $
  execute (Check (Bmm.ParentState hash interval height time bits start startTime count latest)) Validate

elements_hs_signet_validation :: Word32 -> Word64 -> Word64 -> Word64 -> Word64 -> IO Int32
elements_hs_signet_validation phase a b c d = guardResult (-7) $
  execute (Check (Bmm.SignetValidation phase a b c d)) Validate

elements_hs_bmm_proof_run :: Word32 -> Word32 -> FunPtr ProofFacts -> Ptr () -> IO Int32
elements_hs_bmm_proof_run kind start = factsCall (peekArray 4) (\action ->
  execute (Check (Bmm.ProofExecution kind start action)) Validate)

elements_hs_bmm_proof_workflow :: Word32 -> FunPtr ProofFacts -> Ptr () -> IO Int32
elements_hs_bmm_proof_workflow start = factsCall (peekArray 4) (\action ->
  execute (Check (Bmm.ProofWorkflow start action)) Validate)

elements_hs_bmm_signature_workflow :: Word32 -> Int32 -> Word32 -> Word32 -> Word64 -> Word64 -> Word64 -> Ptr Word8 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_bmm_signature_workflow mode hashType witness index inputs outputs size bytes effect context =
  run `catch` handleFailure (-1)
  where
    native = nativeBytes effect context
    run
      | mode == 2 = execute (Bmm.SignatureHashWorkflow hashType index outputs native) Bmm.RunSignature
      | mode > 1 || size > fromIntegral (maxBound :: Int) || (size /= 0 && bytes == nullPtr) = pure (-1)
      | otherwise = do
          signature <- if size == 0 then pure B.empty else B.packCStringLen (castPtr bytes,fromIntegral size)
          execute (Bmm.SignatureVerifyWorkflow mode witness index inputs outputs signature native) Bmm.RunSignature

factsCall :: (Ptr Word64 -> IO reply) -> ((Word32 -> IO reply) -> IO Int32) -> FunPtr ProofFacts -> Ptr () -> IO Int32
factsCall decode run callback context
  | callback == nullFunPtr = pure minBound
  | otherwise = (`catch` handleFailure minBound) $ allocaArray 4 $ \fields ->
      run (\phase -> do
        pokeArray fields [0,0,0,0]
        status <- callProofFacts callback context phase fields
        if status == 1 then decode fields else ioError (userError "fact callback failed"))

elements_hs_peg_read_run :: Word32 -> Word32 -> Word64 -> FunPtr ProofFacts -> Ptr () -> IO Int32
elements_hs_peg_read_run mode kind limit = factsCall (`peekElemOff` 0) (\action ->
  execute (Check (Deposit.ReadExecution mode kind limit action)) Validate)

elements_hs_bmm_state_flow :: Word32 -> Int32 -> IO Int32
elements_hs_bmm_state_flow phase reply = guardResult (-2) $
  execute (Check (Bmm.StateFlow phase reply)) Validate

elements_hs_bmm_state_run :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_bmm_state_run start = callbackCall callMatchFact (\action ->
  execute (Check (Bmm.StateExecution start action)) Validate)

elements_hs_bmm_state_workflow :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_bmm_state_workflow start = callbackCall callMatchFact (\action ->
  execute (Check (Bmm.StateWorkflow start action)) Validate)

elements_hs_bmm_lifecycle :: Word32 -> Word32 -> IO Int32
elements_hs_bmm_lifecycle phase facts = guardResult (-8) $
  execute (Check (Bmm.Lifecycle phase facts)) Validate

elements_hs_bmm_state_source :: Word32 -> Word32 -> IO Int32
elements_hs_bmm_state_source phase facts = guardResult (-4) $
  execute (Check (Bmm.StateSource phase facts)) Validate

elements_hs_bmm_advance :: Int64 -> Word32 -> Word32 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_bmm_advance interval time bits count fields
  | count /= 16 || fields == nullPtr = pure (-1)
  | otherwise = (do
      input <- peekArray 16 fields
      output <- mapM evaluate (execute (Check (Bmm.Advance interval time bits input)) Validate)
      pokeArray fields output
      pure 0) `catch` handleFailure (-1)

elements_hs_bmm_traversal :: Word32 -> Word64 -> Word64 -> IO Int32
elements_hs_bmm_traversal phase a b = guardResult (-3) $
  execute (Check (Bmm.Traversal phase a b)) Validate

elements_hs_bmm_codec :: Word32 -> Word32 -> Word64 -> Word64 -> IO Int32
elements_hs_bmm_codec phase facts a b = guardResult (-1) $
  execute (Check (Bmm.Codec phase facts a b)) Validate

elements_hs_bmm_sighash_plan :: Int32 -> Word32 -> Word64 -> IO Int32
elements_hs_bmm_sighash_plan hashType index outputs = guardResult (-1) $
  execute (Check (Bmm.HashPlan hashType index outputs)) Validate

elements_hs_bmm_signature_gate :: Word32 -> Word64 -> Word32 -> Word64 -> IO Int32
elements_hs_bmm_signature_gate witness size index inputs = guardResult (-1) $
  execute (Check (Bmm.SignatureGate witness size index inputs)) Validate

elements_hs_signet_extract :: FunPtr Deposit.ReadPegFields -> Ptr () -> IO Int32
elements_hs_signet_extract reader context =
  execute (Bmm.SignetRequest reader context) Bmm.extractSignetRequest `catch` handleFailure (-1)

elements_hs_bmm_retarget_workflow :: Word32 -> Int64 -> Int64 -> Word32 -> Word32 -> FunPtr NativeBytesEffect -> Ptr () -> IO Int32
elements_hs_bmm_retarget_workflow height interval target time start effect context =
  execute (Check (Bmm.RetargetWorkflow height interval target time start (nativeBytes effect context))) Validate
    `catch` handleFailure (-1)

elements_hs_bmm_retarget :: Word32 -> Int64 -> Int64 -> Word32 -> Word32 -> IO Int64
elements_hs_bmm_retarget height interval target time start = guardResult (-2) $
  execute (Check (Bmm.Retarget height interval target time start)) Validate

elements_hs_bmm_median :: Word32 -> Ptr Word32 -> IO Int64
elements_hs_bmm_median = bmmMedian Bmm.Median

elements_hs_bmm_parent_median :: Word32 -> Ptr Word32 -> IO Int64
elements_hs_bmm_parent_median = bmmMedian Bmm.ParentMedian

bmmMedian :: ([Word32] -> Bmm.Timing) -> Word32 -> Ptr Word32 -> IO Int64
bmmMedian operation count times = run `catch` handleFailure (-2)
  where
    run | count == 0 || times == nullPtr = pure (-2)
        | otherwise = do
            values <- peekArray (fromIntegral count) times
            guardResult (-2) $ execute (Check (operation values)) Validate

elements_hs_bmm_commitment :: Word32 -> Int32 -> Word32 -> FunPtr Bmm.ReadScript -> Ptr () -> IO Int64
elements_hs_bmm_commitment kind slot count reader context =
  execute (Check (Bmm.Commitment kind slot count reader context)) Validate `catch` handleFailure (-3)

elements_hs_bmm_header :: Word32 -> IO Int32
elements_hs_bmm_header facts = guardResult (-1) $ execute (Check (Bmm.Header facts)) Validate

elements_hs_bmm_activation :: Word32 -> Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_bmm_activation phase facts height activation = guardResult (-1) $
  execute (Check (Bmm.Activation phase facts height activation)) Validate

elements_hs_bmm_proof :: Word32 -> Word32 -> Word64 -> Word64 -> Word64 -> IO Int32
elements_hs_bmm_proof phase facts a b c = guardResult (-1) $
  execute (Check (Bmm.Proof phase facts a b c)) Validate

elements_hs_peg_event :: Word32 -> Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_peg_event kind a b c = guardResult (-6) $
  execute (Check (Deposit.PegEvent kind a b c)) Validate

elements_hs_withdrawal_status :: Int64 -> Ptr Word8 -> Word32 -> IO Int64
elements_hs_withdrawal_status state input size = run `catch` handleFailure (-6)
  where run = do
          status <- B.packCStringLen (castPtr input, fromIntegral size)
          guardResult (-6) $ execute (Check (Deposit.WithdrawalStatus state status)) Validate

elements_hs_live_evidence :: Word32 -> FunPtr Deposit.ReadPegFields -> Ptr () -> IO Int32
elements_hs_live_evidence phase reader context
  | reader == nullFunPtr = pure (-2)
  | otherwise = execute (Check (Deposit.LiveEvidence phase reader context)) Validate
      `catch` handleFailure (-2)

writeReply :: B.ByteString -> Ptr Word8 -> Word32 -> IO Int32
writeReply reply output capacity
  | B.length reply > fromIntegral capacity = pure (-1)
  | B.null reply = pure 0
  | otherwise = B.useAsCStringLen reply $ \(source,count) ->
      copyBytes output (castPtr source) count >> pure (fromIntegral count)

elements_hs_event_identity :: Word32 -> Ptr Word8 -> Word32 -> Word64 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_event_identity kind input size number status output capacity = run `catch` handleFailure (-1)
  where run
          | size > 64 = pure (-1)
          | otherwise = do
              hash <- B.packCStringLen (castPtr input, fromIntegral size)
              writeReply (execute (Check (Deposit.EventIdentity kind hash number status)) Validate) output capacity

elements_hs_event_layout :: Word32 -> Word32 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_event_layout kind index status keyBuffer valueBuffer capacity sizes = run `catch` handleFailure (-1)
  where run = case execute (Check (Deposit.EventLayout kind index status)) Validate of
          Nothing -> pure 0
          Just (key,value,terminal) -> do
            let literal = maybe B.empty id value
            if B.length key > fromIntegral capacity || B.length literal > fromIntegral capacity ||
                sizes == nullPtr || keyBuffer == nullPtr || (not (B.null literal) && valueBuffer == nullPtr)
              then pure (-1)
              else do
                _ <- writeReply key keyBuffer capacity
                _ <- writeReply literal valueBuffer capacity
                pokeArray sizes [fromIntegral (B.length key), fromIntegral (B.length literal)]
                pure (maybe 1 (const 2) value + if terminal then 256 else 0)

elements_hs_checkpoint :: Word32 -> Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_checkpoint eligible txid previous vout output capacity =
  (execute (Check (Deposit.CheckpointLookup eligible txid previous vout)) Validate >>=
    \reply -> writeReply reply output capacity) `catch` handleFailure (-1)

elements_hs_legacy_claim :: Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_legacy_claim facts actual expected = guardResult (-1) $
  execute (Check (Deposit.LegacyClaim facts actual expected)) Validate

elements_hs_treasury_delta :: Int64 -> Int64 -> Int64 -> Int64 -> IO Int32
elements_hs_treasury_delta previous current claimed maximumValue = guardResult (-1) $
  fromIntegral . fromEnum $ execute (Check (Deposit.TreasuryDelta previous current claimed maximumValue)) Validate

elements_hs_deposit_preflight :: Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_deposit_preflight rule amount bound = guardResult (-1) $
  execute (Check (Deposit.Preflight rule amount bound)) Validate

elements_hs_deposit_broadcast_message :: Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_deposit_broadcast_message kind size input
  | kind>2 || size>fromIntegral (maxBound :: Int) || (size/=0 && input==nullPtr) = pure (-1)
  | otherwise = (do
      message <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
      evaluate (execute (Check (Deposit.MessageMatches kind message)) Validate)) `catch` handleFailure (-1)

elements_hs_deposit_destination :: Word32 -> FunPtr Deposit.InspectDestination -> Ptr () -> IO Int64
elements_hs_deposit_destination count inspector context =
  execute (Check (Deposit.DepositDestination count inspector context)) Validate `catch` handleFailure (-3)

elements_hs_sidechain_events :: Word32 -> Word32 -> IO Int64
elements_hs_sidechain_events phase result = guardResult (-2) $
  execute (Check (Deposit.SidechainEvents phase result)) Validate

elements_hs_l1_location :: Word32 -> Word32 -> IO Int64
elements_hs_l1_location phase result = guardResult (-2) $
  execute (Check (Deposit.L1Location phase result)) Validate

elements_hs_peg_schema :: Word32 -> Word32 -> Word64 -> Word64 -> IO Int64
elements_hs_peg_schema kind phase value limit = guardResult (-2) $
  execute (Check (Deposit.PegSchema kind phase value limit)) Validate

elements_hs_l1_normalization :: Word32 -> Word32 -> IO Int64
elements_hs_l1_normalization phase result = guardResult (-2) $
  execute (Check (Deposit.L1Normalization phase result)) Validate

elements_hs_withdrawal_status_flow :: Word32 -> Word32 -> IO Int64
elements_hs_withdrawal_status_flow phase result = guardResult (-2) $
  execute (Check (Deposit.WithdrawalStatusFlow phase result)) Validate

elements_hs_deposit_projection :: Word32 -> Word64 -> IO Int32
elements_hs_deposit_projection phase value = guardResult (-1) $
  execute (Check (Deposit.DepositProjection phase value)) Validate

elements_hs_deposit_verification :: Word32 -> Word32 -> IO Int32
elements_hs_deposit_verification phase result = guardResult (-2) $
  execute (Check (Deposit.DepositVerification phase result)) Validate

elements_hs_deposit_state :: Word32 -> Word32 -> IO Int32
elements_hs_deposit_state phase facts = guardResult (-1) $
  execute (Check (Deposit.DepositStateRule phase facts)) Validate

elements_hs_ctip_script :: FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_ctip_script reader context =
  execute (Check (Deposit.CtipScript (Deposit.readCtipOpcode reader context))) Validate
    `catch` handleFailure (-1)

elements_hs_persisted_ctip :: Word32 -> Int64 -> Word32 -> FunPtr Deposit.DecodeCtip -> Ptr () -> IO Int32
elements_hs_persisted_ctip facts amount script decoder context =
  execute (Check (Deposit.PersistedCtip facts amount script decoder context)) Validate
    `catch` handleFailure (-1)

elements_hs_persisted_ctip_workflow :: Word32 -> Int64 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> FunPtr Deposit.DecodeCtip -> Ptr () -> IO Int32
elements_hs_persisted_ctip_workflow facts amount reader context decoder payload =
  callbackCall Deposit.readCtipOpcode (\readOpcode ->
    execute (Check (Deposit.PersistedCtipWorkflow facts amount readOpcode decoder payload)) Validate) reader context

elements_hs_deposit_inclusion :: Word32 -> Word64 -> Word32 -> FunPtr Deposit.CheckParentHeader -> Ptr () -> IO Int32
elements_hs_deposit_inclusion facts matches count checker context =
  execute (Check (Deposit.DepositInclusion facts matches count checker context)) Validate
    `catch` handleFailure (-1)

elements_hs_deposit_ctip :: Word32 -> Word64 -> Int64 -> Int64 -> Int64 -> IO Int32
elements_hs_deposit_ctip facts matches current previous witnessed = guardResult (-1) $
  execute (Check (Deposit.DepositCtip facts matches current previous witnessed)) Validate

elements_hs_deposit_evidence :: Word32 -> Word32 -> Ptr Word32 -> Ptr (Ptr Word8) -> Ptr Word8
  -> FunPtr Deposit.HashTransaction -> FunPtr Deposit.DecodeEvidence -> Ptr () -> IO Int32
elements_hs_deposit_evidence maximumTx count sizes fields prevout hasher decoder context =
  execute (Check (Deposit.DeterministicEvidence maximumTx count sizes fields prevout hasher decoder context)) Validate
    `catch` handleFailure (-1)

elements_hs_authenticated_deposit :: Word64 -> Word64 -> Word64 -> Word32 -> Int64 -> Int64
  -> Word64 -> Ptr Word8 -> Ptr Int64 -> IO Int32
elements_hs_authenticated_deposit inputs index witnesses facts claimed witnessed count flags amounts =
  (Deposit.authenticatedRules inputs index witnesses facts claimed witnessed count flags amounts >>= evaluate)
    `catch` handleFailure (-1)

elements_hs_deposit_witness :: Int64 -> Word32 -> Word32 -> Word32 -> Ptr Word32 -> Ptr (Ptr Word8)
  -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> FunPtr Deposit.HashTransaction -> Ptr Int64 -> IO Int32
elements_hs_deposit_witness maximumMoney maximumTx mode count sizes fields asset genesis prevout hasher value =
  execute (Check (Deposit.DepositWitness maximumMoney maximumTx mode count sizes fields asset genesis prevout hasher value))
    Validate
    `catch` handleFailure (-1)

elements_hs_deposit_outputs :: Word32 -> Int64 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Int64 -> IO Int32
elements_hs_deposit_outputs facts value inputCount inputs outputCount flags amounts =
  (Deposit.outputRules facts value inputCount inputs outputCount flags amounts >>= evaluate)
    `catch` handleFailure (-1)

elements_hs_deposit_depth :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_deposit_depth deposit tip required = guardResult (-1) $
  execute (Check (DepositDepth deposit tip required)) Validate

-- Four script bytes packed little-endian by the C++ span adapter. Length is
-- checked there before any read; the script language predicate lives here.
elements_hs_treasury_slot :: Word32 -> Word32 -> IO Int32
elements_hs_treasury_slot script opcode = guardResult (-2) $
  execute (Check (TreasuryScript script opcode)) Validate

elements_hs_withdrawal_payout :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_withdrawal_payout burn fee maximumMoney = guardResult (-4)
  (execute (Check (Withdrawal.WithdrawalPayout burn fee maximumMoney)) Validate)

-- Caller owns both buffers. Never retain a pointer, write past capacity, or
-- allow exceptions (including lazy evaluation/copy failures) across the ABI.
elements_hs_withdrawal_bytes :: Word32 -> Int64 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_withdrawal_bytes op maximumMoney input size output capacity = run `catch` handleFailure (-1)
  where run = do
          bytes <- B.packCStringLen (castPtr input, fromIntegral size)
          let reply = either ((B.singleton 1 <>) . C.pack) (B.singleton 0 <>) (withdrawal op maximumMoney bytes)
          writeReply reply output capacity

-- Exact funded-custody policy only; this function never authenticates a proof.
