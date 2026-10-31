{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances #-}
{-# LANGUAGE GADTs, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ParentHeader where

import CapabilityContext (CapabilityContext)
import Control.Exception (Exception, SomeException, catch, finally, fromException, throwIO, try)
import Control.Monad (replicateM, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation (validate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.List (sort)
import Data.Word (Word32, Word64)
import Deposit (constructionScalar)
import qualified ParentReplay as Replay
import qualified Bmm
import Bmm (SignetConstruction(..), SignetCommitment(..))
import Workflow (NativeBytes)
import Withdrawal (readLE, wordLE)

type HeaderCheck = ExceptT Int32 IO
data DeadlineMode = HookDeadline | NativeDeadline
data Header = Header Word32 Bool DeadlineMode NativeBytes

scalar :: NativeBytes -> Word32 -> Word64 -> HeaderCheck Word64
scalar native step index = liftIO (constructionScalar native step index)

flag :: NativeBytes -> Word32 -> HeaderCheck Bool
flag native step = flagAt native step 0

flagAt :: NativeBytes -> Word32 -> Word64 -> HeaderCheck Bool
flagAt native step index = scalar native step index >>= \value -> case value of
  0 -> pure False
  1 -> pure True
  _ -> throwE (-1)

effect :: NativeBytes -> Word32 -> Word64 -> HeaderCheck ()
effect native step index = scalar native step index >>= \value -> unless (value == 1) (throwE (-1))

report :: NativeBytes -> Word64 -> HeaderCheck a
report native code = scalar native 40 code >> throwE 0

class ProofTarget op where
  checkProof :: op -> HeaderCheck ()
  calculateWork :: op -> HeaderCheck ()
  checkWorkIncrement :: op -> HeaderCheck ()

class RawHeader op where
  decodeRaw :: op -> HeaderCheck ()

class AncestorTimes op where
  beginAncestors :: op -> HeaderCheck ()
  readAncestorTime :: op -> HeaderCheck Word32
  publishMedian :: op -> Word32 -> HeaderCheck ()

class HeaderDeadline op where
  checkDeadline :: op -> Word32 -> HeaderCheck ()

instance HeaderDeadline Header where
  checkDeadline (Header _ _ HookDeadline native) step = effect native step 0
  checkDeadline (Header _ _ NativeDeadline native) _ = do
    result <- liftIO (Replay.runDeadline (fmap fromIntegral . constructionScalar native 36 . fromIntegral))
    unless (result == 0) (throwE (-1))

class CanonicalHash op where
  canonicalHash :: op -> Word64 -> HeaderCheck Bool

-- Only failures in the native network-identity scope are recoverable. Transport
-- failures during ordinary active-hash reads still escape to their caller.
newtype NetworkFailure = NetworkFailure B.ByteString deriving Show
instance Exception NetworkFailure

networkBytes :: NativeBytes -> NativeBytes
networkBytes native step index input = do
  reply <- native step index input
  case B.uncons reply of
    Just (0,message) -> throwIO (NetworkFailure message)
    Just (1,body) | (step >= 1000 && step <= 1560) || B.length body == 8 -> pure body
    _ -> ioError (userError "invalid parent network reply")

networkHeader :: NativeBytes -> Header
networkHeader native = Header 0 False HookDeadline $ \step -> networkBytes native $
  case step of 600 -> 6; 609 -> 9; _ -> step

class ParentNetwork op where
  checkParentNetwork :: op -> HeaderCheck ()

-- Compose admission, authenticated network selection and the local wallet
-- workflow without returning to C++ to select or invoke the next operation.
data BmmBidSubmission = BmmBidSubmission Word64 NativeBytes
class BidAdmission op where
  admitBidSubmission :: op -> HeaderCheck ()
class BidWalletSession op where
  submitWalletBid :: op -> HeaderCheck ()

instance BidAdmission BmmBidSubmission where
  admitBidSubmission (BmmBidSubmission money native) = do
    unless (money > 0 && money <= fromIntegral (maxBound :: Int64)) (throwE (-1))
    bytes <- liftIO (native 100 0 B.empty)
    unless (B.length bytes == 40) (throwE (-1))
    let field position = readLE (B.take 8 (B.drop position bytes)) :: Word64
        require message valid = liftIO (Bmm.bidRequire native message valid)
    require "BMM sidechain slot is outside uint8 range" (field 0 <= 255)
    require "BMM bid must be positive and within the money range" (field 8 > 0 && field 8 <= money)
    require "BMM bid identity is incomplete" (field 16 > 0 && field 24 == 1 && field 32 == 1)
    flag native 101 >>= require "Set -drivechainbmmwallet to an explicitly funded parent wallet"
    host <- liftIO (native 102 0 B.empty >>= Bmm.admitHostSnapshot)
    require "Parent wallet RPC requires numeric loopback" host
    effect native 103 0
    opened <- flag native 104
    unless opened (effect native 105 0)
    effect native 106 0
    flag native 107 >>= require "Parent wallet is on the wrong genesis"

instance ParentNetwork BmmBidSubmission where
  checkParentNetwork (BmmBidSubmission _ native) = do
    effect native 108 0
    ExceptT $ runExceptT (checkParentNetwork (networkHeader (\step -> native (2000+step))))
      `finally` (constructionScalar native 116 0 >>= \value ->
        unless (value == 1) (ioError (userError "invalid bid network release")))

instance BidWalletSession BmmBidSubmission where
  submitWalletBid (BmmBidSubmission money native) = do
    selected <- flag native 109
    when selected $ flag native 110 >>= liftIO . Bmm.bidRequire native "BMM bid slot differs from the selected chain"
    pinned <- flag native 111
    when pinned $ flag native 112 >>= liftIO . Bmm.bidRequire native "Parent wallet is on the wrong fork checkpoint"
    effect native 113 0
    result <- liftIO (Bmm.submitLocalBid (Bmm.LocalBidWallet money (\step -> native (1000+step))))
    unless (result == 1) (throwE (-1))
    effect native 114 0

submitBmmBid :: (BidAdmission op, ParentNetwork op, BidWalletSession op) => op -> HeaderCheck ()
submitBmmBid value = admitBidSubmission value >> checkParentNetwork value >> submitWalletBid value

type BmmBidCapabilities = '[BidAdmission, ParentNetwork, BidWalletSession]
instance Operation BmmBidSubmission BmmBidCapabilities where
  type Context BmmBidSubmission = CapabilityContext BmmBidCapabilities BmmBidSubmission
  type Outcome BmmBidSubmission = IO Int32
  data DSL BmmBidSubmission where
    SubmitBmmBid :: Context BmmBidSubmission => DSL BmmBidSubmission
  interpret operation request = withOperation @BmmBidSubmission operation $ \value -> case request of
    SubmitBmmBid -> Just (either id (const 1) <$> runExceptT (submitBmmBid value))

class ActiveParentHash op where
  readActiveHash :: op -> HeaderCheck ()
class HeaderTransport op where
  requestHeader :: op -> Word32 -> HeaderCheck Bool

requireHeaderRequest :: HeaderTransport op => op -> Word32 -> HeaderCheck ()
requireHeaderRequest value step = requestHeader value step >>= \ready -> unless ready (throwE (-1))

instance HeaderTransport Header where
  requestHeader (Header _ _ _ native) = requestParent True native

-- Retrieval needs the error envelope (including the pruned-data result), while
-- header authentication consumes only checked successful RPC results.
requestParent :: Bool -> NativeBytes -> Word32 -> HeaderCheck Bool
requestParent checked native step = do
    mode <- scalar native step 0
    case mode of
      0 -> pure False
      1 -> pure True -- Caller-supplied hook already returned its result.
      2 -> do
        let transport = Bmm.RpcSession (\part -> native (1000+part))
        result <- liftIO (try (runExceptT (Replay.performRpcCall transport >> when checked (Replay.verifyRpcReply transport)))
          :: IO (Either SomeException (Either Int32 ())))
        case result of
          Right (Right ()) -> effect native 600 0 >> pure True
          Left err | Just failure <- fromException err -> liftIO (throwIO (failure :: NetworkFailure))
          _ -> effect native 609 0 >> throwE (-1)
      _ -> throwE (-1)

networkDiagnostic :: NativeBytes -> B.ByteString -> HeaderCheck ()
networkDiagnostic native message = do
  reply <- liftIO (native 5 0 message)
  unless (reply == B.pack [1,0,0,0,0,0,0,0]) (throwE (-1))

instance ParentNetwork Header where
  checkParentNetwork value@(Header _ _ _ native) = do
    selected <- flag native 0
    when selected $ do
      effect native 1 0
      ExceptT $ runExceptT (do
        requireHeaderRequest value 2
        valid <- canonicalHash value 0
        matches <- if valid then flag native 3 else pure False
        unless matches $ do
          effect native 4 0
          networkDiagnostic native (C.pack "parent RPC does not serve the mainnet parent post-fork block at height 967680")
          throwE 0) `catch` \(NetworkFailure message) -> runExceptT $ do
            effect native 4 0
            networkDiagnostic native (C.pack "cannot verify mainnet parent RPC identity: " <> message)
            throwE 0

instance ActiveParentHash Header where
  readActiveHash value@(Header _ _ _ native) = do
    requireHeaderRequest value 7
    valid <- canonicalHash value 0
    unless valid $ do
      height <- scalar native 8 0
      unless (height <= fromIntegral (maxBound :: Word32)) (throwE (-1))
      networkDiagnostic native (C.pack ("getblockhash(" ++ show height ++ ") returned a noncanonical hash"))
      throwE 0

authenticateActiveHash :: (ParentNetwork op, ActiveParentHash op) => op -> HeaderCheck ()
authenticateActiveHash value = checkParentNetwork value >> readActiveHash value

class HeaderMetadata op where
  readMetadata :: op -> HeaderCheck Word32

class HeaderPredecessor op where
  checkPredecessor :: op -> HeaderCheck ()

class HeaderAuthentication op where
  prepareHeader :: op -> HeaderCheck ()
  readCurrentHeader :: op -> HeaderCheck ()
  readHeaderMedian :: op -> Word32 -> HeaderCheck ()
  publishHeader :: op -> HeaderCheck ()

instance ProofTarget Header where
  checkProof (Header _ _ _ native) = do
    effect native 1 0
    invalid <- orM [flag native step | step <- [2,3,4,5]]
    when invalid (report native 1)
    above <- flag native 6
    when above (report native 2)
  calculateWork (Header _ _ _ native) = do
    effect native 1 0
    invalid <- orM [flag native step | step <- [2,4,3]]
    effect native (if invalid then 8 else 7) 0
  checkWorkIncrement (Header _ _ _ native) = do
    empty <- flag native 9
    when empty (report native 3)
    matches <- flag native 10
    unless matches (report native 3)

orM :: Monad m => [m Bool] -> m Bool
orM = foldr (\readFlag next -> readFlag >>= \value -> if value then pure True else next) (pure False)

authenticateRaw :: (RawHeader op, ProofTarget op) => op -> HeaderCheck ()
authenticateRaw value = decodeRaw value >> checkProof value

authenticateChainwork :: ProofTarget op => op -> HeaderCheck ()
authenticateChainwork value = calculateWork value >> checkWorkIncrement value

instance RawHeader Header where
  decodeRaw value@(Header _ _ _ native) = do
    string <- flag native 20
    unless string (report native 4)
    hex <- flag native 21
    unless hex (report native 4)
    checkDeadline value 22
    -- Upstream deserialization retains its partial writes and local exception
    -- translation. Deadline and hashing exceptions must still escape unchanged.
    decoded <- flag native 23
    unless decoded (throwE 0)
    checkDeadline value 22
    matches <- flag native 24
    unless matches (report native 5)

instance AncestorTimes Header where
  beginAncestors (Header _ _ _ native) = effect native 30 0
  readAncestorTime value@(Header _ rpc _ native) = do
    checkDeadline value 31
    readOk <- requestHeader value 32
    unless readOk (throwE 0)
    when rpc (authenticateRaw value)
    time <- scalar native 33 0
    when (time > fromIntegral (maxBound :: Word32)) (throwE (-1))
    effect native 34 0
    pure (fromIntegral time)
  publishMedian value@(Header _ _ _ native) time = checkDeadline value 31 >> effect native 35 (fromIntegral time)

ancestorMedian :: AncestorTimes op => Word32 -> op -> HeaderCheck ()
ancestorMedian height value = do
  beginAncestors value
  -- Widen before adding; even UINT32_MAX still requests only eleven headers.
  let count = fromIntegral (min 11 (toInteger height + 1))
  times <- sort <$> replicateM count (readAncestorTime value)
  publishMedian value (times !! (count `div` 2))

instance CanonicalHash Header where
  canonicalHash (Header _ _ _ native) index = do
    string <- flagAt native 41 index
    if not string then pure False else do
      size <- scalar native 42 index
      if size /= 64 then pure False else do
        hex <- flagAt native 43 index
        if not hex then pure False else do
          effect native 44 index
          flagAt native 45 index

signed :: NativeBytes -> Word32 -> HeaderCheck Int64
signed native step = fromIntegral <$> scalar native step 0

requireAll :: NativeBytes -> Word64 -> [HeaderCheck Bool] -> HeaderCheck ()
requireAll native code checks = orM (map (fmap not) checks) >>= \rejected -> when rejected (report native code)

instance HeaderMetadata Header where
  readMetadata value@(Header _ _ _ native) = do
    requireAll native 6 [flag native 50]
    requireAll native 7 [canonicalHash value 0,flag native 51]
    effect native 52 0
    requireAll native 8 [flag native 53,flag native 54,canonicalHash value 1]
    height <- signed native 55
    confirmations <- signed native 56
    minimumConfirmations <- signed native 57
    unless (height >= 0 && height <= fromIntegral (maxBound :: Word32) && confirmations >= minimumConfirmations)
      (report native 9)
    pure (fromIntegral height)

instance HeaderPredecessor Header where
  checkPredecessor value@(Header _ _ _ native) = do
    height <- signed native 60
    if height == 0 then do
      requireAll native 10 [flag native 61,flag native 62]
      calculateWork value
      requireAll native 11 [flag native 63]
    else do
      requireAll native 12 [canonicalHash value 2,flag native 64]
      requireHeaderRequest value 65
      requireAll native 13 [flag native 66]
      effect native 67 0
      requireAll native 14 [canonicalHash value 3,flag native 68,canonicalHash value 4,flag native 69]
      previous <- signed native 70
      unless (toInteger previous == toInteger height-1) (report native 14)
      calculateWork value
      requireAll native 15 [not <$> flag native 9,flag native 10]

offset :: Word32 -> NativeBytes -> NativeBytes
offset base native step = native (base+step)

-- Header components share one prepared RPC; their scalar observations retain
-- separate namespaces, while the transport and publication effects stay global.
headerOffset :: Word32 -> NativeBytes -> NativeBytes
headerOffset base native step = native $
  if step == 600 || step == 609 || step >= 1000 then step else base+step

instance HeaderAuthentication Header where
  prepareHeader value@(Header _ _ _ native) = do
    minimumConfirmations <- signed native 57
    unless (minimumConfirmations >= 1) (report native 16)
    requireHeaderRequest value 81
    requireAll native 17 [canonicalHash value 5,flag native 82]
    requireHeaderRequest value 83
  readCurrentHeader value@(Header _ rpc deadline native) = do
    requireHeaderRequest value 84
    requireAll native 18 [canonicalHash value 6,flag native 85]
    raw <- requestHeader value 86
    unless raw (throwE 0)
    when rpc (authenticateRaw (Header 0 True deadline (offset 200 native)))
    effect native 87 0
  readHeaderMedian (Header _ rpc deadline native) height = do
    ready <- flag native 88
    unless ready (throwE 0)
    when rpc (ancestorMedian height (Header height True deadline (headerOffset 100 native)))
  publishHeader value@(Header _ _ _ native) = do
    checkDeadline value 89
    effect native 90 0
    empty <- flag native 91
    when empty (report native 19)

authenticateHeader :: (HeaderAuthentication op, HeaderMetadata op, HeaderPredecessor op) => op -> HeaderCheck ()
authenticateHeader value = do
  prepareHeader value
  height <- readMetadata value
  readCurrentHeader value
  checkPredecessor value
  readHeaderMedian value height
  publishHeader value

-- Each scope owns native objects, but sequencing and rejection stay in Haskell.
newtype NetworkHeader = NetworkHeader NativeBytes
class VerifiedParentHeader op where
  readVerifiedParentHeader :: op -> HeaderCheck ()

nativeScope :: NativeBytes -> Word64 -> HeaderCheck a -> HeaderCheck a
nativeScope native scope action = do
  effect native 10000 scope
  result <- liftIO $ runExceptT action `finally` do
    released <- constructionScalar native 10001 scope
    unless (released == 1) (ioError (userError "invalid parent context release"))
  either throwE pure result

instance ParentNetwork NetworkHeader where
  checkParentNetwork (NetworkHeader native) = nativeScope native 1 $
    checkParentNetwork (networkHeader native)
instance VerifiedParentHeader NetworkHeader where
  readVerifiedParentHeader (NetworkHeader native) = nativeScope native 2 $ do
    deadlines <- flag native 10002
    authenticateHeader (Header 0 True (if deadlines then NativeDeadline else HookDeadline) (offset 2000 native))

authenticateNetworkHeader :: (ParentNetwork op, VerifiedParentHeader op) => op -> HeaderCheck ()
authenticateNetworkHeader value = checkParentNetwork value >> readVerifiedParentHeader value

type NetworkHeaderCapabilities = '[ParentNetwork, VerifiedParentHeader]
instance Operation NetworkHeader NetworkHeaderCapabilities where
  type Context NetworkHeader = CapabilityContext NetworkHeaderCapabilities NetworkHeader
  type Outcome NetworkHeader = IO Int32
  data DSL NetworkHeader where
    AuthenticateNetworkHeader :: Context NetworkHeader => DSL NetworkHeader
  interpret operation request = withOperation @NetworkHeader operation $ \value -> case request of
    AuthenticateNetworkHeader -> Just (either id (const 1) <$> runExceptT (authenticateNetworkHeader value))

newtype ParentBlockReader = ParentBlockReader NativeBytes
class ParentBodyRetrieval op where
  fetchParentBody :: op -> HeaderCheck ()
class AuthenticatedParentBody op where
  readAuthenticatedBody :: op -> HeaderCheck ()
class ParentBlockBinding op where
  bindParentBlock :: op -> HeaderCheck ()

instance ParentNetwork ParentBlockReader where
  checkParentNetwork (ParentBlockReader native) = checkParentNetwork (NetworkHeader native)
instance VerifiedParentHeader ParentBlockReader where
  readVerifiedParentHeader (ParentBlockReader native) = readVerifiedParentHeader (NetworkHeader native)

instance ParentBodyRetrieval ParentBlockReader where
  fetchParentBody (ParentBlockReader native) = do
    deadlines <- flag native 460
    let value = Header 0 False (if deadlines then NativeDeadline else HookDeadline) native
        action step = fmap (either (const (-1)) id) $ runExceptT $
          if step == 11 then checkDeadline value 450 >> pure 1
          else if step `elem` [1,14,200,207,400,411] then do
            when (step /= 14) (checkDeadline value 450)
            ready <- requestParent False native step
            unless ready (throwE (-1))
            pure 1
          else signed native step
    result <- liftIO (Bmm.recoverParentBody (Bmm.BodyRecovery action))
    unless (result == 0) (throwE (-1))

instance AuthenticatedParentBody ParentBlockReader where
  readAuthenticatedBody (ParentBlockReader native) = nativeScope native 3 $ do
    -- Arm restoration only after the original deadline constructor succeeds.
    result <- liftIO (Replay.runStore 50 (\step -> fromIntegral <$> constructionScalar native (9000+step) 0))
    unless (result == 1) (throwE (-1))
    effect native 9005 0
    nativeScope native 4 $ do
      fetchParentBody (ParentBlockReader (offset 4000 native))
      effect native 10003 0
    nativeScope native 5 $ do
      deadlines <- flag native 10004
      authenticateBlock (Header 0 False (if deadlines then NativeDeadline else HookDeadline) (offset 6000 native))

instance ParentBlockBinding ParentBlockReader where
  bindParentBlock (ParentBlockReader native) = do
    matches <- flag native 10005
    unless matches (effect native 10006 0 >> throwE 0)

authenticateParentBlock :: (ParentNetwork op, VerifiedParentHeader op, AuthenticatedParentBody op, ParentBlockBinding op)
  => op -> HeaderCheck ()
authenticateParentBlock value = authenticateNetworkHeader value >> readAuthenticatedBody value >> bindParentBlock value

type ParentBlockReaderCapabilities = '[ParentNetwork, VerifiedParentHeader, ParentBodyRetrieval,
  AuthenticatedParentBody, ParentBlockBinding]
instance Operation ParentBlockReader ParentBlockReaderCapabilities where
  type Context ParentBlockReader = CapabilityContext ParentBlockReaderCapabilities ParentBlockReader
  type Outcome ParentBlockReader = IO Int32
  data DSL ParentBlockReader where
    FetchParentBody :: Context ParentBlockReader => DSL ParentBlockReader
    ReadAuthenticatedBody :: Context ParentBlockReader => DSL ParentBlockReader
    AuthenticateParentBlock :: Context ParentBlockReader => DSL ParentBlockReader
  interpret operation request = withOperation @ParentBlockReader operation $ \value ->
    let run = Just . fmap (either id (const 1)) . runExceptT
    in case request of
      FetchParentBody -> run (fetchParentBody value)
      ReadAuthenticatedBody -> run (readAuthenticatedBody value)
      AuthenticateParentBlock -> run (authenticateParentBlock value)

class BlockTransactions op where
  checkBlockTransactions :: op -> HeaderCheck ()
class BlockSignet op where
  checkBlockSignet :: op -> HeaderCheck ()

instance BlockTransactions Header where
  checkBlockTransactions value@(Header _ _ _ native) = do
    let reject code = scalar native 140 code >> throwE 0
        periodic index = when (validate (Replay.Record 14 0 0 index 0) == 1) (checkDeadline value 108)
        walk first count action = go first where
          go index = when (index < count) (periodic index >> action index >> go (index+1))
    count <- scalar native 100 0
    when (count == 0) (reject 0)
    present <- flagAt native 101 0
    unless present (reject 0)
    coinbase <- flagAt native 102 0
    unless coinbase (reject 0)
    walk 1 count $ \index -> do
      exists <- flagAt native 101 index
      unless exists (reject 1)
      extraCoinbase <- flagAt native 102 index
      when extraCoinbase (reject 1)
    effect native 103 0
    walk 0 count (effect native 104)
    effect native 105 0
    mismatch <- flag native 106
    when mismatch (reject 2)
    mutated <- flag native 107
    when mutated (reject 2)
    checkDeadline value 108

instance BlockSignet Header where
  checkBlockSignet value@(Header height rpc deadline native) = do
    effect native 109 0
    empty <- flag native 110
    unless empty $ do
      effect native 111 0
      mode <- scalar native 112 0
      case mode of
        0 -> throwE 0
        1 -> pure () -- Caller-supplied hook already checked Signet.
        2 -> do
          let prepared = offset 2000 native
          result <- liftIO $ runExceptT (authenticateSignet (Header height rpc deadline prepared) prepared)
            `finally` do
              released <- constructionScalar native 113 0
              unless (released == 1) (ioError (userError "invalid parent Signet release"))
          either throwE pure result
        _ -> throwE (-1)
      checkDeadline value 108

authenticateBlock :: (RawHeader op, ProofTarget op, BlockTransactions op, BlockSignet op) => op -> HeaderCheck ()
authenticateBlock value = authenticateRaw value >> checkBlockTransactions value >> checkBlockSignet value

class SignetMerkle op where
  modifiedSignetMerkle :: op -> HeaderCheck ()
class SignetSolution op where
  prepareSignetSolution :: op -> HeaderCheck Bool
  decodeSignetSolution :: op -> HeaderCheck ()
  verifySignetSolution :: op -> HeaderCheck ()

instance SignetConstruction Header where
  buildSignetTransactions (Header _ _ _ native) = Bmm.constructSignet native
  writeSignetBlockData (Header _ _ _ native) = Bmm.writeSignetData native

instance SignetCommitment Header where
  selectSignetCommitment (Header _ _ _ native) = Bmm.selectSignetWitness native

instance SignetMerkle Header where
  modifiedSignetMerkle (Header _ _ _ native) = do
    effect native 601 0
    effect native 602 0
    count <- scalar native 603 0
    let walk index = when (index < count) (effect native 604 index >> walk (index+1))
    walk 1
    effect native 605 0

signetError :: NativeBytes -> Word64 -> HeaderCheck a
signetError native code = scalar native 440 code >> throwE 0

instance SignetSolution Header where
  prepareSignetSolution (Header _ _ _ native) = do
    genesis <- flag native 400
    unless genesis $ do
      empty <- flag native 401
      when empty (signetError native 0)
      coinbase <- flag native 402
      unless coinbase (signetError native 0)
    pure (not genesis)
  decodeSignetSolution (Header _ _ _ native) = do
    empty <- flag native 410
    unless empty $ do
      -- Only native std::exception failures inside the original reader scope
      -- become canonical-encoding errors. Other exceptions still escape.
      let readPart step = do
            reply <- liftIO (native step 0 B.empty)
            case B.uncons reply of
              Just (1,body) | body == wordLE 8 0 -> pure False
              Just (1,body) | body == wordLE 8 1 -> pure True
              _ -> scalar native 425 0 >> throwE 0
          required step = readPart step >>= \ok -> unless ok (scalar native 425 0 >> throwE 0)
      mapM_ required [420,421,422]
      trailing <- readPart 423
      when trailing (readPart 424 >> throwE 0)
  verifySignetSolution (Header _ _ _ native) = do
    mapM_ (\step -> effect native step 0) [414,415]
    valid <- flag native 416
    unless valid (signetError native 2)

authenticateSignet :: (SignetSolution op, SignetCommitment op, SignetConstruction op, SignetMerkle op)
  => op -> NativeBytes -> HeaderCheck ()
authenticateSignet value native = do
  required <- prepareSignetSolution value
  when required $ do
    found <- selectSignetCommitment value
    unless found (signetError native 1)
    mapM_ (\step -> effect native step 0) [407,408,409]
    buildSignetTransactions value
    decodeSignetSolution value
    effect native 412 0
    modifiedSignetMerkle value
    effect native 413 0
    writeSignetBlockData value
    verifySignetSolution value

type HeaderCapabilities = '[ProofTarget, RawHeader, AncestorTimes, HeaderDeadline, CanonicalHash,
  HeaderMetadata, HeaderPredecessor, HeaderAuthentication, ParentNetwork, ActiveParentHash, HeaderTransport,
  BlockTransactions, BlockSignet, SignetConstruction, SignetCommitment, SignetMerkle, SignetSolution]
instance Operation Header HeaderCapabilities where
  type Context Header = CapabilityContext HeaderCapabilities Header
  type Outcome Header = IO Int32
  data DSL Header where
    CheckProof :: Context Header => DSL Header
    CalculateWork :: Context Header => DSL Header
    CheckChainwork :: Context Header => DSL Header
    AuthenticateRaw :: Context Header => DSL Header
    AncestorMedian :: Context Header => DSL Header
    CanonicalHash :: Context Header => DSL Header
    ReadMetadata :: Context Header => DSL Header
    CheckPredecessor :: Context Header => DSL Header
    AuthenticateHeader :: Context Header => DSL Header
    CheckParentNetwork :: Context Header => DSL Header
    ReadActiveHash :: Context Header => DSL Header
    AuthenticateActiveHash :: Context Header => DSL Header
    CheckBlockTransactions :: Context Header => DSL Header
    CheckBlockSignet :: Context Header => DSL Header
    AuthenticateBlock :: Context Header => DSL Header
    AuthenticateSignet :: Context Header => DSL Header
    ModifiedSignetMerkle :: Context Header => DSL Header
    BuildSignetTransactions :: Context Header => DSL Header
    WriteSignetBlockData :: Context Header => DSL Header
    SelectSignetCommitment :: Context Header => DSL Header
  interpret operation request = withOperation @Header operation $ \value@(Header height _ _ native) ->
    let run = Just . fmap (either id (const 1)) . runExceptT
    in case request of
      CheckProof -> run (checkProof value)
      CalculateWork -> run (calculateWork value)
      CheckChainwork -> run (authenticateChainwork value)
      AuthenticateRaw -> run (authenticateRaw value)
      AncestorMedian -> run (ancestorMedian height value)
      CanonicalHash -> run (canonicalHash value 0 >>= \valid -> unless valid (throwE 0))
      ReadMetadata -> run (() <$ readMetadata value)
      CheckPredecessor -> run (checkPredecessor value)
      AuthenticateHeader -> run (authenticateHeader value)
      CheckParentNetwork -> run (checkParentNetwork value)
      ReadActiveHash -> run (readActiveHash value)
      AuthenticateActiveHash -> run (authenticateActiveHash value)
      CheckBlockTransactions -> run (checkBlockTransactions value)
      CheckBlockSignet -> run (checkBlockSignet value)
      AuthenticateBlock -> run (authenticateBlock value)
      AuthenticateSignet -> run (authenticateSignet value native)
      ModifiedSignetMerkle -> run (modifiedSignetMerkle value)
      BuildSignetTransactions -> run (buildSignetTransactions value)
      WriteSignetBlockData -> run (writeSignetBlockData value)
      SelectSignetCommitment -> run (selectSignetCommitment value >>= \found -> unless found (throwE 0))
