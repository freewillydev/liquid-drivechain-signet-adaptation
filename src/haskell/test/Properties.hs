{-# LANGUAGE ForeignFunctionInterface #-}
-- Keep the large test driver cheap to rebuild; production modules retain -O1.
{-# OPTIONS_GHC -O0 #-}
module Main where

import Control.Monad (unless, when)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Control.Monad.Trans.State.Strict (State, modify', runState)
import Control.Exception (bracket, catch, try, SomeException)
import Data.Bits ((.|.), clearBit, shiftL, shiftR, testBit, xor)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Either (isLeft, isRight)
import Data.Int (Int32, Int64)
import Data.IORef (newIORef, modifyIORef', readIORef, writeIORef)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.List as List
import Data.Word (Word8, Word16, Word32, Word64)
import Drivechain
import System.Exit (exitFailure)
import Test.QuickCheck hiding (output)
import Test.QuickCheck.Random (mkQCGen)
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (allocaArray, withArray, peekArray, pokeArray)
import Foreign.Marshal.Utils (withMany)
import Foreign.Ptr (Ptr, FunPtr, castPtr, nullPtr, nullFunPtr, plusPtr, freeHaskellFunPtr)
import Foreign.Storable (peek, poke, peekByteOff, pokeByteOff)
import GHC.Float (castWord64ToDouble)
import Withdrawal (withdrawal, wordBE, wordLE)
import qualified Withdrawal
import Deposit (HashTransaction)
import qualified Deposit
import Workflow (runRequiredEffects, countMatches)
import qualified Workflow
import qualified Bmm
import qualified ParentReplay
import qualified ParentBlockTests
import qualified DepositConstructionTests
import qualified DepositParsingTests
import qualified DepositClaimTests
import qualified NativeDepositTests
import qualified ParentHeaderTests
import qualified ParentRpcTests
import qualified LocalBidTests
import qualified BmmContextTests
import qualified WalletWithdrawalTests
import qualified JournalWorkflowTests
import qualified BmmHeaderPolicyTests
import qualified BmmStateAccessTests
import qualified StateStorageTests
import qualified ProofSessionTests
import qualified BmmChainTests
import qualified CommitmentTests
import qualified SignetSessionTests
import qualified ReplayStoreTests
import qualified ConfirmationDepthTests
import qualified BmmConstants as Constants
import OperationTests
import AbiTests
import qualified NodeRules
import qualified ScriptPolicy
import Control.Operation.Validation (Validation(..))
import Control.Operation (Operation(interpret), SomeOperation(..), execute)

foreign import ccall unsafe reference_depth :: Word32 -> Word32 -> Word32 -> IO Int32
foreign import ccall unsafe reference_wallet_issue_amount :: Ptr Double -> IO Int32

scriptCacheSuffix :: Maybe B.ByteString -> B.ByteString
scriptCacheSuffix endpoint = B.pack
  [0x9f,0xa5,0xb4,0x11,0x85,0xf7,0x39,0x1f,0xfd,0xa6,0x3b,0x6b,0xb1,0x4b,0xa7,0x9b,
   0x13,0x8f,0x46,0x39,0x6b,0xca,0x42,0xb7,0x5e,0xfd,0xe5,0xdc,0x55,0x03,0xfe,0x26,0,1,
   if isJust endpoint then 1 else 0] <> fromMaybe (B.replicate 80 0) endpoint

scriptCacheEndpoint :: Property
scriptCacheEndpoint = forAll (oneof [pure Nothing,Just . B.pack <$> vectorOf 80 arbitrary]) $ \endpoint -> ioProperty $ do
  let input = maybe (B.singleton 0) (B.cons 1) endpoint
      expected = scriptCacheSuffix endpoint
  B.useAsCString input $ \ptr -> allocaArray 117 $ \output -> do
    pokeArray output (replicate 117 (0xa5 :: Word8))
    status <- elements_hs_script_cache_encode 1 (fromIntegral (B.length input)) (castPtr ptr) 115 (output `plusPtr` 1)
    actual <- peekArray 117 output
    pure $ conjoin [status===0,actual === 0xa5 : B.unpack expected ++ [0xa5],
      validate (NodeRules.ScriptCacheEncoding True input)===Just expected]

scriptCacheMalformed :: Property
scriptCacheMalformed = once $ ioProperty $ allocaArray 824 $ \output -> do
  let widths = replicate 20 32 ++ replicate 7 8 ++ [80]
      full = B.cons 1 (B.concat [B.cons 1 (B.replicate width 0) | width <- widths])
      positions = 0 : init (scanl (+) 1 (map (+1) widths))
      corrupt pos = B.take pos full <> B.singleton 2 <> B.drop (pos+1) full
      invalid = map (`B.take` full) [0..804] ++ map corrupt positions ++ [B.snoc full 0]
      check mode capacity input missingInput missingOutput = B.useAsCString input $ \ptr -> do
        pokeArray output (replicate 824 (0xa5 :: Word8))
        status <- elements_hs_script_cache_encode mode (fromIntegral (B.length input))
          (if missingInput then nullPtr else castPtr ptr) capacity (if missingOutput then nullPtr else output `plusPtr` 1)
        remaining <- peekArray 824 output
        pure $ conjoin [status=== -1,remaining===replicate 824 0xa5]
  malformed <- mapM (\input -> do
    actual <- check 0 822 input False False
    pure (actual .&&. validate (NodeRules.ScriptCacheEncoding False input)===Nothing)) invalid
  boundary <- sequence [check 2 822 full False False,check maxBound 822 full False False,
    check 0 821 full False False,check 0 823 full False False,
    check 0 822 full True False,check 0 822 full False True,
    check 1 115 (B.singleton 2) False False,check 1 115 (B.singleton 1) False False,
    check 1 115 (B.replicate 81 0) False False]
  pure (conjoin (malformed ++ boundary))

parameterGateParity :: Property
parameterGateParity = forAll ((,,) <$> elements [0,1,2,3,maxBound] <*> parameterValue <*> parameterValue) $ \(mode,first,second) -> ioProperty $ do
  actual <- elements_hs_parameter_gate mode first second
  let expected
        | mode == 0 = if first >= 0 && second >= first then 1 else 0
        | mode == 1 && first `elem` [0,1] && second `elem` [0,1] = if first == 1 && second == 1 then 1 else 0
        | mode == 2 && second == 0 = if first >= 0 then 1 else 0
        | otherwise = -1
  pure (conjoin [actual === expected,validate (ScriptPolicy.ParameterGate mode first second) === expected])
  where parameterValue = frequency [(1,arbitrary),(3,elements [minBound,-2147483648,-1,0,1,2147483647,maxBound])]

walletIssueAmountParity :: Property
walletIssueAmountParity = forAll (frequency [(1,arbitrary),(2,elements
  [0,0x8000000000000000,1,0x8000000000000001,0x3ff0000000000000,0xbff0000000000000,
   0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,
   0x7ff8000000000000,0xfff8000000000000,0x7ff0000000000001])]) $ \bits ->
  ioProperty $ alloca $ \input -> do
    let amount=castWord64ToDouble bits
    poke input amount
    expected <- reference_wallet_issue_amount input
    actual <- elements_hs_wallet_issue_amount input
    missing <- elements_hs_wallet_issue_amount nullPtr
    pure $ conjoin [actual===expected,missing===(-1),
      validate (Withdrawal.WalletIssueAmount amount)===(expected==1)]

optionalEnvironmentParity :: Property
optionalEnvironmentParity = forAll ((,,) <$> elements [0..6] <*>
  elements [0,1,2,255,maxBound] <*> frequency [(4,choose (0,256)),(1,arbitrary)]) $ \(kind,present,fields) -> ioProperty $ do
    let width = if kind==0 then 1 else if kind==2 then 8 else if kind==5 then 4 else 3
        bits = [testBit fields i | i<-[0..width-1]]
        valid = case kind of
          3 -> if present==1 then bits!!0 && bits!!2 else not (or bits)
          4 -> if present==1 then and bits else not (bits!!0 || bits!!1)
          5 -> if present==1 then bits!!0 && bits!!2 && bits!!3 else not (or bits)
          _ -> if present==1 then and bits else not (or bits)
        expected | kind>5 || present>1 || fields >= 2^width = -1
                 | valid = 1
                 | otherwise = 0
    actual <- elements_hs_optional_environment kind present fields
    pure (conjoin [actual===expected,
      validate (ScriptPolicy.OptionalEnvironment kind present fields)===expected])

merkleReplacementParity :: Property
merkleReplacementParity = forAll ((,,,) <$> elements [0,1,2,3,maxBound] <*>
  elements [0,1,2,maxBound] <*> elements [0,1,2,maxBound] <*> elements [0,1,2,3,4,maxBound]) $
  \(mode,index,position,flags) -> ioProperty $ do
    let result accepted=if accepted then 1 else 0
        expected=case mode of
          0 | flags==0 -> result (index/=maxBound)
          1 | flags<=3 -> result (testBit flags 0 && testBit flags 1 && position==index)
          2 | flags<=1 -> result (index==maxBound || flags/=0)
          _ -> -1
    actual <- elements_hs_merkle_replacement mode index position flags
    pure $ conjoin [actual===expected,
      validate (ScriptPolicy.MerkleReplacement mode index position flags)===expected]

optionalCheckpointParity :: Property
optionalCheckpointParity = forAll ((,,) <$> elements [0,1,2,maxBound] <*>
  choose (0,15 :: Word32) <*> choose (1,255 :: Word8)) $ \(present,fields,value) -> ioProperty $ do
    let checkpointBytes = B.concat [B.replicate (width-1) 0 <> B.singleton (if testBit fields i then value else 0) |
          (i,width) <- zip [0..] [32,8,8,32]]
        nonzero offset width = B.any (/=0) (B.take width (B.drop offset checkpointBytes))
        expected | present>1 = -1
                 | present==0 = if B.all (==0) checkpointBytes then 1 else 0
                 | all (uncurry nonzero) [(0,32),(40,8),(48,32)] = 1
                 | otherwise = 0
    actual <- B.useAsCString checkpointBytes $ \ptr -> elements_hs_optional_checkpoint present (castPtr ptr)
    missing <- elements_hs_optional_checkpoint present nullPtr
    pure (conjoin [actual===expected,missing===(if present>1 then -1 else if present==0 then 1 else 0)])

jetHeightParity :: Property
jetHeightParity = forAll ((,) <$> choose (0,3) <*> frequency [(1,arbitrary),(3,elements [0,1,2,maxBound])]) $
  \(present,height) -> ioProperty $ do
    actual <- elements_hs_jet_height present height
    pure (actual===(if present>1 then -1 else if present==1 && height/=0 then 1 else 0))


boundedAppendRule :: Property
boundedAppendRule = forAll ((,,) <$> size <*> size <*> count) $ \(limit,used,n) -> ioProperty $ do
  actual <- elements_hs_bounded_append limit used n
  let expected = if n < 0 then -1 else fromInteger (min (toInteger n) (max 0 (toInteger limit-toInteger used)))
  pure $ conjoin [validate (Bmm.BoundedAppend limit used n) === expected,actual === expected]
  where
    size = frequency [(1,arbitrary),(2,elements [0,1,4095,4096,4097,maxBound :: Word64])]
    count = frequency [(1,arbitrary),(2,elements [minBound,-1,0,1,4095,4096,4097,maxBound :: Int64])]

approvingParentHeightRule :: Property
approvingParentHeightRule = forAll height $ \parent -> ioProperty $ do
  actual <- elements_hs_approving_parent_height parent
  let expected = if parent < 0 || toInteger parent >= 2^(32 :: Int)-1 then -1 else parent+1
  pure $ conjoin [validate (Bmm.ApprovingParentHeight parent) === expected,actual === expected]
  where height = frequency [(1,arbitrary),(2,elements [minBound,-1,0,1,2147483647,4294967294,4294967295,maxBound :: Int64])]

childBehindRule :: Property
childBehindRule = forAll ((,) <$> height <*> height) $ \(child,parent) -> ioProperty $ do
  actual <- elements_hs_child_behind child parent
  let expected = toInteger child < toInteger parent
  pure $ conjoin [validate (Bmm.ChildBehind child parent) === expected,actual === (if expected then 1 else 0)]
  where height = frequency [(1,arbitrary),(2,elements [minBound,-2147483648,-1,0,1,2147483647,4294967295,maxBound :: Int64])]

boundedWaitRule :: Property
boundedWaitRule = forAll ((,) <$> scalar <*> scalar) $ \(value,limit) -> ioProperty $ do
  actual <- elements_hs_bounded_wait value limit
  let expected | limit < 1 = -1
               | value < 1 = 1
               | value > limit = limit
               | otherwise = value
  pure $ conjoin [validate (Bmm.BoundedWait value limit) === expected,actual === expected]
  where scalar = frequency [(1,arbitrary),(2,elements [minBound,-1,0,1,24,25,26,maxBound :: Int64])]

unsigned32Fields :: Property
unsigned32Fields = forAll (resize 8 (listOf field)) $ \fields -> ioProperty $ withArray fields $ \input -> do
  actual <- elements_hs_unsigned32_fields (fromIntegral (length fields)) input
  unchanged <- peekArray (length fields) input
  missing <- elements_hs_unsigned32_fields 1 nullPtr
  oversized <- elements_hs_unsigned32_fields maxBound input
  empty <- elements_hs_unsigned32_fields 0 nullPtr
  let expected = all (\value -> toInteger value < 2^(32 :: Int)) fields
  pure $ conjoin [validate (NodeRules.Unsigned32Fields fields) === expected,
    actual === (if expected then 1 else 0), unchanged === fields,
    missing === -1, oversized === -1, empty === 1]
  where field = frequency [(1,arbitrary),(2,elements [0,1,4294967294,4294967295,4294967296,9223372036854775808,maxBound])]

pegEventDefaultStart :: Property
pegEventDefaultStart = forAll (frequency [(1,arbitrary),(3,elements [minBound,-1,0,1,998,999,1000,maxBound])]) $ \tip -> ioProperty $
  withArray ([12345,67890,54321] :: [Int32]) $ \output -> do
    let expected = fromInteger (max 0 (toInteger tip - 999))
    code <- elements_hs_export_range 3 0 0 0 tip (output `plusPtr` 4)
    contents <- peekArray 3 output
    invalid <- sequence [elements_hs_export_range 3 a b c tip output |
      (a,b,c) <- [(1,0,0),(0,1,0),(0,0,1),(-1,0,0),(0,-1,0),(0,0,-1)]]
    missing <- elements_hs_export_range 3 0 0 0 tip nullPtr
    unchanged <- peekArray 3 output
    pure $ conjoin [validate (NodeRules.PegEventStart tip) === Right expected,code===0,
      contents===[12345,expected,54321],invalid===replicate 6 (-1),missing===(-1),unchanged===contents]

pegEventRange :: Property
pegEventRange = forAll ((,,) <$> field <*> field <*> field) $ \(start,count,tip) -> ioProperty $
  withArray ([12345,67890,54321] :: [Int32]) $ \output -> do
    let expected | start < 0 || start > tip = Left 1
                 | count < 1 || count > 10000 = Left 2
                 | otherwise = Right (fromInteger (min (toInteger tip) (toInteger start+toInteger count-1)))
    code <- elements_hs_export_range 2 start count 0 tip (output `plusPtr` 4)
    contents <- peekArray 3 output
    reserved <- elements_hs_export_range 2 start count 1 tip output
    missing <- elements_hs_export_range 2 start count 0 tip nullPtr
    invalid <- elements_hs_export_range maxBound start count 0 tip output
    unchanged <- peekArray 3 output
    pure $ conjoin [validate (NodeRules.PegEventRange start count tip) === expected,
      code === either id (const 0) expected,
      contents === [12345,either (const 67890) id expected,54321],
      reserved === -1,missing === -1,invalid === -1,unchanged === contents]
  where field = frequency [(1,arbitrary),(3,elements [minBound,-1,0,1,9999,10000,10001,maxBound-9999,maxBound])]

anchorRules :: Property
anchorRules = forAll fixture $ \(candidate,previous) -> ioProperty $ do
  let sane [version,ph,bh,pw,bw,height,successor,median] = version==1 &&
        all (>0) [ph,bh,pw,bw] && bw>pw && successor==(height+1) `mod` 4294967296 && median<=4294967295
      sane _ = False
      follows = sane candidate && sane previous && candidate!!5>=previous!!6 &&
        (if candidate!!5==previous!!6 then candidate!!1==previous!!2 && candidate!!3==previous!!4
         else candidate!!3>previous!!4)
      encode = B.pack . concat . zipWith (\width value ->
        take width (map fromIntegral (iterate (`div` 256) value))) [1,32,32,32,32,4,4,8]
      check encoded expected = B.useAsCString encoded $ \ptr -> do
        code <- elements_hs_anchor_rule (fromIntegral (B.length encoded)) (castPtr ptr)
        pure $ conjoin [validate (Bmm.AnchorRule encoded)===expected,code===(if expected then 1 else 0)]
      checkpoint fields = B.useAsCString (encode fields) $ \ptr -> withArray (replicate 82 (0xa5 :: Word8)) $ \buffer -> do
        let result = B.pack [fromIntegral (value `shiftR` shift) |
              (width,value) <- zip [32,8,8,32] [fields!!1,fields!!5,fields!!7,fields!!3],
              shift <- reverse [0,8..8*(width-1)]]
            expected = if sane fields then Right result else Left 1
        code <- elements_hs_anchor_checkpoint 145 (castPtr ptr) (buffer `plusPtr` 1)
        observed <- peekArray 82 buffer
        pure $ conjoin [validate (Bmm.AnchorCheckpoint (encode fields))===expected,
          code===(if sane fields then 0 else 1),
          observed===(if sane fields then [0xa5]++B.unpack result++[0xa5] else replicate 82 0xa5)]
  conjoin <$> sequence ([check (encode candidate) (sane candidate),
    check (encode previous) (sane previous),check (encode candidate<>encode previous) follows,
    checkpoint candidate,checkpoint previous] ++
    [check (wordLE 4 status<>encode old<>encode candidate<>if withPrevious then encode previous else B.empty)
       (status==1 && sane old && sane candidate && old/=candidate && (not withPrevious || follows))
     | status <- [0,1,2,4294967295], old <- [candidate,previous], withPrevious <- [False,True]])
  where
    fixture :: Gen ([Integer],[Integer])
    fixture = do
      height <- elements [0,100,4294967294]
      work <- elements [1,255,256,2^(255::Int),2^(256::Int)-3]
      nextHeight <- elements [0,height,height+1,(height+2) `mod` 4294967296,4294967295]
      nextWork <- elements [work,work+1,work+2]
      sameHash <- arbitrary
      let previous = [1,1,2,work,work+1,height,height+1,4294967295]
          candidate = [1,if sameHash then 2 else 3,4,nextWork,(nextWork+1) `mod` 2^(256::Int),nextHeight,
            (nextHeight+1) `mod` 4294967296,0]
      (,) <$> mutate candidate <*> mutate previous
    mutate :: [Integer] -> Gen [Integer]
    mutate fields = do
      index <- choose (-4,7 :: Int)
      if index<0 then pure fields else do
        replacement <- elements $ case index of
          0 -> [0,1,2,255]
          5 -> [0,1,4294967294,4294967295]
          6 -> [0,1,2,4294967295]
          7 -> [0,4294967295,4294967296,18446744073709551615]
          _ -> [0,1,255,256,2^(255::Int),2^(256::Int)-1]
        pure (take index fields++[replacement]++drop (index+1) fields)

anchorFraming :: Property
anchorFraming = once $ ioProperty $ do
  malformed <- sequence [elements_hs_anchor_rule size nullPtr | size <- [0..445]++[maxBound]]
  let sizes = filter (`notElem` [145,290,294,439]) [0..445]
  pure $ conjoin [property (all (==(-1)) malformed),
    conjoin [validate (Bmm.AnchorRule (B.replicate size 1))===False | size <- sizes]]

anchorCheckpointFraming :: Property
anchorCheckpointFraming = once $ ioProperty $
  withArray (replicate 145 (0 :: Word8)) $ \input -> withArray (replicate 82 (0xa5 :: Word8)) $ \buffer -> do
    codes <- sequence [elements_hs_anchor_checkpoint size input (buffer `plusPtr` 1) | size <- [0..445]++[maxBound]]
    missingInput <- elements_hs_anchor_checkpoint 145 nullPtr (buffer `plusPtr` 1)
    missingOutput <- elements_hs_anchor_checkpoint 145 input nullPtr
    observed <- peekArray 82 buffer
    pure $ conjoin [codes===[if size==145 then 1 else -1 | size <- [0..445 :: Word32]++[maxBound]],
      missingInput===(-1),missingOutput===(-1),observed===replicate 82 0xa5,
      conjoin [validate (Bmm.AnchorCheckpoint (B.replicate size 0))===Left 1 | size <- [0..445]]]

depositInputLimitAbi :: Property
depositInputLimitAbi = forAll gen $ \(enabled,rows,limit,fault) -> ioProperty $ do
  let events = if not enabled then [] else concat
        [[((0,fromIntegral tx,0),fromIntegral (length row))] ++
          [((1,fromIntegral tx,fromIntegral input),if flag then 1 else 0)
            | (input,flag) <- zip [0::Int ..] row]
          | (tx,row) <- zip [0::Int ..] rows]
      totals = tail (scanl (+) (0::Integer)
        [if step==1 then fromIntegral fieldValue else 0 | ((step,_,_),fieldValue) <- events])
      inRange = length (takeWhile (<=fromIntegral limit) totals)
      accepted = inRange == length events
      wanted = map fst (take (inRange+1) events)
      value key = maybe (error "unexpected deposit input read") id (lookup key events)
      count = fromIntegral (length rows)
  directTrace <- newIORef []
  direct <- validate (Deposit.InputLimit enabled count limit (\step tx input -> do
    let key = (step,tx,input)
    modifyIORef' directTrace (++[key])
    pure (value key)))
  directReads <- readIORef directTrace
  abiTrace <- newIORef []
  actual <- bracket (makeCursorEffect (\_ step tx input field -> do
    prior <- readIORef abiTrace
    let key = (step,tx,input)
    modifyIORef' abiTrace (++[key])
    if length prior == fault then pure 0 else poke field (value key) >> pure 1))
    freeHaskellFunPtr $ \callback ->
      elements_hs_deposit_input_limit (if enabled then 1 else 0) count limit callback nullPtr
  abiReads <- readIORef abiTrace
  missing <- elements_hs_deposit_input_limit 0 0 0 nullFunPtr nullPtr
  invalid <- elements_hs_deposit_input_limit 2 0 0 nullFunPtr nullPtr
  malformed <- bracket (makeCursorEffect (\_ _ _ _ field -> poke field 2 >> pure 1))
    freeHaskellFunPtr $ \callback -> elements_hs_deposit_input_limit 1 1 0 callback nullPtr
  let failed = fault>=0 && fault<length wanted
  pure $ conjoin [direct===accepted,directReads===wanted,
    actual===(if failed then -1 else if accepted then 1 else 0),
    abiReads===(if failed then take (fault+1) wanted else wanted),
    missing===(-1),invalid===(-1),malformed===(-1)]
  where
    gen = do
      enabled <- arbitrary
      count <- chooseInt (0,6)
      rows <- vectorOf count (chooseInt (0,20) >>= \n -> vectorOf n arbitrary)
      limit <- frequency [(4,choose (0,10)),(1,elements [64,maxBound])]
      fault <- chooseInt (-1,126)
      pure (enabled,rows,limit,fault)

peerAdmissionOrder :: Property
peerAdmissionOrder = forAll ((,,) <$> arbitrary <*> vectorOf 7 arbitrary <*> choose (-1,8 :: Int)) $
  \(syncing,flags,fault) ->
  let yes step = flags !! (if not syncing && step==7 then 2 else step-1)
      branch step accepted rejected =
        let (code,rest) = if yes step then accepted else rejected
        in (code,(fromIntegral step,if yes step then 1 else 0):rest)
      accept = (1,[])
      reject = (0,[])
      (expected,script) = if syncing then branch 1 (branch 2 accept reject) reject
        else branch 1 (let (code,rest) = branch 3 accept (branch 4 (branch 5 (branch 6 accept reject) reject) reject)
                       in (code,(2,1):rest)) (branch 7 accept reject)
  in ioProperty $ commandTrace (if syncing then 265 else 264) (if syncing then 2 else 7)
       (\phase result -> validate (Bmm.PeerAdmissionFlow syncing phase result)) script fault expected

ctvAdmissionAbi :: Property
ctvAdmissionAbi = forAll gen $ \(flags,size) -> ioProperty $ do
  actual <- elements_hs_ctv_admission flags size
  let enabled = testBit flags 0
      discourage = testBit flags 1
      nops = testBit flags 2
      future = testBit flags 3
      present = testBit flags 4
      expected | flags > 31 || (not present && size /= 0) = -1
               | discourage || (not enabled && nops) = 1
               | not enabled = 0
               | not present = 2
               | size == 32 = 3
               | future = 1
               | otherwise = 0
  pure $ conjoin [actual===expected,validate (ScriptPolicy.TemplateAdmission flags size)===expected]
  where
    gen = frequency [(1,arbitrary),(5,(,) <$> choose (0,31) <*> elements [0,1,31,32,33,520,maxBound])]

paymentUriAbi :: Property
paymentUriAbi = forAll gen $ \(flags,scheme) -> ioProperty $ do
  actual <- elements_hs_payment_uri flags scheme
  let table = [(0,[0]),(2,[2,3]),(0,[0]),(1,[1]),(0,[0]),(3,[2,3]),(0,[0]),(1,[1])]
      expected | flags>7 || scheme>5 = -1
               | otherwise = let (selected,accepted) = table !! fromIntegral flags
                             in if scheme==4 then selected else if scheme `elem` accepted then 1 else 0
  pure $ conjoin [actual===expected,validate (NodeRules.PaymentUri flags scheme)===expected]
  where gen = frequency [(1,arbitrary),(5,(,) <$> elements [0..8] <*> elements [0,1,2,3,4,5,6,maxBound])]

addressAliasAbi :: Property
addressAliasAbi = forAll gen $ \(network,prefix) -> ioProperty $
  B.useAsCStringLen network $ \(n,ns) -> B.useAsCStringLen prefix $ \(p,ps) -> do
    checks <- sequence [do
      actual <- elements_hs_address_alias flags (fromIntegral ns) (castPtr n) (fromIntegral ps) (castPtr p)
      let expected | flags>3 = -1
                   | (flags,C.unpack network,C.unpack prefix) `elem`
                       [(0,"elements","ert"),(2,"elements","el")] = 1
                   | otherwise = 0
      pure $ conjoin [actual===expected,validate (NodeRules.AddressAlias flags network prefix)===expected]
      | flags <- [0,1,2,3,4,maxBound]]
    badNetwork <- elements_hs_address_alias 0 1 nullPtr 0 nullPtr
    badPrefix <- elements_hs_address_alias 0 0 nullPtr 1 nullPtr
    oversized <- elements_hs_address_alias 0 maxBound nullPtr 0 nullPtr
    empty <- elements_hs_address_alias 0 0 nullPtr 0 nullPtr
    pure $ conjoin (checks++[badNetwork===(-1),badPrefix===(-1),oversized===(-1),empty===0])
  where
    gen = frequency [(1,(,) <$> (B.pack <$> arbitrary) <*> (B.pack <$> arbitrary)),
      (4,(,) <$> elements (map C.pack ["elements","elementsregtest","signet","main","liquidv1","Elements","elements\NUL",""])
             <*> elements (map C.pack ["ert","el","ERT","EL","ert\NUL","el\NUL","elements","elementsl",""]))]

networkSelectionAbi :: Property
networkSelectionAbi = forAll (frequency [(1,B.pack <$> arbitrary),(3,elements (map C.pack
  ["","elements","liquidv1","liquidtestnet","Elements","elements\NUL","usdd","usdd\NUL","signet","simplicity","dynafed",
   "simplicity:0:1","dynafed:bad","simplicity\NUL:0","Simplicity:0",":dynafed"]))]) $ \text ->
  ioProperty $ B.useAsCStringLen text $ \(input,size) -> do
    checks <- sequence [do
      actual <- elements_hs_network_selection mode flags (fromIntegral size) (castPtr input)
      let name = takeWhile (/= ':') (C.unpack text)
          expected | mode>3 || flags>1 || (mode/=2 && flags/=0) = -1
                   | mode==3 = if C.unpack text `elem` ["elements","liquidv1"] then 1 else 0
                   | mode==0 = if C.unpack text=="elements" then 0 else 1
                   | mode==1 = if C.unpack text=="usdd" then 2 else 0
                   | flags==1 = 3
                   | name=="simplicity" = 4
                   | name=="dynafed" = 5
                   | otherwise = 0
      pure $ conjoin [actual===expected,validate (NodeRules.NetworkSelection mode flags text)===expected]
      | mode <- [0,1,2,3,4,maxBound], flags <- [0,1,2,maxBound]]
    missing <- elements_hs_network_selection 0 1 0 nullPtr
    noInput <- elements_hs_network_selection 0 0 1 nullPtr
    oversized <- elements_hs_network_selection 0 0 maxBound nullPtr
    empty <- elements_hs_network_selection 1 0 0 nullPtr
    pure $ conjoin (checks++[missing===(-1),noInput===(-1),oversized===(-1),empty===0])

configurationFieldAbi :: Property
configurationFieldAbi = forAll gen $ \(kind,text,capacity) -> ioProperty $
  B.useAsCStringLen text $ \(input,size) -> allocaBytes (capacity+2) $ \output -> do
    pokeArray output (replicate (capacity+2) (0xa5 :: Word8))
    actual <- elements_hs_configuration_field kind (fromIntegral size) (castPtr input)
      (fromIntegral capacity) (output `plusPtr` 1)
    outputBytes <- peekArray (capacity+2) output
    noOutput <- elements_hs_configuration_field kind (fromIntegral size) (castPtr input) 0 nullPtr
    noInput <- elements_hs_configuration_field kind 1 nullPtr 1 output
    invalid <- elements_hs_configuration_field 10 maxBound nullPtr 0 output
    let parsed = validate (NodeRules.ConfigurationField kind text)
        (expected,payload) = case parsed of
          Left code -> (fromIntegral (-1-code),[])
          Right value | B.length value<=capacity -> (fromIntegral (B.length value),B.unpack value)
          _ -> (-1,[])
    pure $ conjoin [actual===expected,outputBytes===([0xa5]++payload++replicate (capacity+1-length payload) 0xa5),
      noOutput===(-1),noInput===(-1),invalid===(-1)]
  where
    gen = do
      kind <- choose (0,9)
      hexText <- B.pack <$> vectorOf 64 (elements ([48..57]++[65..70]++[97..102]))
      registryText <- B.pack <$> vectorOf 650 (elements ([48..57]++[65..70]++[97..102]))
      text <- frequency [(3,pure hexText),(3,pure (hexText<>C.pack ":+4294967295")),
        (2,pure (C.pack "__cookie__:"<>hexText)),(2,elements (map C.pack ["u:p","__cookie__:p","u::p"])),
        (3,pure registryText),(1,pure (B.take 649 registryText)),(1,pure (registryText<>C.pack "00")),
        (1,pure (B.replicate 64 48)),(2,B.pack <$> resize 100 arbitrary),
        (1,elements (map C.pack ["", "00", "6a", "gg", "00:0", " 00", "00\NUL"]))]
      capacity <- frequency [(2,choose (0,100)),(1,elements [324,325,326])]
      pure (kind,text,capacity)

proposalDescriptionBoundaries :: Property
proposalDescriptionBoundaries = once $ ioProperty $ do
  checks <- sequence [B.useAsCString payload $ \input -> allocaBytes (capacity+2) $ \output -> do
    pokeArray output (replicate (capacity+2) (0xa5 :: Word8))
    code <- elements_hs_configuration_field 9 (fromIntegral size) (castPtr input)
      (fromIntegral capacity) (output `plusPtr` 1)
    observed <- peekArray (capacity+2) output
    let valid = size>=52 && size<=65526
        expected = B.pack [0,8,69,108,101,109,101,110,116,115] <> payload
        written = if valid && capacity>=B.length expected then B.unpack expected else []
        status = if not valid then -2 else if null written then -1 else length written
    pure $ conjoin [fromIntegral code===status,
      observed===([0xa5]++written++replicate (capacity+1-length written) 0xa5),
      validate (NodeRules.ConfigurationField 9 payload)===(if valid then Right expected else Left 1)]
    | size <- [0,51,52,53,65526,65527], capacity <- [size+9,size+10,size+11],
      let payload = B.pack (take size (cycle [0,255,1,128]))]
  pure (conjoin checks)

replayInitialActions :: Property
replayInitialActions = forAll arbitrary $ \reply -> conjoin
  [validate (ParentReplay.StoreFlow kind 0 reply) ===
    (if kind==61 then 2 else if kind<=128 then 1 else -1)
  | kind <- [0..146]++[255,65535,maxBound]]

configuredSlotPolicy :: Property
configuredSlotPolicy = forAll ((,,) <$> elements [0,1,2,maxBound] <*>
  frequency [(4,elements [minBound,-1,0,24,130,255,256,maxBound]),(1,arbitrary)] <*>
  frequency [(4,choose (0,256)),(1,arbitrary)]) $ \(present,requested,configured) -> ioProperty $ do
    actual <- elements_hs_parent_replay_record 23 present requested configured 0
    let expected = present==1 && requested>=0 && requested<=255 && configured<=255 && fromIntegral requested==configured
    pure (actual === if expected then 1 else 0)

definitiveWaitError :: Property
definitiveWaitError = messageMatchParity 0 Bmm.DefinitiveWaitError
  ["BMM successor", "not the exact successor of committed parent",
   "not the active-chain block at its declared height",
   "cached parent edge has no unique enforcer-recognized M7",
   "expected critical hash does not match the cached enforcer-recognized M7"]

duplicateRequest :: Property
duplicateRequest = messageMatchParity 1 Bmm.DuplicateRequest
  ["AlreadyExists", "same `sidechain_number` and `prev_bytes` already exists"]

messageMatchParity :: Word32 -> (B.ByteString -> Bmm.MessageMatch) -> [String] -> Property
messageMatchParity kind rule markers = forAll ((,,) <$> arbitrary <*> arbitrary <*> elements markers) $ \(prefix,suffix,marker) ->
  forAll (choose (0,length marker)) $ \width -> ioProperty $ do
    let message = B.pack prefix <> C.pack (take width marker) <> B.pack suffix
        expected = any (`List.isInfixOf` C.unpack message) markers
    actual <- B.useAsCStringLen message $ \(ptr,size) -> elements_hs_bmm_message kind (fromIntegral size) (castPtr ptr)
    legacy <- if kind/=0 then pure actual else B.useAsCStringLen message $ \(ptr,size) ->
      elements_hs_bmm_wait_error (fromIntegral size) (castPtr ptr)
    empty <- elements_hs_bmm_message kind 0 nullPtr
    invalid <- elements_hs_bmm_message kind 1 nullPtr
    oversized <- elements_hs_bmm_message kind maxBound nullPtr
    unknown <- elements_hs_bmm_message 2 0 nullPtr
    pure $ conjoin [validate (rule message) === expected,legacy===actual,
      actual === (if expected then 1 else 0),empty===0,invalid===(-1),oversized===(-1),unknown===(-1)]

workBidAdmission :: Property
workBidAdmission = forAll gen $ \(flags,height,fees,work,reserve,requested,rate) -> ioProperty $ do
  let bound = 2100000000000000
      scaled = toInteger work * toInteger rate + 999999
      cost = scaled `quot` 1000000
      cap = toInteger fees-cost-toInteger reserve
      preflight | flags>3 = -1 | flags/=3 = 1
                | height<=0 || height>4294967295 = 2
                | fees<=0 || work<0 || reserve<0 || requested<=0 = 3
                | otherwise = 0
      code | preflight/=0 = preflight
           | any (\n -> n<0 || n>bound) [fees,rate,reserve] || scaled>toInteger (maxBound :: Word64) ||
             cost>toInteger bound || cap<0 = 4
           | toInteger requested>cap = 5
           | otherwise = 0
      fields = if code `elem` [0,5] then map fromInteger
        [cost,cost+toInteger reserve,cap,if code==0 then cap-toInteger requested else 0] else replicate 4 0
      calls = if preflight==0 then [0] else []
  directTrace <- newIORef ([] :: [Word32])
  direct <- validate (Bmm.WorkBid flags height fees work reserve requested bound
    (modifyIORef' directTrace (++[0]) >> pure rate))
  abiTrace <- newIORef []
  (actual,outputWords,missing) <- bracket (wrapMatchFact (\_ step -> modifyIORef' abiTrace (++[step]) >> pure rate)) freeHaskellFunPtr $ \reader ->
    withArray (replicate 6 (-77 :: Int64)) $ \ptr -> do
      noOutput <- elements_hs_bmm_work_bid flags height fees work reserve requested bound nullPtr reader nullPtr
      result <- elements_hs_bmm_work_bid flags height fees work reserve requested bound (ptr `plusPtr` 8) reader nullPtr
      values <- peekArray 6 ptr
      pure (result,values,noOutput)
  seenDirect <- readIORef directTrace
  seenAbi <- readIORef abiTrace
  pure $ conjoin [direct === (code,fields), actual === code, outputWords === ([-77]++fields++[-77]),
    seenDirect === calls, seenAbi === calls, missing === (-1)]
  where
    sampleAmount = frequency [(3,elements [minBound,-1,0,1,100,1000,4294967295,4294967296,2100000000000000,maxBound]),(1,arbitrary)]
    gen = frequency [(3,(,,,,,,) <$> elements [0,1,2,3,4,maxBound] <*> sampleAmount <*> sampleAmount <*> sampleAmount <*> sampleAmount <*> sampleAmount <*> sampleAmount),
      (1,elements [(3,1,1000,0,100,400,1000),(3,4294967295,200000,50000,10000,140000,1000),
                   (3,1,1000,1,0,999,1000),(3,1,2100000000000000,0,2100000000000000,1,0)])]

depositPreviousSequence :: Property
depositPreviousSequence = forAll (frequency [(1,elements [minBound,-1,0,1,2,maxBound]),(3,arbitrary)]) $ \current -> ioProperty $ do
  actual <- elements_hs_deposit_previous_sequence current
  let expected = if current > 0 then fromInteger (toInteger current - 1) else -1
  pure $ conjoin [actual === expected, validate (Deposit.PreviousSequence current) === expected]

depositBroadcastMessage :: Property
depositBroadcastMessage = forAll ((,,,) <$> elements [0,1,2,3,maxBound] <*> resize 32 arbitrary <*>
  elements ["","already in block chain","txn-already-in-mempool","Already in block chain","txn-already-in-mempoo",
    "multiple slot CTIP","Multiple slot CTIP","multiple slot CTI","multiple slot ctip"] <*>
  resize 32 arbitrary) $ \(kind,before,token,after) -> ioProperty $ do
    let message = B.pack before <> C.pack token <> B.pack after
        needle = case kind of 0 -> "already in block chain"; 1 -> "txn-already-in-mempool"; _ -> "multiple slot CTIP"
        expected = if kind>2 then -1 else if needle `List.isInfixOf` C.unpack message then 1 else 0
    actual <- B.useAsCStringLen message $ \(ptr,size) ->
      elements_hs_deposit_broadcast_message kind (fromIntegral size) (castPtr ptr)
    malformed <- sequence [elements_hs_deposit_broadcast_message 0 1 nullPtr,
      elements_hs_deposit_broadcast_message 0 maxBound nullPtr,
      elements_hs_deposit_broadcast_message 3 0 nullPtr]
    empty <- elements_hs_deposit_broadcast_message 0 0 nullPtr
    pure $ conjoin [actual === expected, validate (Deposit.MessageMatches kind message) === expected,
      malformed === replicate 3 (-1), empty === 0]

walletBalanceTotal :: Property
walletBalanceTotal = forAll ((,,) <$> part <*> part <*> part) $ \(trusted,pending,immature) ->
  ioProperty $ do
    let values = [trusted,pending,immature]
        combined = sum (map toInteger values)
        expected = if all (>=0) values && combined<=toInteger (maxBound :: Int64) then fromInteger combined else -1
    actual <- elements_hs_wallet_balance trusted pending immature
    pure $ conjoin [actual === expected, validate (Withdrawal.WalletBalance values) === expected]
  where part = frequency [(3,elements [minBound,-1,0,1,maxBound]),(2,arbitrary)]

amountSumPolicy :: Property
amountSumPolicy = forAll ((,,) <$> frequency [(3,elements [minBound,-1,0,1,maxBound]),(2,arbitrary)] <*>
  frequency [(3,elements [0,1,maxBound]),(2,arbitrary)] <*>
  frequency [(3,elements [0,1,2100000000000000,maxBound]),(2,arbitrary)]) $ \(amount,accumulated,limit) -> ioProperty $ do
    actual <- elements_hs_parent_replay_record 24 0 amount accumulated limit
    let expected = amount >= 0 && accumulated <= limit && toInteger amount <= toInteger limit - toInteger accumulated
        direct = validate (ParentReplay.Record 24 0 amount accumulated limit)
    pure (conjoin [actual === if expected then 1 else 0, direct === actual])

transactionAdmissionModes :: Property
transactionAdmissionModes = forAll (frequency [(4,choose (0,31)),(1,arbitrary)]) $ \flags -> ioProperty $ do
  let modes | flags > 7 = -1
            | testBit flags 0 = 0
            | not (testBit flags 1) = 1
            | testBit flags 2 = 2
            | otherwise = 3
      parent | flags > 3 = -1
             | flags == 1 = 1
             | otherwise = 0
  checks <- sequence [do
    actual <- elements_hs_parent_replay_record kind flags 0 0 0
    pure (conjoin [actual === expected, validate (ParentReplay.Record kind flags 0 0 0) === expected])
    | (kind,expected) <- [(25,modes),(26,parent)]]
  pure (conjoin checks)

headerLayoutPolicy :: Property
headerLayoutPolicy = forAll ((,,) <$> arbitrary <*> elements ([0..48] ++ [maxBound]) <*>
  elements [0,1,2,3,maxBound]) $ \(version,flags,count) -> ioProperty $
  withArray (replicate 4 (0xa5a5a5a5 :: Word32)) $ \output -> do
    let reading = testBit flags 1
        hasWithdrawal = if reading || flags == 16 then testBit version 30 else testBit flags 2
        dynamic = if reading || flags == 16 then testBit version 31 else testBit flags 3
        clean = clearBit (clearBit version 30) 31
        encoded = if reading then clean else clean + (if hasWithdrawal then 0x40000000 else 0) + (if dynamic then 0x80000000 else 0)
        fields = sum [if enabled then weight else 0 | (enabled,weight) <-
          [(hasWithdrawal,1),(testBit version 20,2),(dynamic,64),(testBit flags 5,256)]]
        validFlags = flags <= 16 || (flags >= 32 && flags <= 47)
        expected | not validFlags = Nothing
                 | flags == 16 = Just (version,fields)
                 | testBit flags 0 = Just (encoded,fields)
                 | otherwise = Just (version,0)
        admitted = count == 2 && validFlags
        wanted = case expected of Just (v,f) | admitted -> [0xa5a5a5a5,v,f,0xa5a5a5a5]; _ -> replicate 4 0xa5a5a5a5
    actual <- elements_hs_bmm_header_layout version flags count (output `plusPtr` 4)
    observed <- peekArray 4 output
    missing <- elements_hs_bmm_header_layout version flags count nullPtr
    pure (conjoin [actual === if admitted then 0 else -1, observed === wanted, missing === -1,
      validate (Bmm.HeaderLayout version flags) === expected])

foreign import ccall unsafe reference_parent_replay_record :: Word32 -> Word32 -> Int64 -> Word64 -> Word64 -> IO Int32
parentReplayRecordParity :: Property
parentReplayRecordParity = forAll gen $ \(kind,facts,value,first,second) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record kind facts value first second
  expected <- reference_parent_replay_record kind facts value first second
  pure (actual === expected)
  where
    gen = (,,,,) <$> elements ([0..12] ++ [maxBound]) <*> frequency [(4,choose (0,16)),(1,arbitrary)] <*>
      frequency [(4,elements [minBound,-1,0,1,2100000000000000,2100000000000001,maxBound]),(1,arbitrary)] <*>
      width <*> width
    width = frequency [(4,elements [0,1,4,5,127,128,129,2147483647,2147483648,4294967294,4294967295,4294967296,2100000000000000,maxBound]),(1,arbitrary)]

replayDistanceRule :: Property
replayDistanceRule = forAll ((,) <$> width <*> width) $ \(upper,lower) -> ioProperty $ do
  let expected = if lower <= upper then fromIntegral upper - fromIntegral lower else -1
  actual <- elements_hs_replay_distance upper lower
  pure $ conjoin [actual === expected, validate (ParentReplay.Distance upper lower) === expected]
  where width = frequency [(1,arbitrary),(3,elements [0,1,2147483647,2147483648,maxBound :: Word32])]

signedPredecessorRule :: Property
signedPredecessorRule = forAll ((,) <$> height <*> height) $ \(current,previous) -> ioProperty $ do
  let expected = if toInteger previous == toInteger current - 1 then 1 else 0
  actual <- elements_hs_parent_replay_record 32 0 previous (fromIntegral current) 0
  pure $ conjoin [actual === expected,
    validate (ParentReplay.Record 32 0 previous (fromIntegral current) 0) === expected]
  where height = frequency [(1,arbitrary),(3,elements [minBound,minBound+1,-2,-1,0,1,4294967295,maxBound-1,maxBound :: Int64])]

currentEpochRule :: Property
currentEpochRule = forAll ((,) <$> width <*> width) $ \(authenticated,other) ->
  forAll (elements [authenticated,other]) $ \observed -> ioProperty $ do
    let expected = authenticated /= 0 && authenticated == observed
        result = if expected then 1 else 0
    actual <- elements_hs_parent_replay_record 31 0 0 authenticated observed
    anchor <- elements_hs_parent_replay_record 20 1 24 authenticated observed
    missing <- elements_hs_parent_replay_record 20 0 24 authenticated observed
    invalidSlot <- elements_hs_parent_replay_record 20 1 256 authenticated observed
    pure $ conjoin [actual === result, anchor === result, missing === 0, invalidSlot === 0,
      ParentReplay.currentEpoch authenticated observed === expected,
      validate (ParentReplay.Record 31 0 0 authenticated observed) === result]
  where width = frequency [(1,arbitrary),(3,elements [0,1,2,4294967295,4294967296,maxBound :: Word64])]

depositRoutingRule :: Property
depositRoutingRule = forAll ((,) <$> elements ([0..12] ++ [maxBound]) <*> elements ([0..8] ++ [maxBound])) $
  \(count,flags) -> ioProperty $ do
    actual <- elements_hs_parent_replay_record 30 flags 0 count 0
    let ecx = (count == 6 && testBit flags 0) || (count == 11 && testBit flags 1)
        expected | flags > 7 = -1
                 | ecx = fromIntegral count * 256 + if testBit flags 2 then 3 else 2
                 | testBit flags 1 = 8 * 256 + 1
                 | otherwise = 6 * 256 + if testBit flags 2 then 4 else 0
    pure (actual === expected)

nonEmptyBoundedRule :: Property
nonEmptyBoundedRule = forAll ((,) <$> width <*> width) $ \(size,limit) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 29 0 0 size limit
  let expected = size /= 0 && toInteger size <= toInteger limit
  pure $ conjoin [actual === if expected then 1 else 0,
    ParentReplay.nonEmptyBounded size limit === expected]
  where
    width = frequency [(1,arbitrary),(3,elements [0,1,127,128,129,4294967296,maxBound :: Word64])]

laneLimitRule :: Property
laneLimitRule = forAll ((,,) <$> width <*> width <*> width) $ \(limit,current,additional) -> ioProperty $ do
  let expected = toInteger current + toInteger additional > toInteger limit
      narrow = fromIntegral limit :: Word32
  actual <- elements_hs_parent_replay_record 28 narrow 0 current additional
  pure $ conjoin [ParentReplay.exceedsLane limit current additional === expected,
    actual === if toInteger current + toInteger additional > toInteger narrow then 1 else 0]
  where width = frequency [(3,elements [0,1,2,4294967295,4294967296,maxBound]),(1,arbitrary)]

cacheExpiryRule :: Property
cacheExpiryRule = forAll ((,,) <$> arbitrary <*> arbitrary <*> arbitrary) $ \(first,other,expired) ->
  forAll (elements [first,other]) $ \second -> ioProperty $ do
    let flags = if expired then 1 else 0
        expected = if first/=second || expired then 1 else 0
    actual <- elements_hs_parent_replay_record 27 flags 0 first second
    malformed <- mapM (\bad -> elements_hs_parent_replay_record 27 bad 0 first second) [2,3,maxBound]
    pure $ conjoin [actual === expected,
      validate (ParentReplay.Record 27 flags 0 first second) === expected,
      malformed === replicate 3 (-1)]

parentRuleCatalog :: Property
parentRuleCatalog = forAll (frequency [(3,elements [0,3,4,5,6,maxBound]),(1,arbitrary)]) $ \version ->
  let rows = Constants.parentRuleCatalog
      selected = lookup version [(v,(enums,texts)) | (v,enums,texts) <- rows]
  in conjoin [Constants.betanetReplayVersion === 5,
       map (\(v,_,_) -> v) rows === [4,5],
       [take 2 enums | (_,enums,_) <- rows] ===
         [["TreasuryOpcode::NOP5", "DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6"],
          ["TreasuryOpcode::NOP8", "DrivechainM6ReplayRule::SEQUENTIAL_M6"]],
       property (all (\(_,enums,texts) -> length enums == 3 && length texts == 3) rows),
       property (case selected of Nothing -> version /= 4 && version /= 5; Just _ -> version == 4 || version == 5)]

parentBootstrapCatalog :: Property
parentBootstrapCatalog = forAll (frequency [(3,elements [0,3,4,5,6,maxBound]),(1,arbitrary)]) $ \version ->
  let actual = Constants.bootstrapSlots version
      ids = fmap (map (\(slot,_,_,_,_) -> slot)) actual
      expected = case version of 4 -> Just [2,4,9,13,98,99,255]; 5 -> Just []; _ -> Nothing
  in conjoin [ids === expected, Constants.emptyBootstrapVersion === 5,
       Constants.emptyBootstrapHeight === 967679,
       property (maybe True (all (\(_,active,txid,_,_) -> length active == 64 && length txid == 64)) actual)]

parentLifecyclePlans :: Property
parentLifecyclePlans = forAll ((,,) <$> elements [minBound..maxBound] <*> arbitrary <*> arbitrary) $ \(kind,enabled,boundary) ->
  let expected = if kind == Constants.BundleReserve then
          [if enabled then 1 else if boundary then 2 else 3]
        else if not enabled then [] else case kind of
        Constants.BudgetEnter -> if boundary then [1,2,3,4,5,6,7,8] else [1]
        Constants.BudgetExit -> if boundary then [1,2,3,4,5,6,7] else [1,2]
        Constants.AdmissionEnter -> [1]
        Constants.AdmissionExit -> [1,2]
        Constants.BundleAbort -> [1]
        Constants.BundleReserve -> [1]
  in conjoin [Constants.lifecyclePlan kind enabled boundary === expected,
       property (all (\action -> action > 0 && action <= 8) expected),
       property (length expected <= 8)]

parentReplayConstantsFrozen :: Property
parentReplayConstantsFrozen =
  let expected = [("uint32_t","REPLAY_UNIQUE_SCHEMA",4),("uint32_t","REPLAY_REPROPOSAL_SCHEMA",5),
        ("size_t","DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES",4194304),
        ("uint8_t","REPLAY_DEFAULT_HISTORY_RULE",0),
        ("bool","REPLAY_DB_MEMORY_ONLY",0),("bool","REPLAY_DB_OBFUSCATE",0),
        ("bool","REPLAY_DB_SYNC",1),("bool","REPLAY_RESET_WIPE",1),
        ("uint8_t","DB_REPLAY_IDENTITY",73),("uint8_t","DB_REPLAY_TIP",84),
        ("uint8_t","DB_REPLAY_DEPOSIT",100),("uint8_t","DB_REPLAY_BMM_EDGE",101),
        ("uint8_t","DB_REPLAY_SUCCESSFUL_WITHDRAWAL",119),("uint8_t","DB_REPLAY_WITHDRAWAL_OCCURRENCE",87),
        ("int","REPLAY_LOAD_EMPTY",0),("int","REPLAY_LOAD_LOADED",1),
        ("int","REPLAY_LOAD_CORRUPT",2),("int","REPLAY_LOAD_IDENTITY_MISMATCH",3),
        ("int","REPLAY_READ_FOUND",0),("int","REPLAY_READ_NOT_FOUND",1),("int","REPLAY_READ_CORRUPT",2),
        ("int64_t","LOCKED_PARENT_DEADLINE_SECONDS",2),
        ("int64_t","ANCHOR_WARM_DEADLINE_SECONDS",120),
        ("size_t","MAX_ECX_DEPLOYMENT_IDENTITY_BYTES",1024),
        ("uint32_t","LOCKED_MAX_REPLAY_STEPS",2),("int64_t","PARENT_RPC_BACKOFF_SECONDS",5),
        ("size_t","MAX_MAINCHAIN_RPC_RESPONSE_SIZE",16777216),("size_t","MAX_MAINCHAIN_RPC_HEADER_SIZE",65536),
        ("int64_t","AUTHENTICATED_GRPC_TIMEOUT_SECONDS",30),("size_t","MAX_AUTHENTICATED_GRPC_RESPONSE_SIZE",16777216)]
  in Constants.replayConstants === expected

commandFlowFraming :: Property
commandFlowFraming = forAll generator $ \(bound,command,reply,next) -> ioProperty $ do
  called <- newIORef []
  let fields = fromIntegral command :: Word32
      step = fields `mod` 256
      status = (fields `div` 256) `mod` 256
      terminal = testBit fields 16
      committing = testBit fields 17
      flags = if terminal then 65536 else if committing then 131072 else 0
      valid = bound >= 1 && bound <= 255 && command > 0 && step > 0 && step <= fromIntegral bound &&
        status <= 3 && not (terminal && committing) && fields == step + flags + (if flags == 0 then 0 else 256*status)
      finish code = if code >= -13 && code <= -10 then -10-code else -1
      expected | bound < 1 || bound > 255 = -1
               | command <= 0 = finish command
               | not valid || reply < 0 || reply > 4294967295 = -1
               | terminal || (committing && reply == 1) = fromIntegral status
               | otherwise = finish next
      action phase = modifyIORef' called (++[phase]) >> pure reply
      transition phase result
        | phase == 0 = command
        | phase == step && result == fromIntegral reply = next
        | otherwise = error "unexpected command continuation"
  actual <- validate (Workflow.CommandFlow bound transition action)
  trace <- readIORef called
  pure (conjoin [actual === expected,trace === [step | valid]])
  where
    generator = (,,,) <$> elements [-1,0,1,7,255,256,maxBound] <*>
      frequency [(3, do
        step <- elements [0,1,7,8,255]
        status <- elements [0,1,2,3,4,255]
        flags <- elements [0,65536,131072,196608,262144]
        pure (step + 256*status + flags)), (1,arbitrary)] <*>
      elements [-1,0,1,2,4294967295,4294967296,maxBound :: Int64] <*> elements [-14,-13,-12,-11,-10,-1,0]

commandFlowLongRun :: Property
commandFlowLongRun = once $ ioProperty $ do
  calls <- newIORef (0 :: Int)
  let action _ = do
        modifyIORef' calls (+1)
        count <- readIORef calls
        pure (if count < 100000 then 1 else 0)
      transition phase reply = if phase == 0 || reply == 1 then 1 else -10
  actual <- validate (Workflow.CommandFlow 1 transition action)
  count <- readIORef calls
  absent <- mapM (\kind -> elements_hs_parent_replay_run kind nullFunPtr nullPtr) [0..190]
  pure (conjoin [actual === 0,count === 100000,absent === replicate 191 (-1)])

predicateFlowFraming :: Property
predicateFlowFraming = forAll generator $ \(acceptZero,bound,command,reply,next) -> ioProperty $ do
  called <- newIORef []
  let terminal = odd (command `div` 256)
      step = command - if terminal then 256 else 0
      valid = command > 0 && step >= 1 && step <= bound
      finish code | code < -1 = -1
                  | code == 0 && acceptZero = 0
                  | otherwise = 1
      expected | command <= 0 = finish command
               | not valid = -2
               | reply /= 0 && reply /= 1 = -1
               | terminal = 1-fromIntegral reply
               | otherwise = finish next
      action phase = modifyIORef' called (++[phase]) >> pure reply
      transition phase result
        | phase == 1000 && result == 0 = command
        | phase == fromIntegral step && result == fromIntegral reply = next
        | otherwise = error "unexpected predicate continuation"
  actual <- validate (Workflow.PredicateFlow acceptZero 1000 bound transition action)
  trace <- readIORef called
  pure (conjoin [actual === expected,trace === [fromIntegral step | valid]])
  where
    generator = (,,,,) <$> arbitrary <*> elements [-1,0,1,6,17,27,34,51,82,255] <*>
      frequency [(4, elements [-3,-2,-1,0,1,6,17,27,34,51,82,83,255,256,257,338,339,511,512,4294967297,maxBound]),
        (1,arbitrary)] <*> elements [-1,0,1,2,4294967295,maxBound :: Int64] <*> elements [-3,-2,-1,0]

foreign import ccall "wrapper" wrapMatchFact :: MatchFact -> IO (FunPtr MatchFact)
foreign import ccall "wrapper" wrapProofFacts :: ProofFacts -> IO (FunPtr ProofFacts)

predicateFlowFaults :: Property
predicateFlowFaults = once $ ioProperty $ do
  calls <- newIORef ([] :: [Word32])
  let entries = elements_hs_parent_replay_tip_run : [elements_hs_deposit_run kind 0 | kind <- [0..5]]
  checks <- sequence [do
    writeIORef calls []
    result <- bracket (wrapMatchFact (\_ step -> modifyIORef' calls (++[step]) >> pure reply)) freeHaskellFunPtr $ \callback ->
      entry callback nullPtr
    trace <- readIORef calls
    pure (result == -1 && length trace == 1) | entry <- entries, reply <- [-1,2,maxBound]]
  nulls <- mapM (\entry -> entry nullFunPtr nullPtr) entries
  writeIORef calls []
  invalid <- bracket (wrapMatchFact (\_ step -> modifyIORef' calls (++[step]) >> pure 1)) freeHaskellFunPtr $ \callback ->
    sequence [elements_hs_deposit_run kind start callback nullPtr |
      (kind,start) <- [(6,0),(maxBound,0),(1,1),(2,1),(3,1),(4,1),(5,1)]]
  untouched <- readIORef calls
  count <- newIORef (0 :: Int)
  let action _ = modifyIORef' count (+1) >> readIORef count >>= \n -> pure (if n < 100000 then 1 else 0)
      transition phase result = if phase == 0 || result == 1 then 1 else 0
  long <- validate (Workflow.PredicateFlow True 0 1 transition action)
  iterations <- readIORef count
  pure (conjoin [property (and checks),nulls === replicate 7 (-1),invalid === replicate 7 (-1),
    untouched === [],long === 0,iterations === 100000])

headerAdmissionBounds :: Property
headerAdmissionBounds = once $ ioProperty $ do
  bounds <- mapM (\kind -> elements_hs_parent_replay_store_checked kind maxBound 0) [210,211]
  malformed <- sequence [elements_hs_parent_replay_store_checked kind phase reply |
    kind <- [210,211], phase <- [1..7], reply <- [2,maxBound]]
  invalid <- sequence [elements_hs_parent_replay_store_checked kind phase reply |
    kind <- [210,211], phase <- [8,maxBound], reply <- [0,1], phase/=maxBound || reply/=0]
  pure $ conjoin [bounds===[7,7],malformed===replicate 28 (-1),invalid===replicate 6 (-1)]

feeFreeSelectionOrder :: Property
feeFreeSelectionOrder = forAll ((,,) <$> arbitrary <*>
  resize 8 (listOf (frequency [(1,pure (replicate 10 True)),(1,vectorOf 10 arbitrary)])) <*>
  choose (-1,100 :: Int)) $ \(native,rows,fault) -> ioProperty $ do
    let yes row step = (rows !! row) !! (step-4)
        eligible row steps rest = case steps of
          [] -> rest
          step:more -> step : if yes row step then eligible row more rest else []
        candidate row = eligible row [4..9] ([10] ++ if yes row 10
          then eligible row [11] admitted else admitted)
          where admitted=eligible row [12,13] [14,15]
        script = [(1 :: Word32,0 :: Int)] ++ if not native then [] else [(2,0)] ++
          concat [[(fromIntegral step,row) | step <- [3]++candidate row++[16]] | row <- [0..length rows-1]] ++ [(3,length rows)]
        failed = fault>=0 && fault<length script
        planned = if failed then take (fault+1) script else script
        run invoke = do
          trace <- newIORef []
          index <- newIORef (0 :: Int)
          code <- invoke (\step -> do
            seen <- readIORef trace
            row <- readIORef index
            modifyIORef' trace (++[(step,row)])
            if length seen==fault then pure (-1) else case step of
              1 -> pure (if native then 1 else 0)
              2 -> writeIORef index 0 >> pure 1
              3 -> pure (if row<length rows then 1 else 0)
              14 -> pure 1
              15 -> pure 1
              16 -> modifyIORef' index (+1) >> pure 1
              _ -> pure (if yes row (fromIntegral step) then 1 else 0))
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Workflow.CommandFlow 16 (\phase result ->
      validate (Deposit.FeeFreeSelectionFlow phase result)) action))
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run 218 callback nullPtr)
    bound <- elements_hs_parent_replay_store_checked 218 maxBound 0
    pure $ conjoin [direct===((if failed then -1 else 1),planned),abi===direct,bound===16]

feeFreeSelectionValues :: Property
feeFreeSelectionValues = forAll ((,,,,,,) <$> arbitrary <*> timestamp <*> timestamp <*> timestamp <*>
  frequency [(2,pure [0,1,1,0,0]),(1,vectorOf 5 (elements [0,1,2,maxBound]))] <*>
  arbitrary <*> arbitrary) $ \(native,age,entered,now,fields,canonical,package) -> ioProperty $ do
    let checks [] rest = rest
        checks ((step,ok):xs) rest = step : if ok then checks xs rest else []
        admitted = checks [(12,package),(13,True)] [14,15]
        ageChecks = if age<=0 then admitted else [11,17] ++
          if toInteger entered<=toInteger now-toInteger age then admitted else []
        candidate = checks (zip [4..8] (zipWith (==) fields [0,1,1,0,0]) ++ [(9,canonical)]) ageChecks
        planned = [1] ++ if native then [2,3]++candidate++[16,3] else []
        run invoke = do
          trace <- newIORef []
          exhausted <- newIORef False
          result <- invoke (\step -> do
            modifyIORef' trace (++[step])
            done <- readIORef exhausted
            case step of
              1 -> pure (if native then 1 else 0)
              3 -> pure (if done then 0 else 1)
              9 -> pure (if canonical then 1 else 0)
              11 -> pure (fromIntegral entered)
              17 -> pure (fromIntegral now)
              12 -> pure (if package then 1 else 0)
              16 -> writeIORef exhausted True >> pure 1
              _ | step>=4 && step<=8 -> pure (fields !! (fromIntegral step-4))
                | otherwise -> pure 1)
          seen <- readIORef trace
          pure (result,seen)
    direct <- run (validate . Deposit.FeeFreeSelection age)
    abi <- run (\action -> bracket (makeCursorEffect (\_ step a b field ->
      if a/=0 || b/=0 then pure (-1) else action step >>= poke field >> pure 1)) freeHaskellFunPtr $ \callback ->
      elements_hs_fee_free_selection age callback nullPtr)
    missing <- elements_hs_fee_free_selection age nullFunPtr nullPtr
    pure $ conjoin [direct===(1,planned),abi===direct,missing=== -1]
  where timestamp = elements [minBound,-1,0,1,10,maxBound :: Int64]

templateCommitmentOrder :: Property
templateCommitmentOrder = forAll ((,) <$> vectorOf 3 arbitrary <*> choose (-1,4 :: Int)) $
  \(flags,fault) -> ioProperty $ do
    let yes step = flags !! (step-1)
        script = [1 :: Int] ++ if yes 1 then [2] ++ if yes 2 then [3] else [] else []
        failed = fault>=0 && fault<length script
        planned = if failed then take (fault+1) script else script
        wanted = if failed then -1 else 1
        kind = 216
        bound = 3
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> do
            seen <- readIORef trace
            modifyIORef' trace (++[fromIntegral step])
            pure $ if length seen==fault then -1 else
              if step == 3 || yes (fromIntegral step) then 1 else 0)
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Workflow.CommandFlow bound (\phase result ->
      validate (Bmm.TemplateCommitmentFlow phase result)) action))
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run kind callback nullPtr)
    actualBound <- elements_hs_parent_replay_store_checked kind maxBound 0
    invalid <- sequence [elements_hs_parent_replay_store_checked kind phase reply |
      phase <- [1..fromIntegral bound], reply <- [2,maxBound]]
    pure $ conjoin [direct===(wanted,planned),abi===direct,actualBound===bound,
      invalid===replicate (2*fromIntegral bound) (-1)]

templateSelectionOrder :: Property
templateSelectionOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,4 :: Int)) $
  \(native,authenticated,fault) -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,1),(2,flag native)] ++ if native then
          [(3,flag authenticated),(if authenticated then 4 else 5,1)] else []
    in commandTrace 215 5 (\phase result -> validate (Bmm.TemplateSelectionFlow phase result))
      script fault (if native && not authenticated then 0 else 1)

templateAdmissionOrder :: Property
templateAdmissionOrder = forAll ((,) <$> vectorOf 8 arbitrary <*> choose (-1,8 :: Int)) $ \(flags,fault) -> ioProperty $
  let yes step = flags !! (step-1)
      checked = [7 :: Int] ++ if yes 7 then [] else [8]
      validity = [5] ++ if yes 5 then checked else [6] ++ if yes 6 then checked else []
      script = [1] ++ if not (yes 1) then validity else [2] ++ if yes 2 then validity else
        [3] ++ if yes 3 then [4] else validity
      replies = [(fromIntegral step,if step `elem` [4,8] || yes step then 1 else 0) | step <- script]
  in commandTrace 214 8 (\phase result -> validate (Bmm.TemplateAdmissionFlow phase result))
    replies fault (if last script `elem` [4,8] then 0 else 1)

peginConfirmationPolicy :: Property
peginConfirmationPolicy = forAll gen $ \(mode,height,configured,flags,fault) -> ioProperty $ do
  let match steps = let (accepted,rejected) = span (flags !!) steps
                    in (null rejected,accepted ++ take 1 rejected)
      (alpha,alphaTrace) = match [0,1,2,3,4,5,6,7]
      (beta,betaTrace) = match [0,1,2,3,8,9,5,7]
      (wanted,script)
        | mode>2 = (-1,[])
        | mode==2 = (fromIntegral (max 1 configured),[])
        | mode==0 = (if alpha then 1 else 0,alphaTrace)
        | beta = (6,betaTrace)
        | height>=64 = (if alpha then 1 else fromIntegral configured,betaTrace++alphaTrace)
        | otherwise = (fromIntegral configured,betaTrace)
      failed = fault>=0 && fault<length script
      planned = if failed then take (fault+1) script else script
      run invoke = do
        trace <- newIORef []
        code <- invoke (\step -> do
          seen <- readIORef trace
          modifyIORef' trace (++[fromIntegral step])
          pure $ if length seen==fault then -1 else if flags !! fromIntegral step then 1 else 0)
        seen <- readIORef trace
        pure (code,seen)
  direct <- run (validate . Deposit.ConfirmationPolicy mode height configured)
  abi <- run (\action -> bracket (wrapPolicyEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_pegin_confirmation_policy mode height configured callback nullPtr)
  missing <- elements_hs_pegin_confirmation_policy mode height configured nullFunPtr nullPtr
  malformed <- bracket (wrapPolicyEffect (\_ _ -> pure 2)) freeHaskellFunPtr $ \callback ->
    elements_hs_pegin_confirmation_policy mode height configured callback nullPtr
  pure $ conjoin [direct===(if failed then -1 else wanted,planned),abi===direct,missing=== -1,
    malformed===(if mode==2 then wanted else -1)]
  where
    gen = (,,,,) <$> elements [0,1,2,3,maxBound] <*>
      frequency [(1,arbitrary),(3,elements [minBound,-1,0,63,64,65,2147483647,maxBound])] <*>
      frequency [(1,arbitrary),(3,elements [0,1,6,100,maxBound])] <*>
      frequency [(1,pure (replicate 10 True)),(1,pure (replicate 8 True ++ [False,False])),(3,vectorOf 10 arbitrary)] <*>
      choose (-1,16 :: Int)

withdrawalHistoryOrder :: Property
withdrawalHistoryOrder = forAll ((,) <$> resize 12 (listOf (frequency [(1,pure Nothing),(4,Just <$> choose (0,20 :: Word64))]))
  <*> choose (-1,90 :: Int)) $ \(rows,fault) -> ioProperty $ do
  let model _ [] = (0,[1])
      model prior (row:rest) = case row of
        Nothing -> (1,[1,2,3])
        Just count | count < prior -> (2,[1,2,3,4])
        Just count -> let (code,steps) = model count rest
                      in (code,[1,2,3,4,5] ++ [6 | count/=prior] ++ [7] ++ steps)
      (normal,script) = model 0 rows
      failed = fault>=0 && fault<length script
      planned = if failed then take (fault+1) script else script
      completed = if failed then take fault script else script
      expected = if failed then -1 else normal
      selected = length (filter (==6) completed)
      run invoke = do
        index <- newIORef 0
        prior <- newIORef 0
        chosen <- newIORef (0 :: Int)
        trace <- newIORef []
        code <- invoke (\step -> do
          seen <- readIORef trace
          modifyIORef' trace (++[step])
          i <- readIORef index
          before <- readIORef prior
          let row = rows !! i
              count = maybe 0 id row
              yes value = pure (if value then 1 else 0)
          if length seen==fault then pure (-1) else case step of
            1 -> yes (i<length rows)
            2 -> pure 1
            3 -> yes (case row of Nothing -> False; Just _ -> True)
            4 -> yes (count>=before)
            5 -> yes (count/=before)
            6 -> modifyIORef' chosen (+1) >> pure 1
            7 -> writeIORef prior count >> modifyIORef' index (+1) >> pure 1
            _ -> pure (-1))
        seen <- readIORef trace
        n <- readIORef chosen
        pure (code,seen,n)
  direct <- run (\action -> validate (Workflow.CommandFlow 7 (\phase reply ->
    validate (ParentReplay.StoreFlow 227 phase reply)) action))
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 227 callback nullPtr)
  bound <- elements_hs_parent_replay_store_checked 227 maxBound 0
  missing <- elements_hs_parent_replay_run 227 nullFunPtr nullPtr
  malformed <- sequence [elements_hs_parent_replay_store_checked 227 phase reply |
    phase <- [1..7], reply <- [2,maxBound]]
  pure $ conjoin [direct===(expected,planned,selected),abi===direct,bound===7,missing===(-1),malformed===replicate 14 (-1)]

commandTrace :: Word32 -> Int32 -> (Word32 -> Word32 -> Int32) -> [(Word32,Int64)] -> Int -> Int32 -> IO Property
commandTrace = commandTraceWith (const [2,maxBound])

commandTraceWith :: (Word32 -> [Word32]) -> Word32 -> Int32 -> (Word32 -> Word32 -> Int32)
  -> [(Word32,Int64)] -> Int -> Int32 -> IO Property
commandTraceWith invalidReplies kind limit next script fault expected = do
  let failed = fault>=0 && fault<length script
      planned = map fst (if failed then take (fault+1) script else script)
      run invoke = do
        trace <- newIORef []
        code <- invoke (\step -> do
          seen <- readIORef trace
          modifyIORef' trace (++[step])
          pure $ if length seen==fault || length seen>=length script then -1 else snd (script !! length seen))
        seen <- readIORef trace
        pure (code,seen)
  direct <- run (validate . Workflow.CommandFlow limit next)
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run kind callback nullPtr)
  bound <- elements_hs_parent_replay_store_checked kind maxBound 0
  missing <- elements_hs_parent_replay_run kind nullFunPtr nullPtr
  malformed <- sequence [elements_hs_parent_replay_store_checked kind phase reply |
    phase <- [1..fromIntegral limit], reply <- invalidReplies phase]
  pure $ conjoin [direct===(if failed then -1 else expected,planned),abi===direct,
    bound===limit,missing===(-1),malformed===replicate (length malformed) (-1)]

cacheRoutingOrder :: Property
cacheRoutingOrder = forAll ((,,,) <$> arbitrary <*> choose (0,3) <*> choose (0,3) <*> choose (-1,9 :: Int)) $
  \((hit,firstTrust,secondTrust,negative),cachedStatus,indexStatus,fault) -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,1),(2,flag hit)] ++ if hit then [(3,cachedStatus)] else
          [(4,flag firstTrust)] ++ [(5,indexStatus) | firstTrust] ++
          if firstTrust && indexStatus/=0 then [] else [(6,flag secondTrust)] ++
          if secondTrust then [] else [(7,1),(8,flag negative)] ++ [(9,3) | negative]
        finished = hit || (firstTrust && indexStatus/=0) || (not secondTrust && negative)
        invalidReplies phase = if phase `elem` [3,5,9] then [4,maxBound] else [2,maxBound]
    in commandTraceWith invalidReplies 236 9 (\phase reply -> validate (Bmm.CacheRoutingFlow phase reply))
      script fault (if finished then 1 else 0)

walletCommandOrder :: Property
walletCommandOrder = forAll ((,) <$> arbitrary <*> choose (-1,7 :: Int)) $ \((finished,success,emptyError,parsed),fault) -> ioProperty $
  let flag value = if value then 1 else 0
      script = [(1,flag finished)] ++ if not finished then [(2,1)] else [(3,flag success)] ++
        if not success then [(4,1),(5,flag emptyError)] ++ [(6,1) | emptyError] ++ [(7,1)]
        else [(8,1),(9,flag parsed)] ++ [(10,1) | not parsed]
  in commandTrace 233 10 (\phase reply -> validate (Withdrawal.WalletCommandFlow phase reply))
    script fault (if finished && success && parsed then 1 else -1)

minedPreflightOrder :: Property
minedPreflightOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,3 :: Int)) $ \(slot,nonNull,fault) -> ioProperty $
  let script = [(1,if slot then 1 else 0)] ++
        if not slot then [] else [(2,if nonNull then 1 else 0)] ++ [(3,0) | not nonNull]
  in commandTrace 234 3 (\phase reply -> validate (Bmm.MinedPreflightFlow phase reply))
    script fault (if slot && nonNull then 1 else 0)

bundleEventOrder :: Property
bundleEventOrder = forAll ((,,,) <$> arbitrary <*> arbitrary <*> choose (0,2) <*> choose (-1,5 :: Int)) $
  \(clearing,present,rejection,fault) -> ioProperty $
    let flag value = if value then 1 else 0
        script = if clearing then [(1,flag present)] ++
          (if present then [(2,1),(3,flag (rejection==2))] ++ [(4,1) | rejection==2] else [])
          else [(1,1),(2,1),(3,fromIntegral rejection)] ++ [(rejection+3,1) | rejection/=0]
        invalid phase = if not clearing && phase==3 then [3,maxBound] else [2,maxBound]
    in commandTraceWith invalid (if clearing then 258 else 257) (if clearing then 4 else 5)
      (\phase reply -> validate (Withdrawal.BundleEventFlow clearing phase reply)) script fault
      (if clearing || rejection==0 then 1 else -1)

parentReportOrder :: Property
parentReportOrder = forAll ((,,) <$> arbitrary <*> elements [0,1,maxBound :: Word32]
  <*> choose (-1,14 :: Int)) $ \((native,checkpoint,effective,context,regtest,matching),height,fault) -> ioProperty $
    let flag value = if value then 1 else 0
        prefix = [(1,flag native)] ++ if native then [(2,flag checkpoint),(if checkpoint then 4 else 3,1)]
          else [(5,flag effective)] ++ if effective then [(6,flag context)] ++ [(7,1) | not context]
          else [(8,flag regtest)] ++ if not regtest then [(7,1)] else [(9,fromIntegral height),(if height==0 then 10 else 11,1)]
        established = if native then checkpoint else if effective then context else regtest && height/=0
        suffix = if not established then [] else [(12,fromIntegral height)] ++ if height==0 then [(14,1)]
          else [(13,flag matching)] ++ [(14,1) | not matching]
        invalid phase = if phase `elem` [9,12] then [] else [2,maxBound]
    in commandTraceWith invalid 260 14 (\phase reply -> validate (NodeRules.ParentReportFlow phase reply))
      (prefix++suffix) fault (if established && height/=0 && matching then 1 else -1)

parentRequestOrder :: Property
parentRequestOrder = forAll ((,) <$> arbitrary <*> choose (-1,5 :: Int)) $ \((hasError,slot,success),fault) -> ioProperty $
  let flag value = if value then 1 else 0
      script = [(1,1),(2,flag hasError)] ++ [(3,1) | hasError] ++ [(4,flag slot)] ++ [(5,flag success) | slot]
  in commandTrace 256 5 (\phase reply -> validate (ParentReplay.ParentRequestFlow phase reply))
    script fault (if slot && success then 1 else 0)

configuredSlotOrder :: Property
configuredSlotOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,3 :: Int)) $ \(present,matches,fault) -> ioProperty $
  let script = [(1,if present then 1 else 0)] ++
        if not present then [(2,0)] else [(3,if matches then 1 else 0)] ++ [(4,0) | not matches]
  in commandTrace 235 4 (\phase reply -> validate (ParentReplay.ConfiguredSlotFlow phase reply))
    script fault (if present && matches then 1 else 0)

mempoolSweepPreflightOrder :: Property
mempoolSweepPreflightOrder = once $ ioProperty $ fmap conjoin $ sequence
  [ let slot = testBit mask 0
        nonzero = testBit mask 1
        current = testBit mask 2
        pool = testBit mask 3
        flag value = if value then 1 else 0
        script = [(1,flag slot)] ++ if not slot then [] else [(2,flag nonzero)] ++
          [(3,flag current) | nonzero] ++ if not (nonzero && current) then [(4,0)] else
          [(5,flag pool)] ++ [(6,1) | not pool]
        result = if not slot then 1 else if not (nonzero && current) then 0 else if pool then 2 else 1
    in commandTrace 310 6 (\phase reply -> validate (ParentReplay.MempoolSweepPreflight phase reply))
      script fault result
  | mask <- [0..15 :: Int], fault <- [-1..6] ]

parentRpcHostOrder :: Property
parentRpcHostOrder = once $ ioProperty $ fmap conjoin $ sequence
  [ let native = testBit mask 0
        parsed = testBit mask 1
        ipv4 = testBit mask 2
        allow4 = testBit mask 3
        ipv6 = testBit mask 4
        allow6 = testBit mask 5
        flag value = if value then 1 else 0
        script = [(1,flag native)] ++ if not native then [] else [(2,flag parsed)] ++
          if not parsed then [] else [(3,flag ipv4)] ++ if ipv4 then [(4,flag allow4)] else
          [(5,flag ipv6)] ++ [(6,flag allow6) | ipv6]
        allowed = not native || parsed && (if ipv4 then allow4 else ipv6 && allow6)
    in commandTrace 311 6 (\phase reply -> validate (ParentReplay.ParentRpcHostFlow phase reply))
      script fault (flag allowed)
  | mask <- [0..63 :: Int], fault <- [-1..6] ]

-- Procedural reference of the native branches, independent of the transition tables.
type AdmissionModel = ExceptT Int32 (State [(Word32,Int64)])

admissionReply :: Word32 -> Int64 -> AdmissionModel Bool
admissionReply step reply = lift (modify' (++[(step,reply)])) >> pure (reply /= 0)

admissionModel :: Word32 -> Word32 -> AdmissionModel Int32
admissionModel kind mask = case kind of
  312 -> do
    mapM_ (\step -> query step >>= (`unless` throwE 0)) [1,2,3]
    query 4 >>= (`unless` throwE 1)
    let require step failure = query step >>= (`unless` (admissionReply failure 0 >> throwE 2))
        check step = query step >>= (`unless` throwE 2)
    require 5 6
    require 7 8
    check 9
    check 10
    require 11 12
    require 13 14
    require 15 16
    nonGenesis <- query 17
    when nonGenesis $ do
      present <- query 18
      follows <- if present then query 19 else pure False
      unless follows (admissionReply 20 0 >> throwE 2)
    check 21
    effect 22
    pure 0
  313 -> do
    nonGenesis <- query 1
    native <- if nonGenesis then query 2 else pure False
    when native $ do
      reused <- query 3
      if reused then effect 4 else do
        derived <- query 5
        unless derived (effect 6 >> reject)
        effect 7
      effect 8
      valid <- query 9
      unless valid $ do
        effect 10
        invalid <- query 11
        when invalid (effect 12)
        reject
      sane <- query 13
      unless sane (effect 14 >> reject)
      bound <- query 15
      when bound $ do
        matching <- query 16
        unless matching (effect 17 >> reject)
      predecessor <- query 18
      when predecessor $ do
        nonGenesisParent <- query 19
        when nonGenesisParent $ do
          anchored <- query 20
          unless anchored (effect 21 >> reject)
      predecessorAgain <- query 22
      when predecessorAgain $ do
        anchored <- query 23
        when anchored $ do
          follows <- query 24
          unless follows (effect 25 >> reject)
      effect 26
    needsDeposits <- query 27
    when needsDeposits $ do
      valid <- query 28
      unless valid $ do
        invalid <- query 29
        when invalid (effect 30)
        reject
    pure 1
  314 -> do
    anchored <- query 1
    when anchored $ do
      effect 2
      synced <- query 3
      when synced $ do
        signals <- query 4
        when signals $ do
          active <- query 5
          when active (effect 6)
    native <- query 7
    when native $ do
      authenticated <- query 8
      when authenticated $ do
        best <- query 9
        better <- if best then query 10 else pure True
        when better (effect 11)
    pure 1
  _ -> error "unknown admission model"
  where
    query step = admissionReply step (if testBit mask (fromIntegral step-1) then 1 else 0)
    effect step = admissionReply step 1 >> pure ()
    reject = effect 31 >> throwE 0

blockAdmissionOrder :: Word32 -> Int32 -> (Word32 -> Word32 -> Bmm.AnchorFlow) -> Property
blockAdmissionOrder kind bound flow = forAll ((,) <$> masks <*> choose (-1,fromIntegral bound)) $ \(mask,fault) ->
  ioProperty $ let (result,script) = runState (runExceptT (admissionModel kind mask)) []
    in commandTrace kind bound (\phase reply -> validate (flow phase reply)) script fault (either id id result)
  where
    masks = frequency [(1,arbitrary),(3,do
      base <- elements [0,maxBound,clearBit maxBound 2]
      bit <- choose (0,31)
      pure (base `xor` (1 `shiftL` bit)))]

producerPreparationOrder :: Property
producerPreparationOrder = once $ ioProperty $ fmap conjoin $ sequence
  [ let signed = testBit mask 0
        mined = testBit mask 1
        witnessed = testBit mask 2
        dynamic = testBit mask 3
        flag value = if value then 1 else 0
        prepared = signed || mined
        script = [(1,flag signed)] ++ [(2,flag mined) | not signed] ++
          if not prepared then [] else [(3,flag witnessed)] ++
          if witnessed then [] else [(4,flag dynamic)] ++ [(5,1) | dynamic]
    in commandTrace 308 5 (\phase reply -> validate (Bmm.BlockPreparationFlow phase reply))
      script fault (flag (prepared && (witnessed || not dynamic)))
  | mask <- [0..15 :: Int], fault <- [-1..5] ]

producerRoutingOrder :: Property
producerRoutingOrder = once $ ioProperty $ fmap conjoin $ sequence
  [ let native = testBit mask 0
        step = if native then 2 else 3
        flag value = if value then 1 else 0
    in commandTrace 307 3 (\phase reply -> validate (Bmm.ProductionRoutingFlow phase reply))
      [(1,flag native),(step,flag (testBit mask (fromIntegral step-1)))] fault
      (flag (testBit mask (fromIntegral step-1)))
  | mask <- [0..7 :: Int], fault <- [-1..2] ]

producerAcceptanceOrder :: Property
producerAcceptanceOrder = once $ ioProperty $ fmap conjoin $ sequence
  [ commandTrace 309 2 (\phase reply -> validate (Bmm.BlockAcceptanceFlow phase reply))
      ([(1,if accepted then 1 else 0)] ++ [(2,1) | not accepted]) fault
      (if accepted then 1 else 0)
  | accepted <- [False,True], fault <- [-1..2] ]

rewardWalletOrder :: Property
rewardWalletOrder = forAll ((,,) <$> arbitrary <*> resize 6 arbitrary <*> choose (-1,30 :: Int)) $ \(loader,wallets,fault) -> ioProperty $
  let flag value = if value then 1 else 0
      scan [] = [(3,0)]
      scan ((disabled,spendable):rest) = [(3,1),(4,flag disabled)] ++ [(5,flag spendable) | not disabled] ++
        if not disabled && spendable then [] else [(6,1)] ++ scan rest
      script = [(1,flag loader)] ++ if loader then [(2,1)] ++ scan wallets else []
      accepted = loader && any (\(disabled,spendable) -> not disabled && spendable) wallets
  in commandTrace 245 6 (\phase reply -> validate (Bmm.RewardWalletFlow phase reply))
       script fault (if accepted then 1 else 0)

waitProbeOrder :: Property
waitProbeOrder = forAll ((,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> choose (-1,2 :: Int)) $ \(proof,first,second,fault) -> ioProperty $
  let flag value = if value then 1 else 0
      script = [(1,flag first)] ++ [(2,flag second) | first == proof]
      expected = if proof then if not first then 0 else if second then 1 else 2
                 else if first then 1 else if second then 2 else 0
      (kind,next) = if proof then (243,Bmm.SuccessorProbe) else (242,Bmm.CommitmentProbe)
  in commandTrace kind 2 (\phase reply -> validate (next phase reply)) script fault expected

fundedSubmissionOrder :: Property
fundedSubmissionOrder = forAll ((,,,) <$> arbitrary <*> arbitrary <*> choose (0,2 :: Int64) <*> choose (-1,3 :: Int)) $ \(template,current,status,fault) -> ioProperty $
  let flag value = if value then 1 else 0
      submitted = status == 2
      script = [(1,flag current)] ++ if template then
        if current then [(3,status)] ++ [(4,1) | status == 0] else [(2,1)]
        else [(2,flag submitted) | current] ++ [(if submitted then 4 else 3,1) | current]
      (kind,next) = if template then (244,Bmm.TemplateCreationFlow) else (241,Bmm.FundedSubmissionFlow)
      invalid phase = if template && phase == 3 then [3,maxBound] else [2,maxBound]
  in commandTraceWith invalid kind 4 (\phase reply -> validate (next phase reply))
       script fault (if current && submitted then 1 else 0)

bidInputOrder :: Property
bidInputOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,7 :: Int)) $ \(configured,(first,second,third),fault) -> ioProperty $
  let flag value = if value then 1 else 0
      (kind,bound,next,script,accepted) = if configured then
        (239,5,Bmm.ConfiguredBidFlow,
         [(1,flag first)] ++ if first then [(2,flag second)] else [(3,1),(4,flag third)] ++ [(5,1) | third],
         not first || second)
        else (240,7,Bmm.ParsedBidFlow,
          [(1,flag first)] ++ [(2,1) | first] ++ [(3,flag second)] ++
          if not second then [(4,flag first)] ++ [(5,1) | first] else [(6,flag third)] ++ [(7,1) | third],
          second && third)
  in commandTrace kind bound (\phase reply -> validate (next phase reply)) script fault (if accepted then 1 else 0)

nativeDepositAdmissionOrder :: Property
nativeDepositAdmissionOrder = forAll ((,,) <$> vectorOf 5 arbitrary <*> choose (0,2 :: Int) <*> choose (-1,9 :: Int)) $
  \(facts,status,fault) -> ioProperty $ do
    let accepted = length (takeWhile id facts)
        prefix = take (accepted+1) (zip [1..] [if fact then 1 else 0 | fact <- facts])
        script = prefix ++ if accepted < 5 then [(fromIntegral accepted+9,0)] else
          [(6,if status==0 then 1 else 0)] ++ if status==0 then [] else
          [(7,if status==2 then 1 else 0)] ++ [(8,0) | status==2] ++ [(14,0)]
        expected = if accepted==5 && status==0 then 0 else 1
    commandTrace 268 14 (\phase reply -> validate (Deposit.NativeAdmissionFlow phase reply)) script fault expected

requiredFactsOrder :: Property
requiredFactsOrder = forAll ((,,) <$> elements [(237,3),(238,2),(248,4),(267,7)] <*> vectorOf 7 arbitrary <*> choose (-1,8 :: Int)) $
  \((kind,count),flags,fault) -> ioProperty $ do
    let selected = take count flags
        script = take (length (takeWhile id selected)+1) (zip [1..] [if flag then 1 else 0 | flag <- selected]) ++
          [(fromIntegral count+1,0) | not (and selected)]
    checked <- commandTrace kind (fromIntegral count+1)
      (\phase reply -> validate (ParentReplay.RequiredFactsFlow (fromIntegral count) phase reply))
      script fault (if and selected then 1 else 0)
    pure $ conjoin (checked : [validate (ParentReplay.RequiredFactsFlow invalid 0 0) === (-1) | invalid <- [0,255,maxBound]])

bidParentOrder :: Property
bidParentOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,5 :: Int)) $ \(height,sameHash,fault) -> ioProperty $
  let script = [(1,1),(2,1),(3,if height then 1 else 0)] ++
        if not height then [(5,1)] else [(4,if sameHash then 1 else 0)] ++ [(5,1) | not sameHash]
  in commandTrace 232 5 (\phase reply -> validate (Bmm.BidParentFlow phase reply)) script fault (if height && sameHash then 1 else 0)

syncPreflightOrder :: Property
syncPreflightOrder = forAll ((,) <$> vectorOf 5 arbitrary <*> choose (-1,5 :: Int)) $ \(flags,fault) -> ioProperty $
  let script = take (length (takeWhile id flags)+1) (zip [1..] [if flag then 1 else 0 | flag <- flags])
  in commandTrace 230 5 (\phase reply -> validate (Bmm.SyncPreflightFlow phase reply))
       script fault (if and flags then 1 else 0)

syncLoopOrder :: Property
syncLoopOrder = forAll ((,,) <$> choose (0,20 :: Int) <*> arbitrary <*> choose (-1,65 :: Int)) $ \(cycles,shutdown,fault) -> ioProperty $
  let script = concat (replicate cycles [(1,1),(2,1),(3,1)]) ++
        if shutdown then [(1,0)] else [(1,1),(2,1),(3,0)]
  in commandTrace 231 3 (\phase reply -> validate (Bmm.SyncLoopFlow phase reply)) script fault 1

reverificationOrder :: Property
reverificationOrder = forAll ((,) <$> arbitrary <*> choose (-1,7 :: Int)) $ \((native,warm,current,refreshed),fault) -> ioProperty $ do
  let script = [1] ++ (if not native then [] else [2] ++
        if not warm then [3] else [4,5] ++ if current then [] else [6] ++ [7 | not refreshed])
      reply step = if case step of
        1 -> native; 2 -> warm; 5 -> current; 6 -> refreshed; _ -> True
        then 1 else 0
  commandTrace 229 7 (\phase value -> validate (Bmm.ReverificationFlow phase value))
    [(step,reply step) | step <- script] fault 1

childPreflightOrder :: Property
childPreflightOrder = forAll ((,) <$> arbitrary <*> choose (-1,4 :: Int)) $ \((executable,limits,cancelled),fault) -> ioProperty $ do
  let script = [1] ++ if not executable then [2] else [3] ++
        if not limits then [4] else [5] ++ [6 | cancelled]
      reply step = if case step of
        1 -> executable; 3 -> limits; 5 -> cancelled; _ -> True
        then 1 else 0
  commandTrace 228 6 (\phase value -> validate (Bmm.ChildPreflightFlow phase value))
    [(step,reply step) | step <- script] fault (if executable && limits && not cancelled then 1 else 0)

blockPreparationOrder :: Property
blockPreparationOrder = forAll ((,) <$> vectorOf 4 arbitrary <*> choose (-1,4 :: Int)) $ \(flags,fault) -> ioProperty $ do
  let yes step = flags !! (step-1)
      script = [1] ++ if not (yes 1) then [] else [2] ++
        if not (yes 2) then [4] else [3] ++ [4 | yes 3]
      failed = fault>=0 && fault<length script
      planned = if failed then take (fault+1) script else script
      expected | failed = -1
               | not (yes 1) = 1
               | yes 2 && not (yes 3) = 2
               | not (yes 4) = 3
               | otherwise = 0
      run invoke = do
        trace <- newIORef []
        code <- invoke (\step -> do
          seen <- readIORef trace
          modifyIORef' trace (++[fromIntegral step :: Int])
          pure $ if length seen==fault then -1 else if yes (fromIntegral step) then 1 else 0)
        seen <- readIORef trace
        pure (code,seen)
  direct <- run (\action -> validate (Workflow.CommandFlow 4 (\phase reply ->
    validate (ParentReplay.StoreFlow 226 phase reply)) action))
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 226 callback nullPtr)
  bound <- elements_hs_parent_replay_store_checked 226 maxBound 0
  missing <- elements_hs_parent_replay_run 226 nullFunPtr nullPtr
  malformed <- sequence [elements_hs_parent_replay_store_checked 226 phase reply |
    phase <- [1..4], reply <- [2,maxBound]]
  pure $ conjoin [direct===(expected,planned),abi===direct,bound===4,missing===(-1),malformed===replicate 8 (-1)]

bmmRpcSourceOrder :: Property
bmmRpcSourceOrder = forAll ((,) <$> vectorOf 7 arbitrary <*> choose (-1,7 :: Int)) $ \(flags,fault) -> ioProperty $ do
  let yes step = flags !! (step-1)
      branch = if yes 3 then [4] ++ [5 | yes 4] else [6] ++ [7 | yes 6]
      script = [1] ++ if yes 1 then [2,3] ++ branch else []
      failed = fault>=0 && fault<length script
      planned = if failed then take (fault+1) script else script
      expected | failed = -1
               | not (yes 1) = 1
               | yes 3 = if yes 4 then 0 else 2
               | yes 6 && yes 7 = 0
               | otherwise = 3
      run invoke = do
        trace <- newIORef []
        code <- invoke (\step -> do
          seen <- readIORef trace
          modifyIORef' trace (++[fromIntegral step :: Int])
          pure $ if length seen==fault then -1 else if step `elem` [2,5] || yes (fromIntegral step) then 1 else 0)
        seen <- readIORef trace
        pure (code,seen)
  direct <- run (\action -> validate (Workflow.CommandFlow 7 (\phase reply ->
    validate (ParentReplay.StoreFlow 225 phase reply)) action))
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 225 callback nullPtr)
  bound <- elements_hs_parent_replay_store_checked 225 maxBound 0
  missing <- elements_hs_parent_replay_run 225 nullFunPtr nullPtr
  malformed <- sequence [elements_hs_parent_replay_store_checked 225 phase reply |
    phase <- [1..7], reply <- [2,maxBound]]
  pure $ conjoin [direct===(expected,planned),abi===direct,bound===7,missing===(-1),malformed===replicate 14 (-1)]

bmmRpcAuthenticationOrder :: Property
bmmRpcAuthenticationOrder = forAll ((,,) <$> arbitrary <*> choose (0,5 :: Int) <*> choose (-1,6 :: Int)) $
  \(present,rejected,fault) -> ioProperty $ do
    let end = if rejected == 0 then 5 else rejected
        script = (1,if present then 1 else 0) :
          [(fromIntegral step+1,if step == rejected then 0 else 1) | step <- [1..end],present]
        expected | not present || rejected==0 = 0
                 | rejected==1 = 1
                 | rejected<=3 = 2
                 | rejected==4 = 3
                 | otherwise = -1
    commandTrace 224 6 (\phase reply -> validate (ParentReplay.StoreFlow 224 phase reply)) script fault expected

checkpointKeyOrder :: Property
checkpointKeyOrder = forAll (elements [221,222,223]) $ \kind ->
  forAll (vectorOf 6 arbitrary) $ \flags ->
  forAll (choose (-1,6 :: Int)) $ \fault -> ioProperty $ do
    let end = if kind == 221 then 6 else 4
        yes step = flags !! (step-1)
        checks [] = []
        checks (step:rest) = step : if yes step then checks rest else []
        script = checks [1..end]
        failed = fault>=0 && fault<length script
        planned = if failed then take (fault+1) script else script
        wanted
          | failed = -1
          | kind == 223 = case last script of
              1 -> 0
              2 -> -1
              lastStep -> if lastStep==4 && yes 4 then 1 else 2
          | otherwise = case last script of
              1 -> 0
              2 -> 2
              3 -> 0
              lastStep -> if lastStep==end && yes lastStep then 1 else 3
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> do
            seen <- readIORef trace
            modifyIORef' trace (++[fromIntegral step])
            pure $ if length seen==fault then -1 else if yes (fromIntegral step) then 1 else 0)
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Workflow.CommandFlow (fromIntegral end) (\phase reply ->
      validate (ParentReplay.StoreFlow kind phase reply)) action))
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run kind callback nullPtr)
    bound <- elements_hs_parent_replay_store_checked kind maxBound 0
    malformed <- sequence [elements_hs_parent_replay_store_checked kind phase reply |
      phase <- [1..fromIntegral end], reply <- [2,maxBound]]
    pure $ conjoin [direct === (wanted,planned), abi === direct, bound === fromIntegral end,
      malformed === replicate (2*end) (-1)]

checkpointMetadataOrder :: Property
checkpointMetadataOrder = forAll (vectorOf 8 arbitrary) $ \flags ->
  forAll (choose (-1,8 :: Int)) $ \fault -> ioProperty $ do
    let yes step = flags !! (step-1)
        best = takeChecks [4..8]
        takeChecks [] = []
        takeChecks (step:rest) = step : if yes step then takeChecks rest else []
        script = [1] ++ if not (yes 1) then best else
          [2] ++ if not (yes 2) then [] else [3] ++ if yes 3 then best else []
        failed = fault >= 0 && fault < length script
        planned = if failed then take (fault+1) script else script
        wanted = if failed then -1 else if last script <= 3 then 1 else
          if last script == 8 && yes 8 then 0 else 2
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> do
            seen <- readIORef trace
            modifyIORef' trace (++[fromIntegral step])
            pure $ if length seen == fault then -1 else if yes (fromIntegral step) then 1 else 0)
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Workflow.CommandFlow 8 (\phase reply ->
      validate (ParentReplay.StoreFlow 220 phase reply)) action))
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run 220 callback nullPtr)
    bound <- elements_hs_parent_replay_store_checked 220 maxBound 0
    malformed <- sequence [elements_hs_parent_replay_store_checked 220 phase reply |
      phase <- [1..8], reply <- [2,maxBound]]
    pure $ conjoin [direct === (wanted,planned), abi === direct, bound === 8,
      malformed === replicate 16 (-1)]

childCheckpointOrder :: Property
childCheckpointOrder = forAll ((,) <$> frequency [(1,pure (replicate 15 True)),(3,vectorOf 15 arbitrary)] <*>
  choose (-1,20 :: Int)) $ \(flags,fault) -> ioProperty $
  let yes step = flags !! (step-1)
      checks [] = []
      checks ((step,err):rest) = step : if yes step then checks rest else [err]
      afterSnapshot = checks [(8,18),(11,19),(12,19),(13,19),(14,19),(15,19)]
      before = if not (yes 1) then [1,16] else if not (yes 2) then [1,2,16]
        else [1,2,3] ++ if yes 3 then [4] ++ if yes 4 then afterSnapshot else [16] else afterSnapshot
      effects step = case step of 8 -> [7,8]; 11 -> [9,10,11]; _ -> [step]
      script = concatMap effects before
      replies = [(fromIntegral step,if step `elem` [7,9,10] || step>=16 || yes step then 1 else 0) | step <- script]
  in commandTrace 219 19 (\phase result -> validate (ParentReplay.StoreFlow 219 phase result))
    replies fault (if last script>=16 then -1 else 0)

templateParentOrder :: Property
templateParentOrder = forAll ((,) <$> vectorOf 11 arbitrary <*> choose (-1,12 :: Int)) $ \(flags,fault) -> ioProperty $
  let yes step = flags !! (step-1)
      prepared = [11 :: Int] ++ if yes 11 then [] else [12]
      native = [3] ++ if not (yes 3) then [12] else [4] ++
        if yes 4 && not (yes 5) then [5,13] else (if yes 4 then [5] else []) ++ [6] ++ prepared
      fallback = [7] ++ if yes 7 then prepared else [8] ++ if not (yes 8) then prepared else
        [9] ++ (if yes 9 then [10] else []) ++ prepared
      script = [1] ++ if not (yes 1) then [] else [2] ++ if yes 2 then native else fallback
      replies = [(fromIntegral step,if step `elem` [6,10,12,13] || yes step then 1 else 0) | step <- script]
  in commandTrace 213 13 (\phase result -> validate (Bmm.TemplateParentFlow phase result))
    replies fault (if last script `elem` [12,13] then 0 else 1)

parentReplayBounds :: Property
parentReplayBounds = once $ ioProperty $ do
  let catalogue = [9,9,9,9,9,9,9,9,9,9,9,66,38,14,14,26,24,18,49,28,16,33,9,9,9,9,9,9,44,15,9,9,9,9,9,9,9,9,9,9,9,9,9,14,18,26,33,28,9,9,9,9,17,9,9,9,14,9,12,9,18,15,9,9,9,9,11,19,22,9,9,12,9,16,10,9,9,9,9,9,10,9,13,15,25,9,9,27,9,9,9,9,9,43,23,31,18,18,9,9,9,9,19,9,9,9,9,9,9,9,9,9,9,9,23,9,12,11,9,24,9,17,11,23,9,9] ++ [22,9,9,11,8,7,14,-1,16,18,13,5,7,11,10,6,5,12,21,10,7,10,14,12,11,8,17,29,19,10,17,17,11,8,6,12,74,45,15,64,10,15,15,13,9,12,12,10,12,7,5,10,8,4,26,11,18,46,10,6,4,4,13,22,11,21,5,2,11,14,26,12,15,5,11,4,8,14,8,19,7,13,12,12] :: [Int32]
      retired = [129..131] ++ [149..176] ++ [183,188,189,198,199,200,209,212,217,246,247] ++
        [249..255] ++ [259,261,262,263,266,269,271,272,274,276,278,289,290,292,293,295,323,326]
      expected = [if kind `elem` retired then -1 else bound | (kind,bound) <- zip [0..] catalogue]
  actual <- mapM (\kind -> elements_hs_parent_replay_store_checked kind maxBound 0) [0..209]
  invalid <- mapM (\kind -> elements_hs_parent_replay_store_checked kind maxBound 0) [335,maxBound]
  rejected <- sequence [elements_hs_parent_replay_store_checked kind phase reply |
    kind <- retired, phase <- [0,1,16,maxBound], reply <- [0,1,2,maxBound]]
  calls <- newIORef ([] :: [Word32])
  outcomes <- bracket (wrapMatchFact (\_ step -> modifyIORef' calls (++[step]) >> pure 1)) freeHaskellFunPtr $ \callback ->
    mapM (\kind -> elements_hs_parent_replay_run kind callback nullPtr) retired
  trace <- readIORef calls
  malformed <- mapM (\kind -> elements_hs_parent_replay_store_checked kind maxBound 1) [0..209]
  unchanged <- sequence [do
    old <- elements_hs_parent_replay_store kind phase result
    new <- elements_hs_parent_replay_store_checked kind phase result
    pure (old==new) | kind <- [0..209], phase <- [0..85], result <- [0..3]]
  pure $ conjoin [actual===expected, invalid===replicate 2 (-1),
    rejected===replicate (length retired*16) (-1), outcomes===replicate (length retired) (-1),
    trace===[], malformed===replicate 210 (-1), property (and unchanged)]

recoveryComposedOrder :: Property
recoveryComposedOrder = forAll ((,,) <$> choose (0,6 :: Int) <*> choose (0,4 :: Int) <*> choose (-1,180 :: Int)) $
  \(scenario,retries,fault) -> ioProperty $ do
    let yes steps = [(step,1) | step <- steps]
        pruned = yes [101..105]
        checked = yes [301,302]
        header height = yes [200] ++ checked ++ yes (212:[201..207]) ++ checked ++
          yes [214,208,209] ++ [(213,height)]
        peers = yes [400] ++ checked ++ yes [415,412,414] ++
          if scenario == 5 then [(401,0),(410,-1)] else
            yes [401,402,403,404,405,406,407,411] ++ checked ++ yes [417]
        poll index = yes [11] ++ [(12,if scenario == 3 then 1 else 0)] ++
          if scenario == 3 then [(13,-1)] else yes [14] ++
            if index < retries then pruned ++ yes [16] ++ poll (index+1) else
              [(101,0)] ++ yes [17,18] ++ header (if scenario == 4 then 13 else 12) ++
                [(21,-1) | scenario == 4]
        script :: [(Word32,Int64)]
        script = yes [1] ++ if scenario == 0 then [(101,0)] ++ yes [3,4] else
          pruned ++ [(6,if scenario == 2 then 0 else 1)] ++
            if scenario == 2 then [(7,-1)] else yes [8] ++
              if scenario == 6 then [(200,1),(301,1),(302,0),(303,-1)] else
                header 12 ++ peers ++ if scenario == 5 then [] else poll 0
        run invoke = do
          seen <- newIORef []
          code <- invoke $ \step -> do
            prior <- readIORef seen
            modifyIORef' seen (++[step])
            let index = length prior
            pure $ if index == fault || index >= length script || fst (script !! index) /= step
              then -1 else snd (script !! index)
          observed <- readIORef seen
          pure (code,observed)
        failed = fault >= 0 && fault < length script
        prefix = map fst (if failed then take (fault+1) script else script)
        expected = (if failed || scenario >= 2 then -1 else 0,prefix)
    direct <- run (\action -> execute (Bmm.BodyRecovery action) Bmm.RecoverBody)
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run 334 callback nullPtr)
    pure $ conjoin [direct === expected,abi === expected]

recoveryComposedBoundary :: Property
recoveryComposedBoundary = once $ ioProperty $ do
  missing <- elements_hs_parent_replay_run 334 nullFunPtr nullPtr
  seen <- newIORef (0 :: Int)
  invalid <- bracket (wrapMatchFact (\_ _ -> modifyIORef' seen (+1) >> pure 1)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 335 callback nullPtr
  calls <- readIORef seen
  pure $ conjoin [missing === -1,invalid === -1,calls === 0]

recoveryValidationOrder :: Property
recoveryValidationOrder = forAll ((,,) <$> elements [192,193,194] <*> vectorOf 9 arbitrary <*> choose (-1,12 :: Int)) $ \(kind,flags,fault) -> ioProperty $ do
  let header = kind==194
      end = if header then 9 else if kind==192 then 5 else 2
      script step
        | step>end = []
        | header && step==7 = (step,1):script (step+1)
        | flags !! (step-1) = (step,1):script (step+1)
        | otherwise = (step,0):if header then [(if step<=6 then 10 else 11,1)] else []
      steps = script 1
      failed = fault>=0 && fault<length steps
      expected = map (fromIntegral . fst) (if failed then take (fault+1) steps else steps)
      result = if failed then -1 else if any ((==0) . snd) steps then 1 else 0
      transition phase reply = if header then validate (Bmm.RecoveryHeaderFlow phase reply)
        else validate (Bmm.RecoveryReplyFlow (kind==192) phase reply)
      run invoke = do
        seen <- newIORef []
        code <- invoke (\step -> do
          previous <- readIORef seen
          modifyIORef' seen (++[step])
          let index=length previous
          pure $ if index==fault || index>=length steps || fromIntegral (fst (steps !! index))/=step
            then -1 else snd (steps !! index))
        observed <- readIORef seen
        pure (code,observed)
  direct <- run (\action -> validate (Workflow.CommandFlow (if header then 11 else fromIntegral end) transition action))
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run kind callback nullPtr)
  pure $ conjoin [direct === (result,expected),abi === (result,expected)]

recoveryBodyOrder :: Property
recoveryBodyOrder = forAll generator $ \(pruned,allow,flags,retries,expired,sameHeight,fault) -> ioProperty $ do
  let bit value = if value then 1 else 0
      checked first ok present err rest = (first,bit ok):
        if not ok then [(err,1)] else (first+1,bit present):if present then rest else [(err,1)]
      poll index = [(11,1),(12,bit (index==expired))] ++
        if index==expired then [(13,1)] else [(14,1),(15,bit (index<retries))] ++
          if index<retries then (16,1):poll (index+1) else checked 17 (flags !! 2) (flags !! 3) 19
            ((20,bit sameHeight):if sameHeight then [] else [(21,1)])
      script = [(1,1),(2,bit pruned)] ++
        if not pruned then checked 3 (flags !! 0) (flags !! 1) 5 [] else (6,bit allow):
          if not allow then [(7,1)] else [(8,1),(9,1),(10,1)] ++ poll 0
      failed = fault>=0 && fault<length script
      expected = map fst (if failed then take (fault+1) script else script)
      run invoke = do
        seen <- newIORef []
        code <- invoke (\step -> do
          previous <- readIORef seen
          modifyIORef' seen (++[step])
          let index=length previous
          pure $ if index==fault || index>=length script || fst (script !! index)/=step
            then -1 else snd (script !! index))
        observed <- readIORef seen
        pure (code,observed)
  direct <- run (\action -> validate (Workflow.CommandFlow 21
    (\phase reply -> validate (Bmm.RecoveryBodyFlow phase reply)) action))
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 191 callback nullPtr)
  let result = if failed then -1 else if fst (last script) `elem` [5,7,13,19,21] then 1 else 0
  pure $ conjoin [direct === (result,expected),abi === (result,expected)]
  where generator = (,,,,,,) <$> arbitrary <*> arbitrary <*> vectorOf 4 arbitrary <*> choose (0,4 :: Int) <*>
          choose (-1,5) <*> arbitrary <*> choose (-1,80 :: Int)

recoveryPeerOrder :: Property
recoveryPeerOrder = forAll generator $ \(peers,fault,admit,validShape) -> ioProperty $ do
  let bit value = if value then 1 else 0
      scan [] = [(1,0),(10,0)]
      scan ((validId,validServices,services):rest) = [(1,1),(2,bit validId)] ++
        if not validId then next else (3,bit validServices):
          if not validServices then next else (4,1):findService services
        where
          next = (9,1):scan rest
          findService [] = (5,0):next
          findService ((isText,isNetwork):remaining) = [(5,1),(6,bit isText)] ++
            if not isText then advance else (7,bit isNetwork):
              if isNetwork then [(11,1)] else advance
            where advance = (8,1):findService remaining
      script = if not admit then scan peers else (12,bit validShape):
        if validShape then (14,1):scan peers else [(13,1)]
      failed = fault>=0 && fault<length script
      expected = map fst (if failed then take (fault+1) script else script)
      run invoke = do
        seen <- newIORef []
        code <- invoke (\step -> do
          previous <- readIORef seen
          modifyIORef' seen (++[step])
          let index=length previous
          pure $ if index==fault || index>=length script || fst (script !! index)/=step
            then -1 else snd (script !! index))
        observed <- readIORef seen
        pure (code,observed)
  direct <- run (\action -> validate (Workflow.CommandFlow (if admit then 14 else 11)
    (\phase reply -> if admit then validate (Bmm.RecoveryPeerReplyFlow phase reply)
      else validate (Bmm.RecoveryPeerFlow phase reply)) action))
  abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run (if admit then 195 else 190) callback nullPtr)
  let result = if failed then -1 else if fst (last script) `elem` [10,13] then 1 else 0
  pure $ conjoin [direct === (result,expected),abi === (result,expected)]
  where generator = (,,,) <$> resize 4 (listOf ((,,) <$> arbitrary <*> arbitrary <*>
          resize 4 (listOf ((,) <$> arbitrary <*> arbitrary)))) <*> choose (-1,60 :: Int) <*> arbitrary <*> arbitrary

parentReplayAdmissionTransitions :: Property
parentReplayAdmissionTransitions = forAll ((,) <$> choose (0,24 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store_checked 126 phase result
  let branch yes no = if result==1 then yes else if result==0 then no else -1
      next value = if result==1 then value else -1
      failure step = 65536 + step
      expected = case phase of
        0 -> 1
        1 -> branch 3 (failure 2)
        p | p>=3 && p<=7 -> branch (if p==7 then 9 else fromIntegral p+1) (failure 8)
        9 -> branch 11 (failure 10)
        11 -> branch 13 (failure 12)
        13 -> branch 15 (failure 14)
        15 -> branch 16 19
        16 -> branch 18 (failure 17)
        18 -> next 15
        19 -> branch 20 (-11)
        20 -> branch 22 (failure 21)
        22 -> next 19
        _ -> -1
  pure (actual===expected)

parentReplayStageTransitions :: Property
parentReplayStageTransitions = forAll ((,,) <$> elements [127,128] <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store_checked kind phase result
  let branch yes no = if result==1 then yes else if result==0 then no else -1
      expected = case phase of
        0 -> 1
        p | kind==128 && p>=1 && p<=9 -> branch (if p==9 then -11 else fromIntegral p+1) (-10)
        p | p>=1 && p<=5 -> branch (fromIntegral p+1) (-10)
        6 -> branch (-11) 7
        7 -> branch 8 9
        p | p==8 || p==9 -> branch (-11) (-10)
        _ -> -1
  pure (actual===expected)

parentReplayTipTransitions :: Property
parentReplayTipTransitions = forAll ((,) <$> choose (0,52 :: Word32) <*> choose (0,2 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_tip phase result
  let choices = [(0,(1,1)),(1,(-1,2)),(2,(6,3)),(3,(-1,4)),(4,(-1,5)),(5,(-1,8)),
        (6,(-1,7)),(7,(-1,8)),(8,(9,10)),(9,(-1,11)),(10,(-1,11)),(11,(-1,12)),
        (12,(-1,13)),(13,(18,14)),(14,(-1,15)),(15,(-1,16)),(16,(-1,17)),(17,(-1,13)),
        (18,(-1,19)),(19,(24,20)),(20,(-1,21)),(21,(-1,22)),(22,(-1,23)),(23,(-1,19)),
        (24,(25,26)),(25,(-1,26)),(26,(36,27)),(27,(29,28)),(28,(-1,29)),(29,(-1,30)),
        (30,(40,31)),(31,(-1,32)),(32,(33,34)),(33,(-1,34)),(34,(35,38)),(35,(-1,38)),
        (36,(-1,30)),(38,(-1,39)),(39,(12,41)),(40,(-1,42)),(41,(-1,12)),
        (42,(0,43)),(43,(44,46)),(44,(-1,45)),(45,(-1,46)),(46,(48,47)),
        (47,(-1,51)),(48,(49,-1)),(49,(-1,50)),(50,(-1,51)),(51,(-1,42))]
      expected = if result > 1 then -2 else maybe (-2) (if result == 0 then fst else snd) (lookup phase choices)
  pure (actual === expected)

parentReplayStoreTransitions :: Property
parentReplayStoreTransitions = forAll ((,,) <$> elements ([0..10] ++ [maxBound] :: [Word32]) <*> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (0,0) -> 1
        (0,1) -> branch 2 (-11)
        (0,2) -> branch (-10) 66051
        (1,0) -> 1
        (1,1) -> case result of 0 -> 3; 1 -> 2; 2 -> -12; _ -> -1
        (1,2) -> branch 66052 (-10)
        (1,3) -> branch 5 66310
        (1,5) -> branch 7 66310
        (1,7) -> case result of 0 -> 8; 1 -> 66057; 2 -> -12; _ -> -1
        (1,8) -> branch (-11) 66057
        (2,0) -> 1
        (2,1) -> branch 2 3
        (2,2) -> branch 3 (-1)
        (2,3) -> branch (-10) 66052
        (3,0) -> 1
        (3,1) -> branch 65795 65538
        (4,0) -> 1
        (4,1) -> branch 2 (-1)
        (4,2) -> branch 3 (-1)
        (4,3) -> branch 131332 (-1)
        (4,4) -> branch (-11) 65541
        (5,0) -> 1
        (5,1) -> branch (-10) 66051
        (6,0) -> 1
        (6,1) -> branch 2 66051
        (6,2) -> branch (-10) 66051
        (k,0) | k `elem` [7,8,9,10] -> 1
        (k,1) | k `elem` [7,8,9,10] -> case result of 0 -> 2; 1 -> -11; 2 -> -12; _ -> -1
        (7,2) -> branch 3 66054
        (7,3) -> branch (-10) 66054
        (8,2) -> branch (-10) 66054
        (9,2) -> branch 3 66054
        (9,3) -> branch 4 66054
        (9,4) -> branch (-10) 66054
        (10,2) -> branch 3 66054
        (10,3) -> branch 4 66054
        (10,4) -> branch 5 66054
        (10,5) -> branch (-10) 66054
        _ -> -1
  pure (actual === expected)
parentReplayAppendTransitions :: Property
parentReplayAppendTransitions = forAll ((,) <$> choose (0,70 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 11 phase result
  let diagnostic n = 65536 + n
      branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      checks = [(1,(2,5)),(2,(3,5)),(3,(4,5)),(4,(6,5)),(7,(9,8)),
        (10,(11,13)),(11,(12,13)),(12,(14,13)),(16,(17,21)),(17,(18,21)),
        (18,(19,21)),(19,(20,21)),(24,(25,30)),(25,(26,30)),(26,(27,30)),
        (27,(28,30)),(28,(29,30)),(33,(34,40)),(34,(35,40)),(35,(36,40)),
        (36,(37,40)),(44,(46,45)),(65,(-11,66))]
      mechanical = [(14,15),(22,15),(31,32),(41,32),(42,43),(49,43),(50,51),
        (51,52),(53,54),(54,52),(56,57),(57,58),(60,61),(62,63),(63,58),(64,131393)]
      choices = [(15,(16,23)),(20,(diagnostic 21,22)),(23,(24,31)),
        (29,(diagnostic 30,31)),(32,(33,42)),(37,(38,39)),(38,(diagnostic 40,39)),
        (39,(diagnostic 40,41)),(43,(44,50)),(46,(47,49)),(47,(diagnostic 48,49)),
        (52,(53,55)),(55,(56,57)),(58,(59,64)),(59,(61,60)),(61,(62,63))]
      expected | phase == 0 = 1
               | phase == 6 || phase == 9 = case result of
                   0 -> if phase == 6 then 7 else 10
                   1 -> diagnostic (if phase == 6 then 8 else 13)
                   2 -> diagnostic (if phase == 6 then 8 else 13)
                   _ -> -1
               | Just (yes,no) <- lookup phase checks = branch yes (diagnostic no)
               | Just yes <- lookup phase mechanical = branch yes (-1)
               | Just (yes,no) <- lookup phase choices = branch yes no
               | otherwise = -1
  pure (actual === expected)

parentReplayIdentityTransitions :: Property
parentReplayIdentityTransitions = forAll ((,) <$> choose (0,40 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 12 phase result
  let expected | phase == 0 = 1
               | phase >= 1 && phase < 37 && result == 1 = fromIntegral phase + 1
               | phase == 37 && result == 1 = 65830
               | otherwise = -1
  pure (conjoin [actual === expected,
    Constants.replayIdentityDomain === "ELEMENTS_AUTHENTICATED_PARENT_REPLAY_STORE_V4"])

parentReplayCacheTransitions :: Property
parentReplayCacheTransitions = forAll ((,,) <$> elements [13,14,15,maxBound :: Word32] <*> choose (0,28 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case kind of
        13 | phase == 0 -> 1
           | phase >= 1 && phase < 13 -> branch (fromIntegral phase + 1) (-1)
           | phase == 13 -> branch 65806 (-1)
        14 | phase == 0 -> 1
           | phase >= 1 && phase <= 14 -> branch (if phase == 14 then -11 else fromIntegral phase + 1) (-10)
        15 -> case phase of
          0 -> 1
          1 -> branch 2 (-10)
          p | p >= 2 && p < 18 -> branch (fromIntegral p + 1) 66067
          18 -> branch 20 66067
          20 -> branch 21 (-12)
          21 -> branch 23 66070
          23 -> branch 24 (-12)
          24 -> branch 25 66074
          25 -> branch (-11) 66074
          _ -> -1
        _ -> -1
  pure (actual === expected)

foreign import ccall unsafe reference_parent_message :: Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr Word16 -> IO Int32

parentMessageParity :: Property
parentMessageParity = forAll generator $ \encoded -> ioProperty $
  withArray encoded $ \input -> withArray [77,77,77,77] $ \fields -> withArray [77,77,77,77] $ \referenceFields ->
  withArray (replicate (length encoded + 2) 77) $ \votes -> withArray (replicate (length encoded + 2) 77) $ \referenceVotes -> do
    let count = fromIntegral (length encoded)
    actual <- elements_hs_parent_message count input (fields `plusPtr` 4) (votes `plusPtr` 2)
    expected <- reference_parent_message count input (referenceFields `plusPtr` 4) (referenceVotes `plusPtr` 2)
    observedFields <- peekArray 4 fields
    expectedFields <- peekArray 4 referenceFields
    observedVotes <- peekArray (length encoded + 2) votes
    expectedVotes <- peekArray (length encoded + 2) referenceVotes
    unchanged <- peekArray (length encoded) input
    missingInput <- elements_hs_parent_message (max 1 count) nullPtr fields votes
    missingFields <- elements_hs_parent_message count input nullPtr votes
    missingVotes <- elements_hs_parent_message count input fields nullPtr
    oversized <- elements_hs_parent_message maxBound input fields votes
    afterFields <- peekArray 4 fields
    afterVotes <- peekArray (length encoded + 2) votes
    pure $ conjoin [actual === expected, observedFields === expectedFields,
      [head observedFields,last observedFields] === [77,77],
      [head observedVotes,last observedVotes] === [77,77],
      observedVotes === expectedVotes, unchanged === encoded, afterFields === observedFields,
      afterVotes === observedVotes, conjoin (map (=== (-1)) [missingInput,missingFields,missingVotes,oversized])]
  where
    generator = oneof [resize 100 arbitrary, do
      tag <- elements [[0xd5,0xe0,0xc4,0xaf],[0xd6,0xe1,0xc5,0xdf],[0xd4,0x5a,0xa9,0x43],
                       [0xd7,0x7d,0x17,0x76],[0xd1,0x61,0x73,0x68]]
      mode <- oneof [choose (0,3), arbitrary]
      count <- elements [0,1,2,3,31,32,33,128]
      body <- vectorOf count arbitrary
      pure (tag ++ mode:body)]

snapshotMembershipTransitions :: Property
snapshotMembershipTransitions = forAll ((,,) <$> choose (103,113 :: Word32) <*> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (103,p) | p >= 1 && p <= 3 -> branch (if p == 3 then -11 else fromIntegral p + 1) (-10)
        (104,p) | p >= 1 && p <= 4 -> branch (fromIntegral p + 1) (-10)
        (104,5) -> branch 6 (-1)
        (104,6) -> branch 7 (-1)
        (104,7) -> branch (-11) 8
        (104,8) -> branch (-11) (-10)
        (105,p) | p == 1 || p == 2 -> branch (fromIntegral p + 1) (-10)
        (105,3) -> branch 4 (-1)
        (105,4) -> branch 5 (-10)
        (105,5) -> branch 6 (-1)
        (105,6) -> branch (-11) (-10)
        (106,1) -> branch 2 (-1)
        (107,1) -> branch 2 (-10)
        (106,2) -> branch (-11) 65539
        (107,2) -> branch 4 65539
        (107,4) -> branch (-11) (-10)
        (108,1) -> branch 2 (-1)
        (108,2) -> branch 4 65539
        (108,4) -> branch (-11) 5
        (108,5) -> case result of 0 -> 6; 2 -> 65543; _ -> -11
        (108,6) -> branch (-11) 65544
        (109,p) | p == 1 || p == 2 -> branch (fromIntegral p + 1) (-1)
        (109,3) -> branch 5 65540
        (109,5) -> branch 6 (-10)
        (109,6) -> branch 7 (-1)
        (109,7) -> branch 8 (-10)
        (109,8) -> branch 65801 (-10)
        (110,1) -> branch 2 3
        (110,2) -> branch 3 (-1)
        (110,3) -> branch 4 (-12)
        (110,4) -> branch (-10) 66053
        (111,1) -> branch 2 (-1)
        (111,2) -> branch 3 4
        (111,3) -> branch 4 (-1)
        (111,p) | p == 4 || p == 5 -> branch 65542 (if p == 4 then 5 else 7)
        (111,7) -> branch 65544 9
        (111,9) -> branch (-11) (-10)
        (112,p) | p == 1 || p == 2 -> branch (fromIntegral p + 1) (-1)
        (112,3) -> branch 4 (-10)
        (112,4) -> branch 65797 (-10)
        (113,1) -> branch (-10) 2
        (113,p) | p >= 2 && p <= 4 -> branch (fromIntegral p + 1) 7
        (113,5) -> branch 65798 (-11)
        (113,7) -> branch 66056 (-12)
        _ -> -1
  pure (actual === expected)

signedHeightWindowParity :: Property
signedHeightWindowParity = forAll gen $ \(tip,start,limit) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 22 0 tip start limit
  let distance = toInteger tip - toInteger start
      expected = if tip >= 0 && distance >= 0 && distance <= toInteger limit then 1 else 0
  pure (actual === expected)
  where
    gen = do
      tip <- frequency [(3,elements [minBound,-1,0,1,2016,2017,maxBound]),(1,arbitrary)]
      start <- frequency [(3,elements [0,1,2016,2017,0x7fffffffffffffff,0x8000000000000000,maxBound]),(1,arbitrary)]
      limit <- frequency [(3,elements [0,1,2016,2017,maxBound]),(1,arbitrary)]
      pure (tip,start,limit)

snapshotEpochParity :: Property
snapshotEpochParity = forAll gen $ \(flags,slot,stored,current) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 20 flags slot stored current
  let expected = if flags == 1 && slot >= 0 && slot <= 255 && stored /= 0 && stored == current then 1 else 0
  pure (actual === expected)
  where
    gen = do
      flags <- choose (0,3 :: Word32)
      slot <- frequency [(3,elements [minBound,-1,0,24,255,256,maxBound]),(1,arbitrary)]
      stored <- frequency [(3,elements [0,1,maxBound]),(1,arbitrary)]
      current <- frequency [(3,pure stored),(1,arbitrary)]
      pure (flags,slot,stored,current)

bmmBidTransitions :: Property
bmmBidTransitions = forAll ((,,) <$> elements [124,125] <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (124,1) -> branch 3 65538
        (124,3) -> branch 4 65541
        (124,4) -> branch 6 65541
        (124,6) -> branch 7 65545
        (124,7) -> branch 8 65545
        (124,8) -> branch (-11) 65545
        (125,1) -> branch 2 (-1)
        (125,2) -> branch 4 65539
        (125,4) -> branch 5 (-1)
        (125,5) -> branch 6 65544
        (125,6) -> branch 7 65544
        (125,7) -> branch 65801 65544
        _ -> -1
  pure (actual === expected)

authenticatedJsonTransitions :: Property
authenticatedJsonTransitions = forAll ((,) <$> choose (0,24 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 123 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-1)
        2 -> branch 3 4
        3 -> branch 4 (-1)
        4 -> branch 7 5
        5 -> branch 65542 (-10)
        7 -> branch 8 (-1)
        p | p >= 8 && p <= 14 -> branch (if p == 14 then 17 else fromIntegral p + 1) 15
        15 -> branch 22 (-10)
        22 -> branch 65552 65559
        17 -> branch 18 19
        18 -> branch (-11) 19
        19 -> branch 20 (-1)
        20 -> branch 65557 (-10)
        _ -> -1
  pure (actual === expected)

bmmSuccessorTransitions :: Property
bmmSuccessorTransitions = forAll ((,) <$> choose (0,13 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 122 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-13)
        2 -> branch 4 66307
        4 -> branch 5 (-13)
        5 -> branch 6 (-13)
        6 -> branch 7 (-13)
        7 -> branch 8 66313
        8 -> branch 10 66313
        10 -> branch 11 (-1)
        11 -> branch (-10) (-13)
        _ -> -1
  pure (actual === expected)

bmmPublicationTransitions :: Property
bmmPublicationTransitions = forAll ((,) <$> choose (0,19 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 121 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-13)
        2 -> branch 3 (-1)
        3 -> branch 4 5
        4 -> branch 6 (-1)
        5 -> branch 6 (-1)
        6 -> branch 7 (-1)
        7 -> branch 8 (-1)
        8 -> branch 9 66314
        9 -> branch 11 66314
        11 -> branch 12 (-1)
        12 -> branch 13 14
        13 -> branch 14 (-1)
        14 -> branch 16 66063
        16 -> branch (-10) 66065
        _ -> -1
  pure (actual === expected)

bmmProbeResultTransitions :: Property
bmmProbeResultTransitions = forAll ((,) <$> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 120 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch (-13) 2
        2 -> branch 3 5
        3 -> branch 66052 (-1)
        5 -> branch 6 (-10)
        6 -> branch 7 (-1)
        7 -> branch 66056 (-1)
        _ -> -1
  pure (actual === expected)

bmmAdmissionTransitions :: Property
bmmAdmissionTransitions = forAll ((,) <$> choose (0,26 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 119 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 66306
        3 -> branch 4 66309
        4 -> branch 6 66309
        6 -> branch 8 66311
        8 -> branch 9 (-1)
        9 -> branch 10 13
        10 -> branch 11 (-1)
        11 -> branch 66316 (-1)
        13 -> branch 66318 15
        15 -> branch 16 18
        16 -> branch 22 18
        18 -> branch 19 (-1)
        19 -> branch 20 (-1)
        20 -> branch 66325 (-1)
        22 -> branch 23 66328
        23 -> branch (-10) 66328
        _ -> -1
  pure (actual === expected)

bmmCacheKeyTransitions :: Property
bmmCacheKeyTransitions = forAll ((,) <$> choose (0,4 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 118 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-10)
        2 -> branch (-11) (-10)
        _ -> -1
  pure (actual === expected)

bmmCacheHitTransitions :: Property
bmmCacheHitTransitions = forAll ((,) <$> choose (0,13 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 117 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 66306
        3 -> branch 5 66308
        5 -> branch 6 (-13)
        6 -> branch 7 (-1)
        7 -> branch 8 66313
        8 -> branch 10 66313
        10 -> branch 65547 (-1)
        _ -> -1
  pure (actual === expected)

bmmCachePreflightTransitions :: Property
bmmCachePreflightTransitions = forAll ((,) <$> choose (0,14 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 116 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        p | p == 1 || p == 2 -> branch (fromIntegral p + 1) (-1)
        3 -> branch 4 6
        4 -> branch 7 66309
        6 -> branch 7 (-1)
        7 -> branch 8 (-1)
        8 -> branch 12 9
        9 -> branch 10 (-1)
        10 -> branch 66315 (-1)
        12 -> branch (-10) (-1)
        _ -> -1
  pure (actual === expected)

bmmEdgeRecheckTransitions :: Property
bmmEdgeRecheckTransitions = forAll ((,) <$> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 115 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-10)
        2 -> branch 5 3
        3 -> branch 65540 (-1)
        5 -> branch 6 (-10)
        6 -> branch (-11) 7
        7 -> branch 65544 (-1)
        _ -> -1
  pure (actual === expected)

parentProbeMetadataTransitions :: Property
parentProbeMetadataTransitions = forAll ((,) <$> choose (0,25 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 114 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 4 2
        p | p == 2 || p == 9 || p == 14 -> branch (66048 + fromIntegral p + 1) (-12)
        p | p == 18 || p == 22 -> branch (65792 + fromIntegral p + 1) (-11)
        4 -> branch 5 (-1)
        p | p >= 5 && p <= 8 -> branch (if p == 8 then 11 else fromIntegral p + 1) 9
        p | p == 11 || p == 12 -> branch (fromIntegral p + 1) (-1)
        13 -> branch 16 14
        16 -> branch 17 (-1)
        17 -> branch 20 18
        20 -> branch 21 (-12)
        21 -> branch (-10) 22
        _ -> -1
  pure (actual === expected)

cacheCapacityParity :: Property
cacheCapacityParity = forAll ((,) <$> arbitrary <*> arbitrary) $ \(limit,size) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 11 0 0 limit size
  pure (actual === if size > limit then 1 else 0)

cacheEpochParity :: Property
cacheEpochParity = forAll (do stored <- arbitrary; current <- oneof [pure stored, arbitrary]; pure (stored,current)) $ \(stored,current) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 21 0 0 stored current
  pure (actual === if stored /= current then 1 else 0)

anchorReconcileTransitions :: Property
anchorReconcileTransitions = forAll ((,) <$> choose (0,21 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 102 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-12)
        2 -> branch 4 65795
        4 -> branch 5 (-12)
        5 -> branch 7 65798
        p | p >= 7 && p <= 9 -> branch (fromIntegral p + 1) (-12)
        p | p >= 10 && p <= 16 -> branch (if p == 16 then -10 else fromIntegral p + 1) 17
        17 -> branch 18 (-12)
        18 -> branch 66067 (-12)
        _ -> -1
  pure (actual === expected)

blockContextTransitions :: Property
blockContextTransitions = forAll ((,,) <$> choose (98,101 :: Word32) <*> choose (0,9 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (98,1) -> branch 2 (-1)
        (98,2) -> branch 3 (-10)
        (98,3) -> branch 4 (-10)
        (98,4) -> branch (-11) (-10)
        (99,1) -> branch 2 (-1)
        (99,2) -> branch 65795 (-10)
        (100,1) -> branch 2 (-1)
        (100,2) -> branch 3 4
        (100,3) -> branch 4 (-1)
        (100,4) -> branch 5 (-13)
        (100,5) -> branch 7 65798
        (100,7) -> branch (-10) (-11)
        (101,1) -> branch (-11) 65538
        _ -> -1
  pure (actual === expected)

parentContextTransitions :: Property
parentContextTransitions = forAll ((,,) <$> elements [96,97 :: Word32] <*> choose (0,20 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 65538
        3 -> branch (if kind == 96 then 4 else 15) (-10)
        4 | kind == 96 -> branch 5 (-10)
        p | kind == 96 && p >= 5 && p <= 9 -> branch (if p == 9 then 11 else fromIntegral p + 1) 65546
        p | kind == 96 && (p == 11 || p == 12) -> branch (fromIntegral p + 1) (-10)
        p | kind == 96 && (p == 13 || p == 14) -> branch (fromIntegral p + 1) 65553
        15 -> branch 16 65553
        16 -> branch 65810 65553
        _ -> -1
  pure (actual === expected)

withdrawalLookupTransitions :: Property
withdrawalLookupTransitions = forAll ((,) <$> choose (0,33 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 95 phase result
  let table = [(1,(2,-10)),(2,(3,-10)),(3,(4,-1)),(4,(5,-10)),(5,(7,65542)),
        (7,(8,-1)),(8,(11,9)),(9,(10,16)),(10,(11,16)),(11,(12,-1)),(12,(13,-1)),
        (13,(14,-1)),(14,(15,-10)),(15,(65566,-10)),(16,(17,23)),(17,(18,-10)),
        (18,(23,19)),(19,(20,-1)),(20,(21,-1)),(21,(65558,-1)),(23,(24,-10)),
        (24,(29,25)),(25,(26,-1)),(26,(27,-1)),(27,(65564,-1)),(29,(65823,-11))]
      expected = if phase == 0 then 1 else case lookup phase table of
        Just (yes,no) -> case result of 0 -> no; 1 -> yes; _ -> -1
        Nothing -> -1
  pure (actual === expected)

depositPreflightTransitions :: Property
depositPreflightTransitions = forAll ((,) <$> choose (0,25 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 94 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 3
        2 -> branch 3 (-1)
        3 -> branch 4 5
        4 -> branch 8 5
        5 -> branch 6 (-11)
        6 -> branch 65799 (-11)
        8 -> branch 9 (-1)
        p | p >= 9 && p <= 22 -> branch (if p == 22 then -10 else fromIntegral p + 1) 66071
        _ -> -1
  pure (actual === expected)

confirmedDepositTransitions :: Property
confirmedDepositTransitions = forAll ((,) <$> choose (0,45 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 93 phase result
  let table = [(1,(2,4)),(2,(5,66051)),(4,(5,-1)),(5,(7,66054)),(7,(8,-1)),
        (8,(9,13)),(9,(10,13)),(10,(11,-1)),(11,(13,66060)),(13,(14,-12)),
        (14,(16,66063)),(16,(17,-1)),(17,(18,21)),(18,(19,-1)),(19,(66068,-1)),
        (21,(22,23)),(22,(43,-1)),(23,(24,26)),(24,(25,26)),(25,(27,26)),
        (26,(43,-1)),(27,(29,28)),(28,(43,-1)),(29,(30,-1)),(30,(32,31)),
        (31,(43,-1)),(32,(33,65575)),(33,(34,-12)),(34,(37,35)),(35,(66084,-1)),
        (37,(38,65575)),(38,(65575,-1)),(43,(-11,-12))]
      expected = if phase == 0 then 1 else case lookup phase table of
        Just (yes,no) -> case result of 0 -> no; 1 -> yes; _ -> -1
        Nothing -> -1
  pure (actual === expected)

m8ParseTransitions :: Property
m8ParseTransitions = forAll ((,) <$> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 92 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-10)
        2 -> branch 3 (-1)
        p | p >= 3 && p <= 6 -> branch (fromIntegral p + 1) (-10)
        7 -> branch 8 (-1)
        8 -> branch 65801 (-1)
        _ -> -1
  pure (actual === expected)

messageDispatchTransitions :: Property
messageDispatchTransitions = forAll ((,) <$> choose (0,8 :: Word32) <*> oneof [choose (0,7), arbitrary]) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 91 phase result
  let expected = case phase of
        0 -> 1
        1 -> if result == 1 then 2 else -1
        2 -> case result of
          1 -> 3
          2 -> 4
          3 -> 5
          5 -> -11
          _ -> 6
        p | p >= 3 && p <= 6 -> case result of 0 -> -10; 1 -> -11; _ -> -1
        _ -> -1
  pure (actual === expected)

eachTransitions :: Property
eachTransitions = forAll ((,) <$> choose (0,5 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 90 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-11)
        2 -> branch 3 (-10)
        3 -> branch 1 (-1)
        _ -> -1
  pure (actual === expected)

m4ModeTransitions :: Property
m4ModeTransitions = forAll ((,,) <$> choose (88,89 :: Word32) <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case (kind,phase) of
        (_,0) -> 1
        (88,1) -> branch 3 65538
        (88,3) -> branch 65540 5
        (88,5) -> next 6
        (88,6) -> branch 7 9
        (88,7) -> branch (-11) 65544
        (88,9) -> branch (-12) (-13)
        (89,1) -> branch 2 3
        (89,2) -> next 3
        (89,3) -> branch 4 65799
        (89,4) -> branch 5 6
        (89,5) -> next 6
        (89,6) -> next 3
        _ -> -1
  pure (actual === expected)

m6IdTransitions :: Property
m6IdTransitions = forAll ((,) <$> choose (0,29 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 87 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case phase of
        0 -> 1
        1 -> next 2
        2 -> branch 65539 4
        4 -> branch 6 65541
        6 -> branch 8 65543
        8 -> branch 9 65546
        9 -> branch 11 65546
        11 -> branch 12 17
        12 -> next 13
        13 -> branch 14 65551
        14 -> branch 16 65551
        16 -> next 11
        17 -> branch 18 65555
        18 -> branch 20 65555
        p | p >= 20 && p <= 25 -> next (fromIntegral p + 1)
        26 -> branch 65819 (-11)
        _ -> -1
  pure (actual === expected)

replayFinishTransitions :: Property
replayFinishTransitions = forAll ((,,) <$> choose (85,86 :: Word32) <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case (kind,phase) of
        (_,0) -> 1
        (85,1) -> branch 2 (-11)
        (85,p) | p >= 2 && p <= 7 -> branch (fromIntegral p + 1) 9
        (85,p) | p == 8 || p == 9 -> next 1
        (86,1) -> branch 2 4
        (86,2) -> branch 65539 4
        (86,4) -> branch 5 6
        (86,5) -> next 6
        (86,6) -> branch 7 65800
        (86,7) -> next 65800
        _ -> -1
  pure (actual === expected)

m6WithdrawalTransitions :: Property
m6WithdrawalTransitions = forAll ((,) <$> choose (0,27 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 84 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case phase of
        0 -> 1
        1 -> branch 2 65539
        2 -> branch 4 65539
        4 -> next 5
        5 -> branch 6 65543
        6 -> branch 8 65543
        8 -> branch 9 (-10)
        9 -> branch 11 65546
        11 -> next 12
        12 -> branch 14 65549
        14 -> branch 16 65551
        16 -> branch 17 20
        17 -> branch 18 20
        18 -> branch 65555 20
        20 -> branch 21 22
        p | p >= 21 && p <= 24 -> next (if p == 24 then 65817 else fromIntegral p + 1)
        _ -> -1
  pure (actual === expected)

m5DepositTransitions :: Property
m5DepositTransitions = forAll ((,) <$> choose (0,17 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 83 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case phase of
        0 -> 1
        1 -> branch 2 65539
        2 -> branch 4 65539
        4 -> next 5
        5 -> branch 6 65543
        6 -> branch 8 65543
        8 -> next 9
        9 -> next 10
        p | p >= 10 && p <= 14 -> branch (if p == 14 then 65807 else fromIntegral p + 1) (-11)
        _ -> -1
  pure (actual === expected)

ctipChangeTransitions :: Property
ctipChangeTransitions = forAll ((,) <$> choose (0,15 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 82 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-11)
        2 -> next 3
        3 -> branch 4 7
        4 -> branch 6 65541
        6 -> next 8
        7 -> next 8
        8 -> next 9
        9 -> branch 65546 11
        11 -> branch 12 13
        12 -> next 13
        13 -> next 1
        _ -> -1
  pure (actual === expected)

ctipOutputTransitions :: Property
ctipOutputTransitions = forAll ((,,) <$> choose (80,81 :: Word32) <*> choose (0,12 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case (kind,phase) of
        (_,0) -> 1
        (_,1) -> branch 2 (-11)
        (80,2) -> branch 3 4
        (80,3) -> next 4
        (80,4) -> branch 5 10
        (80,5) -> branch 6 10
        (80,6) -> branch 8 65543
        (80,8) -> branch 10 65545
        (80,10) -> next 1
        (81,2) -> branch 3 5
        (81,3) -> branch 5 65540
        (81,5) -> next 1
        _ -> -1
  pure (actual === expected)

ctipScanTransitions :: Property
ctipScanTransitions = forAll ((,,) <$> choose (78,79 :: Word32) <*> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next x = branch x (-1)
      expected = case (kind,phase) of
        (_,0) -> 1
        (_,1) -> branch 2 (-11)
        (78,2) -> next 3
        (78,3) -> branch 5 65540
        (78,5) -> branch 6 8
        (78,6) -> branch 8 65543
        (79,2) -> branch 3 4
        (79,3) -> next 4
        (79,4) -> next 5
        (79,5) -> branch 6 8
        (79,6) -> branch 65543 8
        (_,8) -> next 1
        _ -> -1
  pure (actual === expected)

expiryTransitions :: Property
expiryTransitions = forAll ((,,) <$> choose (76,77 :: Word32) <*> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-11)
        2 -> branch (if kind == 76 then 4 else 6) 65539
        4 | kind == 76 -> branch 6 65541
        6 -> branch 7 8
        7 -> branch 1 (-1)
        8 -> branch 1 (-1)
        _ -> -1
  pure (actual === expected)

m4DispatchTransitions :: Property
m4DispatchTransitions = forAll ((,,) <$> choose (74,75 :: Word32) <*> choose (0,12 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (74,1) -> branch (-11) 2
        (74,2) -> next 3
        (74,3) -> branch 4 5
        (74,4) -> branch 65802 (-11)
        (74,5) -> branch 6 65543
        (74,6) -> branch 8 (-10)
        (74,8) -> branch 65802 (-11)
        (75,1) -> branch 65538 3
        (75,3) -> next 4
        (75,4) -> branch 5 6
        (75,5) -> branch 7 (-10)
        (75,6) -> branch 65800 (-11)
        (75,7) -> branch 65800 (-11)
        _ -> -1
  pure (actual === expected)

m4LeaderTransitions :: Property
m4LeaderTransitions = forAll ((,) <$> choose (0,18 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 73 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case phase of
        0 -> 1
        1 -> branch (-11) 2
        2 -> branch 3 9
        3 -> branch 4 6
        4 -> branch 5 7
        5 -> next 7
        6 -> branch 10 8
        7 -> next 8
        8 -> next 2
        9 -> next 11
        10 -> next 8
        11 -> branch 12 (-11)
        12 -> branch 13 (-11)
        13 -> branch 14 (-11)
        14 -> next 15
        15 -> branch 65808 (-10)
        _ -> -1
  pure (actual === expected)

m4VoteTransitions :: Property
m4VoteTransitions = forAll ((,,) <$> choose (71,72 :: Word32) <*> choose (0,14 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (71,1) -> branch 2 65540
        (71,2) -> branch 5 3
        (71,3) -> next 1
        (71,5) -> branch 6 (-11)
        (71,6) -> next 7
        (71,7) -> branch 8 65804
        (71,8) -> branch 9 11
        (71,9) -> branch 10 11
        (71,10) -> next 11
        (71,11) -> next 7
        (72,1) -> branch 2 5
        (72,2) -> branch 3 4
        (72,3) -> next 4
        (72,4) -> next 1
        (72,5) -> branch 65798 (-10)
        _ -> -1
  pure (actual === expected)

proposalAdmissionTransitions :: Property
proposalAdmissionTransitions = forAll ((,,) <$> choose (69,70 :: Word32) <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (69,1) -> branch 65794 (-11)
        (70,1) -> branch 65538 3
        (70,3) -> next 4
        (70,4) -> branch 5 8
        (70,5) -> branch 65542 7
        (70,7) -> next 4
        (70,8) -> next 65801
        _ -> -1
  pure (actual === expected)

proposalAckTransitions :: Property
proposalAckTransitions = forAll ((,) <$> choose (0,24 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 68 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-11)
        2 -> branch (-11) 3
        3 -> branch 65540 5
        5 -> next 6
        6 -> next 7
        7 -> branch 8 9
        8 -> next 10
        9 -> next 10
        10 -> branch 11 (-11)
        11 -> branch 12 (-11)
        12 -> next 13
        13 -> next 14
        14 -> branch 15 (-11)
        15 -> branch 16 18
        16 -> branch 65553 18
        18 -> branch 19 (-11)
        19 -> branch 20 (-11)
        20 -> next 21
        21 -> next 65814
        _ -> -1
  pure (actual === expected)

coinbaseMessagesTransitions :: Property
coinbaseMessagesTransitions = forAll ((,) <$> choose (0,21 :: Word32) <*> choose (0,7 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 67 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-11)
        2 -> branch 3 4
        3 -> next 4
        4 -> next 5
        5 -> case result of 0 -> 19; 1 -> 6; 2 -> 8; 3 -> 18; 4 -> 10; 5 -> 14; _ -> -1
        6 -> branch 18 65543
        8 -> branch 18 65545
        10 -> branch 65547 12
        12 -> next 18
        14 -> branch 16 65551
        16 -> next 18
        18 -> next 19
        19 -> next 1
        _ -> -1
  pure (actual === expected)

m8AcceptanceTransitions :: Property
m8AcceptanceTransitions = forAll ((,) <$> choose (0,13 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 66 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = if result == 1 then value else -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-11)
        2 -> next 3
        3 -> branch 4 11
        4 -> next 5
        5 -> branch 6 65543
        6 -> branch 8 65543
        8 -> branch 11 65545
        11 -> next 1
        _ -> -1
  pure (actual === expected)

parentPreflightTransitions :: Property
parentPreflightTransitions = forAll ((,,) <$> choose (62,65 :: Word32) <*> choose (0,6 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (62,1) -> branch 2 3
        (62,2) -> branch (-10) 3
        (62,3) -> branch 4 (-11)
        (62,4) -> branch (-10) (-11)
        (63,1) -> branch (-10) 2
        (63,2) -> branch 3 4
        (63,3) -> branch (-10) 4
        (63,4) -> branch (-11) (-10)
        (64,1) -> branch 3 2
        (64,2) -> branch 3 (-10)
        (64,3) -> branch 4 (-11)
        (64,4) -> branch (-11) (-10)
        (65,1) -> branch (-10) 2
        (65,2) -> branch 3 (-10)
        (65,3) -> branch (-11) (-10)
        _ -> -1
  pure (actual === expected)

headerMtpTransitions :: Property
headerMtpTransitions = forAll ((,) <$> choose (0,17 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 61 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next n = if result == 1 then n else -1
      expected = case phase of
        0 -> 2
        2 -> branch 4 65539
        4 -> next 5
        5 -> branch 6 65544
        6 -> branch 7 65544
        7 -> branch 9 65544
        9 -> branch 10 65547
        10 -> branch 12 65547
        12 -> next 13
        13 -> branch 15 65550
        15 -> branch (-11) (-10)
        _ -> -1
  pure (actual === expected)

checkpointIdentityTransitions :: Property
checkpointIdentityTransitions = forAll ((,) <$> choose (0,20 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 60 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-10)
        2 -> branch 3 11
        3 -> branch 4 5
        4 -> branch 5 11
        5 -> branch 6 11
        6 -> branch 7 11
        7 -> branch 8 11
        8 -> branch 9 11
        9 -> branch (-11) (-10)
        11 -> branch (-10) 12
        12 -> branch 13 (-10)
        13 -> branch (-10) 14
        14 -> branch 15 (-10)
        15 -> branch (-10) 16
        16 -> branch (-10) 17
        17 -> branch 18 (-10)
        18 -> branch (-11) (-10)
        _ -> -1
  pure (actual === expected)

proposalExpiryParity :: Property
proposalExpiryParity = forAll ((,,,) <$> frequency [(3,elements [0,1,3,5,65534,65535,maxBound]),(1,arbitrary :: Gen Word32)] <*>
  frequency [(3,elements [0,1,4,5,6,8,9,10,11,65535,4294967295,4294967296,maxBound]),(1,arbitrary :: Gen Word64)] <*>
  frequency [(3,elements [-1,0,1,4,5,6,10,65535,maxBound]),(1,arbitrary :: Gen Int64)] <*>
  frequency [(3,elements [0,1,8,10,65535,65536,maxBound]),(1,arbitrary :: Gen Word64)]) $ \(threshold,age,votes,maxAge) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 19 threshold votes age maxAge
  let a = toInteger age; v = toInteger votes; m = toInteger maxAge; t = toInteger threshold
      expected | t == 0 || t >= m || m > 65535 || a > 4294967295 || v < 0 || v > a = -1
               | a > m || (a > m - t && a - v >= m - t) = 1
               | otherwise = 0
  pure (actual === expected)

ctipBalanceParity :: Property
ctipBalanceParity = forAll ((,,) <$> choose (0,3) <*>
  frequency [(3,elements [minBound,-1,0,1,2100000000000000,2100000000000001,maxBound]),(1,arbitrary)] <*>
  frequency [(3,elements [0,1,2100000000000000,maxBound]),(1,arbitrary)]) $ \(flags,value,limit) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 18 flags value 0 limit
  let valid = flags <= 1 && ((flags == 0 && value == 0) ||
        (flags == 1 && value >= 0 && toInteger value <= toInteger limit))
  pure (actual === if valid then 1 else 0)

activationWindowParity :: Property
activationWindowParity = forAll ((,) <$> boundary <*> boundary) $ \(threshold,maxAge) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 17 0 0 threshold maxAge
  let rejected = maxAge == 0 || threshold == 0 || threshold >= maxAge
  pure (actual === if rejected then 0 else 1)
  where boundary = frequency [(3,elements [0,1,2,65534,65535,65536,maxBound]),(1,arbitrary)]

checkpointCtipParity :: Property
checkpointCtipParity = forAll ((,,) <$> choose (0,3) <*> frequency [(3,elements [0,1,4294967294,4294967295,4294967296,maxBound]),(1,arbitrary)] <*>
  frequency [(3,elements [minBound,-1,0,1,2100000000000000,2100000000000001,maxBound]),(1,arbitrary)]) $ \(flags,vout,value) -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 16 flags value vout 2100000000000000
  let valid = flags <= 1 && vout <= 4294967295 &&
        ((flags == 1 && vout == 4294967295 && value == 0) ||
         (flags == 0 && vout /= 4294967295 && value > 0 && value <= 2100000000000000))
  pure (actual === if valid then 1 else 0)

credentialTransitions :: Property
credentialTransitions = forAll ((,,) <$> elements [58,59] <*> choose (0,14 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (58,0) -> 1
        (58,1) -> branch 2 6
        (58,2) -> branch 65541 3
        (58,3) -> branch 65541 4
        (58,4) -> branch 65541 6
        (58,6) -> branch 7 10
        (58,7) -> branch 65545 8
        (58,8) -> branch 65545 10
        (58,10) -> if result == 1 then 11 else -1
        (58,11) -> branch 65804 (-10)
        (59,0) -> 1
        (59,1) -> branch 65538 3
        (59,3) -> branch 4 7
        (59,4) -> branch 5 65542
        (59,5) -> branch 65801 65542
        (59,7) -> branch 65801 65544
        _ -> -1
  pure (actual === expected)

cookieCacheTransitions :: Property
cookieCacheTransitions = forAll ((,) <$> choose (0,8 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 57 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 4
        2 -> branch 5 65539
        4 -> if result == 1 then 5 else -1
        5 -> branch 65798 (-10)
        _ -> -1
  pure (actual === expected)

rpcTimeoutTransitions :: Property
rpcTimeoutTransitions = forAll ((,) <$> choose (0,16 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 56 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next n = if result == 1 then n else -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 6
        2 -> next 3
        3 -> branch 65797 65540
        6 -> branch 7 65806
        7 -> next 8
        8 -> branch 10 65545
        10 -> next 11
        11 -> branch 12 65797
        12 -> branch 13 65797
        13 -> next 65797
        _ -> -1
  pure (actual === expected)

signedPositiveParity :: Property
signedPositiveParity = forAll (frequency [(3,elements [minBound,-1,0,1,maxBound]),(1,arbitrary)]) $ \value -> ioProperty $ do
  actual <- elements_hs_parent_replay_record 15 0 value 0 0
  pure (actual === if value > 0 then 1 else 0)

authRetryTransitions :: Property
authRetryTransitions = forAll ((,) <$> choose (0,5 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 55 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-10)
        2 -> if result == 1 then 3 else -1
        3 -> branch (-10) (-11)
        _ -> -1
  pure (actual === expected)

rpcReplyTransitions :: Property
rpcReplyTransitions = forAll ((,) <$> choose (0,6 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 54 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 65538
        3 -> branch 65540 (-11)
        _ -> -1
  pure (actual === expected)

parentWarmupTransitions :: Property
parentWarmupTransitions = forAll ((,) <$> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 53 phase result
  let next n = if result == 1 then n else -1
      branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> next 2
        2 -> branch 4 65539
        4 -> branch 5 (-10)
        5 -> next 6
        6 -> branch 8 65543
        8 -> branch (-11) (-10)
        _ -> -1
  pure (actual === expected)

parentSignetTransitions :: Property
parentSignetTransitions = forAll ((,) <$> choose (0,19 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 52 phase result
  let next n = if result == 1 then n else -1
      branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch (-11) 2
        2 -> branch 65540 3
        3 -> branch 5 65540
        5 -> branch 7 65542
        7 -> next 8
        8 -> next 9
        9 -> next 10
        10 -> branch 12 11
        11 -> branch 12 (-10)
        12 -> next 13
        13 -> next 14
        14 -> next 15
        15 -> next 16
        16 -> branch (-11) 65553
        _ -> -1
  pure (actual === expected)

parentSignetMerkleTransitions :: Property
parentSignetMerkleTransitions = forAll ((,) <$> choose (0,9 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 51 phase result
  let next n = if result == 1 then n else -1
      expected = case phase of
        0 -> 1
        1 -> next 2
        2 -> next 3
        3 -> next 4
        4 -> case result of 0 -> 65799; 1 -> 5; _ -> -1
        5 -> next 6
        6 -> next 4
        _ -> -1
  pure (actual === expected)

parentRecoveryTransitions :: Property
parentRecoveryTransitions = forAll ((,) <$> choose (0,7 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 50 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 (-1)
        2 -> branch 3 65796
        3 -> branch 65796 (-11)
        _ -> -1
  pure (conjoin [actual === expected, Constants.parentRecoverySeconds === 30])

parentBlockWrapperTransitions :: Property
parentBlockWrapperTransitions = forAll ((,,) <$> elements [48,49 :: Word32] <*> choose (0,8 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (48,1) -> branch 2 (-1)
        (48,2) -> branch (-11) 3
        (48,3) -> branch 4 (-1)
        (48,4) -> branch 65797 (-10)
        (49,1) -> branch 2 (-10)
        (49,2) -> branch 3 (-10)
        (49,3) -> branch (-11) 65540
        _ -> -1
  pure (actual === expected)

parentBlockTransactionTransitions :: Property
parentBlockTransactionTransitions = forAll gen $ \(phase,result,index) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 47 phase result
  periodic <- elements_hs_parent_replay_record 14 0 0 index 0
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 65540 2
        2 -> branch 3 65540
        3 -> branch 5 65540
        5 -> branch 6 (-1)
        6 -> branch 7 14
        7 -> branch 8 9
        8 -> branch 9 (-1)
        9 -> branch 10 65547
        10 -> branch 65547 12
        12 -> branch 6 (-1)
        p | p >= 14 && p <= 17 -> branch (fromIntegral p + 1) (-1)
        18 -> branch 19 24
        19 -> branch 20 21
        p | p == 20 || p == 21 -> branch (fromIntegral p + 1) (-1)
        22 -> branch 18 (-1)
        24 -> branch 25 (-1)
        25 -> branch 65563 26
        26 -> branch 65563 65820
        _ -> -1
  pure (conjoin [actual === expected, periodic === if all (not . testBit index) [0..7] then 1 else 0])
  where
    gen = (,,) <$> choose (0,31 :: Word32) <*> choose (0,3 :: Word32) <*>
      frequency [(4,elements [0,1,255,256,257,511,512,513,4294967295,4294967296,maxBound :: Word64]),(1,arbitrary)]

parentVerifiedHeaderTransitions :: Property
parentVerifiedHeaderTransitions = forAll ((,) <$> choose (0,36 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 46 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 65538
        6 -> branch 7 65544
        7 -> branch 9 65544
        p | p `elem` [13,21,23,25] -> branch (fromIntegral p + 1) (-10)
        17 -> branch 18 65555
        18 -> branch 20 65555
        32 -> branch 65569 (-11)
        p | p >= 3 && p <= 31 && p /= 8 && p /= 19 -> branch (fromIntegral p + 1) (-1)
        _ -> -1
  pure (actual === expected)

parentPredecessorTransitions :: Property
parentPredecessorTransitions = forAll ((,) <$> choose (0,29 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 45 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 2 7
        2 -> branch 3 65541
        3 -> branch 4 65541
        4 -> branch (-11) 65542
        7 -> branch 8 65545
        8 -> branch 10 65545
        p | p >= 10 && p <= 13 -> branch (fromIntegral p + 1) (-1)
        14 -> branch 16 65551
        16 -> branch 17 (-1)
        p | p >= 17 && p <= 21 -> branch (if p == 21 then 23 else fromIntegral p + 1) 65558
        23 -> branch 24 (-1)
        24 -> branch 65562 25
        25 -> branch (-11) 65562
        _ -> -1
  pure (actual === expected)

parentHeaderMetadataTransitions :: Property
parentHeaderMetadataTransitions = forAll ((,) <$> choose (0,21 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 44 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 65538
        3 -> branch 4 65541
        4 -> branch 6 65541
        p | p >= 6 && p <= 8 -> branch (fromIntegral p + 1) (-1)
        9 -> branch 10 65548
        10 -> branch 11 65548
        11 -> branch 13 65548
        13 -> branch 14 (-1)
        14 -> branch 15 (-1)
        p | p >= 15 && p <= 17 -> branch 65554 (if p == 17 then -11 else fromIntegral p + 1)
        _ -> -1
  pure (actual === expected)

parentMedianTimeTransitions :: Property
parentMedianTimeTransitions = forAll gen $ \(phase,result,index,height) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 43 phase result
  sampleAllowed <- elements_hs_parent_replay_record 13 0 0 index height
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        4 -> branch 5 12
        7 -> branch 8 (-10)
        11 -> branch 4 (-1)
        13 -> branch 65806 (-1)
        p | p >= 1 && p <= 12 -> branch (fromIntegral p + 1) (-1)
        _ -> -1
      count = min 11 (toInteger height + 1)
      valid = height <= 0xffffffff && toInteger index < count
  pure (conjoin [actual === expected, sampleAllowed === if valid then 1 else 0])
  where
    gen = (,,,) <$> choose (0,16 :: Word32) <*> choose (0,3 :: Word32) <*>
      frequency [(4,choose (0,13)),(1,arbitrary)] <*>
      frequency [(4,elements [0,1,9,10,11,4294967294,4294967295,4294967296,maxBound]),(1,arbitrary)]

parentRawHeaderTransitions :: Property
parentRawHeaderTransitions = forAll ((,,) <$> elements [39,40,41,42 :: Word32] <*> choose (0,8 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (39,1) -> branch 2 65539
        (39,2) -> branch 65796 65539
        (40,p) | p == 1 || p == 2 -> branch (fromIntegral p + 1) (-1)
        (40,3) -> branch 65540 (-11)
        (41,1) -> branch 2 (-1)
        (41,2) -> branch 3 65540
        (41,3) -> branch (-11) (-10)
        (42,p) | p >= 1 && p <= 4 -> branch (fromIntegral p + 1) (-1)
        (42,5) -> branch (-11) (-10)
        _ -> -1
  pure (actual === expected)

parentWorkTransitions :: Property
parentWorkTransitions = forAll ((,,) <$> elements [36,37,38 :: Word32] <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected
        | phase == 0 = 1
        | phase == 1 = branch 2 (-1)
        | kind == 36 && phase >= 2 && phase <= 5 = branch 65542 (if phase == 5 then 7 else fromIntegral phase + 1)
        | kind == 36 && phase == 7 = branch 65544 (-11)
        | kind == 37 && phase >= 2 && phase <= 4 = branch 65541 (if phase == 4 then 65798 else fromIntegral phase + 1)
        | kind == 38 && phase == 2 = branch 65541 3
        | kind == 38 && phase == 3 = branch 65541 (-11)
        | otherwise = -1
  pure (actual === expected)

parentRpcParseTransitions :: Property
parentRpcParseTransitions = forAll ((,,) <$> elements [32,33,34,35 :: Word32] <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected
        | phase == 0 = 1
        | kind == 32 && phase <= 2 = branch (fromIntegral phase + 1) (-1)
        | kind == 32 && phase <= 8 = branch (if phase == 8 then -11 else fromIntegral phase + 1) (-10)
        | kind == 33 && phase <= 3 = branch (fromIntegral phase + 1) (-10)
        | kind == 33 && phase == 4 = branch 5 (-1)
        | kind == 33 && phase == 5 = branch (-11) (-10)
        | kind == 34 && phase == 1 = branch (-11) 65538
        | kind == 35 && phase == 1 = branch 2 (-1)
        | kind == 35 && phase == 2 = branch 65796 65539
        | otherwise = -1
  pure (conjoin [actual === expected, Constants.parentHashHexLength === 64])

parentMessageTransitions :: Property
parentMessageTransitions = forAll ((,,) <$> elements [29,30,31 :: Word32] <*> choose (0,18 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected
        | phase == 0 = 1
        | kind == 30 && phase <= 3 = branch (if phase == 3 then -11 else fromIntegral phase + 1) (-10)
        | kind == 31 && phase <= 3 = branch (fromIntegral phase + 1) (-1)
        | kind == 31 && phase <= 8 = branch (if phase == 8 then 65801 else fromIntegral phase + 1) (-10)
        | kind /= 29 = -1
        | phase <= 3 = branch (if phase == 3 then 5 else fromIntegral phase + 1) 65540
        | Just (yes,no) <- lookup phase [(7,(8,14)),(9,(10,12)),(10,(11,12)),(14,(-11,65551))] = branch yes no
        | Just action <- lookup phase [(5,6),(6,7),(8,9),(11,12),(12,13),(13,7)] = branch action (-1)
        | otherwise = -1
  pure (actual === expected)

parentMilestoneTransitions :: Property
parentMilestoneTransitions = forAll ((,,) <$> elements [27,28 :: Word32] <*> choose (0,47 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected
        | phase == 0 = 1
        | kind == 27 = if phase == 1 then branch (-11) 65538 else -1
        | Just (yes,no) <- lookup phase
            [(2,(3,15)),(3,(4,15)),(4,(5,-10)),(8,(9,-10)),
             (10,(11,65550)),(11,(12,65550)),(12,(13,65550)),
             (15,(16,27)),(16,(17,27)),(17,(18,-10)),(21,(22,-10)),
             (22,(23,65562)),(23,(24,65562)),(27,(28,-11)),(28,(29,-10)),
             (30,(31,35)),(31,(32,38)),(32,(33,38)),(33,(34,38)),(34,(37,38)),
             (35,(36,38)),(36,(37,38)),(39,(40,41)),(42,(43,65580)),(43,(-11,65580))] = branch yes no
        | Just action <- lookup phase
            [(1,2),(5,6),(6,7),(7,8),(9,10),(13,15),(18,19),(19,20),(20,21),
             (24,27),(29,30),(37,39),(38,39),(40,42),(41,42)] = branch action (-1)
        | otherwise = -1
  pure (conjoin [actual === expected, Constants.parentMessageTags ===
    [("PARENT_M1_TAG",[0xd5,0xe0,0xc4,0xaf]),("PARENT_M2_TAG",[0xd6,0xe1,0xc5,0xdf])]])

parentDeadlineTransitions :: Property
parentDeadlineTransitions = forAll ((,,) <$> elements [25,26 :: Word32] <*> choose (0,11 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (25,1) -> branch 2 7
        (25,2) -> branch 3 5
        (25,3) -> branch 65540 5
        (25,5) -> branch 65542 7
        (25,7) -> branch 8 (-10)
        (25,8) -> branch 65545 (-10)
        (26,1) -> branch 2 (-10)
        (26,2) -> branch 65539 (-10)
        _ -> -1
  pure (actual === expected)

parentReplayWrapperTransitions :: Property
parentReplayWrapperTransitions = forAll ((,,) <$> elements [22,23,24 :: Word32] <*> choose (0,10 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case (kind,phase) of
        (_,0) -> 1
        (22,1) -> branch 2 (-11)
        (22,2) -> branch 3 (-1)
        (22,3) -> branch 65798 4
        (22,4) -> branch 65541 (-10)
        (23,1) -> branch 2 (-10)
        (23,2) -> branch 3 (-10)
        (23,p) | p >= 3 && p <= 6 -> branch (if p == 6 then 65543 else fromIntegral p + 1) (-1)
        (24,1) -> branch 2 4
        (24,2) -> branch 5 65539
        (24,4) -> branch 5 (-1)
        (24,5) -> branch 65798 (-10)
        _ -> -1
  pure (actual === expected)

parentReplayAdvanceTransitions :: Property
parentReplayAdvanceTransitions = forAll ((,) <$> choose (0,36 :: Word32) <*> choose (0,3 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 21 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected | phase == 0 = 1
               | Just (no,yes) <- lookup phase
                  [(1,(-11,2)),(3,(-10,4)),(5,(-11,6)),(9,(-10,10)),(11,(-10,12)),
                   (12,(13,15)),(19,(65557,20)),(20,(65557,22)),(24,(28,25)),
                   (28,(65557,29)),(29,(65557,30))] = branch yes no
               | Just action <- lookup phase
                  [(2,3),(4,5),(6,7),(7,8),(8,9),(10,11),(13,65550),
                   (15,16),(16,17),(17,18),(18,19),(22,23),(23,24),
                   (25,26),(26,27),(27,28),(30,31),(31,32),(32,33),(33,5)] = branch action (-1)
               | otherwise = -1
  pure (actual === expected)

parentReplayBoundaryTransitions :: Property
parentReplayBoundaryTransitions = forAll ((,,) <$> elements [19,20 :: Word32] <*> choose (0,31 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      choices = if kind == 19 then
        [(1,(-10,2)),(2,(66051,4)),(4,(5,10)),(5,(7,66054)),(9,(-12,10)),
         (10,(-12,11)),(11,(12,14)),(14,(17,15)),(15,(-12,16)),(17,(18,20)),
         (18,(-12,19)),(20,(26,21)),(22,(24,66071)),(25,(-12,26)),
         (26,(-12,27)),(27,(66076,-11))] else
        [(1,(-10,2)),(2,(3,5)),(5,(-10,6)),(6,(7,9)),(9,(-10,10)),
         (10,(11,13)),(13,(15,14)),(14,(-10,15))]
      actions = if kind == 19 then
        [(7,8),(8,9),(12,66061),(16,17),(19,20),(21,22),(24,25)] else
        [(3,65540),(7,65544),(11,65548),(15,65808)]
      expected | phase == 0 = 1
               | Just (no,yes) <- lookup phase choices = branch yes no
               | Just action <- lookup phase actions = branch action (-1)
               | otherwise = -1
  pure (actual === expected)

parentReplayBootstrapTransitions :: Property
parentReplayBootstrapTransitions = forAll ((,,) <$> elements [17,18 :: Word32] <*> choose (0,52 :: Word32) <*> choose (0,3 :: Word32)) $ \(kind,phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store kind phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      next value = branch value (-1)
      expected
        | phase == 0 = 1
        | kind == 17 = case phase of
            7 -> branch 8 (-11)
            14 -> branch 15 18
            18 -> next 7
            p | p >= 1 && p <= 17 -> next (fromIntegral p + 1)
            _ -> -1
        | otherwise = case lookup phase
            [(1,(40,2)),(5,(7,6)),(6,(7,9)),(11,(32,12)),(12,(15,13)),
             (13,(15,14)),(14,(15,17)),(19,(20,22)),(23,(26,24)),(26,(28,27)),
             (27,(28,30)),(30,(38,31)),(35,(65572,65829)),(41,(65572,42)),
             (42,(43,45)),(46,(65572,47))] of
            Just (no,yes) -> branch yes no
            Nothing -> maybe (-1) next (lookup phase
              [(2,3),(3,4),(4,5),(7,65544),(9,10),(10,11),(15,65552),
               (17,18),(18,19),(20,65557),(22,23),(24,25),(25,30),(28,65565),
               (31,11),(32,33),(33,34),(34,35),(38,65575),(40,41),(43,65580),
               (45,46),(47,48),(48,49),(49,35)])
  pure (actual === expected)

parentReplayCacheLoadTransitions :: Property
parentReplayCacheLoadTransitions = forAll ((,) <$> choose (0,27 :: Word32) <*> choose (0,4 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store 16 phase result
  let branch yes no = case result of 0 -> no; 1 -> yes; _ -> -1
      expected = case phase of
        0 -> 1
        1 -> branch 3 2
        2 -> branch 3 (-1)
        3 -> branch 4 (-1)
        4 -> branch (-10) 5
        5 -> branch (-10) 6
        6 -> case result of 0 -> 22; 1 -> 7; 2 -> 22; 3 -> 22; _ -> -1
        7 -> branch 8 (-1)
        8 -> branch 9 (-1)
        9 -> branch 10 18
        10 -> branch 11 12
        11 -> branch 21 12
        12 -> branch 13 16
        13 -> branch 21 14
        14 -> branch 21 15
        15 -> branch 21 16
        16 -> branch 17 18
        17 -> branch 21 18
        18 -> branch 19 (-1)
        19 -> branch 65812 (-1)
        21 -> branch 22 (-1)
        22 -> branch 65560 23
        23 -> branch 65560 (-10)
        _ -> -1
  pure (conjoin [actual === expected, Constants.replayDirectory === "parent-replay"])

bmmSignetTemplateBounds :: Property
bmmSignetTemplateBounds = forAll ((,) <$> elements [0,5,6,7,maxBound] <*> arbitrary) $ \(count,missing) -> ioProperty $
  withArray (replicate 8 (77 :: Word32)) $ \buffer -> do
    status <- elements_hs_bmm_signet_template count (if missing then nullPtr else buffer `plusPtr` 4)
    observed <- peekArray 8 buffer
    let valid = count == 6 && not missing
    pure (conjoin [status === if valid then 0 else -1,
      observed === if valid then [77,0,0,0,0,0,106,77] else replicate 8 77])

foreign import ccall unsafe reference_split_signature :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Int32

bmmSignatureBytesParity :: Property
bmmSignatureBytesParity = forAll ((,) <$> resize 100 arbitrary <*> elements [0,1,2,3 :: Int]) $ \(signature,mode) -> ioProperty $
  withArray signature $ \input -> withArray [777] $ \actualOut -> withArray [777] $ \expectedOut -> do
    let count = if mode == 3 then maxBound else fromIntegral (length signature)
        ptr = if mode == 1 then nullPtr else input
        actualPtr = if mode == 2 then nullPtr else actualOut
        expectedPtr = if mode == 2 then nullPtr else expectedOut
    actual <- elements_hs_bmm_split_signature count ptr actualPtr
    expected <- reference_split_signature count ptr expectedPtr
    prefix <- peekArray 1 actualOut
    reference <- peekArray 1 expectedOut
    unchanged <- peekArray (length signature) input
    pure (conjoin [actual === expected, prefix === reference, unchanged === signature])
foreign import ccall unsafe reference_private_template
  :: Word32 -> Word32 -> Word32 -> Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr Word8 -> IO ()

bmmPrivateTemplateParity :: Property
bmmPrivateTemplateParity = forAll gen $ \(height,time,median,slot,critical) -> ioProperty $
  withArray critical $ \hashPtr -> withArray (replicate 5 42) $ \fields ->
  withArray (replicate 38 77) $ \payload -> withArray (replicate 5 42) $ \expectedFields ->
  withArray (replicate 38 77) $ \expectedPayload -> do
    status <- elements_hs_bmm_private_template height time median slot hashPtr fields payload
    reference_private_template height time median slot hashPtr expectedFields expectedPayload
    actual <- (,) <$> peekArray 5 fields <*> peekArray 38 payload
    expected <- (,) <$> peekArray 5 expectedFields <*> peekArray 38 expectedPayload
    missing <- sequence [elements_hs_bmm_private_template height time median slot nullPtr fields payload,
      elements_hs_bmm_private_template height time median slot hashPtr nullPtr payload,
      elements_hs_bmm_private_template height time median slot hashPtr fields nullPtr]
    after <- (,) <$> peekArray 5 fields <*> peekArray 38 payload
    pure (conjoin [status === 0, actual === expected, missing === [-1,-1,-1], after === actual])
  where gen = (,,,,) <$> edge [0,1,maxBound] <*> edge [0,1,maxBound] <*>
          edge [0,1,maxBound] <*> edge [0,24,255,256,maxBound] <*> vectorOf 32 arbitrary
foreign import ccall "&reference_state_write" stateWriter :: FunPtr Bmm.WriteState
foreign import ccall unsafe reference_store_state :: Int32 -> Int32 -> Ptr () -> IO Int32
foreign import ccall unsafe reference_encode_state :: Ptr () -> IO Int32
foreign import ccall unsafe reference_preimage :: Word32 -> Ptr () -> IO Int32
foreign import ccall unsafe reference_signature_actions :: Word32 -> Ptr () -> IO Int32
foreign import ccall unsafe reference_signet_actions :: Word32 -> Ptr () -> IO Int32

foreign import ccall unsafe reference_commitment_bytes :: Word32 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
foreign import ccall unsafe reference_bmm_interval :: Int64 -> Int64 -> Ptr Int64 -> IO Int32
foreign import ccall unsafe reference_bmm_preset :: Word32 -> Ptr Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32

foreign import ccall unsafe reference_bmm_checkpoint :: Word32 -> Ptr Word32 -> Ptr Word8 -> IO Int32
foreign import ccall unsafe reference_bmm_identity :: Ptr Word32 -> Ptr Word8 -> IO Int32

bmmIdentityParity :: Property
bmmIdentityParity = forAll arbitrary $ \sentinel -> ioProperty $
  withArray (replicate 4 77) $ \fields -> withArray (replicate 4 77) $ \fieldsRef ->
  withArray (replicate 123 sentinel) $ \payload -> withArray (replicate 123 sentinel) $ \payloadRef -> do
    actual <- elements_hs_bmm_identity (fields `plusPtr` 4) (payload `plusPtr` 1)
    expected <- reference_bmm_identity (fieldsRef `plusPtr` 4) (payloadRef `plusPtr` 1)
    values <- peekArray 4 fields
    expectedValues <- peekArray 4 fieldsRef
    contents <- peekArray 123 payload
    expectedContents <- peekArray 123 payloadRef
    faults <- sequence [elements_hs_bmm_identity nullPtr payload, elements_hs_bmm_identity fields nullPtr]
    valuesAfter <- peekArray 4 fields
    contentsAfter <- peekArray 123 payload
    pure $ conjoin [actual === expected,values === expectedValues,contents === expectedContents,
                    faults === [-1,-1],valuesAfter === values,contentsAfter === contents]

bmmCheckpointParity :: Property
bmmCheckpointParity = forAll (elements [0,1,2,maxBound]) $ \mode -> ioProperty $
  withArray (replicate 18 77) $ \fields -> withArray (replicate 18 77) $ \fieldsRef ->
  withArray (replicate 34 77) $ \blockHash -> withArray (replicate 34 77) $ \hashRef -> do
    actual <- elements_hs_bmm_checkpoint mode (fields `plusPtr` 4) (blockHash `plusPtr` 1)
    expected <- reference_bmm_checkpoint mode (fieldsRef `plusPtr` 4) (hashRef `plusPtr` 1)
    values <- peekArray 18 fields
    expectedValues <- peekArray 18 fieldsRef
    hashBytes <- peekArray 34 blockHash
    expectedBytes <- peekArray 34 hashRef
    faults <- sequence [elements_hs_bmm_checkpoint mode nullPtr blockHash,
                        elements_hs_bmm_checkpoint mode fields nullPtr]
    valuesAfter <- peekArray 18 fields
    bytesAfter <- peekArray 34 blockHash
    pure $ conjoin [actual === expected,values === expectedValues,hashBytes === expectedBytes,
                    faults === [-1,-1],valuesAfter === values,bytesAfter === hashBytes]

bmmPresetParity :: Property
bmmPresetParity = forAll (elements [0,1,2,maxBound]) $ \mode -> ioProperty $
  withArray (replicate 8 77) $ \actualFields -> withArray (replicate 8 77) $ \expectedFields ->
  withArray (replicate 34 77) $ \actualHash -> withArray (replicate 34 77) $ \expectedHash ->
  withArray (replicate 24 77) $ \actualScript -> withArray (replicate 24 77) $ \expectedScript -> do
    actual <- elements_hs_bmm_preset mode (actualFields `plusPtr` 8) (actualHash `plusPtr` 1) (actualScript `plusPtr` 1)
    expected <- reference_bmm_preset mode (expectedFields `plusPtr` 8) (expectedHash `plusPtr` 1) (expectedScript `plusPtr` 1)
    fields <- peekArray 8 actualFields
    fieldsRef <- peekArray 8 expectedFields
    limit <- peekArray 34 actualHash
    limitRef <- peekArray 34 expectedHash
    script <- peekArray 24 actualScript
    scriptRef <- peekArray 24 expectedScript
    faults <- sequence [elements_hs_bmm_preset mode nullPtr actualHash actualScript,
                        elements_hs_bmm_preset mode actualFields nullPtr actualScript,
                        elements_hs_bmm_preset mode actualFields actualHash nullPtr]
    fieldsAfter <- peekArray 8 actualFields
    limitAfter <- peekArray 34 actualHash
    scriptAfter <- peekArray 24 actualScript
    pure (conjoin [actual === expected,fields === fieldsRef,limit === limitRef,script === scriptRef,
                  faults === replicate 3 (-1),fieldsAfter === fields,limitAfter === limit,scriptAfter === script])

bmmIntervalParity :: Property
bmmIntervalParity = forAll ((,) <$> edge [minBound,maxBound,-7,-1,0,1,7,1209600] <*> edge [minBound,maxBound,-3,-1,0,1,3,600]) $
  \(timespan,spacing) -> ioProperty $ withArray [77] $ \actualPtr -> withArray [77] $ \expectedPtr -> do
    actual <- elements_hs_bmm_interval timespan spacing actualPtr
    expected <- reference_bmm_interval timespan spacing expectedPtr
    observed <- peekArray 1 actualPtr
    reference <- peekArray 1 expectedPtr
    missing <- elements_hs_bmm_interval timespan spacing nullPtr
    pure (conjoin [actual === expected, observed === reference, missing === -1])

bmmCommitmentBytesParity :: Property
bmmCommitmentBytesParity = forAll generator $ \(kind,count,payload) -> ioProperty $
  withArray payload $ \input -> withArray (replicate 34 77) $ \actualPtr -> withArray (replicate 34 77) $ \expectedPtr -> do
    actual <- elements_hs_bmm_commitment_bytes kind count input (actualPtr `plusPtr` 1)
    expected <- reference_commitment_bytes kind count input (expectedPtr `plusPtr` 1)
    observed <- peekArray 34 actualPtr
    reference <- peekArray 34 expectedPtr
    unchanged <- peekArray 37 input
    missingInput <- elements_hs_bmm_commitment_bytes kind count nullPtr actualPtr
    missingOutput <- elements_hs_bmm_commitment_bytes kind count input nullPtr
    pure (conjoin [actual === expected, observed === reference, unchanged === payload,
                   missingInput === -1, missingOutput === -1])
  where generator = (,,) <$> elements [0,1,3,maxBound] <*> elements [0,31,32,33,36,37,38,maxBound] <*> vectorOf 37 arbitrary

parentCommitmentBytes :: Property
parentCommitmentBytes = forAll ((,,,) <$> elements [0..4 :: Int] <*> arbitrary <*> vectorOf 32 arbitrary <*> elements [0,5,36,37]) $ \(kind,slot,commitment,count) ->
  ioProperty $ do
    let tags = [[0xd6,0xe1,0xc5,0xdf],[0xd4,0x5a,0xa9,0x43],[0xd1,0x61,0x73,0x68],[0xd5,0xe0,0xc4,0xaf],[0,0,0,0]]
        payload = tags !! kind ++ [slot] ++ commitment
        wanted = if kind == 2 then reverse commitment else commitment
        valid = kind < 3 && count == 37
    withArray payload $ \input -> withArray (replicate 34 77) $ \output -> do
      code <- elements_hs_bmm_commitment_bytes 2 count input (output `plusPtr` 1)
      observed <- peekArray 34 output
      pure $ conjoin [code === if valid then 0 else -1,
        observed === if valid then [77] ++ wanted ++ [77] else replicate 34 77]

bmmSignetActionsParity :: Property
bmmSignetActionsParity = forAll ((,) <$> elements [0,1,2,maxBound] <*> choose (-1,6)) $ \(mode,fault) -> ioProperty $
  withArray [fault,0,0 :: Int64] $ \actualPtr -> withArray [fault,0,0] $ \expectedPtr -> do
    actual <- elements_hs_bmm_signet_actions mode stateWriter (castPtr actualPtr)
    expected <- reference_signet_actions mode (castPtr expectedPtr)
    observed <- peekArray 3 actualPtr
    reference <- peekArray 3 expectedPtr
    missing <- elements_hs_bmm_signet_actions mode nullFunPtr nullPtr
    pure (conjoin [actual === expected, observed === reference, missing === -1])

bmmSignatureActionsParity :: Property
bmmSignatureActionsParity = forAll ((,) <$> elements ([0..17] ++ [maxBound]) <*> choose (-1,4)) $ \(plan,fault) -> ioProperty $
  withArray [fault,0,0 :: Int64] $ \actualPtr -> withArray [fault,0,0] $ \expectedPtr -> do
    actual <- elements_hs_bmm_signature_actions plan stateWriter (castPtr actualPtr)
    expected <- reference_signature_actions plan (castPtr expectedPtr)
    observed <- peekArray 3 actualPtr
    reference <- peekArray 3 expectedPtr
    missing <- elements_hs_bmm_signature_actions plan nullFunPtr nullPtr
    pure $ conjoin [actual === expected, observed === reference, missing === (if plan == 0 then 1 else -1)]

bmmPreimageParity :: Property
bmmPreimageParity = forAll ((,) <$> elements [0,1,2,maxBound] <*> choose (-1,10)) $ \(kind,fault) -> ioProperty $
  withArray [fault,0,0 :: Int64] $ \actualPtr -> withArray [fault,0,0] $ \expectedPtr -> do
    actual <- elements_hs_bmm_preimage kind stateWriter (castPtr actualPtr)
    expected <- reference_preimage kind (castPtr expectedPtr)
    observed <- peekArray 3 actualPtr
    reference <- peekArray 3 expectedPtr
    missing <- elements_hs_bmm_preimage kind nullFunPtr nullPtr
    pure (conjoin [actual === expected, observed === reference, missing === -1])

bmmEncodingParity :: Property
bmmEncodingParity = forAll (elements [-1,0,1,2,3]) $ \fault -> ioProperty $
  withArray [fault,0,0 :: Int64] $ \actualPtr -> withArray [fault,0,0] $ \expectedPtr -> do
    actual <- elements_hs_bmm_encode_state stateWriter (castPtr actualPtr)
    expected <- reference_encode_state (castPtr expectedPtr)
    observed <- peekArray 3 actualPtr
    reference <- peekArray 3 expectedPtr
    missing <- elements_hs_bmm_encode_state nullFunPtr nullPtr
    pure (conjoin [actual === expected, observed === reference, missing === -1])

bmmStoreParity :: Property
bmmStoreParity = forAll ((,,) <$> edge [minBound,-1,0,1,maxBound] <*> elements [-1,0,1,2] <*> arbitrary) $
  \(height,fault,restore) -> ioProperty $
    withArray [fault,0,0 :: Int64] $ \actualPtr -> withArray [fault,0,0] $ \expectedPtr -> do
      let run = if restore then elements_hs_bmm_restore_state else elements_hs_bmm_store_state
      actual <- run height stateWriter (castPtr actualPtr)
      expected <- reference_store_state height (if restore then 1 else 0) (castPtr expectedPtr)
      observed <- peekArray 3 actualPtr
      reference <- peekArray 3 expectedPtr
      missing <- run height nullFunPtr nullPtr
      pure (conjoin [actual === expected, observed === reference, missing === -1])
foreign import ccall unsafe reference_bmm_scale_target :: Word32 -> Word64 -> Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32

bmmScaleParity :: Property
bmmScaleParity = forAll gen $ \(count,factor,divisor,target,limit) -> ioProperty $
  withArray (77 : target ++ [88]) $ \buffer -> withArray target $ \expectedPtr -> withArray limit $ \bound -> do
    let actualPtr = buffer `plusPtr` 1
    actual <- elements_hs_bmm_scale_target count factor divisor actualPtr bound
    expected <- reference_bmm_scale_target count factor divisor expectedPtr bound
    result <- peekArray 34 buffer
    reference <- peekArray 32 expectedPtr
    unchangedBound <- peekArray 32 bound
    missingTarget <- elements_hs_bmm_scale_target count factor divisor nullPtr bound
    missingLimit <- elements_hs_bmm_scale_target count factor divisor actualPtr nullPtr
    pure (conjoin [actual === expected, result === (77 : reference ++ [88]),
      unchangedBound === limit, missingTarget === -1, missingLimit === -1])
  where
    gen :: Gen (Word32, Word64, Word64, [Word8], [Word8])
    gen = (,,,,) <$> elements [0,31,32,32,32,33,maxBound] <*>
      edge [0,1,0xffffffff,0x100000000,0x100000001,maxBound] <*>
      edge [0,1,2,1209600,0x100000000,0x8000000000000000,maxBound] <*>
      vectorOf 32 arbitrary <*> vectorOf 32 arbitrary
foreign import ccall "&reference_fingerprint_read" fingerprintReader :: FunPtr Bmm.ReadFingerprint
foreign import ccall "&reference_fingerprint_write" fingerprintWriter :: FunPtr WriteFingerprint
foreign import ccall unsafe reference_fingerprint :: Ptr () -> IO Int32

bmmFingerprintParity :: Property
bmmFingerprintParity = forAll gen $ \(seed,mode,fault,writeFault) -> ioProperty $ do
  let fields = [seed,mode,fault,writeFault] ++ replicate 1020 0
  withArray fields $ \actualPtr -> withArray fields $ \expectedPtr -> do
    actual <- elements_hs_bmm_fingerprint 0 fingerprintReader fingerprintWriter (castPtr actualPtr)
    expected <- reference_fingerprint (castPtr expectedPtr)
    actualBytes <- peekArray 1024 actualPtr
    expectedBytes <- peekArray 1024 expectedPtr
    noReader <- elements_hs_bmm_fingerprint 0 nullFunPtr fingerprintWriter (castPtr actualPtr)
    noWriter <- elements_hs_bmm_fingerprint 0 fingerprintReader nullFunPtr (castPtr actualPtr)
    badProfile <- elements_hs_bmm_fingerprint 3 fingerprintReader fingerprintWriter (castPtr actualPtr)
    pure (conjoin [actual === expected, actualBytes === expectedBytes, noReader === -1, noWriter === -1, badProfile === -1])
  where
    gen :: Gen (Word64, Word64, Word64, Word64)
    gen = (,,,) <$> arbitrary <*> elements [0,1,2,maxBound] <*>
      frequency [(4,pure 0),(1,choose (1,180))] <*> elements [0,1]
data PoisonedFingerprint = PoisonedFingerprint
instance Bmm.FingerprintSource PoisonedFingerprint where
  fingerprintNumber _ _ _ = pure 0
  fingerprintBytes _ _ = pure [error "unevaluated fingerprint byte"]

fingerprintFinalization :: Property
fingerprintFinalization = once $ ioProperty $ do
  outcomes <- sequence [try (Bmm.encodeFingerprint format PoisonedFingerprint)
    :: IO (Either SomeException [Word8]) | format <- [Bmm.BmmFormat]]
  pure (property (all isLeft outcomes))

foreign import ccall unsafe reference_signet_validation :: Ptr Word64 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_sighash_plan :: Int32 -> Word32 -> Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_signature_gate :: Word32 -> Word64 -> Word32 -> Word64 -> IO Int32
foreign import ccall "&reference_signet_step" signetStep :: FunPtr Deposit.ReadPegFields
foreign import ccall "&reference_signet_fail_write" signetFailWrite :: FunPtr Deposit.ReadPegFields
foreign import ccall unsafe reference_signet_extract :: Ptr () -> IO Int32
foreign import ccall unsafe reference_bmm_retarget :: Word32 -> Int64 -> Int64 -> Word32 -> Word32 -> IO Int64
foreign import ccall unsafe reference_bmm_median :: Word32 -> Ptr Word32 -> IO Int64
foreign import ccall unsafe reference_bmm_activation :: Word32 -> Word32 -> Int64 -> Int64 -> IO Int32
foreign import ccall "&reference_bmm_script" bmmFields :: FunPtr Bmm.ReadScript
foreign import ccall unsafe reference_bmm_commitment :: Word32 -> Int32 -> Word32 -> Ptr () -> IO Int64
foreign import ccall unsafe reference_bmm_state :: Word32 -> Int64 -> Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> Word64 -> Word32 -> IO Int32
foreign import ccall unsafe reference_bmm_header :: Word32 -> IO Int32
foreign import ccall unsafe reference_bmm_state_flow :: Word32 -> Ptr Int32 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_private_build :: Word32 -> Word32 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_lifecycle :: Word32 -> Word32 -> IO Int32
foreign import ccall unsafe reference_bmm_state_source :: Word32 -> Word32 -> IO Int32
foreign import ccall unsafe reference_bmm_wrapper :: Word32 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_advance :: Int64 -> Word32 -> Word32 -> Ptr Word32 -> IO Int32
foreign import ccall unsafe reference_bmm_traversal :: Word64 -> Word64 -> Word64 -> Word32 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_codec :: Word32 -> Word32 -> Word64 -> Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_proof :: Word32 -> Word32 -> Word64 -> Word64 -> Word64 -> IO Int32
foreign import ccall unsafe reference_peg_event :: Word32 -> Int64 -> Int64 -> Int64 -> IO Int64
foreign import ccall unsafe reference_deposit_state :: Word32 -> Word32 -> IO Int32
foreign import ccall "&reference_live_fields" referenceLive :: FunPtr Deposit.ReadPegFields
foreign import ccall "wrapper" wrapPegFields :: Deposit.ReadPegFields -> IO (FunPtr Deposit.ReadPegFields)
foreign import ccall "&reference_scripted_fields" referenceScripted :: FunPtr Deposit.ReadPegFields
foreign import ccall unsafe reference_live_evidence :: Word32 -> FunPtr Deposit.ReadPegFields -> Ptr () -> IO Int32
foreign import ccall unsafe reference_legacy_claim :: Word32 -> Int64 -> Int64 -> IO Int32
foreign import ccall "&reference_destination_inspect" referenceDestination :: FunPtr Deposit.InspectDestination
foreign import ccall "&reference_destination_inspect_v2" referenceDestinationV2 :: FunPtr Deposit.InspectDestination
foreign import ccall unsafe reference_deposit_destination :: Word32 -> FunPtr Deposit.InspectDestination -> Ptr () -> IO Int64
foreign import ccall unsafe reference_slot :: Word32 -> Word32 -> IO Int32
foreign import ccall unsafe reference_payout :: Int64 -> Int64 -> Int64 -> IO Int64
foreign import ccall unsafe reference_legacy_frame :: Ptr Word8 -> Word32 -> IO Int32
foreign import ccall "&reference_transaction_hash" referenceHasher :: FunPtr HashTransaction
foreign import ccall unsafe reference_deposit_witness :: Int64 -> Word32 -> Word32 -> Word32
  -> Ptr Word32 -> Ptr (Ptr Word8) -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
  -> FunPtr HashTransaction -> Ptr Int64 -> IO Int32
foreign import ccall unsafe reference_deposit_outputs :: Word32 -> Int64 -> Word32 -> Ptr Word8
  -> Word32 -> Ptr Word8 -> Ptr Int64 -> IO Int32
foreign import ccall unsafe reference_authenticated_deposit :: Word64 -> Word64 -> Word64 -> Word32
  -> Int64 -> Int64 -> Word64 -> Ptr Word8 -> Ptr Int64 -> IO Int32
foreign import ccall "&reference_evidence_decode" referenceDecoder :: FunPtr Deposit.DecodeEvidence
foreign import ccall unsafe reference_deposit_evidence :: Word32 -> Word32 -> Ptr Word32 -> Ptr (Ptr Word8)
  -> Ptr Word8 -> FunPtr HashTransaction -> FunPtr Deposit.DecodeEvidence -> Ptr () -> IO Int32
foreign import ccall "&reference_parent_header" referenceHeader :: FunPtr Deposit.CheckParentHeader
foreign import ccall unsafe reference_deposit_inclusion :: Word32 -> Word64 -> Word32
  -> FunPtr Deposit.CheckParentHeader -> Ptr () -> IO Int32
foreign import ccall unsafe reference_deposit_ctip :: Word32 -> Word64 -> Int64 -> Int64 -> Int64 -> IO Int32
foreign import ccall "&reference_ctip_decode" referenceCtipDecoder :: FunPtr Deposit.DecodeCtip
foreign import ccall unsafe reference_persisted_ctip :: Word32 -> Int64 -> Word32
  -> FunPtr Deposit.DecodeCtip -> Ptr () -> IO Int32

edge :: (Bounded a, Integral a) => [a] -> Gen a
edge xs = frequency [(1, elements (minBound : maxBound : xs)), (3, chooseBoundedIntegral (minBound,maxBound))]

same :: (Eq a, Show a) => IO a -> IO a -> Property
same actual expected = ioProperty $ (===) <$> actual <*> expected

depthParity :: Property
depthParity = forAllShrink ((,,) <$> g <*> g <*> g) shrink $ \(d,t,n) ->
  same (elements_hs_deposit_depth d t n) (reference_depth d t n)
  where g = edge [0,1,5,6,100,1000,1005]

treasuryMatchParity :: Property
treasuryMatchParity = forAll gen $ \(expected,opcode,script) -> ioProperty $ do
  decoded <- if B.length script==4 then reference_slot (fromIntegral (Withdrawal.readLE script)) opcode else pure (-1)
  let validExpected=expected>=0 && expected<=255
      wanted=validExpected && decoded==expected
  actual <- B.useAsCStringLen script $ \(input,size) ->
    elements_hs_treasury_match expected opcode (fromIntegral size) (castPtr input)
  calls <- newIORef (0::Int)
  result <- validate (TreasuryMatch expected (modifyIORef' calls (+1) >> pure decoded))
  count <- readIORef calls
  lazyResult <- if validExpected then pure False else
    validate (TreasuryMatch expected (error "invalid expected slot forced script read"))
  missing <- elements_hs_treasury_match expected opcode 4 nullPtr
  oversized <- elements_hs_treasury_match expected opcode maxBound nullPtr
  pure $ conjoin [actual===(if wanted then 1 else 0),result===wanted,
    count===(if validExpected then 1 else 0),lazyResult===False,missing===0,oversized===0]
  where gen = do
          opcode <- frequency [(3,elements [0xb4,0xb7]),(1,arbitrary)]
          slot <- choose (0,255)
          expected <- frequency [(2,pure slot),(1,elements [minBound,-1,0,24,255,256,maxBound]),(1,arbitrary)]
          script <- frequency [(3,pure (B.pack [fromIntegral opcode,1,fromIntegral slot,0x51])),
            (1,B.pack <$> resize 8 arbitrary)]
          pure (expected,opcode,script)

treasuryParity :: Property
treasuryParity = forAllShrink gen shrink $ \(script,op) ->
  same (elements_hs_treasury_slot script op) (reference_slot script op)
  where gen = do
          op <- frequency [(2, elements [0xb4,0xb7]), (1, choose (0,255))]
          slot <- choose (0,255)
          bit <- choose (0,31)
          let valid = 0x51000100 .|. (slot `shiftL` 16) .|. op
          script <- oneof [pure valid, pure (valid `xor` (1 `shiftL` bit)), chooseBoundedIntegral (minBound,maxBound)]
          pure (script,op)

money :: Int64
money = 21000000 * 100000000

amounts :: Gen (Int64, Int64)
amounts = (,) <$> amount <*> amount
  where amount = frequency [(1, edge [minBound,-1,0,1,money-1,money,money+1,maxBound]), (2, choose (0,money))]

payoutParity :: Property
payoutParity = forAllShrink ((,) <$> amounts <*> edge [minBound,-1,0,1,money,maxBound]) shrink $ \((burn,fee),limit) ->
  ioProperty $ do
    actual <- elements_hs_withdrawal_payout burn fee limit
    expected <- reference_payout burn fee limit
    pure (conjoin [actual === expected, validate (Withdrawal.WithdrawalPayout burn fee limit) === expected])

conservation :: Property
conservation = forAllShrink amounts shrink $ \(burn,fee) -> ioProperty $ do
  payout <- elements_hs_withdrawal_payout burn fee money
  pure $ if payout > 0 then conjoin [property (fee >= 0), property (payout <= money),
                                    toInteger payout + toInteger fee === toInteger burn]
                      else property (payout >= -3 && payout <= -1)

sixConfirmations :: Property
sixConfirmations = forAllShrink (choose (0,maxBound-6)) shrink $ \deposit -> ioProperty $ do
  below <- elements_hs_deposit_depth deposit (deposit+4) 6
  exact <- elements_hs_deposit_depth deposit (deposit+5) 6
  above <- elements_hs_deposit_depth deposit (deposit+6) 6
  pure $ (below,exact,above) === (0,1,1)

bytes :: Int -> Gen B.ByteString
bytes n = B.pack <$> vectorOf n arbitrary

hash :: Gen B.ByteString
hash = B.cons 1 <$> bytes 31

scriptCase :: Gen (B.ByteString, B.ByteString, Word64)
scriptCase = (,,) <$> hash <*> (choose (1,128) >>= bytes) <*> choose (0,fromIntegral money)

shrinkScriptCase :: (B.ByteString, B.ByteString, Word64) -> [(B.ByteString, B.ByteString, Word64)]
shrinkScriptCase (genesis,dest,value) =
  [(genesis,B.pack d,v) | (d,v) <- shrink (B.unpack dest,value), not (null d)]

scriptRoundTrip :: Property
scriptRoundTrip = forAllShrink scriptCase shrinkScriptCase $ \(genesis,dest,value) ->
  let built = withdrawal 1 money (genesis <> wordLE 8 value <> dest)
      parsed = built >>= withdrawal 2 money . (genesis <>)
  in parsed === Right (wordLE 8 value <> dest)

scriptMutations :: Property
scriptMutations = forAllShrink scriptCase shrinkScriptCase $ \(genesis,dest,value) ->
  case withdrawal 1 money (genesis <> wordLE 8 value <> dest) of
    Left message -> counterexample message False
    Right script -> conjoin $ map (property . isLeft . withdrawal 2 money . (genesis <>)) $
      -- Replace canonical genesis push by every nonminimal push width.
      [B.pack [106,76,32] <> B.drop 2 script,
       B.pack [106,77,32,0] <> B.drop 2 script,
       B.pack [106,78,32,0,0,0] <> B.drop 2 script,
       script <> B.singleton 0, B.init script, B.tail script]

referenceRoundTrip :: Property
referenceRoundTrip = forAll ((,,,) <$> hash <*> arbitrary <*> hash <*> choose (0,0xfffffffe :: Word32)) $
  \(genesis,slot,txid,vout) ->
    let context = genesis <> B.singleton slot <> txid <> wordBE 4 (fromIntegral vout)
        built = withdrawal 3 money context
        parsed = built >>= withdrawal 4 money . (B.pack [106,74] <>)
    in conjoin [built === Right (B.pack [69,76,87,68,1] <> context), parsed === Right context]

legacyFrameParity :: Property
legacyFrameParity = forAllShrink gen (map B.pack . shrink . B.unpack) $ \input -> ioProperty $
  B.useAsCStringLen input $ \(ptr,size) -> do
    expected <- reference_legacy_frame (castPtr ptr) (fromIntegral size)
    pure (isRight (withdrawal 5 money input) === (expected == 1))
  where
    output n = (<>) <$> bytes 8 <*> ((B.singleton (fromIntegral n) <>) <$> bytes n)
    frame = B.concat <$> sequence [bytes 4, pure (B.pack [0,3]), output 10, output 76,
                                  choose (1,128) >>= output, bytes 4]
    gen = oneof [choose (0,300) >>= bytes, frame, do
      valid <- frame
      position <- choose (0,B.length valid-1)
      mutation <- arbitrary
      pure (B.take position valid <> B.singleton mutation <> B.drop (position+1) valid)]

feeBounds :: Property
feeBounds = forAll (edge [0,1,fromIntegral money,fromIntegral money+1]) $ \value ->
  let input = wordBE 8 value
      result = withdrawal 6 money input
  in if value <= fromIntegral money then result === Right (wordLE 8 value)
     else property (isLeft result)

walletBundleAdmission :: Property
walletBundleAdmission = forAll (vectorOf 32 arbitrary) $ \value ->
  let hashes = [B.replicate 32 0, B.pack value, B.replicate 32 255]
  in conjoin ([withdrawal 20 money (B.singleton busy <> current <> requested) ===
        (if busy > 1 then Left "invalid withdrawal reservation flag"
         else Right (B.pack [if busy == 0 && current == B.replicate 32 0 then 1 else 0,
                             if current == requested then 1 else 0]))
      | busy <- [0,1,2,255], current <- hashes, requested <- hashes] ++
      [ioProperty $ B.useAsCStringLen (B.replicate size 0) $ \(ptr,len) -> allocaBytes 256 $ \output -> do
        result <- elements_hs_withdrawal_bytes 20 money (castPtr ptr) (fromIntegral len) output 256
        pure (result === -1) | size <- [0,1,64,66]])

grpcConfigTransitions :: Property
grpcConfigTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 144 phase result
    let expected
          | phase==maxBound = if result==0 then 21 else -1
          | phase==0 = 1
          | phase==5 = if result>7 then -1 else if result==7 then 7 else 6
          | result>1 = -1
          | phase `elem` [2,4..16] = if result==1 then -10 else -1
          | otherwise = case lookup (fromIntegral phase :: Int) ([(9,(11,20)),(11,(13,21)),(20,(10,11)),(21,(12,13))] ++ [(n,(n+1,n+2)) | n <- [1,3..15]] ++ [(17,(-10,18)),(18,(-10,19)),(19,(-10,-11))]) of
              Just (no,yes) -> if result==0 then no else yes
              _ -> -1
    pure (actual===fromIntegral expected) | phase <- [0..22]++[maxBound], result <- [0..8]++[maxBound]]
  pure (conjoin checks)

grpcEndpointAdmission :: Property
grpcEndpointAdmission = forAll (choose (0,7) :: Gen Word32) $ \hostFlags ->
  forAll arbitrary $ \(hasPeg,pegMatches,hasWallet,walletMatches) -> ioProperty $ do
    calls <- newIORef []
    let prefix = [1,3,5]
        peg = [7,9] ++ [20 | hasPeg]
        wallet = [11] ++ [21 | hasWallet]
        (expected,planned)
          | hostFlags/=7 = (0,prefix++[6])
          | hasPeg && not pegMatches = (0,prefix++peg++[10])
          | hasWallet && not walletMatches = (0,prefix++peg++wallet++[12])
          | otherwise = (1,prefix++peg++wallet++[13,15,17,18,19])
        fact step = do
          modifyIORef' calls (++[step])
          pure $ case step of
            5 -> fromIntegral hostFlags
            9 -> if hasPeg then 1 else 0
            20 -> if pegMatches then 1 else 0
            11 -> if hasWallet then 1 else 0
            21 -> if walletMatches then 1 else 0
            _ -> 1
    actual <- bracket (wrapMatchFact (\_ -> fact)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run 144 callback nullPtr
    observed <- readIORef calls
    pure (conjoin [actual===expected,observed===planned])

grpcRequestTransitions :: Property
grpcRequestTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 145 phase result
    let expected
          | phase==maxBound = if result==0 then 10 else -1
          | phase==0 = 1
          | otherwise = case lookup phase [(1,(2,3)),(2,(-1,-10)),(3,(4,5)),(4,(-1,-10)),(5,(6,7)),(6,(-1,-10)),(7,(9,8)),(8,(9,10)),(9,(-1,-10)),(10,(-1,-11))] of
              Just (no,yes) | result==0 -> no
                            | result==1 -> yes
              _ -> -1
    pure (actual===expected) | phase <- [0..11]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

grpcRequestAdmission :: Property
grpcRequestAdmission = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 197 phase result
    old <- elements_hs_parent_replay_store_checked 145 phase result
    let expected
          | phase==maxBound = if result==0 then 12 else -1
          | phase==0 = 11
          | phase==11 = if result<=128 then 1 else 2
          | phase==1 && result==1 = 12
          | phase==12 = if result>0 && result<=1048576 then 5 else 4
          | otherwise = old
    pure (actual===expected) | phase <- [0..13]++[maxBound],
      result <- [0,1,2,127,128,129,1048575,1048576,1048577,maxBound]]
  pure (conjoin checks)

grpcExecutableTransitions :: Property
grpcExecutableTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 146 phase result
    let expected
          | phase==maxBound = if result==0 then 7 else -1
          | phase==0 = 1
          | result>1 = -1
          | phase==1 = if result==0 then 2 else 3
          | phase==3 = if result==0 then 4 else 5
          | phase==5 = if result==0 then -10 else 6
          | phase==6 = if result==0 then 7 else -11
          | phase `elem` [2,4,7] && result==1 = -10
          | otherwise = -1
    pure (actual===expected) | phase <- [0..8]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

rpcServerTransitions :: Property
rpcServerTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 147 phase result
    let expected
          | phase==maxBound = if result==0 then 10 else -1
          | phase==0 = 1
          | phase==7 = if result>3 then -1 else if result==3 then 10 else 8
          | otherwise = case lookup phase [(1,(3,2)),(2,(-1,-10)),(3,(4,5)),(4,(-1,-10)),(5,(-1,6)),(6,(-11,7)),(8,(-1,-10)),(9,(-1,6)),(10,(8,9))] of
              Just (no,yes) | result==0 -> no
                            | result==1 -> yes
              _ -> -1
    pure (actual===expected) | phase <- [0..11]++[maxBound], result <- [0..4]++[maxBound]]
  pure (conjoin checks)

rpcBindAdmission :: Property
rpcBindAdmission = forAll (resize 12 (listOf ((,) <$> choose (0,3 :: Word32) <*> arbitrary))) $ \bindings -> ioProperty $ do
  calls <- newIORef []
  index <- newIORef (0 :: Int)
  let plan [] = (1,[6])
      plan ((flags,allowed):rest)
        | flags/=3 = (0,[6,7,8])
        | not allowed = (0,[6,7,10,8])
        | otherwise = let (result,remaining) = plan rest in (result,[6,7,10,9]++remaining)
      (expected,steps) = plan bindings
      fact step = do
        modifyIORef' calls (++[step])
        i <- readIORef index
        case step of
          1 -> pure 0
          6 -> pure (if i<length bindings then 1 else 0)
          7 -> pure (fromIntegral (fst (bindings !! i)))
          10 -> pure (if snd (bindings !! i) then 1 else 0)
          9 -> modifyIORef' index (+1) >> pure 1
          _ -> pure 1
  actual <- bracket (wrapMatchFact (\_ -> fact)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 147 callback nullPtr
  observed <- readIORef calls
  pure (conjoin [actual===expected,observed===([1,3,5]++steps)])

tlsCredentialTransitions :: Property
tlsCredentialTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 148 phase result
    let expected
          | phase==maxBound = if result==0 then 14 else -1
          | phase==0 = 1
          | phase==1 = case result of 0 -> 2; 1 -> 3; 2 -> 13; _ -> -1
          | result>1 = -1
          | phase `elem` [2,4..14] = if result==1 then -10 else -1
          | phase `elem` [3,5,7,9] = fromIntegral phase + if result==1 then 2 else 1
          | phase==11 || phase==13 = if result==1 then -11 else fromIntegral phase+1
          | otherwise = -1
    pure (actual===expected) | phase <- [0..15]++[maxBound], result <- [0,1,2,32,maxBound]]
  pure (conjoin checks)

grpcArgumentPlan :: Property
grpcArgumentPlan = forAll (B.pack <$> listOf1 arbitrary) $ \payload ->
  let method = C.pack "cusf.mainchain.v1.ValidatorService/GetChainTip"
  in interpret (SomeOperation (Bmm.GrpcPlan method payload)) Bmm.planGrpc === Just (Right ())

grpcArgumentRejections :: Property
grpcArgumentRejections = once $ conjoin
  [ case interpret (SomeOperation (Bmm.GrpcPlan (C.pack method) payload)) Bmm.planGrpc of
      Just (Left message) -> message === expected
      _ -> counterexample "invalid gRPC plan accepted" False
  | (method,payload,expected) <-
      [("invalid",B.empty,"refusing an unrecognized enforcer gRPC method"),
       ("cusf.mainchain.v1.ValidatorService/GetChainTip",B.empty,"enforcer gRPC payload must contain 1..1048576 bytes"),
       ("cusf.mainchain.v1.ValidatorService/GetChainTip",B.replicate 1048577 0,"enforcer gRPC payload must contain 1..1048576 bytes")]]

grpcTextAdmission :: Property
grpcTextAdmission = forAll ((,) <$> textBytes <*> textBytes) $ \(address,authority) -> ioProperty $ do
  let clean value = all (\byte -> byte>32 && byte/=127) (B.unpack value)
      flag bit accepted = if accepted then bit else 0
      expected = flag 1 (not (B.null address) && not ([58,47,47] `List.isInfixOf` B.unpack address)) +
        flag 2 (B.length address<=512 && clean address) + flag 4 (clean authority)
  actual <- B.useAsCStringLen address $ \(a,n) -> B.useAsCStringLen authority $ \(b,m) ->
    elements_hs_grpc_text (fromIntegral n) (castPtr a) (fromIntegral m) (castPtr b)
  pure $ conjoin [validate (Bmm.GrpcTextAdmission address authority) === expected,actual === expected]
  where textBytes = frequency [(2,elements (map C.pack ["","http://127.0.0.1","127.0.0.1:55051","[::1]:55051"])),
          (3,do size <- elements [0,1,511,512,513,1024]
                B.pack <$> vectorOf size (frequency [(1,arbitrary),(3,choose (33,126))]))]

grpcTextBounds :: Property
grpcTextBounds = once $ ioProperty $ do
  empty <- elements_hs_grpc_text 0 nullPtr 0 nullPtr
  invalid <- sequence [elements_hs_grpc_text 1 nullPtr 0 nullPtr,
    elements_hs_grpc_text 0 nullPtr 1 nullPtr,
    elements_hs_grpc_text maxBound nullPtr 0 nullPtr,
    elements_hs_grpc_text 0 nullPtr maxBound nullPtr]
  pure $ conjoin [empty === 6,invalid === replicate 4 (-1)]

grpcPlanFfiBounds :: Property
grpcPlanFfiBounds = once $ ioProperty $ allocaBytes 128 $ \out -> do
  pokeArray out (replicate 128 (0xaa :: Word8))
  invalid <- elements_hs_grpc_plan 3 nullPtr nullPtr out 128
  missing <- elements_hs_grpc_plan 2 nullPtr nullPtr out 128
  let method = C.pack "cusf.mainchain.v1.ValidatorService/GetCtip"
  short <- B.useAsCString method $ \ptr -> withArray [castPtr ptr,nullPtr] $ \inputs ->
    withArray [fromIntegral (B.length method),0] $ \sizes -> elements_hs_grpc_plan 2 inputs sizes out 1
  after <- peekArray 128 out
  pure $ conjoin [invalid===(-1),missing===(-1),short===(-1),after===replicate 128 0xaa]

nativeWithdrawalSubmissionOrder :: Property
nativeWithdrawalSubmissionOrder = forAll ((,) <$> arbitrary <*> choose (-1,8 :: Int)) $ \((present,transaction,detailed),fault) -> ioProperty $ do
  let flag value = if value then 1 else 0
      script = [(1,1),(2,1),(3,flag present)] ++ if not present then [(5,-1)]
        else [(4,flag transaction)] ++ if not transaction then [(5,-1)]
        else [(6,1),(7,flag detailed)] ++ [(8,1) | detailed]
      expected = if not (present && transaction) then -1 else flag detailed
  commandTrace 270 8 (\phase reply -> validate (Withdrawal.NativeSubmissionFlow phase reply)) script fault expected

withdrawalPreflightOrder :: Property
withdrawalPreflightOrder = forAll ((,) <$> vectorOf 8 arbitrary <*> choose (-1,11 :: Int)) $ \(flags,fault) -> ioProperty $ do
  let facts = zip [1,9,10,4,6,7,11,12] flags
      walk [] = []
      walk ((step,yes):rest) = (step,if yes then 1 else 0) :
        if not yes then [(if step `elem` [1,9,10] then 2 else if step `elem` [4,6] then 5 else 8,-1)]
        else [(3,1) | step==10] ++ walk rest
  commandTrace 143 12 (\phase reply -> validate (Withdrawal.PreflightFlow phase reply))
    (walk facts) fault (if and flags then 1 else -1)

withdrawalPreflightTransitions :: Property
withdrawalPreflightTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 143 phase result
    let expected
          | phase==maxBound = if result==0 then 12 else -1
          | phase==0 = 1
          | otherwise = case lookup phase [(1,(2,9)),(9,(2,10)),(10,(2,3)),(3,(-1,4)),(4,(5,6)),
                                          (6,(5,7)),(7,(8,11)),(11,(8,12)),(12,(8,-11))] of
              Just (no,yes) | result==0 -> no
                            | result==1 -> yes
              _ -> -1
    pure (actual===expected) | phase <- [0..13]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

defaultWalletTransitions :: Property
defaultWalletTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 142 phase result
    let expected
          | phase==maxBound = if result==0 then 5 else -1
          | phase==0 = 1
          | result>1 = -1
          | phase==1 = if result==1 then -11 else 2
          | phase==2 = if result==1 then 4 else 3
          | phase==4 = if result==1 then -11 else 5
          | otherwise = -1
    pure (actual===expected) | phase <- [0..6]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

depositPreflightBounds :: Property
depositPreflightBounds = forAll ((,,) <$> elements ([0..12]++[maxBound]) <*> arbitrary <*> arbitrary) $ \(rule,amount,bound) -> ioProperty $ do
  actual <- elements_hs_deposit_preflight rule amount bound
  let expected = case rule of
        0 -> fromEnum (amount>0 && amount<=bound)
        1 -> fromEnum (amount>=0 && amount<=bound)
        2 -> fromEnum (amount>0)
        3 -> fromEnum (amount>=0 && amount<bound)
        4 -> fromEnum (amount>=0 && toInteger amount<=4294967295)
        5 -> fromEnum (amount==1)
        6 -> fromEnum (amount==1 && bound==1)
        7 -> fromEnum (amount==1 && bound==1)
        8 -> fromEnum (amount==1 && bound==1)
        9 -> fromEnum (amount==1)
        10 -> fromEnum (amount==0)
        11 -> fromEnum (amount<=bound)
        _ -> -1
  pure (actual===fromIntegral expected)

depositNativeImportTransitions :: Property
depositNativeImportTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 141 phase result
    let expected
          | phase==maxBound = if result==0 then 6 else -1
          | phase==0 = 1
          | otherwise = case lookup phase [(1,(2,3)),(3,(-1,4)),(4,(6,5)),(5,(-1,6)),(6,(-1,-11))] of
              Just (no,yes) | result==0 -> no
                            | result==1 -> yes
              _ -> -1
    pure (actual===expected) | phase <- [0..7]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

depositImportTransitions :: Property
depositImportTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 140 phase result
    let expected
          | phase==maxBound = if result==0 then 10 else -1
          | phase==0 = 1
          | otherwise = case lookup phase [(1,(-1,2)),(2,(4,3)),(3,(-1,4)),
                          (4,(-1,5)),(5,(6,7)),(7,(8,9)),(9,(-1,10)),(10,(-1,-11))] of
              Just (no,yes) | result==0 -> no
                            | result==1 -> yes
              _ -> -1
    pure (actual===expected) | phase <- [0..11]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

depositSponsorshipTransitions :: Property
depositSponsorshipTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 139 phase result
    let expected
          | phase==maxBound = if result==0 then 11 else -1
          | phase==0 = 1
          | otherwise = case lookup phase [(1,(2,3)),(3,(4,5)),(5,(-1,6)),
                                            (6,(10,7)),(7,(9,8)),(9,(-1,6)),(10,(11,-11))] of
              Just (no,yes) | result==0 -> no
                            | result==1 -> yes
              _ -> -1
    pure (actual===expected) | phase <- [0..12]++[maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

depositSatoshiTransitions :: Property
depositSatoshiTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 138 phase result
    let expected
          | phase == maxBound = if result == 0 then 7 else -1
          | phase == 0 = 6
          | phase == 2 = if result == 1 then -11 else -1
          | Just (yes,no) <- lookup phase [(1,(2,3)),(3,(4,5)),(4,(-11,5)),(6,(7,1)),(7,(-11,1))] =
              if result == 1 then yes else if result == 0 then no else -1
          | otherwise = -1
    pure (counterexample (show (phase,result)) (actual === expected)) | phase <- [0..8] ++ [maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

depositBroadcastTransitions :: Property
depositBroadcastTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 137 phase result
    let expected
          | phase == maxBound = if result == 0 then 5 else -1
          | phase == 0 = 1
          | Just (yes,no) <- lookup phase [(1,(-11,2)),(2,(-12,3)),(3,(-11,4)),(4,(-11,5))] =
              if result == 1 then yes else if result == 0 then no else -1
          | otherwise = -1
    pure (counterexample (show (phase,result)) (actual === expected)) | phase <- [0..6] ++ [maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

walletNativeGuards :: Property
walletNativeGuards = once $ conjoin
  ([conjoin [withdrawal 23 money (B.pack [tag,flag]) ===
     (if flag == (if tag==2 then 0 else 1) then Right B.empty else Left message)
     , withdrawal 24 money (B.pack [tag,flag]) === Right
         (if flag == (if tag==2 then 0 else 1) then wordLE 4 0
          else wordLE 4 (fromIntegral (if tag==4 then -1 else if tag<2 then -32601 else -8 :: Int32)) <> C.pack message)]
     | (tag,message) <- zip [0..]
         ["Native BIP300 withdrawals are not enabled on this network",
          "Native BIP300 withdrawals are disabled on this drivechain: full M3/M4/M6 withdrawal-vote and CTIP-decrease consensus validation is not implemented",
          "subtractfeefromamount is not supported for native BIP300 withdrawals; the Elements fee must remain separate from the exact burn",
          "The resulting irreversible burn is not relayable under this Elements network's standard policy",
          "sendtomainchain is unavailable outside an Elements parent-chain configuration"], flag <- [0,1]] ++
   [ioProperty $ B.useAsCStringLen input $ \(ptr,len) -> allocaBytes 256 $ \output -> do
      result <- elements_hs_withdrawal_bytes op money (castPtr ptr) (fromIntegral len) output 256
      pure (result === -1) | op <- [23,24], input <- map B.pack [[],[0],[0,0,0],[5,1],[255,1],[0,2],[3,255]]])

walletParentDust :: Property
walletParentDust = forAll (arbitrary :: Gen Word32) $ \size ->
  conjoin ([withdrawal 22 money (wordLE 4 (fromIntegral size) <> B.singleton witnessFlag) ===
    Right (wordLE 8 (3 * fromIntegral ((toInteger size + if witnessFlag==1 then 67 else 148) `mod` 4294967296)))
    | witnessFlag <- [0,1]] ++ [ioProperty $ B.useAsCStringLen input $ \(ptr,len) -> allocaBytes 256 $ \output -> do
      result <- elements_hs_withdrawal_bytes 22 money (castPtr ptr) (fromIntegral len) output 256
      pure (result === -1) | input <- [B.empty,B.replicate 4 0,B.replicate 6 0,B.replicate 4 0 <> B.singleton 2]])

walletNativeAmounts :: Property
walletNativeAmounts = forAll amounts $ \(payout,parentFee) ->
  let encode mode = B.singleton mode <> wordLE 8 (fromIntegral payout) <> wordLE 8 (fromIntegral parentFee)
      wideTotal = toInteger payout + toInteger parentFee
      expected mode
        | mode == 2 = if payout > 0 then Right (wordLE 8 (fromIntegral payout)) else Left "Invalid amount for send"
        | mode == 0 = if payout > 0 && payout <= money then Right (wordLE 8 (fromIntegral payout))
                      else Left "Invalid withdrawal payout amount"
        | parentFee >= 0 && parentFee <= money && wideTotal <= toInteger money = Right (wordLE 8 (fromIntegral wideTotal))
        | otherwise = Left "Invalid mainchain fee or withdrawal total"
  in conjoin ([withdrawal 21 money (encode mode) === expected mode | mode <- [0,1,2]] ++
       [ioProperty $ B.useAsCStringLen input $ \(ptr,len) -> allocaBytes 256 $ \output -> do
         result <- elements_hs_withdrawal_bytes 21 money (castPtr ptr) (fromIntegral len) output 256
         pure (result === -1) | input <- [B.empty,B.replicate 16 0,B.replicate 18 0,encode 3,encode 255]])

walletNativePayout :: Property
walletNativePayout = forAll ((,) <$> (arbitrary :: Gen Word32) <*> amounts) $ \(size,(payout,_)) ->
  conjoin ([let dust=3 * ((toInteger size + if witnessFlag==1 then 67 else 148) `mod` 4294967296)
                code :: Int32
                code | payout <= 0 || payout > money = -3
                     | toInteger payout < dust = -8
                     | otherwise = 0
            in withdrawal 26 money (wordLE 8 (fromIntegral payout) <> wordLE 4 (fromIntegral size) <> B.singleton witnessFlag) ===
                Right (wordLE 4 (fromIntegral code) <> wordLE 8 (fromIntegral dust)) | witnessFlag <- [0,1]] ++
    [ioProperty $ B.useAsCStringLen input $ \(ptr,len) -> allocaBytes 256 $ \output -> do
       result <- elements_hs_withdrawal_bytes 26 money (castPtr ptr) (fromIntegral len) output 256
       pure (result === -1) | input <- [B.empty,B.replicate 12 0,B.replicate 14 0,B.replicate 12 0 <> B.singleton 2]])

walletNativeBurnPlan :: Property
walletNativeBurnPlan = forAll ((,,) <$> amounts <*> (B.pack <$> vectorOf 32 arbitrary) <*>
    oneof [pure B.empty,pure (B.singleton 106),B.pack <$> vectorOf 22 arbitrary]) $ \((netAmount,parentFee),parent,dest) ->
  let values=wordLE 8 (fromIntegral netAmount) <> wordLE 8 (fromIntegral parentFee)
      expected = case withdrawal 21 money (B.singleton 1 <> values) of
        Left message -> wordLE 4 (fromIntegral (-3 :: Int32)) <> C.pack message
        Right encodedTotal -> case withdrawal 1 money (parent <> wordLE 8 (fromIntegral parentFee) <> dest) of
          Left message -> wordLE 4 (fromIntegral (-8 :: Int32)) <> C.pack message
          Right script -> wordLE 4 0 <> encodedTotal <> script
  in conjoin [withdrawal 27 money (values <> parent <> dest) === Right expected,
     ioProperty $ B.useAsCStringLen (B.take 47 (values <> parent)) $ \(ptr,len) -> allocaBytes 256 $ \output -> do
       result <- elements_hs_withdrawal_bytes 27 money (castPtr ptr) (fromIntegral len) output 256
       pure (result === -1)]

childDrainWorkflow :: Property
childDrainWorkflow = forAll (vectorOf 8 ((,) <$> choose (0,4) <*> arbitrary)) $ \events -> ioProperty $ do
  let outcomes = events ++ [(1,False)]
      run phase index trace = do
        let (status,truncated) = outcomes !! index
            response = case phase of
              0 -> 0
              1 -> status
              2 -> if truncated then 1 else 0
              _ -> 1
        next <- elements_hs_parent_replay_store_checked 187 phase response
        if next < 0 then pure (trace ++ [next]) else run (fromIntegral next)
          (index + if (phase == 1 && status == 2) || phase == 2 then 1 else 0) (trace ++ [next])
      model [] = [-1]
      model ((status,truncated):rest) = 1 : case status of
        0 -> 2 : if truncated then [-11] else model rest
        1 -> [3,-11]
        2 -> model rest
        3 -> [-11]
        _ -> [4,-10]
  actual <- run 0 0 []
  malformed <- mapM (elements_hs_parent_replay_store_checked 187 1) [5,6,maxBound]
  invalidEffects <- mapM (\phase -> elements_hs_parent_replay_store_checked 187 phase 2) [2,3,4,5]
  pure (conjoin [actual === model outcomes,malformed === replicate 3 (-1),invalidEffects === replicate 4 (-1)])

childReapWorkflow :: Property
childReapWorkflow = forAll arbitrary $ \already -> forAll (vectorOf 8 (choose (0,5))) $ \events -> ioProperty $ do
  let outcomes = events ++ [0]
      run phase index trace = do
        let response = case phase of
              0 -> 0
              1 -> if already then 1 else 0
              2 -> outcomes !! index
              _ -> 1
        next <- elements_hs_parent_replay_store_checked 186 phase response
        if next < 0 then pure (trace ++ [next]) else run (fromIntegral next)
          (index + if phase == 2 then 1 else 0) (trace ++ [next])
      model [] = [-1]
      model (event:rest) = 2 : case event of
        2 -> model rest
        0 -> [-11]
        3 -> [-11]
        4 -> [4,-11]
        _ -> [-11]
  actual <- run 0 0 []
  malformed <- mapM (elements_hs_parent_replay_store_checked 186 2) [6,7,maxBound]
  retired <- mapM (elements_hs_parent_replay_store_checked 186 3) [0,1,2,maxBound]
  invalidEffects <- mapM (\phase -> elements_hs_parent_replay_store_checked 186 phase 2) [1,3,4,5]
  pure (conjoin [actual === (if already then [1,-11] else 1:model outcomes),
    malformed === replicate 3 (-1),retired === replicate 4 (-1),invalidEffects === replicate 4 (-1)])

childGraceWorkflow :: Property
childGraceWorkflow = forAll (vectorOf 4 arbitrary) $ \events -> ioProperty $ do
  let states = events ++ [(False,False,False)]
      run phase iteration trace = do
        let (waiting,reaped,nonblocking) = states !! iteration
            answer = case phase of
              1 -> waiting
              3 -> reaped
              5 -> nonblocking
              _ -> True
        next <- elements_hs_parent_replay_store_checked 185 phase (if phase == 0 then 0 else if answer then 1 else 0)
        if next < 0 then pure (trace ++ [next]) else run (fromIntegral next)
          (iteration + if phase == 6 || (phase == 5 && not nonblocking) then 1 else 0) (trace ++ [next])
      model [] = [-1]
      model ((waiting,reaped,nonblocking):rest)
        | not waiting = [1,-11]
        | reaped = [1,2,3,-11]
        | otherwise = [1,2,3,4,5] ++ [6 | nonblocking] ++ model rest
  actual <- run 0 0 []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked 185 phase 2) [1..7]
  pure (conjoin [actual === model states,malformed === replicate 7 (-1)])

childMonitorWorkflow :: Property
childMonitorWorkflow = forAll arbitrary $ \initialError -> forAll (vectorOf 4 arbitrary) $ \events -> ioProperty $ do
  let states = events ++ [(True,False,False,False,True,True)]
      run phase iteration trace = do
        let (drained,truncated,cancelled,expired,finished,polled) = states !! iteration
            answer = case phase of
              1 -> initialError
              2 -> drained
              4 -> truncated
              5 -> cancelled
              7 -> expired
              9 -> finished
              10 -> polled
              _ -> True
        next <- elements_hs_parent_replay_store_checked 184 phase (if phase == 0 then 0 else if answer then 1 else 0)
        if next < 0 || iteration >= 5 then pure (trace ++ [next])
          else run (fromIntegral next) (iteration + if phase == 10 then 1 else 0) (trace ++ [next])
      model [] = [-1]
      model ((drained,truncated,cancelled,expired,finished,polled):rest)
        | not drained = [2,-11]
        | truncated = [2,3,4,-11]
        | cancelled = [2,3,4,5,6,-11]
        | expired = [2,3,4,5,7,8,-11]
        | finished = [2,3,4,5,7,9,-10]
        | not polled = [2,3,4,5,7,9,10,-11]
        | otherwise = [2,3,4,5,7,9,10] ++ model rest
  actual <- run 0 0 []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked 184 phase 2) [1..11]
  pure (conjoin [actual === (if initialError then [1,-11] else 1:model states),malformed === replicate 11 (-1)])

foreign import ccall "wrapper" wrapPolicyEffect :: PolicyEffect -> IO (FunPtr PolicyEffect)

foreign import ccall "wrapper" wrapProofBuildEffect :: ProofBuildEffect -> IO (FunPtr ProofBuildEffect)

indexedCallbackBoundary :: Property
indexedCallbackBoundary = once $ ioProperty $ do
  calls <- newIORef []
  bracket (wrapProofBuildEffect (\_ stage index -> modifyIORef' calls (++[(stage,index)]) >> pure 1)) freeHaskellFunPtr $ \callback -> do
    missing <- callbackCall (error "converter forced") (error "interpreter forced") callbackNull nullPtr :: IO Int32
    missingWide <- callbackCall (error "converter forced") (error "interpreter forced") callbackNull nullPtr :: IO Int64
    constructed <- proofCall (error "construction failure") callback nullPtr
    rejected <- proofCall (\action -> action 7 maxBound >> ioError (userError "interpreter failure")) callback nullPtr
    accepted <- proofCall (\action -> action 9 42) callback nullPtr
    observed <- readIORef calls
    pure (conjoin [missing === -1,missingWide === -1,constructed === -1,rejected === -1,accepted === 1,
      observed === [(7,maxBound),(9,42)]])
  where callbackNull = nullFunPtr :: FunPtr ProofBuildEffect

foreign import ccall "wrapper" makeStateTransitionEffect :: StateTransitionEffect -> IO (FunPtr StateTransitionEffect)
foreign import ccall "wrapper" makeCursorEffect :: CursorEffect -> IO (FunPtr CursorEffect)

cursorTransportAbi :: Property
cursorTransportAbi = forAll gen $ \(status,code,payload) -> ioProperty $ do
  calls <- newIORef (0::Int)
  let run readField = do
        first <- readField 0 7 9
        second <- readField 1 7 9
        pure (code,first+second)
  bracket (makeCursorEffect (\_ step tx index field -> do
    modifyIORef' calls (+1)
    if tx/=7 || index/=9 then error "cursor arguments changed" else pure ()
    -- The second successful callback deliberately leaves its field unwritten.
    if step==0 then poke field payload else pure ()
    pure status)) freeHaskellFunPtr $ \callback -> withArray [17,19] $ \output -> do
      scalar <- cursorCall (\readField -> fst <$> run readField) callback nullPtr
      scalarCalls <- readIORef calls
      writeIORef calls 0
      paired <- workCall run output callback nullPtr
      pairedCalls <- readIORef calls
      fields <- peekArray 2 output
      writeIORef calls 0
      missingOutput <- workCall run nullPtr callback nullPtr
      missingCallback <- workCall run output nullFunPtr nullPtr
      missingScalar <- cursorCall (\_ -> modifyIORef' calls (+100) >> pure 0) nullFunPtr nullPtr
      rejectedCalls <- readIORef calls
      let expectedCode = if status==1 then code else -1
          expectedCalls = if status==1 then 2 else 1
      pure $ conjoin [scalar===expectedCode,paired===expectedCode,
        scalarCalls===expectedCalls,pairedCalls===expectedCalls,
        fields===[if status==1 && code>=0 then payload else 17,19],
        missingOutput===(-1),missingCallback===(-1),missingScalar===(-1),rejectedCalls===0]
  where
    gen = (,,) <$> elements [-1,0,1,2,maxBound] <*>
      elements [-2,-1,0,1,3,maxBound] <*> arbitrary

bmmSubmissionWorkflow :: Property
bmmSubmissionWorkflow = forAll generator $ \(bid,limit,rows,effect) -> ioProperty $ do
  seen <- newIORef []
  current <- newIORef (-1 :: Int)
  let action step value = do
        modifyIORef' seen (++[(step,value)])
        if step == 1 then modifyIORef' current (+1) else pure ()
        index <- readIORef current
        let (parent,status,delta,duplicate) = rows !! index
        pure $ case step of
          1 -> parent
          2 -> status
          3 -> if delta == 0 then 0 else if delta == -1 then -1 else fromIntegral value + delta
          4 -> effect
          5 -> duplicate
          6 -> effect
          _ -> -1
      model amount index =
        let (parent,status,delta,duplicate) = rows !! index
            finish success =
              let prefix = [(5,0) | not success]
                  present = if success then 1 else duplicate
              in if present /= 1 then (if present == 0 then 2 else -1,prefix)
                 else (if effect == 1 then 0 else -1,prefix ++ [(6,if success then 1 else 0)])
            append before (code,after) = (code,before ++ after)
            retry
              | index == 2 = finish False
              | delta == 0 = append [(3,fromIntegral amount)] (finish False)
              | delta < 0 || toInteger amount+toInteger delta > toInteger limit = (-1,[(3,fromIntegral amount)])
              | effect /= 1 = (-1,[(3,fromIntegral amount),(4,fromIntegral (amount+delta))])
              | otherwise = append [(3,fromIntegral amount),(4,fromIntegral (amount+delta))] (model (amount+delta) (index+1))
        in if parent /= 1 then (if parent == 0 then 1 else -1,[(1,0)])
           else append [(1,0),(2,fromIntegral amount)] $ case status of
             0 -> (2,[])
             1 -> retry
             2 -> finish True
             _ -> (-1,[])
      expected = if bid <= 0 || bid > limit then (-1,[]) else model bid 0
  actual <- execute (Bmm.SubmissionRequest action) (Bmm.submitBmm bid limit)
  observed <- readIORef seen
  missing <- elements_hs_bmm_submit bid limit nullFunPtr nullPtr
  pure $ conjoin [(actual,observed) === expected,missing === (-1)]
  where
    generator = (,,,) <$> elements [minBound,-1,0,1,1000,maxBound-1,maxBound] <*>
      elements [-1,0,999,1000,2000,maxBound-1,maxBound] <*>
      vectorOf 3 ((,,,) <$> elements [1,1,1,1,0,2,-1] <*> elements [1,1,1,2,0,3,-1] <*>
        elements [-1,0,19,1001] <*> elements [0,1,2]) <*> elements [1,1,1,0,-1,2]

coinbaseWorkflowParity :: Property
coinbaseWorkflowParity = forAll (listOf ((,) <$> choose (0,6 :: Int64) <*> arbitrary)) $ \rows -> ioProperty $ do
  seen <- newIORef []
  let action stage index = do
        modifyIORef' seen (++[(stage,index)])
        let (kind,unique) = rows !! fromIntegral index
        pure $ if stage == 2 then kind else if stage `elem` [3,4,5] then if unique then 1 else 0 else 1
      model :: Word64 -> Bool -> [(Int64,Bool)] -> (Int32,[(Word32,Word64)])
      model _ _ [] = (0,[])
      model index saw ((kind,unique):rest) =
        let prefix = [(1,index) | index `mod` 256 == 0] ++ [(2,index)]
            insert = case kind of 1 -> [3]; 2 -> [4]; 5 -> [5]; _ -> []
            rejection = case kind of 1 -> 1; 2 -> 2; _ -> 4
            suffix = [(s,index) | s <- insert]
            next = case model (index+1) (saw || kind == 4) rest of
              (status,trace) -> (status,prefix ++ suffix ++ [(s,index) | s <-
                [6 | kind == 5] ++ [7 | kind /= 0] ++ [8]] ++ trace)
        in if kind > 5 then (-1,prefix)
           else if kind == 4 && saw then (3,prefix)
           else if not (null insert) && not unique then (rejection,prefix ++ suffix)
           else next
  actual <- validate (ParentReplay.CoinbaseMessages (fromIntegral (length rows)) action)
  observed <- readIORef seen
  pure ((actual,observed) === model 0 False rows)

m4RepeatWorkflowParity :: Property
m4RepeatWorkflowParity = forAll ((,,,) <$> elements [0,1,2 :: Word32]
  <*> elements [-1,0,1,2 :: Int64] <*> elements [-1,0,1,2,3 :: Int64]
  <*> elements [-1,0,1,2 :: Int64]) $ \(upvote,active,result,published) -> ioProperty $ do
    seen <- newIORef []
    let action stage = modifyIORef' seen (++[stage]) >> pure (case stage of 1 -> active; 4 -> published; _ -> result)
        voteStage = if upvote == 1 then 2 else 3
        expected :: (Int32,[Word32])
        expected | upvote > 1 = (-1,[])
                 | active == 0 = (1,[1])
                 | active /= 1 = (-1,[1])
                 | result == 0 && upvote == 1 = (2,[1,voteStage])
                 | result == 2 = (0,[1,voteStage])
                 | result == 1 = (if published == 1 then 0 else -1,[1,voteStage,4])
                 | otherwise = (-1,[1,voteStage])
    actual <- validate (ParentReplay.M4Repeat upvote action)
    observed <- readIORef seen
    pure ((actual,observed) === expected)

m8AcceptanceWorkflowParity :: Property
m8AcceptanceWorkflowParity = forAll (listOf (vectorOf 4 (elements [-1,0,1,1,2,maxBound :: Int64]))) $ \rows -> ioProperty $ do
  seen <- newIORef []
  let action stage index = do
        modifyIORef' seen (++[(stage,index)])
        pure (rows !! (fromIntegral index-1) !! (fromIntegral stage-1))
      model :: Word64 -> [[Int64]] -> (Int32,[(Word32,Word64)])
      model _ [] = (0,[])
      model index ([ready,recognized,accepted,current]:rest) =
        let stop status stages = (status,[(stage,index) | stage <- stages])
            advance stages = let (status,trace) = model (index+1) rest
                             in (status,[(stage,index) | stage <- stages] ++ trace)
        in if ready /= 1 then stop (-1) [1]
           else if recognized == 0 then advance [1,2]
           else if recognized /= 1 then stop (-1) [1,2]
           else if accepted /= 1 then stop (if accepted == 0 then 1 else -1) [1,2,3]
           else if current /= 1 then stop (if current == 0 then 2 else -1) [1,2,3,4]
           else advance [1,2,3,4]
      model _ _ = error "invalid fixture row"
  actual <- validate (ParentReplay.M8Acceptance (fromIntegral (length rows)+1) action)
  observed <- readIORef seen
  empty <- validate (ParentReplay.M8Acceptance 0 (\_ _ -> error "empty block callback forced"))
  pure (conjoin [(actual,observed) === model 1 rows,empty === 0])

m2ProposalWorkflowParity :: Property
m2ProposalWorkflowParity = forAll ((,,,,,) <$> elements [-2,0,95,96,98,99,100,101,0xffffffff :: Int64]
  <*> elements [0,1,2,3,65534,65535,0xffffffff :: Int64] <*> arbitrary <*> choose (0,7 :: Int64)
  <*> choose (0,6 :: Word32) <*> elements [-1,0,2,4294967297 :: Int64]) $
  \(proposed,votes,used,flags,failure,bad) -> ioProperty $ do
    seen <- newIORef []
    let reply stage | stage == failure = bad
                    | otherwise = case stage of 1 -> proposed; 2 -> votes; 3 -> if used then 1 else 0; 5 -> flags; _ -> 1
        action stage value = modifyIORef' seen (++[(stage,value)]) >> pure (reply stage)
        -- Independent trace oracle models the original native mutation order.
        expected :: (Int32,[(Word32,Word64)])
        expected = visit 1 0 []
        visit stage value trace =
          let r = reply stage
              trace' = trace ++ [(stage,value)]
              done status = (status,trace')
              next s v = visit s v trace'
              incremented = (reply 2+1) `mod` 0x100000000
          in case stage of
            1 | r == -2 || r == 100 -> done 0
              | r < 0 || r > 0xffffffff -> done (-1)
              | r > 100 -> done 1
              | otherwise -> next 2 0
            2 | r < 0 || r > 0xffffffff -> done (-1)
              | otherwise -> next 3 (fromIntegral incremented)
            3 | r /= 0 && r /= 1 -> done (-1)
              | incremented <= (if r == 1 then 2 else 1) || 100-reply 1 > (if r == 1 then 2 else 4) -> done 0
              | otherwise -> next 4 0
            4 | r == 1 -> next 5 0
              | otherwise -> done (-1)
            5 | r < 0 || r > 7 -> done (-1)
              | r == 3 -> done 2
              | r == 5 -> next 6 0
              | otherwise -> done 0
            _ -> done (if r == 1 then 0 else -1)
    actual <- validate (ParentReplay.M2Proposal 100 4 1 2 2 action)
    observed <- readIORef seen
    pure ((actual,observed) === expected)

m4ModeWorkflowParity :: Property
m4ModeWorkflowParity = forAll ((,,) <$> choose (0,16 :: Word32)
  <*> elements [0,1,100,maxBound :: Word64] <*> elements [-1,0,1,100,maxBound :: Int64]) $
  \(flags,votes,active) -> ioProperty $ do
    seen <- newIORef []
    actual <- validate (ParentReplay.M4Mode flags votes (\stage -> modifyIORef' seen (++[stage]) >> pure active))
    observed <- readIORef seen
    let expected | flags > 15 = -1
                 | even flags = 4
                 | odd (flags `div` 2) = 5
                 | active < 0 = -1
                 | odd (flags `div` 4) = if toInteger votes == toInteger active then 1 else 6
                 | odd (flags `div` 8) = 2
                 | otherwise = 3
        called = flags <= 15 && odd flags && even (flags `div` 2)
    pure (conjoin [actual === expected,observed === [1 | called]])

m3ProposalWorkflowParity :: Property
m3ProposalWorkflowParity = forAll ((,,,) <$> elements [-1,0,1,1,2 :: Int64]
  <*> listOf (elements [0,0,0,1,2,-1 :: Int64]) <*> elements [-1,0,1,1,2 :: Int64]
  <*> elements [-1,0,1,1,2 :: Int64]) $ \(active,matches,firstEffect,secondEffect) -> ioProperty $ do
    seen <- newIORef []
    let action stage index = do
          modifyIORef' seen (++[(stage,index)])
          pure $ case stage of 1 -> active; 2 -> fromIntegral (length matches); 3 -> matches !! fromIntegral index;
                               4 -> firstEffect; 5 -> secondEffect; _ -> -1
        inspected = takeWhile (==0) matches
        hit = length inspected < length matches
        count = length inspected + if hit then 1 else 0
        trace = [(1,0),(2,0)] ++ [(3,fromIntegral i) | i <- [0..count-1]]
        expected :: (Int32,[(Word32,Word64)])
        expected | active == 0 = (1,[(1,0)])
                 | active /= 1 = (-1,[(1,0)])
                 | hit = (if matches !! length inspected == 1 then 2 else -1,trace)
                 | firstEffect /= 1 = (-1,trace ++ [(4,0)])
                 | otherwise = (if secondEffect == 1 then 0 else -1,trace ++ [(4,0),(5,0)])
    actual <- validate (ParentReplay.M3Proposal action)
    observed <- readIORef seen
    pure ((actual,observed) === expected)

m6IdWorkflowParity :: Property
m6IdWorkflowParity = forAll ((,,,,) <$> elements [-1,0,1,50,100,maxBound :: Int64]
  <*> listOf (elements [-1,0,1,50,100,maxBound :: Int64]) <*> elements [0,1,1,2 :: Word64]
  <*> arbitrary <*> arbitrary) $ \(previous,outputs,inputs,parsed,hasSlot) -> ioProperty $ do
    seen <- newIORef []
    let action stage value = do
          modifyIORef' seen (++[(stage,value)])
          pure $ case stage of 2 -> if parsed then 1 else 0; 3 -> head outputs; 4 -> outputs !! fromIntegral value; _ -> 1
        valid value = value >= 0 && value <= 100
        expected :: (Int32,[(Word32,Word64)])
        expected = case outputs of
          [] -> (1,[(1,0)])
          replacement:payments
            | not parsed -> (2,prefix)
            | inputs /= 1 -> (3,prefix)
            | not (valid previous) -> (4,prefix)
            | not (valid replacement) -> (4,prefix ++ [(3,0)])
            | otherwise ->
                let sums = tail (scanl (+) 0 (map toInteger payments))
                    bad = [i | (i,(value,accumulated)) <- zip [1..] (zip payments sums), not (valid value) || accumulated > 100]
                    visited = case bad of i:_ -> i; [] -> length payments
                    trace = prefix ++ [(3,0)] ++ [(4,fromIntegral i) | i <- [1..visited]]
                    fee = toInteger previous-toInteger replacement-sum (map toInteger payments)
                in if not (null bad) then (5,trace)
                   else if fee < 0 then (6,trace)
                   else (0,trace ++ [(5,fromInteger fee)] ++ [(6,0) | hasSlot])
            where prefix = [(1,0),(2,0)]
    actual <- validate (ParentReplay.M6Id (fromIntegral (length outputs)) inputs previous 100 (if hasSlot then 1 else 0) action)
    observed <- readIORef seen
    pure ((actual,observed) === expected)

activeSlotsParity :: Property
activeSlotsParity = forAll (listOf ((,) <$> arbitrary <*> arbitrary)) $ \entries ->
  ioProperty $ withArray (concatMap (\(slot,active) -> [slot,if active then 1 else 0]) entries) $ \input ->
    withArray (123:replicate (length entries) 77 ++ [254] :: [Word8]) $ \out -> do
      let expected = List.sort [slot | (slot,True) <- entries]
      actual <- elements_hs_active_slots (fromIntegral (length entries)) input (out `plusPtr` 1)
      observed <- peekArray (length entries+2) out
      missing <- elements_hs_active_slots 1 nullPtr out
      missingOutput <- elements_hs_active_slots 1 input nullPtr
      oversize <- elements_hs_active_slots 258 nullPtr nullPtr
      empty <- elements_hs_active_slots 0 nullPtr nullPtr
      malformed <- withArray [0,2] $ \invalid -> elements_hs_active_slots 1 invalid out
      pure (conjoin [actual === fromIntegral (length expected),
        observed === 123:expected ++ replicate (length entries-length expected) 77 ++ [254],
        missing === -1,missingOutput === -1,oversize === -1,empty === 0,malformed === -1])

blockPublishWorkflowParity :: Property
blockPublishWorkflowParity = forAll ((,,) <$> choose (0,16 :: Word32) <*> choose (0,3 :: Word32)
  <*> elements [-1,0,1,2 :: Int32]) $ \(flags,failed,status) -> ioProperty $ do
    seen <- newIORef []
    let action stage = modifyIORef' seen (++[stage]) >> pure (if stage == failed then status else 1)
        stages = [1 | odd (flags `div` 4)] ++ [2 | odd (flags `div` 8)] ++ [3]
        prefix = takeWhile (/=failed) stages
        invalid = flags > 15
        rejected = odd flags && even (flags `div` 2)
        stops = failed `elem` stages && status /= 1
        expected | invalid = (-1,[])
                 | rejected = (1,[])
                 | stops = (-1,prefix ++ [failed])
                 | otherwise = (0,stages)
    actual <- validate (ParentReplay.BlockPublish flags action)
    observed <- readIORef seen
    pure ((actual,observed) === expected)

pruneSlotsWorkflowParity :: Property
pruneSlotsWorkflowParity = forAll (listOf ((,) <$> elements [-1,0,1,2,4,8,16,32,63,64 :: Int64]
  <*> elements [-1,0,1,2 :: Int64])) $ \entries -> ioProperty $ do
    remaining <- newIORef entries
    seen <- newIORef []
    let action stage = do
          modifyIORef' seen (++[stage])
          pending <- readIORef remaining
          case pending of
            (occupied,result):rest -> if stage == 1 then pure occupied else writeIORef remaining rest >> pure result
            [] -> error "pruning callback past end"
        model [] = (0,[])
        model ((occupied,result):rest)
          | occupied < 0 || occupied > 63 = (-1,[1])
          | result /= 1 = (-1,[1,step])
          | otherwise = let (code,steps) = model rest in (code,1:step:steps)
          where step = if occupied == 0 then 2 else 3
    actual <- validate (ParentReplay.PruneSlots (fromIntegral (length entries)) action)
    observed <- readIORef seen
    pure ((actual,observed) === model entries)

bmmStateWorkflowParity :: Property
bmmStateWorkflowParity = forAll ((,) <$> elements [0,12,68] <*> vectorOf 115 arbitrary) $ \(start,values) ->
  ioProperty $ do
    let normal step = (values !! fromIntegral step :: Word32) `mod` case step of
          5 -> 4; 7 -> 4; 8 -> 16; 14 -> 8; 18 -> 4; 70 -> 4; 23 -> 1; _ -> 2
        life = [(1,0),(4,2),(5,3),(7,4),(8,5),(13,6),(14,7),(15,8),(16,9),(18,10),(22,11),(23,11)]
        source = [(69,0),(70,1),(71,2),(73,3)]
        run program = do
          seen <- newIORef []
          let action step = modifyIORef' seen (++[step]) >> pure (fromIntegral (normal step))
          result <- program action
          trace <- readIORef seen
          pure (result,trace)
        reference action = do
          failure <- newIORef 0
          let decision base code = do
                when (code < 0) (writeIORef failure (base-code))
                pure (fromIntegral code)
              callback 3 = do
                present <- action 108
                stored <- if present == 1 then pure 1 else action 109
                decision 100 (validate (Bmm.Lifecycle 1 (fromIntegral stored)))
              callback step = do
                value <- action step
                case (lookup step life,lookup step source) of
                  (Just phase,_) -> decision 100 (validate (Bmm.Lifecycle phase (fromIntegral value)))
                  (_,Just phase) -> decision 200 (validate (Bmm.StateSource phase (fromIntegral value)))
                  _ -> pure value
          result <- validate (Bmm.StateExecution start callback)
          code <- readIORef failure
          pure (if code == 0 then result else code)
    actual <- run (validate . Bmm.StateWorkflow start)
    expected <- run reference
    pure (actual === expected)

treasuryTransactionParity :: Property
treasuryTransactionParity = forAll ((,,,,,) <$> choose (0,3) <*> arbitrary <*> choose (0,7)
  <*> choose (0,1) <*> choose (0,130 :: Int) <*> elements [-1,0,1,2,1001,4294967296 :: Int64]) $
  \(rows,isWithdrawal,flags,single,fault,bad) -> ioProperty $ do
    let inputs = if rows == 0 then 0 else 1
        outputs = rows*2
        decreases = if isWithdrawal then rows else 0
        new = if isWithdrawal then 80 else 120
        normal step index = case step of
          0 -> case index of
            0 -> fromIntegral rows; 1 -> fromIntegral rows; 2 -> fromIntegral rows
            3 -> fromIntegral decreases; 4 -> 100; 5 -> new; 6 -> 0; 7 -> fromIntegral flags
            _ -> error "unknown transaction field"
          102 -> 100; 302 -> if even index then 1 else 0; 304 -> new
          503 -> 100; 505 -> new; 601 -> 0; 605 -> 101; 607 -> 0
          704 -> 32; 903 -> 80; 904 -> 0; _ -> 1
        run program = do
          calls <- newIORef []
          let action step index = do
                if step == 0 || step == 800 then pure (normal step index) else do
                  modifyIORef' calls (++[(step,index)])
                  n <- length <$> readIORef calls
                  pure (if n == fault then bad else normal step index)
          result <- program action
          trace <- readIORef calls
          pure (result,trace)
        -- The pre-consolidation caller ran each rule separately and stopped
        -- on its first error. Its native effects are compared byte-for-byte.
        reference action = either id (const 0) <$> runExceptT (do
          let grouped group step index = action (group*100+step) index
              one group step = grouped group step 0
              narrow n | n < fromIntegral (minBound :: Int32) || n > fromIntegral (maxBound :: Int32) = -1
                       | otherwise = fromIntegral n
              checked group runRule = do
                code <- lift runRule
                when (code /= 0) (throwE (if code < 0 then -1 else group*256+code))
          checked 1 (validate (ParentReplay.CtipOwners rows 1000 (one 1)))
          checked 2 (validate (ParentReplay.CtipSpends inputs (\s i -> narrow <$> grouped 2 s i)))
          checked 3 (validate (ParentReplay.CtipOutputs outputs 1000 (grouped 3)))
          checked 4 (validate (ParentReplay.CtipReplacements rows (fmap narrow . one 4)))
          checked 5 (validate (ParentReplay.CtipChanges rows (one 5)))
          when (rows /= 0) $ if decreases /= 0 then do
            idError <- lift (newIORef 0)
            result <- lift (validate (ParentReplay.M6Withdrawal decreases rows inputs 100 single $ \s ->
              if s /= 2 then one 6 s else do
                code <- validate (ParentReplay.M6Id outputs inputs 100 1000 1 (grouped 9))
                writeIORef idError code
                pure (if code == 0 then 1 else 0)))
            checked 9 (readIORef idError)
            checked 6 (pure result)
          else mapM_ (\_ -> checked 7 (validate (ParentReplay.M5Deposit 100 new 1000 0 outputs flags (grouped 7)))) [1..rows])
    actual <- run (validate . ParentReplay.TransactionReplay rows inputs outputs 1000 100 single)
    expected <- run reference
    pure (actual === expected)

treasuryTransactionBoundary :: Property
treasuryTransactionBoundary = once $ ioProperty $ do
  let never _ _ = error "invalid treasury arguments evaluated callback"
  oversized <- validate (ParentReplay.TransactionReplay 0 0 0 maxBound 0 0 never)
  invalidMode <- validate (ParentReplay.TransactionReplay 0 0 0 1000 0 2 never)
  missing <- elements_hs_transaction_replay 0 0 0 1000 0 0 nullFunPtr nullPtr
  -- A negative native count must never wrap into an unbounded traversal.
  trace <- newIORef []
  negative <- validate (ParentReplay.TransactionReplay 0 0 0 1000 0 0 $ \s i ->
    modifyIORef' trace (++[(s,i)]) >> pure (-1))
  calls <- readIORef trace
  pure (conjoin [oversized === -1, invalidMode === -1, missing === -1,
    negative === -1, calls === [(0,0)]])

m6WithdrawalWorkflowParity :: Property
m6WithdrawalWorkflowParity = forAll ((,,,,,) <$> mostlyOne <*> mostlyOne
  <*> mostlyOne <*> elements [0,1,100,65535,maxBound :: Word32]
  <*> elements [0,1,1,1,2 :: Word32] <*> mapM (\normal -> frequency [(4,pure normal),
    (1,elements [-1,0,1,2,100,101,65535,65536,4294967296 :: Int64])]) [0,1,1,1,101,1,0,1,1,1,1,1]) $
  \(decreases,changes,inputs,threshold,single,replies) -> ioProperty $ do
    seen <- newIORef []
    let reply :: Word32 -> Int64
        reply stage = replies !! (fromIntegral stage-1)
        action stage = modifyIORef' seen (++[stage]) >> pure (reply stage)
        -- Independent ordered guard model: the first rejecting guard stops the trace.
        guards = [(1,if reply 1 < 0 || reply 1 > 4294967295 then -1 else if inputs /= 1 || reply 1 /= 0 then 2 else 0)] ++
          [(stage,if reply stage == 1 then 0 else if reply stage == 0 then code else -1) | (stage,code) <- [(2,3),(3,4),(4,5)]] ++
          [(5,if reply 5 < 0 || reply 5 > 65535 then -1 else if reply 5 <= fromIntegral threshold then 6 else 0),
           (6,if reply 6 `elem` [0,1] then 0 else -1)] ++
          [(7,if reply 7 == 0 then 0 else if reply 7 == 1 then 7 else -1) | reply 6 == 1 && single == 1] ++
          [(stage,if reply stage == 1 then 0 else -1) | stage <- [8 | reply 6 == 1] ++ [9..12]]
        model [] = (0,[])
        model ((stage,code):rest)
          | code /= 0 = (code,[stage])
          | otherwise = let (result,steps) = model rest in (result,stage:steps)
        expected :: (Int32,[Word32])
        expected | single > 1 = (-1,[])
                 | decreases /= 1 || changes /= 1 = (1,[])
                 | otherwise = model guards
    actual <- validate (ParentReplay.M6Withdrawal decreases changes inputs threshold single action)
    observed <- readIORef seen
    pure (conjoin [actual === fst expected,observed === snd expected])
  where mostlyOne = elements [0,1,1,1,2 :: Word64]

m5DepositWorkflowParity :: Property
m5DepositWorkflowParity = forAll ((,,,,,,) <$> elements [-1,0,1,50,100,minBound,maxBound :: Int64]
  <*> elements [-1,0,1,50,100,minBound,maxBound :: Int64] <*> elements [0,1,2,maxBound-1,maxBound :: Word64]
  <*> elements [0,1,2,3,maxBound :: Word64] <*> choose (0,8 :: Word32) <*> arbitrary <*>
  elements [minBound,-1,0,1,127,128,129,maxBound :: Int64]) $
  \(old,new,output,outputs,flags,parsed,size) -> ioProperty $ do
    seen <- newIORef []
    let action stage value = do
          modifyIORef' seen (++[(stage,value)])
          pure $ case stage of 1 -> if parsed then 1 else 0; 4 -> size; _ -> 1
        delta = toInteger new-toInteger old
        expected :: (Int32,[(Word32,Word64)])
        expected
          | flags > 7 = (-1,[])
          | toInteger output+1 >= toInteger outputs = (1,[])
          | not parsed = (1,[(1,0)])
          | delta <= 0 || delta > 100 = (2,[(1,0)])
          | flags /= 7 = (0,[(1,0),(2,0),(3,0)])
          | size < 0 = (-1,[(1,0),(2,0),(3,0),(4,0)])
          | otherwise = (0,[(1,0),(2,0),(3,0),(4,0)] ++
              if size > 0 && size <= 128 then [(5,fromInteger delta)] else [])
    actual <- validate (ParentReplay.M5Deposit old new 100 output outputs flags action)
    observed <- readIORef seen
    pure (conjoin [actual === fst expected,observed === snd expected])

ctipChangesWorkflowParity :: Property
ctipChangesWorkflowParity = forAll (listOf ((,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary)) $ \entries ->
  forAll (elements [0,4,6,7]) $ \failedStage ->
  ioProperty $ do
    pending <- newIORef entries
    seen <- newIORef []
    let action stage = do
          modifyIORef' seen (++[stage])
          remaining <- readIORef pending
          if stage == failedStage then pure 0 else case remaining of
            (present,spent,old,new):rest -> case stage of
              1 -> pure (if present then 1 else 0)
              2 -> pure (if spent then 1 else 0)
              3 -> pure old
              4 -> pure 1
              5 -> pure new
              6 -> pure 1
              7 -> writeIORef pending rest >> pure 1
              _ -> pure (-1)
            [] -> error "change callback past end"
        model :: [(Bool,Bool,Int64,Int64)] -> (Int32,[Word32])
        model [] = (0,[])
        model ((present,spent,old,new):rest)
          | present && not spent = (1,[1,2])
          | otherwise = let previous = if present then old else 0
                            prefix = (if present then [1,2,3] else [1,4]) ++ [5]
                            decreased = (fromIntegral new :: Word64) < fromIntegral previous
                            (code,steps) = model rest
                        in if previous == new then (2,prefix)
                           else (code,prefix ++ (if decreased then [6] else []) ++ [7] ++ steps)
    actual <- validate (ParentReplay.CtipChanges (fromIntegral (length entries)) action)
    observed <- readIORef seen
    let (normalCode,normalSteps) = model entries
        (prefix,suffix) = break (==failedStage) normalSteps
        expected = if null suffix then (normalCode,normalSteps) else (-1,prefix ++ [failedStage])
    pure (conjoin [actual === fst expected,observed === snd expected])

repeatEntriesParity :: Property
repeatEntriesParity = forAll (listOf (elements [0,0,0,-1,1,2 :: Int32])) $ \results ->
  ioProperty $ do
    pending <- newIORef results
    calls <- newIORef (0 :: Int)
    actual <- ParentReplay.repeatEntries (fromIntegral (length results)) $ do
      modifyIORef' calls (+1)
      remaining <- readIORef pending
      case remaining of
        result:rest -> writeIORef pending rest >> pure result
        [] -> error "entry traversal exceeded count"
    observed <- readIORef calls
    empty <- ParentReplay.repeatEntries 0 (error "empty traversal forced action")
    hugeStop <- ParentReplay.repeatEntries maxBound (pure 2)
    let prefix = takeWhile (==0) results
        expected = case drop (length prefix) results of [] -> 0; result:_ -> result
    pure (conjoin [actual === expected,observed === length prefix + (if expected == 0 then 0 else 1),
      empty === 0,hugeStop === 2])

ctipReplacementsWorkflowParity :: Property
ctipReplacementsWorkflowParity = forAll (listOf ((,) <$> arbitrary <*> arbitrary)) $ \entries ->
  ioProperty $ do
    pending <- newIORef entries
    seen <- newIORef []
    let action stage = do
          modifyIORef' seen (++[stage])
          remaining <- readIORef pending
          case (stage,remaining) of
            (1,(spent,_):_) -> pure (if spent then 1 else 0)
            (2,(_,replaced):_) -> pure (if replaced then 1 else 0)
            (3,_:rest) -> writeIORef pending rest >> pure 1
            _ -> pure (-1)
        model :: [(Bool,Bool)] -> (Int32,[Word32])
        model [] = (0,[])
        model ((spent,replaced):rest)
          | spent && not replaced = (1,[1,2])
          | otherwise = let (code,steps) = model rest
                        in (code,[1] ++ (if spent then [2] else []) ++ [3] ++ steps)
    actual <- validate (ParentReplay.CtipReplacements (fromIntegral (length entries)) action)
    observed <- readIORef seen
    empty <- validate (ParentReplay.CtipReplacements 0 (error "empty replacements forced callback"))
    pure (conjoin [actual === fst (model entries),observed === snd (model entries),empty === 0])

ctipOutputsWorkflowParity :: Property
ctipOutputsWorkflowParity = forAll (listOf ((,,,) <$> arbitrary <*> arbitrary <*> elements [-1,0,1,100,101 :: Int64] <*> arbitrary)) $ \entries ->
  ioProperty $ do
    seen <- newIORef []
    let action stage index = do
          modifyIORef' seen (++[(stage,index)])
          let (treasury,active,value,inserted) = entries !! fromIntegral index
              flag yes = if yes then 1 else 0
          pure $ case stage of
            1 -> 1
            2 -> flag treasury
            3 -> flag active
            4 -> value
            5 -> flag inserted
            _ -> -1
        model :: Word64 -> [(Bool,Bool,Int64,Bool)] -> (Int32,[(Word32,Word64)])
        model _ [] = (0,[])
        model index ((treasury,active,value,inserted):rest) =
          let prefix = (if index `mod` 256 == 0 then [(1,index)] else []) ++ [(2,index)]
              (code,steps) = model (index+1) rest
          in if not treasury then (code,prefix ++ steps)
             else if not active then (code,prefix ++ [(3,index)] ++ steps)
             else if value < 0 || value > 100 then (1,prefix ++ [(3,index),(4,index)])
             else if not inserted then (2,prefix ++ [(3,index),(4,index),(5,index)])
             else (code,prefix ++ [(3,index),(4,index),(5,index)] ++ steps)
    actual <- validate (ParentReplay.CtipOutputs (fromIntegral (length entries)) 100 action)
    observed <- readIORef seen
    oversized <- validate (ParentReplay.CtipOutputs 0x100000000 100 (error "oversized outputs forced callback"))
    pure (conjoin [actual === fst (model 0 entries),observed === snd (model 0 entries),oversized === -1])

ctipSpendsWorkflowParity :: Property
ctipSpendsWorkflowParity = forAll (listOf (elements [-1,0,1,2 :: Int])) $ \owners ->
  ioProperty $ do
    spent <- newIORef []
    seen <- newIORef []
    let action stage index = do
          modifyIORef' seen (++[(stage,index)])
          let owner = owners !! fromIntegral index
          case stage of
            1 -> pure 1
            2 -> pure (if owner < 0 then 0 else 1)
            3 -> do
              modifyIORef' spent (++[owner])
              counts <- readIORef spent
              pure (fromIntegral (length (filter (==owner) counts)))
            _ -> pure (-1)
        model :: Word64 -> [Int] -> [Int] -> (Int32,[(Word32,Word64)])
        model _ _ [] = (0,[])
        model index prior (owner:rest) =
          let prefix = (if index `mod` 256 == 0 then [(1,index)] else []) ++ [(2,index)]
              (code,steps) = model (index+1) (owner:prior) rest
          in if owner < 0 then (code,prefix ++ steps)
             else if owner `elem` prior then (1,prefix ++ [(3,index)])
             else (code,prefix ++ [(3,index)] ++ steps)
    actual <- validate (ParentReplay.CtipSpends (fromIntegral (length owners)) action)
    observed <- readIORef seen
    pure (conjoin [actual === fst (model 0 [] owners), observed === snd (model 0 [] owners)])

ctipOwnersWorkflowParity :: Property
ctipOwnersWorkflowParity = forAll (listOf ((,,) <$> arbitrary <*> elements [-1,0,1,100,101 :: Int64] <*> arbitrary)) $ \entries ->
  ioProperty $ do
    pending <- newIORef entries
    seen <- newIORef []
    let action stage = do
          modifyIORef' seen (++[stage])
          remaining <- readIORef pending
          case (stage,remaining) of
            (1,(present,_,_):_) -> pure (if present then 1 else 0)
            (2,(_,value,_):_) -> pure value
            (3,(_,_,inserted):_) -> pure (if inserted then 1 else 0)
            (4,_:rest) -> writeIORef pending rest >> pure 1
            _ -> pure (-1)
        model :: [(Bool,Int64,Bool)] -> (Int32,[Word32])
        model [] = (0,[])
        model ((present,value,inserted):rest)
          | if present then value < 0 || value > 100 else value /= 0 = (1,[1,2])
          | present && not inserted = (2,[1,2,3])
          | otherwise = let (code,steps) = model rest
                        in (code,[1,2] ++ (if present then [3] else []) ++ [4] ++ steps)
    actual <- validate (ParentReplay.CtipOwners (fromIntegral (length entries)) 100 action)
    observed <- readIORef seen
    empty <- validate (ParentReplay.CtipOwners 0 0 (error "empty ownership forced callback"))
    pure (conjoin [actual === fst (model entries),observed === snd (model entries),empty === 0])

withdrawalExpiryWorkflowParity :: Property
withdrawalExpiryWorkflowParity = forAll (listOf (frequency [(3,choose (980,1002 :: Int64)),
  (1,elements [minBound,-1,0,0xffffffff,0x100000000,maxBound])])) $ \entries ->
  ioProperty $ do
    pending <- newIORef entries
    seen <- newIORef []
    let action stage = do
          modifyIORef' seen (++[stage])
          remaining <- readIORef pending
          case (stage,remaining) of
            (1,height:_) -> pure height
            (3,_:rest) -> writeIORef pending rest >> pure 1
            (4,_:rest) -> writeIORef pending rest >> pure 1
            _ -> pure (-1)
        model :: [Int64] -> (Int32,[Word32])
        model [] = (0,[])
        model (height:rest)
          | height < 0 || height > 0xffffffff = (-1,[1])
          | height > 1000 = (1,[1])
          | otherwise = let (code,steps) = model rest
                        in (code,[1,if 1000-height > 10 then 3 else 4] ++ steps)
    actual <- validate (ParentReplay.ExpireWithdrawals (fromIntegral (length entries)) 1000 10 action)
    observed <- readIORef seen
    stopped <- newIORef []
    rejected <- validate (ParentReplay.ExpireWithdrawals 2 1000 10 (\stage ->
      modifyIORef' stopped (++[stage]) >> pure 0))
    rejectedTrace <- readIORef stopped
    pure (conjoin [actual === fst (model entries),observed === snd (model entries),
      rejected === -1,rejectedTrace === [1,3]])

proposalExpiryWorkflowParity :: Property
proposalExpiryWorkflowParity = forAll (listOf ((,) <$>
  frequency [(3,choose (980,1002 :: Int64)),(1,elements [minBound,-1,0,0xffffffff,0x100000000,maxBound])] <*>
  frequency [(3,choose (0,25 :: Int64)),(1,elements [minBound,-1,65535,65536,maxBound])])) $ \entries ->
  ioProperty $ do
    pending <- newIORef entries
    seen <- newIORef []
    let action stage = do
          modifyIORef' seen (++[stage])
          remaining <- readIORef pending
          case (stage,remaining) of
            (1,(height,_):_) -> pure height
            (2,(_,votes):_) -> pure votes
            (3,_:rest) -> writeIORef pending rest >> pure 1
            (4,_:rest) -> writeIORef pending rest >> pure 1
            _ -> pure (-1)
        model :: [(Int64,Int64)] -> (Int32,[Word32])
        model [] = (0,[])
        model ((height,votes):rest)
          | height < 0 || height > 0xffffffff = (-1,[1])
          | height > 1000 = (1,[1])
          | votes < 0 || votes > 65535 = (-1,[1,2])
          | votes > 1000-height = (2,[1,2])
          | otherwise = let age = 1000-height
                            stage = if age > 10 || (age > 5 && age-votes >= 5) then 3 else 4
                            (code,steps) = model rest
                        in (code,[1,2,stage] ++ steps)
    actual <- validate (ParentReplay.ExpireProposals (fromIntegral (length entries)) 1000 5 10 action)
    observed <- readIORef seen
    empty <- validate (ParentReplay.ExpireProposals 0 0 0 0 (error "empty expiry forced callback"))
    pure (conjoin [actual === fst (model entries),observed === snd (model entries),empty === 0])

expectedVoteLeader :: [Word16] -> Int
expectedVoteLeader [] = -1
expectedVoteLeader values =
  let best = maximum values
      index = length (takeWhile (/=best) values)
      runnerUp = maximum (0:take index values ++ drop (index+1) values)
  in if best /= maxBound && toInteger best-toInteger runnerUp >= 50 then index else -1

replayLeaderParity :: Property
replayLeaderParity = forAll (listOf (frequency [(1,arbitrary),(1,elements [0,1,49,50,51,65534,65535 :: Word16])])) $ \values ->
  ioProperty $ withArray values $ \input -> do
    actual <- elements_hs_replay_leader (fromIntegral (length values)) input
    missing <- elements_hs_replay_leader 1 nullPtr
    empty <- elements_hs_replay_leader 0 nullPtr
    let expected = fromIntegral (expectedVoteLeader values)
    pure (conjoin [actual === expected,missing === -2,empty === -1])

replayLeadingParity :: Property
replayLeadingParity = forAll (listOf ((,) <$> elements [0,1,2 :: Word8] <*>
  frequency [(1,arbitrary),(1,elements [0,1,49,50,51,65534,65535 :: Word16])])) $ \entries ->
  let (keys,values) = unzip entries
      expectedLeader = expectedVoteLeader values
      selected = if expectedLeader < 0 then -1 else length (takeWhile (/= keys !! expectedLeader) keys)
      expectedVotes = if selected < 0 then values else
        [if i == selected then v+1 else if v == 0 then 0 else v-1 | (i,v) <- zip [0..] values]
  in ioProperty $ withArray (concatMap (replicate 32) keys) $ \hashes ->
    withArray (12345:values ++ [54321]) $ \out -> do
      actual <- elements_hs_replay_leading (fromIntegral (length values)) hashes (out `plusPtr` 2)
      observed <- peekArray (length values+2) out
      missing <- elements_hs_replay_leading 1 nullPtr (out `plusPtr` 2)
      missingVotes <- elements_hs_replay_leading 1 hashes nullPtr
      empty <- elements_hs_replay_leading 0 nullPtr nullPtr
      pure (conjoin [actual === fromIntegral expectedLeader, observed === 12345:expectedVotes ++ [54321],
        missing === -2, missingVotes === -2, empty === -1])

replayExplicitParity :: Property
replayExplicitParity = forAll (listOf ((,) <$> elements [0,1,2 :: Word8] <*>
  elements [0,1,65534,65535 :: Word16])) $ \entries ->
  forAll (elements ([0..fromIntegral (length entries)] ++ [65534,65535])) $ \vote ->
    let (keys,values) = unzip entries
        dec n = if n == 0 then 0 else n-1
        expected
          | vote == 65535 = (0,values)
          | vote == 65534 = (if any (>0) values then 2 else 0,map dec values)
          | fromIntegral vote >= length values = (3,values)
          | otherwise = let selected = length (takeWhile (/= keys !! fromIntegral vote) keys)
                        in if values !! selected == maxBound then (0,values) else
                          (1,[if i == selected then v+1 else dec v | (i,v) <- zip [0..] values])
    in ioProperty $ withArray (concatMap (replicate 32) keys) $ \hashes ->
      withArray (12345:values ++ [54321]) $ \out -> do
        actual <- elements_hs_replay_explicit vote (fromIntegral (length values)) hashes (out `plusPtr` 2)
        observed <- peekArray (length values+2) out
        missing <- elements_hs_replay_explicit 0 1 nullPtr nullPtr
        missingVotes <- elements_hs_replay_explicit 0 1 hashes nullPtr
        abstain <- elements_hs_replay_explicit 65535 maxBound nullPtr nullPtr
        invalid <- elements_hs_replay_explicit 65536 0 nullPtr nullPtr
        pure (conjoin [actual === fst expected,observed === 12345:snd expected ++ [54321],
          missing === -1,missingVotes === -1,abstain === 0,invalid === -1])

replayAlarmParity :: Property
replayAlarmParity = forAll (listOf (frequency [(1,arbitrary),(1,elements [0,1,65535 :: Word16])])) $ \values ->
  ioProperty $ withArray (12345:values ++ [54321]) $ \out -> do
    actual <- elements_hs_replay_alarm (fromIntegral (length values)) (out `plusPtr` 2)
    observed <- peekArray (length values+2) out
    missing <- elements_hs_replay_alarm 1 nullPtr
    empty <- elements_hs_replay_alarm 0 nullPtr
    let expected = [if n == 0 then 0 else n-1 | n <- values]
    pure (conjoin [actual === if any (/=0) values then 1 else 2,
      observed === 12345:expected ++ [54321],missing === -1,empty === 2])

replayUpvoteParity :: Property
replayUpvoteParity = forAll (listOf ((,) <$> choose (0,5 :: Word8) <*> elements [0,1,2,65534,65535 :: Word16])) $ \rows ->
  forAll (choose (0,6 :: Word8)) $ \target -> ioProperty $ do
    let keys = concatMap (replicate 32 . fst) rows
        values = map snd rows
        matches = [i | (i,(key,_)) <- zip [0..] rows, key == target]
        (expected,updated) = case matches of
          [] -> (0,values)
          first:_ | values !! first == maxBound -> (2,values)
                  | otherwise -> (1,[if i == first then n+1 else if n == 0 then 0 else n-1 | (i,n) <- zip [0..] values])
    withArray keys $ \hashes -> withArray (replicate 32 target) $ \key ->
      withArray (12345:values ++ [54321]) $ \out -> do
        actual <- elements_hs_replay_upvote (fromIntegral (length rows)) hashes key (out `plusPtr` 2)
        observed <- peekArray (length rows+2) out
        missing <- elements_hs_replay_upvote 1 nullPtr key (out `plusPtr` 2)
        missingVotes <- elements_hs_replay_upvote 1 hashes key nullPtr
        missingTarget <- elements_hs_replay_upvote 1 hashes nullPtr (out `plusPtr` 2)
        pure (conjoin [actual === expected,observed === 12345:updated ++ [54321],
          missing === -1,missingVotes === -1,missingTarget === -1])

rawDepositMatchParity :: Property
rawDepositMatchParity = forAll (elements [-1,0,24,255,256 :: Int64]) $ \slot ->
  forAll (elements [-1,0,1,100,101 :: Int64]) $ \amount ->
  forAll (elements [0,1,2 :: Word32]) $ \hasAddress ->
  forAll (choose (0,7)) $ \changed ->
  forAll (elements [-1,0,1,2,maxBound :: Int64]) $ \replacement -> ioProperty $ do
    calls <- newIORef []
    let success = [0,1,0,1,1,1,0,1]
        facts = take changed success ++ [replacement] ++ drop (changed+1) success
        valid = slot >= 0 && slot <= 255 && amount > 0 && amount <= 100 && hasAddress == 1
        answers :: [Int32]
        answers = [case head facts of 0 -> 0; 1 -> 3; 2 -> 2; _ -> -1] ++
          [if n < 0 || (i /= 6 && i /= 7 && n > 1) then -1
           else if (if i == 3 then n == 0 else if i == 7 then n <= 1 else n == 1) then 0 else i+1
           | (i,n) <- zip [2..8] (tail facts)]
        passed = length (takeWhile (==0) answers)
        expected = if not valid then 1 else if passed == 8 then 0 else answers !! passed
    actual <- validate (Deposit.RawMatch slot amount 100 hasAddress (\stage -> do
      modifyIORef' calls (++[stage])
      pure (facts !! (fromIntegral stage-1))))
    observed <- readIORef calls
    missing <- elements_hs_deposit_match slot amount 100 hasAddress nullFunPtr nullPtr
    pure (conjoin [actual === fromIntegral expected,
      observed === if valid then [1..fromIntegral (min 8 (passed+1))] else [],missing === -1])

matchScanParity :: Property
matchScanParity = forAll (listOf (elements [-1,0,1,2 :: Int32])) $ \facts -> ioProperty $ do
  calls <- newIORef []
  let action index = modifyIORef' calls (++[index]) >> pure (facts !! fromIntegral index)
      valid = takeWhile (\n -> n == 0 || n == 1) facts
      failed = length valid /= length facts
  result <- countMatches (fromIntegral (length facts)) action
  observed <- readIORef calls
  missing <- elements_hs_count_matches 0 nullFunPtr nullPtr
  oversized <- countMatches maxBound (error "oversized scan forced callback")
  pure (conjoin [result === if failed then -1 else fromIntegral (length (filter (==1) facts)),
    observed === map fromIntegral [0..length valid - if failed then 0 else 1],
    missing === -1,oversized === -1])

treasuryDeltaParity :: Property
treasuryDeltaParity = forAll amount $ \previous -> forAll amount $ \current ->
  forAll amount $ \claimed -> forAll amount $ \maximumValue -> ioProperty $ do
    actual <- elements_hs_treasury_delta previous current claimed maximumValue
    let expected = current >= 0 && current <= maximumValue && current > previous &&
          toInteger current == toInteger previous + toInteger claimed
    pure (actual === if expected then 1 else 0)
  where amount = frequency [(1,arbitrary),(1,elements [minBound,-1,0,1,2100000000000000,maxBound :: Int64])]

orderedFactsParity :: Property
orderedFactsParity = forAll (resize 12 (listOf ((,) <$> arbitrary <*>
  frequency [(3,pure 1),(1,elements [-1,0,2,4294967297 :: Int64])]))) $ \facts ->
  forAll arbitrary $ \success -> ioProperty $ do
    calls <- newIORef []
    let passed = length (takeWhile ((==1) . snd) facts)
        expected = if passed==length facts then success else
          let (code,reply) = facts !! passed in if reply==0 then code else -1
        checks = zip [0 :: Int ..] (map fst facts)
    actual <- Workflow.orderedFacts (\step -> modifyIORef' calls (++[step]) >> pure (snd (facts !! step))) checks success
    observed <- readIORef calls
    accepted <- Workflow.orderedFacts (\_ -> pure (1 :: Int64)) [((),error "success forced rejection code")] success
    malformed <- Workflow.orderedFacts (\_ -> pure (4294967297 :: Int64))
      [((),error "malformed status forced rejection code")] success
    rejected <- Workflow.orderedFacts (\_ -> pure (0 :: Int64))
      (((),7):error "rejection forced remaining checks") (error "rejection forced success")
    pure $ conjoin [actual===expected,observed===take (passed+1) [0..length facts-1],
      accepted===success,malformed===(-1),rejected===7]

reportedEffects :: Property
reportedEffects = forAll ((,,) <$> elements [-1,0,1,2 :: Int32] <*> arbitrary <*> elements [-1,0,1,2 :: Int32]) $
  \(first,reporting,reply) -> ioProperty $ do
    calls <- newIORef []
    let action stage = modifyIORef' calls (++[stage]) >> pure (if stage == 1 then first else if stage == 3 then reply else 1)
        rejection _ | first /= 0 = error "non-rejection forced the reporter mapping"
                    | reporting = Just (3 :: Int)
                    | otherwise = Nothing
    actual <- Workflow.runReportedEffects action rejection [1,2]
    observed <- readIORef calls
    pure $ conjoin [actual === (if first == 1 then 0 else -1),
      observed === if first == 1 then [1,2] else if first == 0 && reporting then [1,3] else [1]]

liveVerifyWorkflow :: Property
liveVerifyWorkflow = forAll (elements [0,1,2,maxBound :: Word64]) $ \index ->
  forAll (elements [0,1,2,maxBound :: Word64]) $ \inputs ->
  forAll (elements [0,1,2,maxBound :: Word64]) $ \witnessCount ->
  forAll (vectorOf 17 (elements [-1,0,1,2 :: Int32])) $ \facts -> ioProperty $ do
    calls <- newIORef []
    let action stage = modifyIORef' calls (++[stage]) >> pure (facts !! (fromIntegral stage-1))
    actual <- validate (Deposit.LiveVerify index inputs witnessCount action)
    observed <- readIORef calls
    writeIORef calls []
    abi <- bracket (wrapPolicyEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_deposit_verify index inputs witnessCount callback nullPtr
    abiTrace <- readIORef calls
    missing <- elements_hs_deposit_verify index inputs witnessCount nullFunPtr nullPtr
    let valid = index < inputs && index < witnessCount
        passed = length (takeWhile (==1) (take 12 facts))
        report = if valid && passed < 12 && facts !! passed == 0 then
          maybe [] pure (lookup (passed+1) [(1,13),(3,14),(4,14),(5,14),(6,15),(7,16),(8,17),(9,17),(10,17),(11,17)]) else []
        trace = if not valid then [] else [1..fromIntegral (min 12 (passed+1))] ++ report
    pure (conjoin [actual === if not valid then 1 else if passed == 12 then 0 else -1,
      observed === trace,abi === actual,abiTrace === trace,
      missing === -1])

evidenceBuildWorkflow :: Property
evidenceBuildWorkflow = forAll (elements [-1,0,1,maxBound :: Int64]) $ \sequenceNumber ->
  forAll (elements [-1,0,1,maxBound :: Int64]) $ \height ->
  forAll (choose (0,7 :: Word32)) $ \flags ->
  forAll (vectorOf 8 (elements [-1,0,1,2 :: Int32])) $ \facts -> ioProperty $ do
    calls <- newIORef []
    let action stage = do
          modifyIORef' calls (++[stage])
          pure (facts !! (fromIntegral stage-1))
    actual <- validate (Deposit.EvidenceBuild sequenceNumber height flags action)
    observed <- readIORef calls
    writeIORef calls []
    abi <- bracket (wrapPolicyEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_deposit_build sequenceNumber height flags callback nullPtr
    abiTrace <- readIORef calls
    let valid = sequenceNumber > 0 && height >= 0 && flags == 3
        planned = [1,5,6,7,2,3,4]
        replies = map (\stage -> facts !! (fromIntegral stage-1)) planned
        passed = length (takeWhile (==1) replies)
        report = if passed < 7 && replies !! passed == 0 && planned !! passed `elem` [5,6,7] then [8] else []
        trace = if not valid then [] else take (passed+1) planned ++ report
    missing <- elements_hs_deposit_build sequenceNumber height flags nullFunPtr nullPtr
    lazyStop <- runRequiredEffects (\_ -> pure (0 :: Int32)) ((1 :: Int):error "rejected effect tail forced")
    wideStop <- runRequiredEffects (\_ -> pure (4294967297 :: Int64)) ((1 :: Int):error "wide failure tail forced")
    pure (conjoin [actual === if not valid then 1 else if passed == 7 then 0 else -1,
      observed === trace,abi === actual,abiTrace === trace,
      missing === -1,lazyStop === -1,wideStop === -1])

depositHeaderWorkflow :: Property
depositHeaderWorkflow = forAll (choose (0,1000000 :: Word64)) $ \first ->
  forAll (elements [-1,0,1,2,2016,2017 :: Int64]) $ \distance ->
  forAll (choose (0,4040 :: Int)) $ \stop -> ioProperty $ do
    calls <- newIORef []
    counter <- newIORef (0 :: Int)
    let tip = fromIntegral first + distance
        valid = tip >= 0 && distance >= 0 && distance <= 2016
        planned = (1,0) : [(stage,height) | height <- [first..fromIntegral tip], stage <- [2,4]]
        action stage height = do
          modifyIORef' calls ((stage,height):)
          modifyIORef' counter (+1)
          count <- readIORef counter
          pure (if count == stop then 0 else 1)
    actual <- validate (Deposit.HeaderBuild first tip action)
    observed <- reverse <$> readIORef calls
    writeIORef calls []
    writeIORef counter 0
    abi <- bracket (wrapProofBuildEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_deposit_headers first tip callback nullPtr
    abiTrace <- reverse <$> readIORef calls
    missing <- elements_hs_deposit_headers first tip nullFunPtr nullPtr
    let rejected = stop > 0 && stop <= length planned
        prefix = take stop planned
        report = if rejected && fst (last prefix) == 2 then [(3,snd (last prefix))] else []
    pure (conjoin [actual === if not valid then 1 else if rejected then -1 else 0,
      observed === if not valid then [] else if rejected then prefix ++ report else planned,
      abi === actual,abiTrace === observed,
      missing === -1])

ctipSearchWorkflow :: Property
ctipSearchWorkflow = forAll (choose (0,30)) $ \count ->
  forAll (vectorOf count (vectorOf 5 (elements [-1,0,1,2 :: Int32]))) $ \facts -> ioProperty $ do
    calls <- newIORef []
    let model _ found [] = (if found then 0 else 1,[])
        model index found (row:rest) =
          let next matched prefix = let (code,remaining) = model (index+1) matched rest in (code,prefix++remaining)
              stages = [1,3,4,5]
              replies = map (\stage -> row !! (stage-1)) stages
              passed = length (takeWhile (==1) replies)
              probe = if passed == 4 then 1 else replies !! passed
              stored = row !! 1
              probeTrace = [(fromIntegral stage,index) | stage <- take (passed+1) stages]
              storeTrace = probeTrace ++ [(2,index)]
          in case probe of
            0 -> next found probeTrace
            1 | found -> (2,probeTrace)
              | stored == 0 -> next False storeTrace
              | stored == 1 -> next True storeTrace
              | otherwise -> (-1,storeTrace)
            _ -> (-1,probeTrace)
        (expected,trace) = model 0 False facts
        action stage index = do
          modifyIORef' calls (++[(stage,index)])
          pure (facts !! fromIntegral index !! (fromIntegral stage-1))
    actual <- validate (Deposit.CtipSearch (fromIntegral count) action)
    observed <- readIORef calls
    writeIORef calls []
    abi <- bracket (wrapProofBuildEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_deposit_ctip_search (fromIntegral count) callback nullPtr
    abiTrace <- readIORef calls
    missing <- elements_hs_deposit_ctip_search (fromIntegral count) nullFunPtr nullPtr
    pure (conjoin [actual === expected,observed === trace,abi === actual,abiTrace === trace,missing === -1])

proofBuildWorkflow :: Property
proofBuildWorkflow = forAll (choose (0,1000000 :: Word64)) $ \previous ->
  forAll (elements [-1,0,1,126,127,128,129 :: Int64]) $ \distance ->
  forAll (choose (0,650 :: Int)) $ \stop -> ioProperty $ do
    calls <- newIORef []
    let parent = fromIntegral previous + distance
        valid = parent >= 0 && distance >= 0 && distance < 128
        planned = [(1,previous),(2,fromIntegral parent),(3,0)] ++
          [(stage,height) | height <- [previous+1..fromIntegral parent+1], stage <- [4,9,10,11,12]] ++ [(5,0)]
        action stage height = do
          modifyIORef' calls (++[(stage,height)])
          observed <- readIORef calls
          pure (if length observed == stop then 0 else 1)
    actual <- validate (Bmm.ProofBuild previous parent action)
    observed <- readIORef calls
    writeIORef calls []
    abi <- bracket (wrapProofBuildEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_bmm_proof_build previous parent callback nullPtr
    abiTrace <- readIORef calls
    let rejected = stop > 0 && stop <= length planned
        prefix = take stop planned
        report = if rejected then case lookup (fst (last prefix)) [(1,6),(2,7),(5,8),(9,13),(10,13),(11,13)] of
            Just stage -> [(stage,snd (last prefix))]
            Nothing -> []
          else []
        trace = if not valid then [] else if rejected then prefix ++ report else planned
    missing <- elements_hs_bmm_proof_build previous parent nullFunPtr nullPtr
    pure (conjoin [actual === if not valid then 1 else if rejected then -1 else 0,
      observed === trace,abi === actual,abiTrace === trace,
      missing === -1])

resultPublication :: Property
resultPublication = once $ ioProperty $ withArray ([99,99,99,99] :: [Word8]) $ \output -> do
  rejected <- publishResult (error "rejected writer forced") (Left 7 :: Either Int32 Int)
  rejectedBytes <- publishBytes 4 output (Left 5 :: Either Int32 B.ByteString)
  unchanged <- peekArray 4 output
  accepted <- publishBytes 4 output (Right (B.pack [1,2,3,4]) :: Either Int32 B.ByteString)
  copied <- peekArray 4 output
  calls <- newIORef (0 :: Int)
  failed <- try (publishResult (\_ -> modifyIORef' calls (+1) >> ioError (userError "write failure"))
    (Right () :: Either Int32 ())) :: IO (Either SomeException Int32)
  observed <- readIORef calls
  pure (conjoin [rejected === 7,rejectedBytes === 5,unchanged === replicate 4 99,
    accepted === 0,copied === [1,2,3,4],observed === 1,
    counterexample "write exception was swallowed" (either (const True) (const False) failed)])

parentRpcAddress :: Property
parentRpcAddress = forAll arbitrary $ \ipv4 ->
  forAll (vectorOf 16 arbitrary) $ \ipv6 -> ioProperty $ do
    v4 <- elements_hs_parent_rpc_address 4 ipv4 0 nullPtr
    v6 <- B.useAsCString (B.pack ipv6) $ \ptr ->
      elements_hs_parent_rpc_address 6 0 16 (castPtr ptr)
    missing <- elements_hs_parent_rpc_address 6 0 16 nullPtr
    unsupported <- elements_hs_parent_rpc_address 0 0 0 nullPtr
    truncated <- elements_hs_parent_rpc_address 6 0 15 nullPtr
    loopback <- B.useAsCString (B.pack (replicate 15 0 ++ [1])) $ \ptr ->
      elements_hs_parent_rpc_address 6 0 16 (castPtr ptr)
    pure (conjoin [v4 === if ipv4 `div` 16777216 == 127 then 1 else 0,
      v6 === if ipv6 == replicate 15 0 ++ [1] then 1 else 0,
      missing === -1,unsupported === -1,truncated === -1,loopback === 1])

policyCallBoundary :: Property
policyCallBoundary = once $ ioProperty $ do
  calls <- newIORef []
  bracket (wrapPolicyEffect (\_ step -> modifyIORef' calls (++[step]) >> pure (fromIntegral step))) freeHaskellFunPtr $ \callback -> do
    missing <- policyCall (error "null callback forced interpreter") nullFunPtr nullPtr
    rejected <- policyCall (\readFact -> readFact 7 >> ioError (userError "interpreter failure")) callback nullPtr
    constructionFailure <- policyCall (error "interpreter construction failure") callback nullPtr
    accepted <- policyCall (\readFact -> readFact 9) callback nullPtr
    observed <- readIORef calls
    pure (conjoin [missing === -1,rejected === -1,constructionFailure === -1,accepted === 9,observed === [7,9]])

productionStages :: Property
productionStages = forAllBlind (elements
  [([(13,2)],[1,2,13,3,4,5,6,7,8,9,10],
    [(1,101),(2,102),(13,102),(3,103),(6,106),(7,107)],
    Bmm.NativeProduction,elements_hs_bmm_native_production),
   ([(19,1),(20,2),(15,3),(16,6),(17,9),(18,10)],[1,19,2,20,3,15,4,5,6,16,7,8,9,17,10,18,11,12,13,14],
    [(1,101),(19,101),(2,102),(20,102),(3,103),(15,115),(4,104),
     (6,106),(16,116),(7,107),(9,109),(10,110),(12,112)],
    Bmm.EcxProduction,elements_hs_bmm_ecx_production),
   ([],[1..5],[],Bmm.SyncTick,elements_hs_bmm_sync_tick)]) $ \(originalStages,steps,reports,workflow,entry) ->
  forAll (choose (0,length steps)) $ \position ->
  forAll (elements [-1,0,2]) $ \reply ->
  forAll (elements [-1,0,1,2]) $ \reportReply -> ioProperty $ do
  let failure = if position == length steps then 0 else steps !! position
      expected | failure == 0 = 0
               | reply /= 0 = -1
               | otherwise = fromIntegral (maybe failure id (lookup failure originalStages))
      trace = take (position+1) steps ++
        [report | reply == 0, Just report <- [lookup failure reports]]
      run invoke = do
        calls <- newIORef []
        result <- invoke (\stage -> do
          modifyIORef' calls (++[stage])
          pure (if stage >= 100 then reportReply else if stage == failure then reply else 1))
        observed <- readIORef calls
        pure (result,observed)
  direct <- run (validate . workflow)
  foreignResult <- run $ \action -> bracket (wrapPolicyEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
    entry callback nullPtr
  missing <- entry nullFunPtr nullPtr
  pure (conjoin [direct === (expected,trace),foreignResult === direct,missing === -1])

bmmSyncHeights :: Property
bmmSyncHeights = forAll height $ \parent -> forAll height $ \child ->
  forAll (elements [0,4,5]) $ \failure -> forAll (elements [-1,0,2]) $ \reply -> ioProperty $ do
  let behind = child < parent
      expected | not behind = 3
               | failure == 0 = 0
               | reply == 0 = failure
               | otherwise = -1
      trace | not behind = []
            | failure == 4 = [4]
            | otherwise = [4,5]
      run invoke = do
        calls <- newIORef []
        result <- invoke (\stage -> do
          modifyIORef' calls (++[stage])
          pure (if fromIntegral stage == failure then reply else 1))
        observed <- readIORef calls
        pure (result,observed)
  direct <- run (validate . Bmm.SyncHeights parent child)
  foreignResult <- run $ \action -> bracket (wrapPolicyEffect (\_ -> action)) freeHaskellFunPtr $ \callback ->
    elements_hs_bmm_sync_heights parent child callback nullPtr
  missing <- elements_hs_bmm_sync_heights parent child nullFunPtr nullPtr
  pure (conjoin [direct === (expected,trace),foreignResult === direct,missing === -1])
  where height = oneof [arbitrary,elements [minBound,-1,0,1,maxBound]]

bmmWaitWorkflow :: Property
bmmWaitWorkflow = forAll (vectorOf 12 ((,,) <$> arbitrary <*> choose (-1,4) <*> arbitrary)) $ \observations -> ioProperty $ do
  let events = observations ++ [(False,0,False)]
      model index failures = let (running,status,continued) = events !! index in
        if not running then (0,[1]) else case status of
          1 -> (1,[1,2,4])
          2 | failures == 2 -> (0,[1,2,5])
          n | n `elem` [0,2,3] ->
            let failures' = if n == 0 then 0 else if n == 2 then failures+1 else failures
                prefix = [1,2] ++ [3 | index `mod` 4 == 0] ++ [6]
                (result,rest) = if continued then model (index+1) failures' else (0,[])
            in (result,prefix++rest)
          _ -> (-1,[1,2])
  position <- newIORef 0
  calls <- newIORef []
  actual <- validate (Bmm.WaitForBmm (\step -> do
    modifyIORef' calls (++[step])
    index <- readIORef position
    let (running,status,continued) = events !! index
    case step of
      1 -> pure (if running then 1 else 0)
      2 -> pure status
      6 -> writeIORef position (index+1) >> pure (if continued then 1 else 0)
      _ -> pure 1))
  observed <- readIORef calls
  missing <- elements_hs_bmm_wait nullFunPtr nullPtr
  pure (conjoin [(actual,observed) === model 0 (0 :: Int),missing === -1])

feeAssetResolution :: Property
feeAssetResolution = forAll (vectorOf 32 arbitrary) $ \raw -> forAll arbitrary $ \canonical ->
  forAll (choose (0,4 :: Int)) $ \choice -> ioProperty $ do
    let pegged = replicate 32 7
        requested = case choice of 1 -> pegged; 4 -> replicate 32 0; _ -> raw
        text = if choice == 3 then C.pack (replicate 64 'z') else if choice == 0 then B.empty
          else C.pack (concatMap (\n -> ["0123456789ABCDEF" !! fromIntegral (n `div` 16),
                                        "0123456789ABCDEF" !! fromIntegral (n `mod` 16)]) (reverse requested))
        flags = (if choice == 0 then 0 else 1) + (if canonical then 2 else 0)
        expected | choice == 3 = 1
                 | choice /= 0 && canonical && requested /= pegged = 2
                 | otherwise = 0
        wanted = if expected /= 0 then replicate 32 170 else if choice == 0 then pegged else requested
    withArray pegged $ \asset -> withArray (B.unpack text) $ \input -> withArray (replicate 32 170) $ \output -> do
      code <- elements_hs_fee_asset flags (fromIntegral (B.length text)) input asset output
      actual <- peekArray 32 output
      malformed <- elements_hs_fee_asset 4 0 nullPtr asset output
      pure (conjoin [code === expected,actual === wanted,malformed === -1])

bmmRewardAdmission :: Property
bmmRewardAdmission = forAll (vectorOf 5 (elements [-1,0,1,2])) $ \facts -> ioProperty $ do
  calls <- newIORef []
  actual <- validate (Bmm.RewardAddress (\step -> do
    modifyIORef' calls (++ [step])
    pure (facts !! (fromIntegral step-1))))
  observed <- readIORef calls
  let passed = length (takeWhile (==1) facts)
      expected | passed == 5 = 0
               | facts !! passed == 0 = fromIntegral (passed+1)
               | otherwise = -1
  missing <- elements_hs_bmm_reward_address nullFunPtr nullPtr
  pure (conjoin [actual === expected,observed === [1..fromIntegral (min 5 (passed+1))],missing === -1])

depositStateWorkflowParity :: Property
depositStateWorkflowParity = forAll ((,,) <$> elements [0,11,19,27 :: Word32] <*>
    vectorOf 83 (choose (0,7 :: Int64)) <*> choose (-1,30 :: Int)) $ \(start,facts,fault) -> ioProperty $ do
  let states = [(2,0),(9,1),(25,2),(28,3),(30,4),(33,5),(13,6),(17,7)]
      run combined = do
        seen <- newIORef []
        let raw step = do
              trace <- readIORef seen
              modifyIORef' seen (++[step])
              if length trace == fault then ioError (userError "state callback failure")
              else pure (if step > 82 then 1 else case lookup step states of
                    Nothing -> facts !! fromIntegral step `mod` 2
                    Just _ -> facts !! fromIntegral step)
            legacy step = do
              value <- raw step
              case lookup step states of
                Nothing -> pure value
                Just phase -> case validate (Deposit.DepositStateRule phase (fromIntegral value)) of
                  0 -> pure 1
                  code -> raw (82+fromIntegral code) >> pure 0
        result <- try (if combined then validate (Deposit.DepositStateWorkflow start raw)
          else validate (Workflow.PredicateFlow True start 82
            (\phase value -> fromIntegral (validate (Deposit.DepositVerification phase value))) legacy))
          :: IO (Either SomeException Int32)
        trace <- readIORef seen
        pure (either (const (-99)) id result,trace)
  old <- run False
  new <- run True
  pure (new === old)

wholeReplayMessages :: Property
wholeReplayMessages = forAll generator $ \(kinds,proposed,votes,used,activation,flags,fault) -> ioProperty $ do
  let run combined = do
        seen <- newIORef []
        let native step index input = do
              trace <- readIORef seen
              modifyIORef' seen (++[(step,index,input)])
              if length trace == fault then ioError (userError "message callback failure")
              else pure $ case step of
                0 -> B.pack [kinds !! fromIntegral index,flags,0,0]
                11 -> wordLE 8 (fromIntegral proposed)
                12 -> wordLE 8 (fromIntegral votes)
                13 -> wordLE 8 (if used then 1 else 0)
                15 -> wordLE 8 activation
                21 -> wordLE 8 (if used then 1 else 0)
                22 -> wordLE 8 0
                30 -> B.pack [24,if used then 1 else 0]
                31 -> B.empty
                32 -> B.singleton (if used then 1 else 0)
                _ | step >= 10 && step < 30 -> wordLE 8 1
                  | otherwise -> B.empty
            scalar base step value = do
              response <- native (base+step) value B.empty
              pure (fromIntegral (B.foldr (\byte rest -> fromIntegral byte+256*rest) (0 :: Word64) response))
            translate group failure result
              | result < 0 = failure
              | result == 0 = 0
              | otherwise = group+result
            legacy index
              | index == length kinds = native 40 0 B.empty >> pure 0
              | otherwise = do
                  _ <- native 0 (fromIntegral index) B.empty
                  result <- case validate (ParentReplay.StoreFlow 91 2 (fromIntegral (kinds !! index))) of
                    3 -> native 2 0 B.empty >> pure 0
                    4 -> do
                      _ <- native 3 0 B.empty
                      translate 0x100 (-2) <$> validate (ParentReplay.M2Proposal 100 4 1 2 2 (scalar 10))
                    5 -> translate 0x200 (-3) <$> validate (ParentReplay.M3Proposal (scalar 20))
                    -11 -> pure 0
                    _ -> translate 0x300 (-4) <$> validate (ParentReplay.M4Workflow (fromIntegral flags) [0]
                           (\step slot input -> native (30+step) slot input))
                  if result == 0 then legacy (index+1) else pure result
        result <- try (if combined then validate (ParentReplay.MessageWorkflow
            (fromIntegral (length kinds)) 100 0x0002000200010004 native)
          else legacy 0) :: IO (Either SomeException Int32)
        trace <- readIORef seen
        pure (either (const (-99)) id result,trace)
  old <- run False
  new <- run True
  pure (new === old)
  where
    generator = (,,,,,,) <$> resize 12 (listOf (elements [0,1,2,3,4,5,6,255 :: Word8]))
      <*> elements [-2,0,95,96,98,99,100,101 :: Int64]
      <*> elements [0,1,2,65535,0xffffffff :: Int64] <*> arbitrary <*> choose (0,7)
      <*> elements [0,1,3,5,9,13,16 :: Word8] <*> choose (-1,60 :: Int)

replayMessageFraming :: Property
replayMessageFraming = forAll ((,) <$> elements [0,1,3,5,7] <*> arbitrary) $ \(size,badEffect) -> ioProperty $ do
  seen <- newIORef []
  let native step _ _ = do
        modifyIORef' seen (++[step])
        pure $ if step == 0 then if badEffect then B.pack [1,0] else B.replicate size 0 else B.singleton 1
  result <- validate (ParentReplay.MessageWorkflow 1 100 0 native)
  trace <- readIORef seen
  pure $ conjoin [result === -1,trace === if badEffect then [0,2] else [0]]

wholeM4Voting :: Property
wholeM4Voting = forAll generator $ \(flags,votes,vote,active,upvote,missing) -> ioProperty $ do
  seen <- newIORef []
  writes <- newIORef []
  let key i = B.replicate 32 (fromIntegral (i+1 :: Int))
      target = key (if missing then length votes else 0)
      native step slot frame = do
        modifyIORef' seen (++[step])
        case step of
          0 -> pure (B.pack [24,if active then 1 else 0])
          1 -> pure (B.pack [24,if upvote then 1 else 0] <> if upvote then target else B.replicate 32 0)
          2 | slot == 24 -> pure (B.singleton (if active then 1 else 0) <>
                if active then B.concat [key i <> wordLE 2 (fromIntegral v) | (i,v) <- zip [0..] votes] else B.empty)
          3 | slot == 24 -> modifyIORef' writes (++[frame]) >> pure B.empty
          _ -> ioError (userError "unexpected voting callback")
      down v = if v == 0 then 0 else v-1
      publish kind digest updated = B.cons kind digest <> B.concat (map (wordLE 2 . fromIntegral) updated)
      alarm = if any (>0) votes then [publish 0 (B.replicate 32 0) (map down votes)] else []
      promote i = if votes !! i == maxBound then [] else [publish 1 (key i)
        [if j == i then v+1 else down v | (j,v) <- zip [0..] votes]]
      leaders = List.sortOn (negate . fromIntegral . snd :: (Int,Word16) -> Int) (zip [0..] votes)
      leading = case leaders of
        (i,best):rest | best /= maxBound && fromIntegral best - (case rest of [] -> 0; (_,second):_ -> fromIntegral second) >= (50 :: Int) -> promote i
        _ -> []
      (wanted,prefix,updates)
        | flags > 15 = (-1,[],[])
        | not (testBit flags 0) = (1,[],[])
        | testBit flags 1 = (2,[],[])
        | testBit flags 2 && not active = (3,[0],[])
        | testBit flags 2 && vote == 65535 = (0,[0],[])
        | testBit flags 2 && vote /= 65534 && fromIntegral vote >= length votes = (4,[0,2],[])
        | testBit flags 2 = (0,[0,2],if vote == 65534 then alarm else promote (fromIntegral vote))
        | testBit flags 3 = (0,if active then [0,2] else [0],if active then leading else [])
        | not active = (5,[0,1,2],[])
        | upvote && (missing || null votes) = (6,[0,1,2],[])
        | otherwise = (0,[0,1,2],if upvote then promote 0 else alarm)
  result <- validate (ParentReplay.M4Workflow flags [vote] native)
  trace <- readIORef seen
  changes <- readIORef writes
  pure $ conjoin [result === wanted, trace === prefix ++ [3 | not (null updates)], changes === updates]
  where
    generator = (,,,,,) <$> elements [0,1,3,5,9,13,16] <*> resize 8 (listOf (elements [0,1,49,50,51,65534,65535 :: Word16]))
      <*> elements [0,1,7,65534,65535 :: Word16] <*> arbitrary <*> arbitrary <*> arbitrary

credentialRecordOrder :: Property
credentialRecordOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,3 :: Int)) $ \(readOk,valid,fault) -> ioProperty $ do
  let script = [(1,if readOk then 1 else 0)] ++ if not readOk then [] else
        [(2,if valid then 1 else 0)] ++ [(3,1) | not valid]
  commandTrace 273 3 (\phase reply -> validate (Bmm.CredentialRecordFlow phase reply))
    script fault (if readOk && valid then 1 else 0)

startupParentOrder :: ParentReplay.StartupParentStage -> Property
startupParentOrder stage = forAll ((,) <$> arbitrary <*> choose (-1,8 :: Int)) $
  \((enabled,warm,epoch,sweep,reconcile,activate),fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        (kind,limit) = case stage of
          ParentReplay.ParentLoad -> (315,8)
          ParentReplay.ParentVerify -> (316,7)
          ParentReplay.ParentServe -> (291,8)
        (script,outcome) = prefix [(7,bit enabled)] $ if not enabled then ([],0) else
          prefix ([(8,1) | stage /= ParentReplay.ParentVerify] ++ [(1,bit warm)]) $
          if not warm then ([],1) else case stage of
            ParentReplay.ParentLoad -> ([(2,bit epoch)],if epoch then 0 else 1)
            ParentReplay.ParentVerify -> ([(5,bit reconcile)],if reconcile then 0 else 3)
            ParentReplay.ParentServe -> prefix [(2,bit epoch)] $ if not epoch then ([],2) else
              prefix ([(3,bit sweep)] ++ [(4,1) | not sweep]) $
                prefix [(5,bit reconcile)] $ if not reconcile then ([],3) else
                  ([(6,bit activate)],if activate then 0 else 3)
    commandTrace kind limit (\phase reply -> validate (ParentReplay.StartupParentFlow stage phase reply)) script fault outcome

startupBundleOrder :: Property
startupBundleOrder = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,6 :: Int)) $
  \(enabled,present,fault) -> ioProperty $ do
    let script = [(1,if enabled then 1 else 0)] ++ if not enabled then [(6,1)] else
          [(2,if present then 1 else 0)] ++ [(3,1) | present] ++ [(4,1),(5,1)]
    commandTrace 317 6 (\phase reply -> validate (ParentReplay.StartupBundleFlow phase reply)) script fault 0

blockValidationOrder :: ParentReplay.BlockValidationStage -> Property
blockValidationOrder stage = forAll ((,) <$> arbitrary <*> choose (-1,9 :: Int)) $
  \((a,b,c,d,e,f,g),fault) -> ioProperty $ do
    let fact n flag = (n,if flag then 1 else 0)
        prefix steps (rest,status) = (steps ++ rest,status)
        result flag = if flag then 1 else 0
        (kind,limit) = case stage of
          ParentReplay.ContextualHeader -> (318,3)
          ParentReplay.ContextualOutputs -> (319,4)
          ParentReplay.CandidateSelfCheck -> (320,9)
          ParentReplay.BranchChoice -> (321,3)
          ParentReplay.StartupReconcile -> (322,6)
          ParentReplay.FinalBmm -> (324,8)
          ParentReplay.BmmFailure -> (325,5)
        (script,outcome) = case stage of
          ParentReplay.ContextualHeader -> prefix [fact 1 a] $ if not a then ([],1) else
            prefix [fact 2 b] $ if not b then ([],0) else ([fact 3 c],result c)
          ParentReplay.ContextualOutputs -> prefix ([fact 1 a] ++ [fact 2 b | a]) $
            if a && not b then ([],0) else prefix [fact 3 c] $
              if c then ([fact 4 d],result d) else ([],1)
          ParentReplay.CandidateSelfCheck -> prefix [fact 1 a] $ if not a then ([],0) else
            prefix [fact 2 b] $ if not b then ([],0) else
              prefix [fact 3 c] $ if not c then ([],0) else
                prefix ([(4,1),fact 5 d] ++ [fact 6 e | not d]) $
                  if d || not e then ([fact 9 g],result g) else
                    prefix [fact 7 f] $ if not f then ([],0) else ([(8,1),fact 9 g],result g)
          ParentReplay.BranchChoice -> ([fact 1 a,if a then fact 2 b else fact 3 c],result (if a then b else c))
          ParentReplay.StartupReconcile -> prefix [fact 1 a] $ if not a then ([(2,0)],0) else
            prefix [(3,1),fact 4 b] $ if not b then ([],0) else
              prefix [fact 5 c] $ if c then ([(6,0)],0) else ([],1)
          ParentReplay.FinalBmm -> prefix [fact 1 a] $ if not a then ([],1) else
            prefix [fact 2 b] $ if not b then ([],1) else
              prefix [fact 3 c] $ if not c then ([(4,0)],0) else
                prefix [fact 5 d] $ if d then ([(6,0)],0) else
                  prefix [fact 7 e] $ if e then ([],1) else ([(8,1)],2)
          ParentReplay.BmmFailure -> prefix [fact 1 a] $ if a then ([(2,0)],0) else
            ([fact 3 b,(if b then 4 else 5,0)],0)
    commandTrace kind limit (\phase reply -> validate (ParentReplay.BlockValidationFlow stage phase reply)) script fault outcome

connectionStateOrder :: Property
connectionStateOrder = forAll ((,) <$> arbitrary <*> choose (-1,12 :: Int)) $
  \((elementsMode,effective,privateMode,parentOk,bmmOk,exchangeOk,bundleOk),fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        rejectAt step = ([(step,0)],0)
        privateLookup = privateMode && effective
        (script,outcome) = prefix [(1,bit elementsMode)] $ if not elementsMode then ([],1) else
          prefix ([(2,bit effective)] ++ [(3,1) | effective] ++ [(4,bit privateLookup)] ++
            [(5,bit parentOk) | privateLookup] ++ [(6,1) | privateLookup && parentOk]) $
          prefix [(7,bit bmmOk)] $ if not bmmOk then rejectAt 8 else
            prefix [(9,bit exchangeOk)] $ if not exchangeOk then rejectAt 10 else
              prefix [(11,bit bundleOk)] (if bundleOk then ([],1) else rejectAt 12)
    commandTrace 288 12 (\phase reply -> validate (ParentReplay.ConnectionStateFlow phase reply))
      script fault outcome

connectionAnchorOrder :: Property
connectionAnchorOrder = forAll ((,) <$> arbitrary <*> choose (-1,11 :: Int)) $
  \((sane,persisted,dryRun,matching,unanchored,badSuccessor),fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        rejectAt step = ([(step,0)],0)
        (script,outcome) = prefix [(1,bit sane)] $ if not sane then rejectAt 2 else
          prefix [(3,bit persisted)] $ if not persisted then
            prefix [(4,bit dryRun)] (if dryRun then ([],1) else rejectAt 5)
          else prefix [(6,bit matching)] $ if not matching then rejectAt 7 else
            prefix [(8,bit unanchored)] $ if unanchored then rejectAt 9 else
              prefix [(10,bit badSuccessor)] (if badSuccessor then rejectAt 11 else ([],1))
    commandTrace 287 11 (\phase reply -> validate (ParentReplay.ConnectionAnchorFlow phase reply))
      script fault outcome

ephemeralHeaderOrder :: Property
ephemeralHeaderOrder = forAll ((,) <$> arbitrary <*> choose (-1,13 :: Int)) $
  \((native,indexed,headerOk,previous,failed,authenticated,contextOk),fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        rejectAt step = ([(step,0)],0)
        (script,outcome) = prefix [(1,bit native)] $ if not native then rejectAt 2 else
          prefix [(3,bit indexed)] $ if indexed then rejectAt 4 else
          prefix [(5,bit headerOk)] $ if not headerOk then ([],0) else
          prefix [(6,bit previous)] $ if not previous then rejectAt 7 else
          prefix [(8,bit failed)] $ if failed then rejectAt 9 else
          prefix [(10,bit authenticated)] $ if not authenticated then rejectAt 11 else
          prefix [(12,bit contextOk)] $ if not contextOk then ([],0) else ([(13,1)],1)
    commandTrace 286 13 (\phase reply -> validate (ParentReplay.EphemeralHeaderFlow phase reply))
      script fault outcome

recoveryAncestorOrder :: Property
recoveryAncestorOrder = forAll ((,,,,) <$> choose (0,6 :: Int) <*> choose (0,6 :: Int) <*>
  arbitrary <*> vectorOf 6 (choose (-3,4 :: Int)) <*> choose (-1,60 :: Int)) $
  \(left,right,forest,heights,fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        parent node = if node==1 || (forest && node==4) then 0 else node `div` 2
        height node = heights !! (node-1)
        both base a b yes no = prefix [(base,bit (a/=0))] $
          if a==0 then no else prefix [(base+1,bit (b/=0))] $ if b==0 then no else yes
        alignLeft a b = both 1 a b
          (let higher = height a > height b in prefix [(3,bit higher)] $
             if higher then prefix [(4,1)] (alignLeft (parent a) b) else alignRight a b)
          (alignRight a b)
        alignRight a b = both 5 a b
          (let higher = height b > height a in prefix [(7,bit higher)] $
             if higher then prefix [(8,1)] (alignRight a (parent b)) else converge a b)
          (converge a b)
        converge a b = both 9 a b
          (prefix [(11,bit (a/=b))] $ if a/=b then
            prefix [(12,1)] (converge (parent a) (parent b)) else finish a b)
          (finish a b)
        finish a b = ([(13,bit (a==b))],if a==b then 1 else 0)
        (script,outcome) = alignLeft left right
    commandTrace 284 13 (\phase reply -> validate (ParentReplay.RecoveryAncestorFlow phase reply))
      script fault outcome

recoveryAdmissionOrder :: Property
recoveryAdmissionOrder = forAll ((,) <$> vectorOf 7 arbitrary <*> choose (-1,8 :: Int)) $
  \(flags,fault) -> ioProperty $ do
    let yes :: Word32 -> Bool
        yes step = flags !! (fromIntegral step-1)
        bit step = if yes step then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        rejected = ([(8,0)],0)
        alternatives [] = ([],1)
        alternatives (step:rest) = prefix [(step,bit step)] $
          if yes step then rejected else alternatives rest
        (script,outcome) = prefix [(1,bit 1)] $ if not (yes 1) then ([],0) else
          prefix [(2,bit 2)] $ if not (yes 2) then ([],0) else
            prefix [(3,bit 3)] (alternatives ((if yes 3 then [4,5] else []) ++ [6,7]))
    commandTrace 285 8 (\phase reply -> validate (ParentReplay.RecoveryAdmissionFlow phase reply))
      script fault outcome

branchReplayOrder :: Property
branchReplayOrder = forAll ((,,) <$> arbitrary <*> resize 4 (listOf
  ((,,,) <$> arbitrary <*> arbitrary <*> vectorOf 4 arbitrary <*>
    resize 4 (listOf (resize 4 (listOf (vectorOf 4 arbitrary)))))) <*> choose (-1,150 :: Int)) $
  \(elementsMode,blocks,fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        found = ([(10,1)],1)
        scan [] = ([(1,0)],1)
        scan ((atFork,readOk,marks,transactions):rest) = prefix [(1,1),(2,bit (not atFork))] $
          if atFork then ([],1) else prefix [(3,bit readOk)] $
          if not readOk then ([(4,0)],0) else prefix [(5,bit elementsMode)] $
          let body = prefix [(11,1)] (txs transactions rest)
          in if elementsMode then alternatives 6 marks body else body
        alternatives _ [] next = next
        alternatives step (flag:rest) next = prefix [(step,bit flag)] $
          if flag then found else alternatives (step+1) rest next
        txs [] rest = prefix [(12,0),(22,1)] (scan rest)
        txs (inputs:restTxs) rest = prefix [(12,1),(13,1)] (ins inputs restTxs rest)
        ins [] restTxs rest = prefix [(14,0),(21,1)] (txs restTxs rest)
        ins (flags:inputs) restTxs rest = prefix [(14,1),(15,bit (head flags))] $
          if head flags then found else prefix [(16,bit elementsMode)] $
            let next = prefix [(20,1)] (ins inputs restTxs rest)
            in if elementsMode then alternatives 17 (tail flags) next else next
        (script,outcome) = scan blocks
    commandTrace 283 22 (\phase reply -> validate (ParentReplay.BranchReplayFlow phase reply))
      script fault outcome

blockDepositPreflightOrder :: Property
blockDepositPreflightOrder = forAll ((,,) <$> arbitrary <*>
  resize 6 (listOf ((,) <$> arbitrary <*> resize 6 (listOf arbitrary))) <*> choose (-1,100 :: Int)) $
  \(enabled,transactions,fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        prefix steps (rest,status) = (steps ++ rest,status)
        rejectAt step = ([(step,0)],0)
        scan [] = ([(3,0)],1)
        scan ((coinbase,inputs):rest) = prefix [(3,1),(4,bit coinbase)] $
          if coinbase then prefix [(17,1)] (scan rest) else prefix [(5,1)] (inspect inputs rest)
        inspect [] rest = prefix [(6,0),(17,1)] (scan rest)
        inspect ((pegin,hasWitness,valid,unavailable,native,outputs):inputs) rest =
          let next = prefix [(16,1)] (inspect inputs rest)
          in prefix [(6,1),(7,bit pegin)] $ if not pegin then next else
            prefix [(8,1),(9,bit hasWitness)] $ if not hasWitness then rejectAt 13 else
            prefix [(10,bit valid)] $ if not valid then
              prefix [(11,bit unavailable)] (rejectAt (if unavailable then 12 else 13)) else
              prefix [(14,bit native)] $ if not native then rejectAt 18 else
                prefix [(15,bit outputs)] $ if outputs then next else rejectAt 19
        (script,outcome) = prefix [(1,bit enabled)] $
          if enabled then prefix [(2,1)] (scan transactions) else ([],1)
    commandTrace 282 19 (\phase reply -> validate (Deposit.BlockPreflightFlow phase reply))
      script fault outcome

explicitVoteOrder :: Property
explicitVoteOrder = forAll ((,,) <$> arbitrary <*> choose (0,3) <*> choose (-1,5 :: Int)) $
  \(abstain,result,fault) -> ioProperty $ do
    let script = [(1,if abstain then 1 else 0)] ++ if abstain then [] else
          [(2,result)] ++ case result of
            1 -> [(3,1)]
            2 -> [(4,1)]
            3 -> [(5,0)]
            _ -> []
    commandTraceWith (\phase -> if phase == 2 then [4,maxBound] else [2,maxBound])
      280 5 (\phase reply -> validate (ParentReplay.ExplicitVoteFlow phase reply))
      script fault (if not abstain && result == 3 then 0 else 1)

canonicalMatchOrder :: Property
canonicalMatchOrder = forAll ((,,) <$> frequency [(1,arbitrary),(1,elements [0,1,2,maxBound :: Word64])] <*>
  arbitrary <*> choose (-1,7 :: Int)) $
  \(count,hasIndex,fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        script = [(1,bit (count /= 0))] ++ if count == 0 then [(4,0)] else
          [(2,bit (count == 1))] ++ if count /= 1 then [(5,0)] else
          [(3,1),(6,bit hasIndex)] ++ [(7,1) | hasIndex]
    commandTrace 279 7 (\phase reply -> validate (Bmm.CanonicalMatchFlow phase reply))
      script fault (bit (count == 1))

retiredPreliminaryWitness :: Property
retiredPreliminaryWitness = forAll arbitrary $ \(phase,reply) -> ioProperty $ do
  result <- elements_hs_parent_replay_store_checked 278 phase reply
  bound <- elements_hs_parent_replay_store_checked 278 maxBound 0
  pure $ conjoin [result === -1, bound === -1]

mempoolWitnessOrder :: Property
mempoolWitnessOrder = forAll ((,) <$> listOf arbitrary <*> choose (-1,80 :: Int)) $ \(inputs,fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        scan [] = [(1,0)]
        scan ((pegin,complete,valid,unavailable,emptyError,native,outputs):rest) =
          [(1,1),(2,bit pegin)] ++ (if not pegin then [] else
            [(3,1),(4,bit complete)] ++ if not complete then [(5,1)] else
            [(6,bit valid)] ++ if not valid then
              [(7,bit unavailable)] ++ (if not unavailable then [(10,1)] else
                [(8,bit emptyError)] ++ [(9,1) | emptyError])
            else [(11,bit native)] ++ if not native then [(12,1)] else
              [(13,bit outputs)] ++ [(10,1) | not outputs]) ++ [(14,1)] ++ scan rest
    commandTrace 277 14 (\phase reply -> validate (Deposit.MempoolWitnessFlow phase reply))
      (scan inputs) fault 1

peerBlockDispatchOrder :: Property
peerBlockDispatchOrder = forAll ((,,) <$> elements [0,1,2,3,maxBound] <*> arbitrary <*> choose (-1,3 :: Int)) $
  \(outcome,present,fault) -> ioProperty $ do
    let script = [(1,fromIntegral (outcome :: Word32))] ++ case outcome of
          1 -> [(2,1)]
          2 -> [(3,if present then 1 else 0)] ++ [(4,1) | present]
          _ -> []
        invalid phase = if phase==1 then [] else [2,maxBound]
    commandTraceWith invalid 275 4 (\phase reply -> validate (Bmm.PeerBlockDispatchFlow phase reply)) script fault 1

credentialFileOrder :: Property
credentialFileOrder = forAll ((,,,) <$> vectorOf 9 arbitrary <*> elements [0,1,2] <*>
  elements (map C.pack ["","\n","\r","\r\n","\n\r","a\n\n","a\r\r","a\r\n"] ++ [B.replicate 4097 97]) <*>
  choose (-1,28 :: Int)) $ \(flags,status,contents,fault) -> ioProperty $ do
    let bit flag = if flag then 1 else 0
        check step flag rest err = (step,bit flag):if flag then rest else [(err,1)]
        lastByte text = if B.null text then 256 else fromIntegral (B.last text)
        trimCR text = (25,lastByte text):if not (B.null text) && B.last text==13 then [(26,1)] else []
        normalized = (23,lastByte contents):if not (B.null contents) && B.last contents==10
          then (24,1):trimCR (B.init contents) else trimCR contents
        posix = check 4 (flags !! 2) ((6,bit (flags !! 3)):if not (flags !! 3) then [] else
          (7,status):if status==1 then [(8,1)] else (9,status):
            if status==2 then [(10,1)] else (11,1):normalized) 5
        windows = (12,bit (flags !! 4)):if flags !! 4 then [(15,1)] else
          check 13 (flags !! 5) (check 14 (flags !! 6) (check 16 (flags !! 7)
            ((18,1):(19,bit (flags !! 8)):if flags !! 8 then [(22,1)] else
              (20,fromIntegral (B.length contents)):if B.length contents>4096 then [(22,1)] else normalized) 17) 15) 15
        script = check 1 (head flags) ((3,bit (flags !! 1)):if flags !! 1 then posix else windows) 2
        failed = fault>=0 && fault<length script
        planned = map fst (if failed then take (fault+1) script else script)
        wanted = if failed then -1 else if fst (last script) `elem` [2,5,6,8,10,15,17,22] then 0 else 1
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> do
            previous <- readIORef trace
            modifyIORef' trace (++[step])
            let index=length previous
            pure $ if index==fault || index>=length script || fst (script !! index)/=step
              then -1 else snd (script !! index))
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Workflow.CommandFlow 26 (\phase result ->
      validate (Bmm.CredentialFileFlow phase result)) action))
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_parent_replay_run 196 callback nullPtr)
    pure $ conjoin [direct === (wanted,planned),abi === direct]

startupArgsOrder :: Property
startupArgsOrder = forAll ((,,,,,) <$> elements [0,24,255,256] <*>
  resize 6 (listOf (elements (filter (/=6) [1..24 :: Word32]))) <*> arbitrary <*>
  elements [0,24,255,256,maxBound] <*> elements [0,1,2100000000000000,2100000000000001,maxBound] <*>
  elements [0,1,2,3,maxBound]) $ \(slot,changes,injectFault,configured,extra,timeout) -> ioProperty $ do
    let value step
          | step==10 = configured
          | step==14 = extra
          | step==15 = timeout
          | otherwise = if (step `elem` [2,3,4,7,11,12,13,16,17,21,24]) /= (step `elem` changes)
              then 1 else 0
        readStep step = [(step,value step)]
        rejected err = [(100+err,1)]
        required step err next = readStep step ++ if value step==1 then next else rejected err
        forbidden step err next = readStep step ++ if value step==0 then next else rejected err
        credentials = readStep 22 ++ if value 22==0 then [] else
          forbidden 23 12 (forbidden 8 12 (forbidden 9 12 (required 17 13 (required 24 14 []))))
        identity = (if value 5==0 then [] else readStep 20 ++ if value 20==0 then [] else
          readStep 21) -- A failed identity check suppresses credential reads.
        afterNetwork = identity ++ if value 5==1 && value 20==1 && value 21==0
          then rejected 11 else credentials
        network | slot==256 = forbidden 18 9 (forbidden 19 10 afterNetwork)
                | otherwise = required 7 2 (forbidden 8 3 (forbidden 9 3
                    (readStep 10 ++ if configured/=fromIntegral slot then rejected 4 else
                    required 11 5 (required 12 5 (required 13 6
                    (readStep 14 ++ if extra>2100000000000000 then rejected 6 else
                    readStep 15 ++ if timeout<1 || timeout>2 then rejected 7 else
                    required 16 0 (required 17 8 afterNetwork)))))))
        afterReward = required 4 0 (readStep 5 ++ network)
        script = readStep 1 ++ if value 1==0 then afterReward else
          required 2 1 (required 3 1 afterReward)
        -- Failed effects are protocol errors, not rendered domain rejections.
        normalized = takeWhile ((/=100) . fst) script
        possibleFaults = [n | (n,(step,_)) <- zip [0..] normalized,step `notElem` [10,14,15]]
        fault = if injectFault then last possibleFaults else -1
        expectedTrace = map fst (if fault<0 then normalized else take (fault+1) normalized)
        expectedCode | fault>=0 || length normalized/=length script = -1
                     | fst (last script)>100 = 1
                     | otherwise = 0
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> do
            observed <- readIORef trace
            modifyIORef' trace (++[step])
            pure $ if length observed==fault then 2 else if step>100 then 1 else value step)
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (validate . Bmm.StartupArgs slot 2100000000000000 2)
    abi <- run (\action -> bracket (makeCursorEffect (\_ step a b field ->
      if a/=0 || b/=0 then pure (-1) else action step >>= poke field >> pure 1)) freeHaskellFunPtr $ \callback ->
        elements_hs_startup_args slot 2100000000000000 2 callback nullPtr)
    missing <- elements_hs_startup_args slot 2100000000000000 2 nullFunPtr nullPtr
    invalid <- mapM (\(s,m,t) -> validate (Bmm.StartupArgs s m t
      (\_ -> fail "invalid startup parameters evaluated callback")))
      [(257,1,2),(24,maxBound,2),(24,1,0),(24,1,2147483648)]
    pure $ conjoin [direct === (expectedCode,expectedTrace),abi === direct,
      missing === -1,invalid === replicate 4 (-1)]

tlsFileAdmission :: Property
tlsFileAdmission = forAll ((,,) <$> arbitrary <*> elements [0,1,1,1,2,3] <*>
  resize 3 (listOf (choose (3,29)))) $ \(privateKey,platform,changes) -> ioProperty $ do
    let value step
          | step==1 = platform
          | step `elem` [9,19,20,24,25] = if step `elem` changes then 1 else 0
          | step `elem` [5,15,17,18,22,23] = if step `elem` changes then 42 else 41
          | step `elem` [26,27,28,29] = if step `elem` changes then 0 else maxBound-3
          | step `elem` [3,7,11,13,16,21] && step `elem` changes = 0
          | otherwise = 1
        yes step = ([step],value step==1)
        equalFields a b = ([a,b],value a==value b)
        zero step = ([step],value step==0)
        admission = [(yes 3,4),(equalFields 5 15,6),(yes 7,8),(yes 16,8),(equalFields 17 18,8),
          (zero 19,8),(zero (if privateKey then 9 else 20),10)]
        opened = [yes 11,yes 21,equalFields 22 23,zero (if privateKey then 24 else 25),equalFields 26 27,equalFields 28 29]
        openTrace [] = [30]
        openTrace ((steps,ok):rest) = steps++if ok then openTrace rest else [30,12]
        admitTrace [] = openTrace opened
        admitTrace (((steps,ok),err):rest) = steps++if ok then admitTrace rest else [err]
        expectedTrace = [1]++case platform of
          0 -> [2]
          1 -> admitTrace admission
          2 -> [13]++if value 13==1 then [] else [14]
          _ -> []
        expectedCode | platform>2 = -1
                     | last expectedTrace `elem` [2,4,6,8,10,12,14] = 0
                     | otherwise = 1
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> modifyIORef' trace (++[step]) >> pure (value step))
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Bmm.TlsFileAdmission privateKey action))
    abi <- run (\action -> bracket (makeCursorEffect (\_ step a b field ->
      if a/=0 || b/=0 then pure (-1) else action step >>= poke field >> pure 1)) freeHaskellFunPtr $ \callback -> do
        code <- elements_hs_tls_file_admission (if privateKey then 1 else 0) callback nullPtr
        invalid <- elements_hs_tls_file_admission 2 callback nullPtr
        pure (if invalid==(-1) then code else minBound))
    missing <- elements_hs_tls_file_admission 0 nullFunPtr nullPtr
    pure $ conjoin [direct === (expectedCode,expectedTrace),abi === direct,missing === -1]

privateFileAdmission :: Property
privateFileAdmission = forAll ((,,,,) <$> arbitrary <*> field <*> field <*> field <*> choose (-1,8 :: Int)) $
  \(regular,owner,user,permissions,fault) -> ioProperty $ do
    let valid value = value>=0 && value<=4294967295
        model | not regular = (0,[(1,0),(2,1)])
              | not (valid owner) = (-1,[(1,1),(3,owner)])
              | not (valid user) = (-1,[(1,1),(3,owner),(4,user)])
              | owner/=user = (0,[(1,1),(3,owner),(4,user),(5,1)])
              | not (valid permissions) = (-1,[(1,1),(3,owner),(4,user),(6,permissions)])
              | permissions/=0 = (0,[(1,1),(3,owner),(4,user),(6,permissions),(7,1)])
              | otherwise = (1,[(1,1),(3,owner),(4,user),(6,permissions)])
        (wanted,script) = model
        failed = fault>=0 && fault<length script
        expectedTrace = map fst (if failed then take (fault+1) script else script)
        run invoke = do
          trace <- newIORef []
          code <- invoke (\step -> do
            previous <- readIORef trace
            modifyIORef' trace (++[step])
            let index=length previous
            pure $ if index==fault || index>=length script || fst (script !! index)/=step
              then -1 else snd (script !! index))
          seen <- readIORef trace
          pure (code,seen)
    direct <- run (\action -> validate (Bmm.PrivateFileAdmission action))
    abi <- run (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_private_file_admission callback nullPtr)
    missing <- elements_hs_private_file_admission nullFunPtr nullPtr
    pure $ conjoin [direct === (if failed then -1 else wanted,expectedTrace),abi === direct,missing === -1]
  where field = elements [-1,0,1,63,4294967295,4294967296,maxBound :: Int64]

credentialRead :: Property
credentialRead = forAll ((,) <$> frequency [(9,pure 4097),(1,elements [0,4096,4098,maxBound])] <*>
  resize 16 (listOf (elements [0,1,64,4096,4097,4098,maxBound,maxBound-1]))) $ \(capacity,replies) -> ioProperty $ do
  let model | capacity/=4097 = (-1,0,[])
            | otherwise = loop 0 (replies++[0])
      loop used _ | used==capacity = (2,used,[])
      loop used (count:rest) =
        let (code,finalUsed,more)
              | count==maxBound = loop used rest
              | count==maxBound-1 = (1,used,[])
              | count>capacity-used = (-1,used,[])
              | count==0 = (0,used,[])
              | otherwise = loop (used+count) rest
        in (code,finalUsed,(used,capacity-used):more)
      loop used [] = (0,used,[])
      (wanted,expectedUsed,planned) = model
      run invoke = do
        trace <- newIORef []
        result <- invoke (\offset available -> do
          previous <- readIORef trace
          modifyIORef' trace (++[(offset,available)])
          pure ((replies++repeat 0) !! length previous))
        seen <- readIORef trace
        pure (result,seen)
  direct <- run (\readBytes -> validate (Bmm.CredentialRead capacity readBytes))
  abi <- run (\readBytes -> withArray [17,19] $ \output ->
    bracket (makeCursorEffect (\_ step offset available field ->
      if step/=0 then pure (-1) else readBytes offset available >>= poke field >> pure 1)) freeHaskellFunPtr $ \callback -> do
      code <- elements_hs_credential_read capacity output callback nullPtr
      values <- peekArray 2 output
      missing <- elements_hs_credential_read capacity output nullFunPtr nullPtr
      absent <- elements_hs_credential_read capacity nullPtr callback nullPtr
      pure (code,values,missing,absent))
  pure $ conjoin [direct === ((wanted,expectedUsed),planned),
    abi === ((wanted,[if wanted<0 then 17 else expectedUsed,19],-1,-1),planned)]

bmmWorkTotal :: Property
bmmWorkTotal = forAll ((,,,) <$> elements [0,1,2] <*> word <*> resize 12 (listOf word) <*> choose (-1,20 :: Int)) $
  \(mode,initial,values,fault) -> ioProperty $ do
    let count = fromIntegral (length values)
        model | mode > 1 = (-1,initial,[])
              | otherwise = go 0 (toInteger initial) values
        go _ accumulated [] = (0,fromInteger accumulated,[])
        go i accumulated (x:xs)
          | summed > 18446744073709551615 && mode == 0 = (1,fromInteger accumulated,[i])
          | otherwise = let (code,result,rest) = go (i+1) (min 18446744073709551615 summed) xs
                        in (code,result,i:rest)
          where summed = accumulated + toInteger x
        (wanted,resultValue,planned) = model
        failing = fault >= 0 && fromIntegral fault `elem` planned
        expectedTrace = if failing then take (fault+1) planned else planned
    directTrace <- newIORef []
    direct <- try (validate (Bmm.WorkTotal mode count initial (\index -> do
      modifyIORef' directTrace (++[index])
      if fromIntegral index == fault then ioError (userError "total fault")
        else pure (values !! fromIntegral index)))) :: IO (Either SomeException (Int32,Word64))
    directSeen <- readIORef directTrace
    trace <- newIORef []
    withArray [17,19] $ \output -> bracket (makeCursorEffect (\_ step index sub field -> do
      modifyIORef' trace (++[(step,index,sub)])
      if fromIntegral index == fault then pure (-1)
        else poke field (values !! fromIntegral index) >> pure 1)) freeHaskellFunPtr $ \callback -> do
      code <- elements_hs_bmm_work_total mode count initial output callback nullPtr
      fields <- peekArray 2 output
      seen <- readIORef trace
      missing <- elements_hs_bmm_work_total mode count initial output nullFunPtr nullPtr
      absent <- elements_hs_bmm_work_total mode count initial nullPtr callback nullPtr
      pure $ conjoin [directSeen === expectedTrace,
        either (const Nothing) Just direct === (if failing then Nothing else Just (wanted,resultValue)),
        seen === map (\i -> (0,i,0)) expectedTrace,
        code === (if failing then -1 else wanted),
        fields === [if failing || wanted < 0 then 17 else resultValue,19],missing === -1,absent === -1]
  where word = frequency [(1,arbitrary),(3,elements [0,1,2,maxBound,maxBound-1,maxBound `div` 2])]

bmmWorkBudget :: Property
bmmWorkBudget = forAll (resize 8 (listOf row)) $ \rows -> forAll (choose (-1,30 :: Int)) $ \fault -> ioProperty $ do
  let readValue step inputIndex index = case rows !! fromIntegral inputIndex of
        [size,final,tag,cmr,serialized] -> case step of
          0 -> size
          1 -> if index == size-1 then final else tag
          2 -> cmr
          _ -> serialized
        _ -> 0
      count = fromIntegral (length rows)
      -- Frozen branch structure uses explicit unsigned overflow checks.
      old readField = go 0 0 where
        go i accumulated | i == count = pure accumulated
                   | otherwise = do
            size <- readField 0 i 0
            if size < 4 then go (i+1) accumulated else do
              final <- readField 1 i (size-1)
              let control = size-1-(if final == 80 then 1 else 0)
              tag <- readField 1 i control
              if tag == 256 || (tag `mod` 256) `div` 2 /= 95 then go (i+1) accumulated else do
                cmr <- readField 2 i (control-1)
                if cmr /= 32 then go (i+1) accumulated else do
                  serialized <- readField 3 i 0
                  let budget = serialized+50
                  if budget > maxBound `div` 1000 || accumulated > maxBound-budget*1000
                    then pure maxBound else go (i+1) (accumulated+budget*1000)
      run program = do
        trace <- newIORef []
        result <- try (program (\step inputIndex index -> do
          previous <- readIORef trace
          modifyIORef' trace (++[(step,inputIndex,index)])
          if length previous == fault then ioError (userError "work fault")
            else pure (readValue step inputIndex index))) :: IO (Either SomeException Word64)
        seen <- readIORef trace
        pure (either (const Nothing) Just result,seen)
  expected <- run old
  actual <- run (validate . Bmm.WorkBudget count)
  seen <- newIORef []
  withArray [17,19] $ \output -> bracket (makeCursorEffect (\_ step inputIndex index field -> do
    previous <- readIORef seen
    modifyIORef' seen (++[(step,inputIndex,index)])
    if length previous == fault then pure (-1) else poke field (readValue step inputIndex index) >> pure 1))
    freeHaskellFunPtr $ \callback -> do
      code <- elements_hs_bmm_work_budget count output callback nullPtr
      fields <- peekArray 2 output
      trace <- readIORef seen
      missing <- elements_hs_bmm_work_budget count output nullFunPtr nullPtr
      absent <- elements_hs_bmm_work_budget count nullPtr callback nullPtr
      pure $ conjoin [actual === expected,trace === snd expected,
        code === maybe (-1) (const 0) (fst expected),
        fields === [maybe 17 id (fst expected),19],missing === -1,absent === -1]
  where
    row = sequence [choose (0,8),elements [0,80,189,190,191,255,256],
      elements [0,80,189,190,191,255,256],elements [0,31,32,33],
      frequency [(1,arbitrary),(3,elements [0,1,maxBound,maxBound-49,maxBound-50,maxBound `div` 1000])]]

bmmWorkQuote :: Property
bmmWorkQuote = forAll ((,,,,) <$> amount <*> weight <*> amount <*> amount <*> amount) $
  \(fees,work,rate,reserve,bound) -> ioProperty $ withArray [91,92,93,94] $ \output -> do
    result <- elements_hs_bmm_work_quote fees work rate reserve bound output
    fields <- peekArray 4 output
    missing <- elements_hs_bmm_work_quote fees work rate reserve bound nullPtr
    displayResult <- elements_hs_bmm_work_quote_display fees work rate reserve bound output
    displayFields <- peekArray 4 output
    missingDisplay <- elements_hs_bmm_work_quote_display fees work rate reserve bound nullPtr
    let scaled = toInteger work * toInteger rate + 999999
        cost = scaled `div` 1000000
        invalid = any (\x -> x < 0 || x > bound) [fees,rate,reserve] ||
          scaled > 18446744073709551615 || cost > toInteger bound
        funded = cost + toInteger reserve <= toInteger fees
        expected | invalid = (False,[0,0,0])
                 | funded = (True,[fromInteger cost,reserve,fees-fromInteger cost-reserve])
                 | otherwise = (False,[fromInteger cost,reserve,0])
    pure $ conjoin [validate (Bmm.WorkQuote fees work rate reserve bound) === expected,
      result === (if fst expected then 1 else 0),fields === snd expected ++ [94],missing === -1,
      displayResult === (if fst expected && last (snd expected)>0 then 1 else 0),
      displayFields === (if fst expected then snd expected else [0,0,0]) ++ [94],missingDisplay === -1]
  where
    amount = frequency [(1,arbitrary),(3,elements [minBound,-1,0,1,1000,2100000000000000,maxBound])]
    weight = frequency [(1,arbitrary),(3,elements [0,1,999999,1000000,1000001,maxBound])]

bmmSelectedBid :: Property
bmmSelectedBid = forAll (vectorOf 3 amount) $ \values -> ioProperty $ case values of
  [configured,fees,limit] -> do
    actual <- elements_hs_bmm_selected_bid configured fees limit
    let expected
          | configured < 1 || configured > limit = -1
          | fees < 0 || fees > limit = -2
          | fees > configured = fees
          | otherwise = configured
    pure (actual === expected)
  _ -> pure (property False)
  where amount = frequency [(1,arbitrary),(3,elements [minBound,-1,0,1,2100000000000000,2100000000000001,maxBound])]

bmmReplacementLimit :: Property
bmmReplacementLimit = forAll ((,,) <$> amount <*> amount <*> amount) $ \(selected,extra,limit) -> ioProperty $ do
  actual <- elements_hs_bmm_replacement_limit selected extra limit
  let expected | extra < 0 || extra > limit = -1
               | selected <= 0 || selected > limit = -2
               | otherwise = selected + min extra (limit-selected)
  pure $ conjoin [actual===expected,validate (Bmm.ReplacementLimit selected extra limit)===expected,
    property (actual < 0 || (actual >= selected && actual <= limit))]
  where amount = frequency [(1,arbitrary),(3,elements [minBound,-1,0,1,2100000000000000,2100000000000001,maxBound-1,maxBound])]

bmmReplacementWorkflow :: Property
bmmReplacementWorkflow = forAll (elements [-1,0,1,1000,10000]) $ \current ->
  forAll (elements [-1,0,1000,2000,10000,10001]) $ \maximumBid ->
  forAll (choose (-1,3000)) $ \paidAmount -> forAll (choose (-1,3000)) $ \neededAmount ->
  forAll arbitrary $ \negative -> ioProperty $ do
    calls <- newIORef []
    let message = C.pack ("insufficient fee, rejecting replacement txid; not enough additional fees to relay; " ++
          (if negative then "-" else "") ++ "paid < 1.0")
        eligible = current > 0 && current <= 10000 && maximumBid <= 10000 && current < maximumBid
        delta = neededAmount - (if negative then -paidAmount else paidAmount)
        expected = if eligible && paidAmount >= 0 && neededAmount >= 0 && delta > 0 && delta <= maximumBid-current
          then Just (current+delta) else Nothing
    actual <- Bmm.replaceBid (Bmm.ReplacementBid current maximumBid 10000 message) $ \token -> do
      modifyIORef' calls (++ [token])
      pure (if token == C.pack "paid" then paidAmount else neededAmount)
    tokens <- readIORef calls
    pure (conjoin [actual === expected,tokens === if eligible then map C.pack ["paid","1.0"] else []])

retiredBmmSubmission :: Property
retiredBmmSubmission = forAll arbitrary $ \(phase,reply) -> ioProperty $ do
  raw <- elements_hs_parent_replay_store 183 phase reply
  checked <- elements_hs_parent_replay_store_checked 183 phase reply
  bound <- elements_hs_parent_replay_store_checked 183 maxBound 0
  calls <- newIORef (0 :: Int)
  result <- bracket (wrapMatchFact (\_ _ -> modifyIORef' calls (+1) >> pure 1)) freeHaskellFunPtr $ \callback ->
    elements_hs_parent_replay_run 183 callback nullPtr
  observed <- readIORef calls
  pure $ conjoin [raw===(-1),checked===(-1),bound===(-1),result===(-1),observed===0]

withdrawalRpcVerify :: Property
withdrawalRpcVerify = forAll (vectorOf 9 arbitrary) $ \outcomes -> ioProperty $ do
  let checks = zip [1,3,5,7,9,11,13,14,16] outcomes
      answer phase = maybe True id (lookup phase checks)
      run phase trace = do
        next <- elements_hs_parent_replay_store_checked 182 phase (if phase == 0 then 0 else if answer phase then 1 else 0)
        if next < 0 || next `elem` [2,4,6,8,10,15,18] then pure (trace ++ [next])
          else run (fromIntegral next) (trace ++ [next])
      stages = [(1,2),(3,4),(5,6),(7,8),(9,10),(11,8),(12,-1),(13,15),(14,15),(16,18),(17,-1)]
      model [] = [-11]
      model ((step,rejection):rest)
        | answer step = fromIntegral step : model rest
        | otherwise = [fromIntegral step,rejection]
  actual <- run 0 []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked 182 phase 2) [1..18]
  failedEffects <- mapM (\phase -> elements_hs_parent_replay_store_checked 182 phase 0) [12,17]
  returnedErrors <- mapM (\phase -> elements_hs_parent_replay_store_checked 182 phase 1) [2,4,6,8,10,15,18]
  pure (conjoin [actual === model stages,malformed === replicate 18 (-1),
    failedEffects === replicate 2 (-1),returnedErrors === replicate 7 (-1)])

anchorOrdering :: Property
anchorOrdering = forAll arbitrary $ \(different,heightLess,hashLess) ->
  forAll (choose (-1,2 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        less = if different then heightLess else hashLess
        script = [(1,flag different),(if different then 2 else 3,flag less)]
    in commandTrace 305 3 (\phase reply -> validate (Bmm.AnchorOrder phase reply)) script fault (flag less)

reconciliationGateOrder :: Property
reconciliationGateOrder = forAll arbitrary $ \(configured,snapshot,authenticated) ->
  forAll (choose (-1,5 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,flag configured)] ++ if not configured then [] else
          [(2,1),(3,flag snapshot)] ++ [(4,flag authenticated) | snapshot] ++
          [(5,1) | snapshot && not authenticated]
    in commandTrace 304 5 (\phase reply -> validate (Bmm.ReconciliationGate phase reply))
      script fault (if configured && (not snapshot || authenticated) then 1 else 0)

anchorReplacementOrder :: Property
anchorReplacementOrder = forAll arbitrary $ \(derived,valid,unavailable,allowed) ->
  forAll arbitrary $ \(eligible,orphaned,predecessor,authenticated,readable) ->
  forAll (choose (-1,16 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        replacement = [(1,flag derived)] ++ if not derived then [(2,1)] else
          [(3,flag valid)] ++ if not valid then
            [(4,flag unavailable)] ++ [(5,1) | unavailable] ++ [(6,1)]
          else [(7,flag allowed),(if allowed then 9 else 8,1)]
        script = [(10,flag eligible)] ++ if not eligible then [] else
          [(11,flag orphaned)] ++ if not orphaned then [] else
          [(12,flag predecessor)] ++ [(13,flag authenticated) | predecessor] ++
          if predecessor && not authenticated then [] else
            [(14,1) | predecessor] ++ [(15,flag readable)] ++ if readable then replacement else [(16,0)]
        fatal = eligible && orphaned && (not predecessor || authenticated) && not readable
    in commandTrace 303 16 (\phase reply -> validate (Bmm.AnchorReplacementFlow phase reply))
      script fault (if fatal then 0 else 1)

snapshotBacklogOrder :: Property
snapshotBacklogOrder = forAll (oneof [elements [0,1,2,maxBound],arbitrary]) $ \count ->
  forAll (choose (-1,2 :: Int)) $ \fault -> ioProperty $
    let script = [(1,fromIntegral (count :: Word32))] ++ [(2,1) | count <= 1]
        invalidReplies phase = if phase == 1 then [] else [2,maxBound]
    in do
      ordered <- commandTraceWith invalidReplies 302 2 (\phase reply -> validate (Bmm.SnapshotBacklogFlow phase reply))
        script fault (if count <= 1 then 1 else 0)
      invalid <- mapM (\phase -> elements_hs_parent_replay_store_checked 302 phase 0) [2,3,4,maxBound-1]
      pure $ conjoin [ordered,invalid===replicate 4 (-1)]

anchorCollectionOrder :: Property
anchorCollectionOrder = forAll (choose (0,4)) $ \count ->
  forAll (vectorOf count ((,,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary)) $ \entries ->
  forAll (choose (-1,29 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        build [] = [(1,0)]
        build ((present,height,unique,anchor,active):rest) = [(1,flag present)] ++
          if not present then [] else [(2,flag height)] ++
          if not height then [] else [(3,flag unique)] ++
          if not unique then [] else [(4,flag anchor)] ++ [(5,1) | anchor] ++ [(6,flag active)] ++
          if active then [] else [(7,1)] ++ build rest
    in commandTrace 306 7 (\phase reply -> validate (Bmm.AnchorCollect phase reply)) (build entries) fault 1

candidateAdmissionOrder :: Property
candidateAdmissionOrder = forAll arbitrary $ \(tipAbsent,worse,authenticated,headerAbsent,better) ->
  forAll (choose (0,4)) $ \count ->
  forAll (vectorOf count (elements [0,1,2,3 :: Word32])) $ \statuses ->
  forAll arbitrary $ \(descends,eligible,transactions) ->
  forAll (choose (-1,26 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        ancestry [] = ([(15,0)],0)
        ancestry (status:rest)
          | status == 1 = ([(15,1),(16,1),(18,1)],status)
          | status == 2 = ([(15,1),(16,0),(17,1),(18,1)],status)
          | otherwise = let (suffix,finalStatus) = ancestry rest
            in ([(15,1),(16,0),(17,0),(19,1)] ++ suffix,finalStatus)
        (prefix,selectedStatus) = ancestry statuses
        active = selectedStatus == 0
        orphaned = selectedStatus == 1
        unavailable = selectedStatus == 2
        script = [(20,flag eligible)] ++ if not eligible then [(21,1)]
          else [(22,flag transactions)] ++ if not transactions then [(23,1)]
          else prefix ++ [(8,flag active)] ++ if not active then
          [(9,1),(10,flag (orphaned && descends))] ++ [(11,1) | orphaned && descends] ++
          [(12,flag unavailable),(if unavailable then 13 else 14,1)]
          else [(1,flag tipAbsent)] ++ [(2,flag worse) | not tipAbsent] ++
          [(3,1) | tipAbsent || not worse] ++ [(4,flag authenticated)] ++
          if authenticated then [(5,flag headerAbsent)] ++ [(6,flag better) | not headerAbsent] ++
            [(7,1) | headerAbsent || better] else []
    in commandTrace 301 23 (\phase reply -> validate (Bmm.CandidateAdmissionFlow phase reply)) script fault 1

anchorDisconnectOrder :: Property
anchorDisconnectOrder = forAll (choose (0,4)) $ \count ->
  forAll (vectorOf count ((,,) <$> elements [0,1,2 :: Word32] <*> arbitrary <*> arbitrary)) $ \entries ->
  forAll arbitrary $ \eligible ->
  forAll (choose (-1,37 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        finish done = [(9,flag done)] ++
          if done then [(10,1),(11,flag eligible)] ++ [(12,1) | eligible] else []
        build done [] = ([(1,0)] ++ finish done,1)
        build done ((status,ok,descends):rest)
          | status == 0 = ([(1,1),(2,1)] ++ finish done,1)
          | status == 1 = ([(1,1),(2,0),(3,1),(4,1)] ++ finish done,1)
          | not ok = (orphan ++ [(6,0),(7,0)],0)
          | otherwise = let (suffix,remainingResult) = build True rest
            in (orphan ++ [(6,1),(8,1)] ++ suffix,remainingResult)
          where orphan = [(1,1),(2,0),(3,0),(5,1),(13,flag descends)] ++ [(14,1) | descends]
        (script,result) = build False entries
    in commandTrace 300 14 (\phase reply -> validate (Bmm.AnchorDisconnectFlow phase reply)) script fault result

anchorPublishOrder :: Property
anchorPublishOrder = forAll arbitrary $ \(changed,written,admitted) ->
  forAll (choose (-1,4 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,flag changed)] ++ [(2,flag written) | changed] ++
          if changed && not written then [(3,0)] else [(4,flag admitted)]
    in commandTrace 299 4 (\phase reply -> validate (Bmm.AnchorPublishFlow phase reply))
      script fault (if (not changed || written) && admitted then 1 else 0)

anchorCacheOrder :: Property
anchorCacheOrder = forAll arbitrary $ \(snapshot,current,inserted,absent,genesis,anchor,covered) ->
  forAll (choose (-1,11 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,flag snapshot)] ++ [(2,flag current) | snapshot] ++
          if snapshot && not current then [(3,1)]
          else [(4,flag inserted)] ++ if not inserted then []
          else [(5,flag absent)] ++ if absent then [(8,1)]
          else [(6,flag genesis)] ++ if genesis then [(8,1)]
          else [(7,flag anchor)] ++ if not anchor then [(9,1)]
          else [(10,flag (snapshot && covered)),(if snapshot && covered then 8 else 11,1)]
    in commandTrace 298 11 (\phase reply -> validate (Bmm.AnchorCacheFlow phase reply)) script fault 1

snapshotPrepareOrder :: Property
snapshotPrepareOrder = forAll arbitrary $ \(slot,interrupted,small,reusable,warmed) ->
  forAll (choose (-1,7 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,flag slot)] ++ if not slot then []
          else [(2,flag interrupted)] ++ if interrupted then [(3,0)]
          else [(4,flag small)] ++ if small then []
          else [(5,flag reusable)] ++ if reusable then []
          else [(6,flag warmed)] ++ [(7,1) | warmed]
        accepted = not slot || not interrupted && (small || reusable || warmed)
    in commandTrace 297 7 (\phase reply -> validate (Bmm.SnapshotPrepareFlow phase reply))
      script fault (if accepted then 1 else 0)

connectionContextOrder :: Property
connectionContextOrder = forAll arbitrary $ \(slot,candidate,derived,finalized,matches,valid) ->
  forAll (choose (-1,14 :: Int)) $ \fault -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,flag slot)] ++
          if not slot then [(2,flag candidate)] ++ [(4,0) | candidate]
          else [(3,flag candidate)] ++ if candidate then [(5,1)]
          else [(6,flag derived)] ++ if not derived then [(7,0)]
          else [(8,flag finalized)] ++ if finalized
            then [(9,flag matches),(if matches then 11 else 10,flag matches)]
            else [(12,flag valid),(if valid then 14 else 13,flag valid)]
        accepted = if not slot then not candidate else candidate || derived && (if finalized then matches else valid)
    in commandTrace 296 14 (\phase reply -> validate (Bmm.ConnectionContextFlow phase reply))
      script fault (if accepted then 1 else 0)

requiredPairAdmission :: Property
requiredPairAdmission = forAll ((,,) <$> arbitrary <*> arbitrary <*> choose (-1,4 :: Int)) $
  \(first,second,fault) -> ioProperty $
    let flag value = if value then 1 else 0
        script = [(1,flag first)] ++ if not first then [(2,1)]
          else [(3,flag second)] ++ [(4,1) | not second]
    in commandTrace 294 4 (\phase reply -> validate (ParentReplay.RequiredPairFlow phase reply))
      script fault (if first && second then 1 else -1)

withdrawalRpcClaim :: Property
withdrawalRpcClaim = forAll arbitrary $ \(built,parsed,identityOK,encodingOK,parentOK) -> ioProperty $ do
  let answer phase = case phase of
        1 -> built
        3 -> parsed
        4 -> identityOK
        5 -> encodingOK
        9 -> parentOK
        _ -> True
      run phase trace = do
        next <- elements_hs_parent_replay_store_checked 181 phase (if phase == 0 then 0 else if answer phase then 1 else 0)
        if next < 0 || next `elem` [2,6,10] then pure (trace ++ [next])
          else run (fromIntegral next) (trace ++ [next])
      expected | not built = [1,2]
               | not parsed = [1,3,6]
               | not identityOK = [1,3,4,6]
               | not encodingOK = [1,3,4,5,6]
               | not parentOK = [1,3,4,5,7,8,9,10]
               | otherwise = [1,3,4,5,7,8,9,11,-11]
  actual <- run 0 []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked 181 phase 2) [1..12]
  pure (conjoin [actual === expected,malformed === replicate 12 (-1)])

withdrawalRpcBurnScan :: Property
withdrawalRpcBurnScan = forAll (oneof [chooseInt (0,5) >>= flip vectorOf arbitrary,pure [True]]) $ \matches ->
  forAll (oneof [chooseInt (0,5) >>= \n -> vectorOf n (chooseInt (0,2)),elements [[1],[1,2],[1,1]]]) $ \outputs ->
  forAll (chooseInt (0,6)) $ \requested ->
  forAll arbitrary $ \(unspendable,supported,notDust) -> ioProperty $ do
  let errors = [4,8,10,14,16,20,22,24,26]
      scan chosen []
        | chosen /= Just requested = 20
        | not unspendable = 22
        | not supported = 24
        | not notDust = 26
        | otherwise = -11
      scan chosen ((index,tag):rest)
        | tag == 2 = 14
        | tag == 1 = maybe (scan (Just index) rest) (const 16) chosen
        | otherwise = scan chosen rest
      expected | length (filter id matches) > 1 = 4
               | not (or matches) = 8
               | requested >= length outputs = 10
               | otherwise = scan Nothing (zip [0..] outputs)
      run phase answer ti oi found chosen trace = do
        next <- elements_hs_parent_replay_store_checked 180 phase answer
        let seen = trace ++ [next]
            resumeResult yes = run (fromIntegral next) (if yes then 1 else 0) ti oi found chosen seen
        if next < 0 || next `elem` errors then pure (next,seen)
        else if length trace > 100 then pure (-99,seen) else case next of
          1 -> resumeResult (ti < length matches)
          2 -> resumeResult (matches !! ti)
          3 -> resumeResult found
          5 -> run 5 1 ti oi True chosen seen
          6 -> run 6 1 (ti+1) oi found chosen seen
          7 -> resumeResult found
          9 -> resumeResult (requested < length outputs)
          11 -> resumeResult (oi < length outputs)
          12 -> resumeResult (outputs !! oi /= 0)
          13 -> resumeResult (outputs !! oi == 1)
          15 -> resumeResult (chosen /= Nothing)
          17 -> run 17 1 ti oi found (Just oi) seen
          18 -> run 18 1 ti (oi+1) found chosen seen
          19 -> resumeResult (chosen == Just requested)
          21 -> resumeResult unspendable
          23 -> resumeResult supported
          25 -> resumeResult notDust
          _ -> pure (-99,seen)
  (actual,trace) <- run 0 0 0 0 False Nothing []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked 180 phase 2) [1..27]
  pure (conjoin [actual === expected, malformed === replicate 27 (-1),
    property (length (filter (==17) trace) <= 1),
    property (actual `notElem` [4,8,10] || 11 `notElem` trace)])

withdrawalProofBounds :: Property
withdrawalProofBounds = forAll (chooseInt (0,1)) $ \stage ->
  forAll (oneof [arbitrary,elements [0,1,9999,10000,10001,0x7fffffffffffffff,0x8000000000000000,maxBound]] :: Gen Word64) $ \index ->
  forAll (oneof [arbitrary,elements [0,1,9999,10000,10001,maxBound]] :: Gen Word64) $ \count -> ioProperty $ do
  let request = B.singleton (fromIntegral stage) <> wordLE 8 index <> wordLE 8 count
      failure :: (Int32,String)
      failure | stage==0 && index>0x7fffffffffffffff = (-8,"Withdrawal index must not be negative")
              | stage==1 && index>=count = (-8,"Withdrawal index is outside this accumulator")
              | stage==1 && count>10000 = (-1,"Proof reconstruction exceeds the safe RPC limit; use a dedicated permissionless indexer")
              | otherwise = (0,"")
      expected = wordLE 4 (fromIntegral (fst failure)) <> C.pack (snd failure)
  actual <- B.useAsCStringLen request $ \(ptr,len) -> allocaBytes 256 $ \output -> do
    size <- elements_hs_withdrawal_bytes 33 money (castPtr ptr) (fromIntegral len) output 256
    if size<0 then pure B.empty else B.packCStringLen (castPtr output,fromIntegral size)
  malformed <- mapM (\invalid -> B.useAsCStringLen invalid $ \(ptr,len) -> allocaBytes 256 $ \output -> do
    size <- elements_hs_withdrawal_bytes 33 money (castPtr ptr) (fromIntegral len) output 256
    pure (size === -1)) [B.init request,request<>B.singleton 0,B.singleton 2<>B.tail request]
  pure $ conjoin ([withdrawal 33 money request === Right expected,actual === B.singleton 0<>expected] ++ malformed)

withdrawalRpcAdmission :: Property
withdrawalRpcAdmission = forAll (chooseInt (0,3)) $ \stage ->
  forAll (chooseInt (0,3)) $ \flags ->
  forAll (elements [minBound,-1,0,1,6,99999,100000,100001,maxBound] :: Gen Int32) $ \depth ->
  forAll (elements [minBound,-1,0,1,6,100000,100001,maxBound] :: Gen Int32) $ \required -> ioProperty $ do
  let request = B.pack [fromIntegral stage,fromIntegral flags] <>
        wordLE 4 (fromIntegral depth) <> wordLE 4 (fromIntegral required)
      anchored = testBit flags 0
      available = testBit flags 1
      failure :: (Int32,String)
      failure
        | stage == 0 && not anchored = (-32601,"Native BIP300 withdrawals are not enabled on this network")
        | stage == 0 && (required < 1 || required > 100000) = (-8,"minconfirmations must be between 1 and 100000")
        | stage == 1 && not anchored = (-5,"Confirming block is not in the active Elements chain")
        | stage == 1 && not available = (-1,"Confirming block data is unavailable on this pruned node")
        | stage == 1 && depth < required = (-25,"Native withdrawal burn has " ++ show depth ++ " confirmation(s); " ++ show required ++ " required")
        | stage == 2 && not anchored = (-25,"Confirming block left the active Elements chain while the withdrawal was authenticated")
        | stage == 3 && not anchored = (-25,"Confirming block left the active Elements chain during parent withdrawal replay")
        | stage == 2 && depth < required = (-25,"Withdrawal no longer has the required active-chain depth")
        | stage == 3 && depth < required = (-25,"Withdrawal lost the required active-chain depth during parent withdrawal replay")
        | otherwise = (0,"")
      expected = wordLE 4 (fromIntegral (fst failure)) <> C.pack (snd failure)
  malformed <- mapM (\invalid -> B.useAsCStringLen invalid $ \(ptr,len) -> allocaBytes 256 $ \output -> do
    result <- elements_hs_withdrawal_bytes 31 money (castPtr ptr) (fromIntegral len) output 256
    pure (result === -1)) [B.init request,B.singleton 4 <> B.tail request,
                           B.take 1 request <> B.singleton 4 <> B.drop 2 request]
  pure (conjoin ((withdrawal 31 money request === Right expected) : malformed))

withdrawalSubmissionPolicy :: Property
withdrawalSubmissionPolicy = forAll (oneof [arbitrary,elements [-1,0,255,256]] :: Gen Int32) $ \slot ->
  forAll (oneof [arbitrary,elements [0,1,1048576,1048577]] :: Gen Word64) $ \size ->
  forAll arbitrary $ \windows -> forAll (choose (0,255)) $ \flags ->
  let request = B.singleton 0 <> wordLE 4 (fromIntegral slot) <> wordLE 8 size <>
        B.singleton (if windows then 1 else 0)
      admission | slot < 0 || slot > 255 = 1
                | size == 0 || size > 1048576 = 2
                | windows = 3
                | otherwise = 0
      tests = [(testBit flags 0,4),(not (testBit flags 1),5),(testBit flags 2,6),
        (testBit flags 3,7),(testBit flags 4,8),(not (testBit flags 5),9),
        (not (testBit flags 6 || testBit flags 7),10)]
      decision = case [code | (failed,code) <- tests,failed] of
        [] -> 0
        code:_ -> code
  in ioProperty $ do
    malformed <- mapM (\invalid -> B.useAsCStringLen invalid $ \(ptr,len) -> allocaBytes 256 $ \output -> do
      result <- elements_hs_withdrawal_bytes 32 money (castPtr ptr) (fromIntegral len) output 256
      pure (result === -1))
      [B.empty,B.singleton 1,B.pack [2,flags],B.pack [2,128,0],B.pack [2,0,2],B.init request,request <> B.singleton 0,
       B.init request <> B.singleton 2]
    pure (conjoin ([withdrawal 32 money request === Right (B.singleton admission),
       withdrawal 32 money (B.pack [1,flags]) === Right (B.singleton decision)] ++ malformed))

grpcDuplicateTextPolicy :: Property
grpcDuplicateTextPolicy = forAll (choose (0,127) :: Gen Word8) $ \flags ->
  forAll arbitrary $ \acceptDuplicate ->
  forAll (elements ["", "failure", "AlreadyExists", "prefix AlreadyExists suffix",
                    "alreadyexists", "AlreadyExist", "Already\0Exists", "\0AlreadyExists\0"]) $ \message ->
  let found = "AlreadyExists" `List.isInfixOf` message
      legacyFlags = flags + if acceptDuplicate && found then 128 else 0
      request = B.pack [2,flags,if acceptDuplicate then 1 else 0] <> C.pack message
  in ioProperty $ do
    actual <- B.useAsCStringLen request $ \(ptr,len) -> allocaBytes 2 $ \output -> do
      result <- elements_hs_withdrawal_bytes 32 money (castPtr ptr) (fromIntegral len) output 2
      reply <- B.packCStringLen (castPtr output,2)
      pure (result,reply)
    pure (conjoin [fst actual === 2, B.head (snd actual) === 0,
      withdrawal 32 money (B.pack [1,legacyFlags]) === Right (B.tail (snd actual))])

withdrawalParentPolicy :: Property
withdrawalParentPolicy = forAll (oneof [choose (0,16),pure maxBound] :: Gen Word32) $ \kind ->
  forAll arbitrary $ \(standard,isWitness) ->
  forAll (oneof [arbitrary,elements [0,maxBound-148,maxBound-67,maxBound]] :: Gen Word32) $ \size -> ioProperty $ do
  let dustFrame = wordLE 4 (fromIntegral size) <> B.singleton (if isWitness then 1 else 0)
      request = wordLE 4 (fromIntegral kind) <> B.singleton (if standard then 1 else 0) <> dustFrame
      allowed = standard && kind `elem` [2,3,4,5,7,8,9]
      expected = B.singleton (if allowed then 1 else 0) <>
        wordLE 8 (3 * fromIntegral (size + if isWitness then 67 else 148))
  destinationResult <- elements_hs_parent_replay_store_checked 132 13 kind
  malformed <- mapM (\invalid -> B.useAsCStringLen invalid $ \(ptr,len) -> allocaBytes 256 $ \output -> do
    result <- elements_hs_withdrawal_bytes 30 money (castPtr ptr) (fromIntegral len) output 256
    pure (result === -1)) [B.init request,B.take 4 request <> B.singleton 2 <> B.drop 5 request,
                           B.init request <> B.singleton 2]
  pure (conjoin ([withdrawal 30 money request === Right expected,
    withdrawal 22 money dustFrame === Right (B.drop 1 expected),
    (standard && destinationResult == -11) === allowed] ++ malformed))

withdrawalJournalPersist :: Property
withdrawalJournalPersist = forAll arbitrary $ \(clearing,opened,committed,renamed) -> ioProperty $ do
  let kind = if clearing then 179 else 178
      answer phase = case phase of
        1 -> opened
        2 | clearing -> committed
        4 | not clearing -> committed
        7 -> renamed
        _ -> True
      run phase trace = do
        next <- elements_hs_parent_replay_store_checked kind phase
          (if phase == 0 then 0 else if answer phase then 1 else 0)
        if next < 0 then pure (next,trace) else run (fromIntegral next) (trace ++ [next])
      expected | clearing && not opened = (-11,[1])
               | clearing && not committed = (-10,[1,2,3])
               | clearing = (-11,[1,2,4])
               | not opened = (-10,[1,2])
               | not committed = (-10,[1,3,4,5])
               | not renamed = (-10,[1,3,4,6,7,8])
               | otherwise = (-11,[1,3,4,6,7])
  actual <- run 0 []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked kind phase 2) [1..9]
  pure (conjoin [actual === expected,malformed === replicate 9 (-1)])

withdrawalJournalRead :: Property
withdrawalJournalRead = forAll arbitrary $ \(opened,magicOK,checksumOK,entryOK) -> ioProperty $ do
  let answer phase = case phase of
        1 -> opened
        4 -> magicOK
        6 -> checksumOK
        8 -> entryOK
        _ -> True
      run phase trace = do
        next <- elements_hs_parent_replay_store_checked 177 phase
          (if phase == 0 then 0 else if answer phase then 1 else 0)
        if next < 0 then pure (next,trace) else run (fromIntegral next) (trace ++ [next])
      expected | not opened = (-10,[1,2])
               | not magicOK = (-10,[1,3,4,5])
               | not checksumOK = (-10,[1,3,4,6,7])
               | not entryOK = (-10,[1,3,4,6,8,9])
               | otherwise = (-11,[1,3,4,6,8,10])
  actual <- run 0 []
  malformed <- mapM (\phase -> elements_hs_parent_replay_store_checked 177 phase 2) [1..11]
  pure (conjoin [actual === expected,malformed === replicate 11 (-1)])

withdrawalJournalAdmission :: Property
withdrawalJournalAdmission =
  forAll (elements [0,1,2,4294967295]) $ \version ->
  forAll (elements [0,1,4,5,255]) $ \state ->
  forAll (elements [-1,0,1,2,money,money+1]) $ \amount ->
  forAll (elements [-1,0,1,2,money,money+1]) $ \fee ->
  forAll (elements [-1,0,24,255,256] :: Gen Int32) $ \slot ->
  forAll (elements [-1,0,1,maxBound] :: Gen Int64) $ \created ->
  forAll (chooseInt (0,63)) $ \flags ->
  let request = wordLE 4 version <> B.singleton state <> wordLE 8 (fromIntegral amount) <>
        wordLE 8 (fromIntegral fee) <> wordLE 4 (fromIntegral slot) <>
        wordLE 8 (fromIntegral created) <> B.singleton (fromIntegral flags)
      expected
        | version /= 1 = Left ("unsupported journal version " ++ show version)
        | state > 4 = Left ("unknown journal state " ++ show state)
        | testBit flags 0 = Left "journal contains a null M6 or sidechain transaction id"
        | amount <= 0 || amount > money || fee <= 0 || fee >= amount || fee > money =
            Left "journal amount or mainchain fee is out of range"
        | slot < 0 || slot > 255 || any (testBit flags) [1..4] =
            Left "journal identity, destination, payout script, or bundle is invalid"
        | created <= 0 = Left "journal creation time is invalid"
        | testBit flags 5 = Left "journal bundle is not the expected witness-encoded M6 transaction"
        | otherwise = Right B.empty
      valid = wordLE 4 1 <> B.singleton 0 <> wordLE 8 2 <> wordLE 8 1 <>
        wordLE 4 24 <> wordLE 8 1 <> B.singleton 0
  in conjoin [withdrawal 29 money request === expected,
      withdrawal 29 money valid === Right B.empty,
      ioProperty $ mapM (\invalid ->
        B.useAsCStringLen invalid $ \(ptr,len) -> allocaBytes 256 $ \output -> do
          result <- elements_hs_withdrawal_bytes 29 money (castPtr ptr) (fromIntegral len) output 256
          pure (result === -1)) [B.init valid,B.init valid <> B.singleton 64] >>= pure . conjoin]

withdrawalJournalPrefix :: Property
withdrawalJournalPrefix = forAll ((,,) <$> chooseInt (0,12) <*> arbitrary <*> elements [0,1,2,3 :: Int]) $
  \(size,correct,defect) -> ioProperty $ do
    let bundle=B.take size (B.pack [2,0,0,0,if correct then 0 else 1,1,0] <> B.replicate 8 0xff)
        prefix=B.take 7 bundle
        framing=B.length bundle>=7 && B.index bundle 4==0 && B.index bundle 5==1
        base=wordLE 4 (if defect==1 then 2 else 1) <> B.singleton 0 <> wordLE 8 2 <> wordLE 8 1 <>
          wordLE 4 24 <> wordLE 8 (if defect==2 then 0 else 1)
        flags=if defect==3 then 1 else 0
        legacy=base <> B.singleton (flags + if framing then 0 else 32)
        request=base <> B.singleton flags <> B.singleton (fromIntegral (B.length prefix)) <>
          prefix <> B.replicate (7-B.length prefix) 0
        expected=withdrawal 29 money legacy
        encoded=either (B.cons 1 . C.pack) (B.cons 0) expected
    result <- B.useAsCStringLen request $ \(ptr,len) -> allocaBytes 256 $ \out -> do
      written <- elements_hs_withdrawal_bytes 29 money (castPtr ptr) (fromIntegral len) out 256
      if written<0 then pure B.empty else B.pack <$> peekArray (fromIntegral written) out
    pure $ conjoin [withdrawal 29 money request===expected,result===encoded]

withdrawalJournalIdentity :: Property
withdrawalJournalIdentity = forAll ((,,) <$> vectorOf 32 arbitrary <*> chooseInt (0,31) <*> arbitrary) $
  \(digest,changed,equalHashes) -> ioProperty $ do
    let actual=B.pack digest
        expectedHash=B.pack [if i==changed && not equalHashes then byte `xor` 1 else byte | (i,byte)<-zip [0..] digest]
        request=actual<>expectedHash
        expected=if equalHashes then Right B.empty else Left "journal M6 identity does not match its serialized bundle"
        encoded=either (B.cons 1 . C.pack) (B.cons 0) expected
    reply <- B.useAsCString request $ \ptr -> allocaBytes 256 $ \out -> do
      written <- elements_hs_withdrawal_bytes 35 money (castPtr ptr) 64 out 256
      if written<0 then pure B.empty else B.pack <$> peekArray (fromIntegral written) out
    malformed <- mapM (\size -> B.useAsCString (B.replicate size 0) $ \ptr -> allocaBytes 256 $ \out ->
      elements_hs_withdrawal_bytes 35 money (castPtr ptr) (fromIntegral size) out 256) [0,31,32,63,65]
    pure $ conjoin [withdrawal 35 money request===expected,reply===encoded,malformed===replicate 5 (-1)]

withdrawalJournalLegacy :: Property
withdrawalJournalLegacy = forAll (B.pack <$> vectorOf 4 arbitrary) $ \version ->
  forAll (B.pack <$> (chooseInt (1,1024) >>= flip vectorOf arbitrary)) $ \payload ->
  let legacy = version <> payload
      transport = version <> B.pack [0,1] <> payload
  in ioProperty $ do
    checks <- mapM (\(encoded,expected) -> B.useAsCStringLen encoded $ \(ptr,len) ->
      allocaBytes (len+3) $ \output -> do
        result <- elements_hs_withdrawal_bytes 34 money (castPtr ptr) (fromIntegral len) output (fromIntegral (len+3))
        actual <- if result > 0 then B.packCStringLen (castPtr output,fromIntegral result) else pure B.empty
        pure $ conjoin [result === expected, if expected > 0 then actual === B.cons 0 legacy else actual === B.empty])
      [(transport,fromIntegral (B.length legacy+1)),(B.take 6 transport,-1),
       (version <> B.pack [1,1] <> payload,-1),(version <> B.pack [0,2] <> payload,-1)]
    pure $ conjoin ((withdrawal 34 money transport === Right legacy) : checks)

walletNativeOutputSelection :: Property
walletNativeOutputSelection = forAll (chooseInt (0,8) >>= \count -> vectorOf count (chooseInt (0,9))) $ \tags ->
  let asset=B.replicate 32 1
      parent=B.replicate 32 2
      script=either error id (withdrawal 1 money (parent <> wordLE 8 100 <> B.pack [0,20] <> B.replicate 20 3))
      header=asset <> parent <> wordLE 8 100100 <> wordLE 8 100000 <> wordLE 8 100 <>
        wordLE 4 (fromIntegral (B.length script)) <> script
      record (index,tag)=wordLE 4 index <> (if tag==1 then B.replicate 32 4 else asset) <>
        B.pack [if tag==2 then 0 else 1,if tag==3 then 0 else 1,if tag==4 then 0 else 1,if tag==5 then 0 else 1] <>
        wordLE 8 (if tag==6 then 100101 else if tag==7 then maxBound else 100100) <>
        B.singleton (if tag==8 then 0 else if tag==9 then 2 else 1)
      indexed=zip [0..] tags
      frame=header <> B.concat (map record indexed)
      failure text=wordLE 4 (fromIntegral (-4 :: Int32)) <> C.pack text
      expected=case [index | (index,0) <- indexed] of
        [] -> failure "Committed transaction is missing its exact native withdrawal burn"
        [index] -> wordLE 4 0 <> wordLE 4 index
        _ -> failure "Committed transaction contains multiple native withdrawal burns"
  in conjoin ([withdrawal 28 money frame === Right expected,
    ioProperty $ B.useAsCStringLen frame $ \(ptr,len) -> allocaBytes 256 $ \output -> do
      result <- elements_hs_withdrawal_bytes 28 money (castPtr ptr) (fromIntegral len) output 256
      actual <- if result > 0 then B.packCStringLen (castPtr output,fromIntegral result) else pure B.empty
      pure (actual === B.cons 0 expected)] ++
    [ioProperty $ B.useAsCStringLen malformed $ \(ptr,len) -> allocaBytes 256 $ \output -> do
       result <- elements_hs_withdrawal_bytes 28 money (castPtr ptr) (fromIntegral len) output 256
       pure (result === -1) | malformed <- [B.empty,B.init frame,B.take 88 frame <> wordLE 4 0xffffffff <> B.drop 92 frame]])

walletRpcPolicies :: Property
walletRpcPolicies = forAll ((,) <$> amounts <*> oneof [elements (map C.pack ["","submitted","succeeded","failed","Failed"]), B.pack <$> arbitrary]) $
  \((amount,parentFee),status) ->
    let expectedFee = if parentFee > 0 && parentFee <= money && parentFee < amount
          then Right (wordLE 8 (fromIntegral parentFee))
          else Left "-drivechainpegoutmainfeesats must be positive and less than the withdrawal amount"
        expectedStatus = B.pack $ case C.unpack status of
          "" -> [1,0]
          "failed" -> [2,1]
          "succeeded" -> [0,1]
          _ -> [0,0]
    in conjoin [withdrawal 18 money (wordLE 8 (fromIntegral amount) <> wordLE 8 (fromIntegral parentFee)) === expectedFee,
                withdrawal 19 money status === Right expectedStatus]

walletOutputTransitions :: Property
walletOutputTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 136 phase result
    let expected
          | phase == maxBound = if result == 0 then 13 else -1
          | phase == 0 = 1
          | Just next <- lookup phase [(1,2),(10,11),(11,2)] = if result == 1 then next else -1
          | Just (yes,no) <- lookup phase ([(2,(3,12)),(8,(9,10)),(12,(-11,13))] ++
              [(n,(fromIntegral n+1,11)) | n <- [3..7]]) =
              if result == 1 then yes else if result == 0 then no else -1
          | otherwise = -1
    pure (counterexample (show (phase,result)) (actual === expected)) | phase <- [0..14] ++ [maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

walletSubmissionTransitions :: Property
walletSubmissionTransitions = once $ ioProperty $ do
  checks <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 135 phase result
    let expected
          | phase == maxBound = if result == 0 then 18 else -1
          | phase == 0 = 1
          | Just (yes,no) <- lookup phase [(5,(7,6)),(8,(9,11)),(9,(12,10)),(17,(18,-10))] =
              if result == 1 then yes else if result == 0 then no else -1
          | Just next <- lookup phase ([(10,8),(18,-11)] ++ [(n,fromIntegral n+1) | n <- [1,2,3,4,7,12,13,14,15,16]]) =
              if result == 1 then next else -1
          | otherwise = -1
    pure (counterexample (show (phase,result)) (actual === expected)) | phase <- [0..19] ++ [maxBound], result <- [0,1,2,maxBound]]
  pure (conjoin checks)

walletEventTransitions :: Property
walletEventTransitions = forAll ((,) <$> choose (0,18 :: Word32) <*> elements [0,1,2,3,31,32,33,maxBound]) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_parent_replay_store_checked 134 phase result
  let expected
        | phase == 0 = 1
        | phase == 11 = if result == 32 then 12 else 10
        | Just next <- lookup phase [(2,3),(5,7),(6,3),(10,7)] = if result == 1 then next else -1
        | Just (yes,no) <- lookup phase [(1,(2,-10)),(3,(4,-10)),(4,(5,6)),(7,(8,6)),
            (8,(9,10)),(9,(11,10)),(12,(13,10)),(13,(14,-10)),(14,(-11,15)),(15,(-12,16)),(16,(-13,-10))] =
              if result == 1 then yes else if result == 0 then no else -1
        | otherwise = -1
  pure (actual === expected)

walletTransport :: Property
walletTransport = once $ ioProperty $ do
  transitions <- sequence [do
    actual <- elements_hs_parent_replay_store_checked 133 phase result
    pure (actual === -1) | phase <- [0..10] ++ [maxBound], result <- [0..3] ++ [maxBound]]
  checks <- mapM (\size -> do
    let input = B.pack (take size (cycle [0..255]))
        expected = B.pack [0] <> B.take 4 input <> B.pack [0,1] <> B.drop 4 input
    B.useAsCStringLen input $ \(ptr,len) -> allocaBytes (size+4) $ \output -> do
      pokeByteOff output 0 (0xa5 :: Word8)
      pokeByteOff output (size+3) (0x5a :: Word8)
      result <- elements_hs_withdrawal_bytes 17 money (castPtr ptr) (fromIntegral len) output (fromIntegral size+3)
      actual <- B.packCStringLen (castPtr output, max 0 (fromIntegral result))
      canary <- peekByteOff output (size+3) :: IO Word8
      pokeByteOff output 0 (0xa5 :: Word8)
      short <- elements_hs_withdrawal_bytes 17 money (castPtr ptr) (fromIntegral len) output (fromIntegral size+2)
      untouched <- peekByteOff output 0 :: IO Word8
      pure $ conjoin [if size < 4 then result === -1 else actual === expected,
                      canary === 0x5a, short === -1, untouched === 0xa5]) [0,1,3,4,10,252,253,10000]
  pure (conjoin (transitions ++ checks))

walletMarker :: Property
walletMarker = forAll ((,,) <$> (arbitrary :: Gen Word32) <*> choose (0,15 :: Int) <*>
  vectorOf 128 arbitrary) $ \(height,zeros,raw) ->
    let fields = [if testBit zeros i then B.replicate 32 0 else B.pack (take 32 (drop (32*i) raw)) | i <- [0..3]]
        input = wordLE 4 (fromIntegral height) <> B.concat fields
        accepted = all (B.any (/=0) . (fields !!)) [0,2,3]
        expected = if accepted then Right (B.pack [1,24] <> head fields <> wordBE 4 (fromIntegral height) <> B.concat (tail fields))
          else Left "Cannot create PXST marker with a null consensus commitment"
        digest = B.pack (take 32 raw)
    in conjoin [withdrawal 15 money input === expected,
                withdrawal 16 money digest === Right (B.pack [106,37,80,88,83,84,1] <> digest)]

walletBundleWorkflow :: Property
walletBundleWorkflow = forAll ((,,,,) <$> amounts <*> elements [0,1,10000,10001,maxBound] <*>
  arbitrary <*> vectorOf 12 arbitrary <*> oneof [pure [], vectorOf 40 arbitrary]) $ \((burn,parentFee),size,known,raw,context) -> ioProperty $ do
    seen <- newIORef []
    let input = wordLE 8 (fromIntegral burn) <> wordLE 8 (fromIntegral parentFee) <>
          wordLE 8 size <> B.singleton (if known then 1 else 0) <> B.pack context
        commitment = if null context then B.empty else B.pack ([2] ++ take 36 context ++ replicate 32 0 ++ drop 36 context)
        serialized = B.pack raw
        build plan = do
          modifyIORef' seen (++[(Withdrawal.bundlePayout plan, Withdrawal.bundleFeeScript plan, Withdrawal.bundleInputs plan, Withdrawal.bundleLayout plan)])
          pure serialized
        operation = Withdrawal.WalletBundleRequest (Withdrawal.WithdrawalRequest money input) build
        accepted = burn>0 && burn<=money && parentFee>=0 && parentFee<=money && parentFee<burn &&
          size>0 && size<=10000 && known
    case interpret (SomeOperation operation) Withdrawal.buildWalletBundle of
      Nothing -> pure (counterexample "bundle dispatch mismatch" False)
      Just run -> do
        result <- run
        calls <- readIORef seen
        pure $ if accepted then conjoin
          [calls === [(fromIntegral (burn-parentFee), B.pack [106,8] <> wordBE 8 (fromIntegral parentFee), commitment, B.pack [2,0,0,0,3,0,1,2])],
           result === Right (serialized, B.take 4 serialized <> B.pack [0,1] <> B.drop 4 serialized)]
          else conjoin [calls === [], property (isLeft result)]

walletBundleWorkflowFailures :: Property
walletBundleWorkflowFailures = once $ ioProperty $ do
  let input = wordLE 8 100 <> wordLE 8 1 <> wordLE 8 1 <> B.singleton 1
      dispatch request callback = case interpret (SomeOperation
          (Withdrawal.WalletBundleRequest (Withdrawal.WithdrawalRequest money request) callback)) Withdrawal.buildWalletBundle of
        Nothing -> error "bundle dispatch mismatch"
        Just run -> run
  calls <- newIORef (0 :: Int)
  let build result _ = modifyIORef' calls (+1) >> result
  malformed <- mapM (\n -> dispatch (B.replicate n 0) (build (error "malformed request reached construction")))
    [n | n <- [0..66], n `notElem` [25,65]]
  invalidAbi <- mapM (\size -> elements_hs_wallet_bundle_context money nullPtr size nullFunPtr nullPtr)
    [0,25,64,65,66,maxBound]
  throwing <- try (dispatch input (build (ioError (userError "bundle construction fault"))))
    :: IO (Either SomeException (Either Withdrawal.BundleFailure (B.ByteString,B.ByteString)))
  short <- mapM (\n -> try (dispatch input (build (pure (B.replicate n 0))))) [0..3]
    :: IO [Either SomeException (Either Withdrawal.BundleFailure (B.ByteString,B.ByteString))]
  observed <- readIORef calls
  let mismatch = case interpret (SomeOperation (Withdrawal.WithdrawalRequest money (error "forced mismatched payload")))
                        Withdrawal.buildWalletBundle of
        Nothing -> True
        Just _ -> False
  pure $ conjoin [property (all isLeft malformed), property (isLeft throwing),
    property (all isLeft short), observed === 5, property mismatch, property (all (==(-1)) invalidAbi)]

walletAnchoredWorkflow :: Word32 -> Property
walletAnchoredWorkflow height = forAll ((,,) <$> elements [0..6 :: Int] <*> arbitrary <*> vectorOf 36 arbitrary) $ \(fault,badAmount,raw) -> ioProperty $ do
  trace <- newIORef []
  let genesis = B.replicate 32 (if fault==1 then 0 else 0x22)
      previous = B.replicate 32 0
      root = B.replicate 32 (if fault==2 then 0 else 0x44)
      commitment = B.replicate 32 (if fault==3 then 0 else 0x55)
      anchor = B.replicate 32 0x66
      context = B.pack raw <> wordLE 4 (fromIntegral height)
      inputs = B.singleton 2 <> B.pack raw <> B.replicate 32 0 <> wordLE 4 (fromIntegral height)
      request = wordLE 8 (if badAmount then 0 else 1000) <> wordLE 8 1 <> wordLE 8 1 <>
        B.singleton 1 <> context <> genesis <> previous <> root
      payload = B.pack [1,24] <> genesis <> wordBE 4 (fromIntegral height) <> previous <> commitment <> root
      tag = C.pack "ECX/perps-m6-state/v1"
      tagged = B.singleton (fromIntegral (B.length tag)) <> tag <> payload
      marker = B.pack [106,37,80,88,83,84,1] <> anchor
      fee = B.pack [106,8] <> wordBE 8 1
      serialized = B.pack [2,0,0,0,7,8,9,0]
      record action chunk = modifyIORef' trace (++[(action,chunk)])
      digest action chunk = do
        record action chunk
        if (fault==4 && action==2) || (fault==5 && action==3) then pure B.empty
          else if action==2 then pure commitment else pure anchor
      build plan = do
        record 0 (wordLE 8 (Withdrawal.bundlePayout plan) <> Withdrawal.bundleLayout plan <> Withdrawal.bundleFeeScript plan <>
          Withdrawal.bundleInputs plan <> Withdrawal.bundleMarker plan)
        if fault==6 then ioError (userError "construction failed") else pure serialized
      run = execute (Withdrawal.AnchoredBundleRequest (Withdrawal.WithdrawalRequest money request) digest build)
        Withdrawal.buildWalletBundle
      rejectedAnchor = fault `elem` [1,2,3]
      expectedTrace = [(2,inputs)] ++ [(3,tagged) | not rejectedAnchor && fault/=4] ++
        [(0,wordLE 8 999 <> B.pack [2,0,0,0,4,0,1,2,3] <> fee <> inputs <> marker) | not rejectedAnchor && fault `notElem` [4,5] && not badAmount]
  outcome <- try run :: IO (Either SomeException (Either Withdrawal.BundleFailure (B.ByteString,B.ByteString)))
  observed <- readIORef trace
  pure $ conjoin [observed === expectedTrace, case outcome of
    Left _ -> property (fault `elem` [4,5] || (fault==6 && not badAmount))
    Right result | rejectedAnchor -> result === Left (Withdrawal.AnchorRejection "Cannot create PXST marker with a null consensus commitment")
                 | badAmount -> result === Left (Withdrawal.BundleRejection "Invalid blinded withdrawal amount, fee, payout, or outpoint")
                 | otherwise -> result === Right (serialized,B.take 4 serialized <> B.pack [0,1] <> B.drop 4 serialized)]

walletAnchoredFraming :: Property
walletAnchoredFraming = once $ ioProperty $ do
  let unused _ _ = error "malformed anchor reached digest"
      build _ = error "malformed anchor reached construction"
      run size = execute (Withdrawal.AnchoredBundleRequest (Withdrawal.WithdrawalRequest money (B.replicate size 0)) unused build)
        Withdrawal.buildWalletBundle
  invalid <- mapM run [0,25,65,160,162]
  abi <- mapM (\size -> elements_hs_wallet_bundle_anchor money nullPtr size nullFunPtr nullPtr)
    [0,25,65,160,161,162,maxBound]
  pure (conjoin [invalid === replicate 5 (Left (Withdrawal.AnchorRejection "invalid withdrawal FFI request")),
    abi === replicate 7 (-1)])

walletBundlePlan :: Property
walletBundlePlan = forAll ((,,,) <$> amounts <*> elements [0,1,252,253,10000,10001,maxBound] <*>
  elements [0,1,2,255] <*> elements [0,24,25]) $ \((burn,parentFee),size,known,requestSize) -> ioProperty $ do
    let input = B.take requestSize (wordLE 8 (fromIntegral burn) <> wordLE 8 (fromIntegral parentFee) <>
          wordLE 8 size <> B.singleton known)
        accepted = burn > 0 && burn <= money && parentFee >= 0 && parentFee <= money &&
          parentFee < burn && size > 0 && size <= 10000 && known == 1
        expected = if accepted then B.singleton 0 <> wordLE 8 (fromIntegral (burn-parentFee)) <>
          B.pack [106,8] <> wordBE 8 (fromIntegral parentFee)
          else B.singleton 1 <> C.pack "Invalid blinded withdrawal amount, fee, payout, or outpoint"
    B.useAsCStringLen input $ \(ptr,len) -> allocaBytes 256 $ \output -> do
      pokeByteOff output 0 (0xa5 :: Word8)
      result <- elements_hs_withdrawal_bytes 14 money (castPtr ptr) (fromIntegral len) output 256
      actual <- B.packCStringLen (castPtr output, max 0 (fromIntegral result))
      untouched <- peekByteOff output 0 :: IO Word8
      pure $ if requestSize /= 25 then conjoin [result === -1, untouched === 0xa5]
        else actual === expected

destinationTransitions :: Property
destinationTransitions = forAll ((,) <$> choose (0,16 :: Word32) <*>
  elements ([0..15] ++ [128,129,256,257,maxBound])) $ \(phase,result) -> ioProperty $ do
    actual <- elements_hs_parent_replay_store_checked 132 phase result
    let boolean yes no = case result of {0 -> no; 1 -> yes; _ -> -1}
        expected = case phase of
          0 -> 1
          1 -> boolean 2 5
          2 -> if result > 256 then 4 else 3
          3 -> boolean 6 4
          5 -> boolean 8 10
          6 -> if result == 1 then 9 else -1
          8 -> if result == 1 then 9 else -1
          9 -> if result == 0 || result > 128 then 12 else 11
          11 -> boolean 13 12
          13 -> if (result >= 2 && result <= 5) || (result >= 7 && result <= 9) then -11 else 14
          _ -> -1
    pure (actual === expected)

anchorPayload :: Property
anchorPayload = forAll ((,) <$> (arbitrary :: Gen Word32) <*> vectorOf 128 arbitrary) $ \(height,fields) -> ioProperty $ do
  let input = wordLE 4 (fromIntegral height) <> B.pack fields
      expected = B.pack ([0,1,24] ++ take 32 fields ++
        [fromIntegral (height `shiftR` n) | n <- [24,16,8,0]] ++ drop 32 fields)
  B.useAsCStringLen input $ \(ptr,size) -> allocaBytes 136 $ \output -> do
    pokeByteOff output 135 (0xa5 :: Word8)
    result <- elements_hs_withdrawal_bytes 13 money (castPtr ptr) (fromIntegral size) output 135
    actual <- B.packCStringLen (castPtr output, max 0 (fromIntegral result))
    canary <- peekByteOff output 135 :: IO Word8
    pokeByteOff output 0 (0xff :: Word8)
    tooSmall <- elements_hs_withdrawal_bytes 13 money (castPtr ptr) (fromIntegral size) output 134
    truncated <- elements_hs_withdrawal_bytes 13 money (castPtr ptr) (fromIntegral size-1) output 135
    untouched <- peekByteOff output 0 :: IO Word8
    pure $ conjoin [result === 135, actual === expected, canary === 0xa5,
                    tooSmall === -1, truncated === -1, untouched === 0xff]

byteAbi :: Property
byteAbi = forAllShrink scriptCase shrinkScriptCase $ \(genesis,dest,value) -> ioProperty $ do
  let input = genesis <> wordLE 8 value <> dest
      expected = either ((B.singleton 1 <>) . C.pack) (B.singleton 0 <>) (withdrawal 1 money input)
  B.useAsCStringLen input $ \(ptr,size) -> allocaBytes 258 $ \output -> do
    pokeByteOff output 256 (0xa5 :: Word8)
    pokeByteOff output 257 (0x5a :: Word8)
    result <- elements_hs_withdrawal_bytes 1 money (castPtr ptr) (fromIntegral size) output 256
    actual <- B.packCStringLen (castPtr output, max 0 (fromIntegral result))
    canary <- (,) <$> (peekByteOff output 256 :: IO Word8) <*> (peekByteOff output 257 :: IO Word8)
    pokeByteOff output 0 (0xff :: Word8)
    tooSmall <- elements_hs_withdrawal_bytes 1 money (castPtr ptr) (fromIntegral size) output 1
    untouched <- peekByteOff output 0 :: IO Word8
    pure $ conjoin [actual === expected, canary === (0xa5,0x5a), tooSmall === -1, untouched === 0xff]

outputRoundTrip :: Property
outputRoundTrip = forAllShrink scriptCase shrinkScriptCase $ \(genesis,dest,parentFee) ->
  let burn = min money (fromIntegral parentFee + 1)
      actualFee = min (money-1) (fromIntegral parentFee)
      asset = B.replicate 32 2
      built = withdrawal 8 money (asset <> genesis <> wordLE 8 (fromIntegral burn) <> wordLE 8 (fromIntegral actualFee) <> dest)
      request flags script = asset <> asset <> B.pack flags <> wordLE 8 (fromIntegral burn) <> genesis <> script
  in case built of
    Left message -> counterexample message False
    Right script -> conjoin $
      (withdrawal 9 money (request [1,1,1,1] script) === Right (wordLE 8 (fromIntegral actualFee) <> wordLE 8 1 <> dest)) :
      [property (isLeft (withdrawal 9 money (request flags script))) | flags <- [[0,1,1,1],[1,0,1,1],[1,1,0,1],[1,1,1,0]]]

m6RoundTrip :: Property
m6RoundTrip = forAllShrink scriptCase shrinkScriptCase $ \(genesis,dest,parentFee) -> forAllShrink arbitrary shrink $ \slot ->
  let context = genesis <> B.singleton slot <> B.replicate 32 2 <> wordBE 4 7
      actualFee = min (fromIntegral money-1) parentFee
      input = context <> wordLE 8 (actualFee+1) <> wordLE 8 actualFee <> wordLE 8 1 <> dest
  in case withdrawal 10 money input of
    Left message -> counterexample message False
    Right tx -> conjoin $
      [withdrawal 11 money (context <> tx) === Right (wordLE 8 actualFee <> wordLE 8 (actualFee+1)),
       withdrawal 5 money tx === Right B.empty] ++
      [property (isLeft (withdrawal 11 money (context <> mutated))) |
       mutated <- [B.cons 1 (B.tail tx), B.init tx <> B.singleton 1,
                   B.take 6 tx <> B.singleton 1 <> B.drop 7 tx]] ++
      [property (isLeft (withdrawal 11 money (mutated <> tx))) |
       mutated <- [B.replicate 32 0 <> B.drop 32 context,
                   B.take 33 context <> B.replicate 32 0 <> B.drop 65 context,
                   B.take 65 context <> B.replicate 4 255,
                   genesis <> B.singleton (slot `xor` 1) <> B.drop 33 context]]

legacyWitnessShapePolicy :: Property
legacyWitnessShapePolicy = forAll ((,,) <$> chooseInt (0,12) <*>
  elements (map C.pack ["drivechain-deposit-v1","drivechain-deposit-v2","", "drivechain-deposit-v1x"]) <*>
  elements [0,31,32,33 :: Int]) $ \(count,marker,txidSize) -> ioProperty $ do
    let stack = take count ([B.empty,B.empty,B.empty,B.empty,marker,B.replicate txidSize 0] ++ replicate 6 B.empty)
        expected = count == 6 && marker == C.pack "drivechain-deposit-v1" && txidSize == 32
    withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
      withArray (map (fromIntegral . B.length) stack) $ \sizes -> alloca $ \output -> do
        poke output (-123 :: Int64)
        result <- elements_hs_deposit_witness 0 0 3 (fromIntegral count) sizes fields nullPtr nullPtr nullPtr nullFunPtr output
        untouched <- peek output
        pure $ conjoin [result === if expected then 1 else 0, untouched === -123,
          Deposit.legacyWitnessShape (fromIntegral count) marker (fromIntegral txidSize) === expected]

depositWitnessParity :: Property
depositWitnessParity = forAllShrink gen shrinkWitness $ \(mode,limit,stack,asset,genesis,txid) -> ioProperty $
  withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
  withArray (map (fromIntegral . B.length) stack) $ \sizes ->
  withMany B.useAsCString [asset,genesis,txid] $ \expected ->
  alloca $ \actualValue -> alloca $ \expectedValue -> do
    poke actualValue (-123 :: Int64)
    poke expectedValue (-123 :: Int64)
    let call f out = f money limit mode (fromIntegral (length stack)) sizes fields
          (castPtr (expected !! 0)) (castPtr (expected !! 1)) (castPtr (expected !! 2)) referenceHasher out
    actual <- call elements_hs_deposit_witness actualValue
    wanted <- call reference_deposit_witness expectedValue
    av <- peek actualValue
    ev <- peek expectedValue
    pure $ counterexample (show (mode,limit,map B.length stack)) ((actual,av) === (wanted,ev))
  where
    shrinkWitness (mode,limit,stack,asset,genesis,txid) =
      [(mode,limit,map B.pack fields,asset,genesis,txid) | fields <- shrink (map B.unpack stack)]
    gen = do
      kind <- elements [1,2,3 :: Int]
      mode <- choose (0,2)
      limit <- elements [0,31,32,40,100,4000000]
      asset <- hash
      genesis <- hash
      txid <- hash
      value <- frequency [(3,choose (1,money)), (1,edge [-1,0,money,money+1])]
      claim <- choose (0,101) >>= bytes
      let prefix = [wordLE 8 (fromIntegral value),asset,genesis,claim,
                    C.pack ("drivechain-deposit-v" ++ if kind == 1 then "1" else "2"),txid]
      suffix <- case kind of
        1 -> pure []
        2 -> sequence [hash, choose (1,128) >>= bytes]
        _ -> vectorOf 5 (bytes 8)
      stack <- frequency [(3,pure (prefix ++ suffix)), (2,do
        index <- choose (0,length prefix + length suffix - 1)
        replacement <- choose (0,140) >>= bytes
        pure (take index (prefix ++ suffix) ++ [replacement] ++ drop (index+1) (prefix ++ suffix))),
        (1,pure (take 3 prefix)), (1,pure ((head prefix <> B.singleton 0) : tail prefix ++ suffix))]
      pure (mode,limit,stack,asset,genesis,txid)

depositOutputParity :: Property
depositOutputParity = forAllShrink gen shrink $ \(facts,value,inputs,recipients) -> ioProperty $
  withArray inputs $ \ins -> withArray (map fst recipients) $ \flags ->
  withArray (map snd recipients) $ \values ->
    sameIO (elements_hs_deposit_outputs facts value (fromIntegral (length inputs)) ins
      (fromIntegral (length recipients)) flags values)
      (reference_deposit_outputs facts value (fromIntegral (length inputs)) ins
      (fromIntegral (length recipients)) flags values)
  where
    sameIO a b = (===) <$> a <*> b
    gen = do
      value <- choose (1,money)
      oneof [do
        extras <- listOf (elements [0,2,4,6,8,10,12,14])
        pure (14,value,[3,0],(7,value) : [(f,0) | f <- extras]),
        (,,,) <$> choose (0,15) <*> pure value <*> (choose (0,5) >>= \n -> vectorOf n (choose (0,3))) <*>
          (choose (0,5) >>= \n -> vectorOf n ((,) <$> choose (0,15) <*> elements [0,value,value+1]))]

authenticatedDepositParity :: Property
authenticatedDepositParity = forAllShrink gen shrinkRequest $ \(ins,index,wits,facts,claimed,witnessed,count,outs) -> ioProperty $
  withArray (map fst outs) $ \flags -> withArray (map snd outs) $ \values ->
    sameIO (elements_hs_authenticated_deposit ins index wits facts claimed witnessed count flags values)
      (reference_authenticated_deposit ins index wits facts claimed witnessed count flags values)
  where
    shrinkRequest = filter (\(_,_,_,_,_,_,_,outs) -> length outs == 2) . shrink
    sameIO a b = (===) <$> a <*> b
    gen = do
      claimed <- choose (1,money)
      fee <- choose (0,claimed-1)
      let valid = (1,0,1,127,claimed,claimed,2,[(23,claimed-fee),(15,fee)])
      frequency [(2,pure valid), (3, do
        counts <- vectorOf 4 (elements [0,1,2,3,maxBound])
        facts <- choose (0,255)
        witnessed <- elements [0,claimed,claimed+1]
        outputs <- vectorOf 2 ((,) <$> choose (0,31) <*> choose (-money,money))
        pure (counts !! 0, counts !! 1, counts !! 2, facts, claimed, witnessed, counts !! 3, outputs))]

authenticatedDepositBounds :: Property
authenticatedDepositBounds = forAll (choose (1,maxBound :: Int64)) $ \amount ->
  let result claimed outs = validate (Deposit.AuthenticatedDeposit 1 0 1 127 claimed claimed 2 outs)
  in conjoin [result maxBound [(23,maxBound),(15,amount)] === 8,
              result maxBound [(23,1),(15,maxBound-1)] === 0,
              result amount [(7,1),(0,1)] === 7,
              result amount [(0,1),(7,1)] === 6]

evidenceParity :: Property
evidenceParity = forAllShrink gen shrinkEvidence $ \(limit,stack,txid,state) -> ioProperty $
  withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
  withArray (map (fromIntegral . B.length) stack) $ \sizes -> B.useAsCString txid $ \tx ->
  withArray (state ++ [0]) $ \context -> do
    let call f = f limit (fromIntegral (length stack)) sizes fields (castPtr tx)
          referenceHasher referenceDecoder (castPtr context)
    actual <- call elements_hs_deposit_evidence
    actualCalls <- peekByteOff context 32 :: IO Int64
    pokeByteOff context 32 (0 :: Int64)
    expected <- call reference_deposit_evidence
    expectedCalls <- peekByteOff context 32 :: IO Int64
    pure $ tabulate "evidence result" [show actual] ((actual,actualCalls) === (expected,expectedCalls))
  where
    shrinkEvidence (limit,stack,txid,state) =
      [(limit,map B.pack fields,txid,state) | fields <- shrink (map B.unpack stack)]
    gen = do
      txid <- hash
      previous <- choose (0,maxBound-1 :: Int64)
      let valid = replicate 4 B.empty ++ [C.pack "drivechain-deposit-v2",txid,B.singleton 1,
            B.singleton 1,wordLE 8 (fromIntegral previous+1),wordLE 8 (fromIntegral previous),B.singleton 1]
      stack <- frequency [(3,pure valid), (2,do
        index <- choose (4,10)
        replacement <- choose (0,64) >>= bytes
        pure (take index valid ++ [replacement] ++ drop (index+1) valid)), (1,pure (take 5 valid))]
      state <- frequency [(3,pure [1,previous+1,previous,1]), (2,sequence
        [elements [0,1],edge [0,previous,previous+1],edge [0,previous],elements [0,1,2017,2018]])]
      limit <- elements [31,32,64,4000000]
      pure (limit,stack,txid,state)

evidenceFaults :: Property
evidenceFaults = forAll (elements [-1,2,maxBound :: Int64]) $ \fault -> ioProperty $ do
  -- A wrong shape must not touch any caller memory or invoke callbacks.
  early <- elements_hs_deposit_evidence 100 0 nullPtr nullPtr nullPtr nullFunPtr nullFunPtr nullPtr
  let txid = B.replicate 32 1
      stack = replicate 4 B.empty ++ [C.pack "drivechain-deposit-v2",txid,B.singleton 1,B.singleton 1,
                wordLE 8 1,wordLE 8 0,B.singleton 1]
  withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
    withArray (map (fromIntegral . B.length) stack) $ \sizes -> B.useAsCString txid $ \tx ->
    withArray [fault,1,0,1,0] $ \context -> do
      result <- elements_hs_deposit_evidence 100 11 sizes fields (castPtr tx) referenceHasher referenceDecoder (castPtr context)
      calls <- peekByteOff context 32 :: IO Int64
      pure $ conjoin [early === 1, result === -1, calls === 1]

inclusionParity :: Property
inclusionParity = forAllShrink gen shrink $ \(facts,matches,headers) -> ioProperty $
  withArray (0 : headers) $ \state -> do
    let call f = f facts matches (fromIntegral (length headers)) referenceHeader (castPtr state)
    actual <- call elements_hs_deposit_inclusion
    calls <- peek state
    poke state 0
    expected <- call reference_deposit_inclusion
    expectedCalls <- peek state
    pure $ tabulate "inclusion result" [show actual] ((actual,calls) === (expected,expectedCalls))
  where
    gen = do
      facts <- frequency [(2,pure 15), (1,choose (0,31))]
      matches <- frequency [(2,pure 1), (1,elements [0,1,2,maxBound])]
      count <- chooseInt (1,20)
      headers <- oneof [pure (1 : replicate (count-1) 3), vectorOf count (choose (0,3 :: Int64))]
      pure (facts,matches,headers)

inclusionFaults :: Property
inclusionFaults = forAll (elements [-1,4,fromIntegral (maxBound :: Int32) :: Int64]) $ \fault -> ioProperty $
  withArray [0,fault] $ \state -> do
    early <- elements_hs_deposit_inclusion 0 1 1 nullFunPtr nullPtr
    merkle <- elements_hs_deposit_inclusion 1 1 1 nullFunPtr nullPtr
    counts <- mapM (\count -> elements_hs_deposit_inclusion 15 1 count nullFunPtr nullPtr) [0,2018,maxBound]
    result <- elements_hs_deposit_inclusion 15 1 1 referenceHeader (castPtr state)
    calls <- peek state
    pure $ conjoin [early === 1, merkle === 2, counts === replicate 3 (-1), result === -1, calls === 1]

ctipParity :: Property
ctipParity = forAllShrink gen shrink $ \(facts,matches,current,previous,witnessed) ->
  same (elements_hs_deposit_ctip facts matches current previous witnessed)
       (reference_deposit_ctip facts matches current previous witnessed)
  where
    gen = frequency [(2,do
      previous <- choose (1,maxBound-1 :: Int64)
      delta <- choose (1,maxBound-previous)
      pure (3,1,previous+delta,previous,delta)), (3,
      (,,,,) <$> choose (0,7) <*> elements [0,1,2,maxBound] <*> edge [-1,0,1] <*>
        edge [-1,0,1] <*> edge [-1,0,1])]

depositVerificationFlow :: Property
depositVerificationFlow = forAll (choose (0,1023 :: Word32)) $ \flags -> ioProperty $ do
  let passed step = testBit flags (step - 1)
      chain [] = ([],True)
      chain (step:rest) = if passed step then let (trace,ok) = chain rest in (step:trace,ok)
                         else ([step],False)
      prefix steps (trace,ok) = (steps ++ trace,ok)
      expected | passed 1 = prefix [1] (chain [2,3,4])
               | not (passed 5) = prefix [1,5] (chain [8,9,10])
               | passed 6 = ([1,5,6,7],False)
               | otherwise = prefix [1,5,6] (chain [8,9,10])
      walk 0 trace = pure (reverse trace,True)
      walk (-1) trace = pure (reverse trace,False)
      walk step trace
        | step < 1 || step > 10 || length trace >= 10 = error "invalid verification transition"
        | otherwise = do
            next <- elements_hs_deposit_verification (fromIntegral step) (if passed (fromIntegral step) then 1 else 0)
            walk next (fromIntegral step:trace)
  start <- elements_hs_deposit_verification 0 0
  actual <- walk start []
  pure (actual === expected)

depositAnchorFlow :: Property
depositAnchorFlow = forAll (choose (0,127 :: Word32)) $ \flags -> ioProperty $ do
  let passed step = step == 7 || testBit flags (step - 12)
      expected :: ([Int], Bool)
      expected | passed 12 = ([12,13],passed 13)
               | passed 14 && passed 15 = ([12,14,15,7],False)
               | otherwise =
                   let prefix = if passed 14 then [12,14,15] else [12,14]
                   in if not (passed 16) then (prefix ++ [16],False)
                      else if passed 17 then (prefix ++ [16,17],True)
                      else (prefix ++ [16,17,18],False)
      walk 0 trace = pure (reverse trace,True)
      walk (-1) trace = pure (reverse trace,False)
      walk step trace
        | step < 1 || step > 18 || length trace >= 10 = error "invalid anchor transition"
        | otherwise = do
            next <- elements_hs_deposit_verification (fromIntegral step) (if passed (fromIntegral step) then 1 else 0)
            walk next (fromIntegral step:trace)
  start <- elements_hs_deposit_verification 11 0
  actual <- walk start []
  pure (actual === expected)

depositLifecycleFlow :: Property
depositLifecycleFlow = forAll ((,) <$> arbitrary <*> choose (0,127 :: Word32)) $ \(undo,flags) -> ioProperty $ do
  let passed step = testBit flags (step - if undo then 28 else 20)
      chain [] = ([],True)
      chain (step:rest) = if passed step then let (trace,ok) = chain rest in (step:trace,ok)
                         else ([step],False)
      prefix steps (trace,ok) = (steps ++ trace,ok)
      expected | not undo = prefix [20] (chain (if passed 20 then [21,22,23] else [24,25,26]))
               | not (passed 28) = ([28],False)
               | otherwise = prefix [28,29] (chain (if passed 29 then [30,31] else [32,33,34]))
      walk (-1) trace = pure (reverse trace,False)
      walk step trace
        | step >= 256 = let terminal = fromIntegral (step - 256) in pure (reverse (terminal:trace),passed terminal)
        | step < 20 || step > 34 || length trace >= 10 = error "invalid lifecycle transition"
        | otherwise = do
            next <- elements_hs_deposit_verification (fromIntegral step) (if passed (fromIntegral step) then 1 else 0)
            walk next (fromIntegral step:trace)
  start <- elements_hs_deposit_verification (if undo then 27 else 19) 0
  actual <- walk start []
  pure (actual === expected)

depositParsingFlow :: Property
depositParsingFlow = forAll (choose (0,511 :: Word32)) $ \flags -> ioProperty $ do
  let passed step = maybe True (testBit flags) (lookup step (zip [36,37,39,40,41,42,44,48,49] [0..]))
      reference step trace
        | step == 50 = (reverse (step:trace),True)
        | not (passed step) = case step of
            36 -> (reverse (38:step:trace),False)
            37 -> (reverse (38:step:trace),False)
            40 -> (reverse (43:step:trace),False)
            41 -> (reverse (43:step:trace),False)
            42 -> (reverse (43:step:trace),False)
            _ -> (reverse (step:trace),False)
        | otherwise = reference (if step == 37 then 39 else if step == 42 then 44 else step+1) (step:trace)
      walk (-1) trace = pure (reverse trace,False)
      walk 306 trace = pure (reverse (50:trace),True)
      walk step trace
        | step < 36 || step > 49 || length trace > 15 = error "invalid parsing transition"
        | otherwise = do
            next <- elements_hs_deposit_verification (fromIntegral step) (if passed step then 1 else 0)
            walk next (step:trace)
  start <- elements_hs_deposit_verification 35 0
  actual <- walk start []
  pure (actual === reference 36 [])

ctipInputScanFlow :: Property
ctipInputScanFlow = forAll (resize 24 (listOf (choose (0,7 :: Word32)))) $ \inputs -> ioProperty $ do
  let matches = [i | (i,flags) <- zip [0..] inputs, flags == 7]
      lastMatch = if null matches then 0 else last matches
      traceOne flags = [52,53] ++ (if testBit flags 0 then [54] ++
        (if testBit flags 1 then [55] ++ (if testBit flags 2 then [56] else []) else []) else []) ++ [57]
      expectedTrace = concatMap traceOne inputs ++ [52,58,if null matches then 60 else 59]
      walk step index count selected trace
        | step >= 256 = pure (count,selected,reverse (step-256:trace))
        | length trace > 6 * length inputs + 3 = error "CTIP scan failed to terminate"
        | otherwise = do
            let result = case step of
                  52 -> index < length inputs
                  53 -> testBit (inputs !! index) 0
                  54 -> testBit (inputs !! index) 1
                  55 -> testBit (inputs !! index) 2
                  58 -> count > 0
                  56 -> True
                  57 -> True
                  _ -> error "invalid CTIP scan phase"
            next <- elements_hs_deposit_verification (fromIntegral step) (if result then 1 else 0)
            walk next (if step == 57 then index+1 else index)
              (if step == 56 then count+1 else count) (if step == 56 then index else selected) (step:trace)
  start <- elements_hs_deposit_verification 51 0
  actual <- walk start 0 0 0 []
  pure (actual === (length matches,lastMatch,expectedTrace))

depositAuthenticationFlow :: Property
depositAuthenticationFlow = forAll (choose (0,31 :: Word32)) $ \flags -> ioProperty $ do
  let passed :: Int32 -> Bool
      passed step = testBit flags (fromIntegral step - 62)
      expected step = if step == 66 || not (passed step) then ([step],passed step)
                      else let (trace,ok) = expected (step+1) in (step:trace,ok)
      walk (-1) trace = pure (reverse trace,False)
      walk 322 trace = pure (reverse (66:trace),passed 66)
      walk step trace
        | step < 62 || step > 65 || length trace > 4 = error "invalid authentication transition"
        | otherwise = do
            next <- elements_hs_deposit_verification (fromIntegral step) (if passed step then 1 else 0)
            walk next (step:trace)
  start <- elements_hs_deposit_verification 61 0
  actual <- walk start []
  pure (actual === expected 62)

depositAccessFlow :: Property
depositAccessFlow = forAll ((,) <$> elements [67,72,77 :: Int32] <*> choose (0,31 :: Word32)) $ \(start,flags) -> ioProperty $ do
  let first = start + 1
      passed step = testBit flags (fromIntegral (step - first))
      linear step = if step == first + 3 || not (passed step) then ([step],passed step)
                    else let (trace,ok) = linear (step+1) in (step:trace,ok)
      expected = if start /= 77 then linear first else
        if not (passed 78) then ([78],False) else
        if passed 79 then ([78,79,82],passed 82) else
        if passed 80 then ([78,79,80,81],passed 81) else ([78,79,80],False)
      walk 0 trace = pure (reverse trace,True)
      walk (-1) trace = pure (reverse trace,False)
      walk command trace
        | step < first || step > first + (if start == 77 then 4 else 3) || length trace > 4 = error "invalid deposit access transition"
        | command >= 256 = pure (reverse (step:trace),passed step)
        | otherwise = do
            next <- elements_hs_deposit_verification (fromIntegral step) (if passed step then 1 else 0)
            walk next (step:trace)
        where step = command `mod` 256
  command <- elements_hs_deposit_verification (fromIntegral start) 0
  actual <- walk command []
  pure (actual === expected)

pegReadRunnerParity :: Property
pegReadRunnerParity = forAll gen $ \(mode,kind,limit,values,fault) -> ioProperty $ do
  let value phase = values !! fromIntegral phase
      next phase input | mode == 0 = elements_hs_peg_schema kind phase input limit
                       | otherwise = fromIntegral <$> elements_hs_deposit_projection phase input
      legacy command trace
        | command <= 0 = pure (if command < -1 || (mode == 1 && command /= 0) then minBound else fromIntegral (-command),trace)
        | step < 1 || step > (if mode == 0 then 5 else 10) = pure (minBound,trace)
        | otherwise = do
            let observed = trace ++ [fromIntegral step]
            if step == fault then pure (minBound,observed)
            else if mode == 0 && testBit command 8 then pure (if value step == 1 then 0 else 1,observed)
            else next (fromIntegral step) (value step) >>= \command' -> legacy command' observed
        where step = if mode == 0 then clearBit command 8 else command
      shared entry = do
        observed <- newIORef []
        let action phase = do
              modifyIORef' observed (++[phase])
              if fromIntegral phase == fault then ioError (userError "read failure") else pure (value phase)
        result <- try (entry action) :: IO (Either SomeException Int32)
        trace <- readIORef observed
        pure (either (const minBound) id result,trace)
  expected <- if mode > 1 || (mode == 1 && (kind /= 0 || limit /= 0)) then pure (minBound,[])
              else next 0 0 >>= \first -> legacy first []
  direct <- shared (validate . Deposit.ReadExecution mode kind limit)
  abi <- shared (\action -> bracket (wrapProofFacts (\_ phase ptr -> do
      result <- try (action phase) :: IO (Either SomeException Word64)
      case result of
        Left _ -> pure (-1)
        Right number -> poke ptr number >> pure 1)) freeHaskellFunPtr $ \callback ->
      elements_hs_peg_read_run mode kind limit callback nullPtr)
  missing <- elements_hs_peg_read_run mode kind limit nullFunPtr nullPtr
  pure (conjoin [direct === expected,abi === expected,missing === minBound])
  where
    gen = do
      mode <- frequency [(9,elements [0,1]),(1,elements [2,maxBound])]
      kind <- if mode == 1 then frequency [(9,pure 0),(1,arbitrary)] else elements [0..7]
      limit <- if mode == 1 then frequency [(9,pure 0),(1,arbitrary)] else edge [0,1,9223372036854775808,maxBound]
      values <- vectorOf 11 (frequency [(5,elements [0,1]),(1,edge [2,15,limit*2,maxBound])])
      fault <- choose (0,10)
      pure (mode,kind,limit,values,fault)

depositProjectionFlow :: Property
depositProjectionFlow = forAll gen $ \(inputs,index,witnessCount,facts,outputs) -> ioProperty $ do
  let expected = [1] ++ (if inputs == 1 then [2] ++ (if index == 0 then [3] ++
        (if witnessCount == 1 then [4] ++ (if facts == 15 then [5] else []) else []) else []) else []) ++
        [7] ++ (if outputs > 0 then [8,9] ++ (if outputs > 1 then [10] else []) else [])
      value step = case step of
        1 -> inputs
        2 -> index
        3 -> witnessCount
        4 -> facts
        7 -> outputs
        9 -> outputs
        _ -> 0
      walk 0 trace = pure (reverse trace)
      walk step trace
        | step < 1 || step > 10 || length trace >= 10 = error "invalid projection transition"
        | otherwise = do
            next <- elements_hs_deposit_projection (fromIntegral step) (value step)
            walk next (step:trace)
  start <- elements_hs_deposit_projection 0 0
  actual <- walk start []
  let shared entry = do
        observed <- newIORef []
        result <- entry (\phase -> modifyIORef' observed (++[fromIntegral phase]) >> pure (value (fromIntegral phase :: Int32)))
        trace <- readIORef observed
        pure (result,trace)
  direct <- shared (validate . Deposit.ReadExecution 1 0 0)
  abi <- shared (\action -> bracket (wrapProofFacts (\_ phase ptr -> action phase >>= poke ptr >> pure 1)) freeHaskellFunPtr $ \callback ->
    elements_hs_peg_read_run 1 0 0 callback nullPtr)
  pure (conjoin [actual === expected,direct === (0,expected),abi === direct])
  where
    field = elements [0,1,2,3,15,16,maxBound :: Word64]
    gen = (,,,,) <$> field <*> field <*> field <*> field <*> field

withdrawalStatusTraversal :: Property
withdrawalStatusTraversal = forAll ((,) <$> arbitrary <*> resize 12 (listOf (choose (0,511 :: Word32)))) $ \(valid,events) -> ioProperty $ do
  let passed :: Word32 -> Int64 -> Bool
      passed flags step = testBit flags (fromIntegral step - 5)
      eventTrace flags =
        let filters [] trace = detail (trace ++ [9])
            filters (s:ss) trace = if passed flags s then filters ss (trace ++ [s]) else (trace ++ [s,16],True)
            detail trace | not (passed flags 9) = (trace ++ [11],False)
                         | not (passed flags 10) = (trace ++ [10,11],False)
                         | not (passed flags 12) = (trace ++ [10,12,16],True)
                         | not (passed flags 13) = (trace ++ [10,12,13,15],False)
                         | otherwise = (trace ++ [10,12,13,14,16],True)
        in filters [5..8] []
      reference [] = ([4,17],True)
      reference (flags:rest) = let (trace,ok) = eventTrace flags in
        if not ok then (4:trace,False) else let (later,result) = reference rest in (4:trace ++ later,result)
      expected = if not valid then ([1,3],False) else let (trace,ok) = reference events in (1:2:trace,ok)
      walk (-1) _ trace = pure (reverse trace,False)
      walk 273 _ trace = pure (reverse (17:trace),True)
      walk step index trace
        | length trace > 14 * length events + 5 = error "status traversal did not terminate"
        | otherwise = do
            let result = case step of
                  1 -> valid
                  2 -> True
                  3 -> False
                  4 -> index < length events
                  11 -> False
                  14 -> True
                  15 -> False
                  16 -> True
                  _ | step >= 5 && step <= 13 -> passed (events !! index) step
                    | otherwise -> error "invalid status traversal phase"
            next <- elements_hs_withdrawal_status_flow (fromIntegral step) (if result then 1 else 0)
            walk next (if step == 16 then index+1 else index) (step:trace)
  start <- elements_hs_withdrawal_status_flow 0 0
  actual <- walk start 0 []
  pure (actual === expected)

l1NormalizationTransitions :: Property
l1NormalizationTransitions = forAll ((,) <$> choose (0,35 :: Word32) <*> choose (0,2 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_l1_normalization phase result
  let table = [(0,(1,1)),(1,(3,2)),(2,(-1,4)),(3,(-1,-1)),(4,(290,5)),
        (5,(7,6)),(6,(-1,8)),(7,(-1,-1)),(8,(9,32)),(9,(11,10)),(10,(-1,12)),
        (11,(-1,-1)),(12,(32,13)),(13,(15,14)),(14,(17,16)),(15,(-1,-1)),
        (16,(-1,27)),(17,(31,18)),(18,(-1,19)),(19,(21,20)),(20,(-1,21)),
        (21,(23,22)),(22,(-1,23)),(23,(-1,27)),(27,(-1,28)),(28,(30,29)),
        (29,(-1,31)),(30,(33,31)),(31,(-1,12)),(32,(-1,4)),(33,(-1,-1))]
      expected = if result > 1 then -2 else maybe (-2) (if result == 0 then fst else snd) (lookup phase table)
  pure (actual === expected)

foreign import ccall unsafe reference_event_identity
  :: Word32 -> Ptr Word8 -> Word32 -> Word64 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32

eventIdentityParity :: Property
eventIdentityParity = forAll gen $ \(kind,hashBytes,number,status,capacity) -> ioProperty $
  B.useAsCStringLen hashBytes $ \(input,size) ->
  withArray (replicate 130 (0xa5 :: Word8)) $ \actualBuffer ->
  withArray (replicate 130 (0xa5 :: Word8)) $ \expectedBuffer -> do
    let call f buffer = f kind (castPtr input) (fromIntegral size) number status (buffer `plusPtr` 1) capacity
    actual <- call elements_hs_event_identity actualBuffer
    expected <- call reference_event_identity expectedBuffer
    observed <- peekArray 130 actualBuffer
    wanted <- peekArray 130 expectedBuffer
    oversized <- elements_hs_event_identity kind nullPtr 65 number status nullPtr 0
    pure (conjoin [actual === expected, observed === wanted, oversized === -1])
  where
    gen = (,,,,) <$> elements [0,1,2,3,4,5,maxBound] <*>
      (chooseInt (0,66) >>= \size -> B.pack <$> vectorOf size arbitrary) <*>
      frequency [(3,elements [0,1,0x7fffffffffffffff,0x8000000000000000,maxBound]),(1,arbitrary)] <*>
      elements [0,1,2,3,maxBound] <*> elements [0,64,96,128]

eventLayoutAbi :: Property
eventLayoutAbi = forAll gen $ \(kind,index,status,capacity,missing) -> ioProperty $
  withArray (replicate 34 (0xa5 :: Word8)) $ \key ->
  withArray (replicate 34 (0xa5 :: Word8)) $ \value ->
  withArray (replicate 4 (0xa5 :: Word32)) $ \sizes -> do
    actual <- elements_hs_event_layout kind index status
      (if testBit missing 0 then nullPtr else key `plusPtr` 1)
      (if testBit missing 1 then nullPtr else value `plusPtr` 1) capacity
      (if testBit missing 2 then nullPtr else sizes `plusPtr` 4)
    observedKey <- peekArray 34 key
    observedValue <- peekArray 34 value
    observedSizes <- peekArray 4 sizes
    let state = ["submitted","succeeded","failed"] !! fromIntegral (min 2 status)
        ack = ["pending","accepted","rejected"] !! fromIntegral (min 2 status)
        schemas = [
          "event_id source=sidechain kind=bundle_commitment status=sidechain_committed m6id sidechain",
          "event_id source=sidechain kind=deposit status=sidechain_confirmed sidechain_txid vin mainchain_txid mainchain_vout value_sats asset claim_script sidechain",
          "event_id source=sidechain kind=withdrawal status=sidechain_confirmed sidechain_txid vout value_sats asset mainchain_genesis_hash mainchain_script",
          "event_id source=l1 kind=deposit status=l1_confirmed sidechain_id sequence_number mainchain_txid mainchain_vout address_hex value_sats",
          "event_id source=l1 kind=withdrawal_bundle status=" ++ state ++ " sidechain_id m6id",
          "m6id","sidechain","sequence_number","mainchain_transaction","acknowledgement=" ++ ack,
          "l1","block_hash height","block_hash","height","timestamp",
          "sidechainId valueSats height criticalHash prevBytes","hex","sidechainId endBlockHash"]
        invalid = kind > 17 || ((kind == 4 || kind == 9) && status > 2)
        fields = words (schemas !! fromIntegral (min 17 kind))
        ended = fromIntegral index >= length fields
        (name,suffix) = if ended then ("","") else break (== '=') (fields !! fromIntegral index)
        literal = drop 1 suffix
        fault = length name > fromIntegral capacity || length literal > fromIntegral capacity ||
          testBit missing 0 || testBit missing 2 || (not (null literal) && testBit missing 1)
        expected | invalid = -1
                 | ended = 0
                 | fault = -1
                 | otherwise = (if null suffix then 1 else 2) + (if fromIntegral index + 1 == length fields then 256 else 0)
        buffer text = [0xa5] ++ B.unpack (C.pack text) ++ replicate (33 - length text) 0xa5
    pure (conjoin [actual === expected,
      observedKey === if expected > 0 then buffer name else replicate 34 0xa5,
      observedValue === if expected > 0 then buffer literal else replicate 34 0xa5,
      observedSizes === if expected > 0 then [0xa5,fromIntegral (length name),fromIntegral (length literal),0xa5] else replicate 4 0xa5])
  where
    gen = (,,,,) <$> choose (0,18) <*> frequency [(4,pure 0),(2,choose (0,13))] <*> choose (0,3) <*>
      frequency [(3,pure 32),(1,elements [0,2,8,16])] <*> frequency [(4,pure (0 :: Word32)),(1,choose (0,7))]

pegSchemaTransitions :: Property
pegSchemaTransitions = forAll ((,,,) <$> choose (0,7 :: Word32) <*> choose (0,6 :: Word32) <*>
  frequency [(4,elements [0,1,2,64,maxBound]),(1,arbitrary)] <*>
  elements [0,1,32,maxBound :: Word64]) $ \(kind,phase,value,limit) -> ioProperty $ do
    actual <- elements_hs_peg_schema kind phase value limit
    let branch yes no = if value == 0 then no else if value == 1 then yes else -2
        expected = case (kind,phase) of
          (0,0) -> 1
          (0,1) -> branch 0 (-1)
          (1,0) -> 1
          (1,1) -> branch 258 3
          (1,3) -> branch 4 (-1)
          (1,4) -> branch 261 (-1)
          (2,0) -> 1
          (2,1) -> branch 2 (-1)
          (2,2) -> branch (if limit == 0 then 260 else 3) (-1)
          (2,3) -> if limit == 0 || value == limit * 2 then 260 else -1
          (3,0) -> 1
          (3,1) -> branch 3 258
          (3,3) -> branch 260 261
          (4,0) -> 1
          (4,1) -> branch 258 259
          (5,0) -> 1
          (5,1) -> branch 2 (-1)
          (5,2) -> branch (-1) 0
          (6,0) -> 1
          (6,1) -> branch 258 0
          _ -> -2
    pure (actual === expected)

l1LocationTransitions :: Property
l1LocationTransitions = forAll ((,) <$> choose (0,7 :: Word32) <*> choose (0,2 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_l1_location phase result
  let table = [(0,(1,1)),(1,(-1,2)),(2,(-1,3)),(3,(-1,4)),(4,(262,5)),(5,(-1,262))]
      expected = if result > 1 then -2 else maybe (-2) (if result == 0 then fst else snd) (lookup phase table)
  pure (actual === expected)

sidechainEventTransitions :: Property
sidechainEventTransitions = forAll ((,) <$> choose (0,28 :: Word32) <*> choose (0,2 :: Word32)) $ \(phase,result) -> ioProperty $ do
  actual <- elements_hs_sidechain_events phase result
  let table = [(0,(1,1)),(1,(4,2)),(2,(4,3)),(3,(-1,4)),(4,(283,5)),(5,(-1,6)),
        (6,(11,7)),(7,(10,8)),(8,(10,9)),(9,(-1,10)),(10,(-1,6)),(11,(26,12)),
        (12,(25,13)),(13,(25,14)),(14,(25,15)),(15,(25,16)),(16,(25,17)),
        (17,(-1,18)),(18,(20,19)),(19,(-1,20)),(20,(-1,25)),(25,(-1,11)),(26,(-1,4))]
      expected = if result > 1 then -2 else maybe (-2) (if result == 0 then fst else snd) (lookup phase table)
  pure (actual === expected)

ctipScriptPacking :: Property
ctipScriptPacking = forAll (vectorOf 3 (choose (0,256 :: Int32))) $ \opcodes -> ioProperty $ do
  calls <- newIORef []
  actual <- validate (Deposit.CtipScript (\index -> do
    modifyIORef' calls (++ [index])
    pure (opcodes !! fromIntegral index)))
  order <- readIORef calls
  let expected = foldr (.|.) 0 (zipWith shiftL opcodes [0,9,18])
  pure (conjoin [actual === expected, order === [0,1,2]])

persistedCtipParity :: Property
persistedCtipParity = forAllShrink gen (filter (\(_,_,_,state) -> length state == 3) . shrink) $
  \(facts,amount,script,values) -> ioProperty $ withArray (values ++ [0]) $ \context -> do
    let call f = f facts amount script referenceCtipDecoder (castPtr context)
    actual <- call elements_hs_persisted_ctip
    calls <- peekByteOff context 24 :: IO Int64
    pokeByteOff context 24 (0 :: Int64)
    expected <- call reference_persisted_ctip
    expectedCalls <- peekByteOff context 24 :: IO Int64
    pure $ tabulate "persisted CTIP result" [show actual] ((actual,calls) === (expected,expectedCalls))
  where
    gen = do
      facts <- frequency [(4,pure 31), (1,choose (0,63))]
      amount <- frequency [(4,pure 0), (1,edge [-1,0,1])]
      script <- frequency [(4,pure (71 .|. (117 `shiftL` 9))), (1,arbitrary)]
      status <- elements [0,8,9,10,11,12,13,14,15,15,15,-1,4,16 :: Int64]
      value <- edge [0,1,100]
      sequenceNumber <- edge [-1,0,1]
      pure (facts,amount,script,[status,value,sequenceNumber])

persistedCtipWorkflow :: Property
persistedCtipWorkflow = forAll gen $ \(facts,amount,opcodes,ended,values) -> ioProperty $
  withArray (values ++ [0]) $ \context -> do
    seen <- newIORef []
    let script = fromIntegral (foldr (.|.) 0 (zipWith shiftL opcodes [0,9,18]))
    expected <- reference_persisted_ctip (facts .|. (fromIntegral ended `shiftL` 4)) amount script referenceCtipDecoder (castPtr context)
    expectedCalls <- peekByteOff context 24 :: IO Int64
    pokeByteOff context 24 (0 :: Int64)
    direct <- validate (Deposit.PersistedCtipWorkflow facts amount (\index -> do
        modifyIORef' seen (++[index])
        pure (if index == 3 then ended else opcodes !! fromIntegral index)) referenceCtipDecoder (castPtr context))
        `catch` handleFailure (-1)
    directCalls <- peekByteOff context 24 :: IO Int64
    pokeByteOff context 24 (0 :: Int64)
    -- The production opcode callback is native-only; do not re-enter Haskell through it.
    (actual,opcodeCalls) <- withArray (0 : map fromIntegral (opcodes ++ [ended]) :: [Int64]) $ \opcodeContext -> do
      result <- elements_hs_persisted_ctip_workflow facts amount referenceHeader (castPtr opcodeContext) referenceCtipDecoder (castPtr context)
      count <- peek opcodeContext
      pure (result,count)
    calls <- peekByteOff context 24 :: IO Int64
    trace <- readIORef seen
    missing <- elements_hs_persisted_ctip_workflow facts amount nullFunPtr nullPtr referenceCtipDecoder (castPtr context)
    pure (conjoin [(actual,calls) === (expected,expectedCalls),
      (direct,directCalls) === (expected,expectedCalls),trace === [0,1,2,3],opcodeCalls === 4,missing === -1])
  where
    gen :: Gen (Word32,Int64,[Int32],Int32,[Int64])
    gen = (,,,,) <$> frequency [(4,pure 15),(1,choose (0,15))] <*>
      frequency [(4,pure 0),(1,edge [-1,0,1])] <*>
      frequency [(4,pure [71,117,0]),(1,vectorOf 3 (choose (0,256 :: Int32)))] <*>
      elements [0,1,1,1] <*>
      ((\status value sequenceNumber -> [status,value,sequenceNumber]) <$>
        elements [0,8,15,15,-1,16] <*> edge [0,1,100] <*> edge [-1,0,1])

stateRuleParity :: Property
stateRuleParity = forAll ((,) <$> frequency [(4,choose (0,7)), (1,edge [8,9])] <*> arbitrary) $
  \(phase,facts) -> same (elements_hs_deposit_state phase facts) (reference_deposit_state phase facts)

legacyClaimParity :: Property
legacyClaimParity = forAll ((,,) <$> arbitrary <*> edge [0,2000,100000] <*> arbitrary) $
  \(facts,actual,different) -> conjoin
    [same (elements_hs_legacy_claim facts actual expected) (reference_legacy_claim facts actual expected)
    | expected <- [actual,different]]

destinationParity :: Property
destinationParity = forAll gen $ \outputs -> ioProperty $
  withArray ([0,0,-1] ++ concatMap (\(script,valid) -> [script,valid]) outputs) $ \context -> do
    let call f = f (fromIntegral (length outputs)) referenceDestination (castPtr context)
    actual <- elements_hs_deposit_destination (fromIntegral (length outputs)) referenceDestinationV2 (castPtr context)
    calls <- peekArray 3 context
    pokeByteOff context 0 (0 :: Int64)
    pokeByteOff context 8 (0 :: Int64)
    pokeByteOff context 16 (-1 :: Int64)
    expected <- call reference_deposit_destination
    expectedCalls <- peekArray 3 context
    empty <- elements_hs_deposit_destination 0 nullFunPtr nullPtr
    pure $ conjoin [(actual,calls) === (expected,expectedCalls), empty === -1]
  where
    gen :: Gen [(Int64, Int64)]
    gen = chooseInt (0,12) >>= \count -> vectorOf count ((,) <$>
      frequency [(4,pure (106 + 43 * 512 + 3 * 262144)),
                 (1,elements [-1,1048576,0,256,106 + 79 * 512 + 3 * 262144]),
                 (1,choose (0,1048575))] <*> elements [0,1,1,1,-1,2])

checkpointAbi :: Property
checkpointAbi = forAll gen $ \((txid,previous,record),mode,capacity) -> ioProperty $
  let mutate wanted value = if mode == wanted then B.cons (B.head value `xor` 1) (B.tail value) else value
  in B.useAsCString (mutate 1 txid) $ \identity -> B.useAsCString (mutate 2 previous) $ \prior ->
    withArray (replicate 138 (0xa5 :: Word8)) $ \buffer -> do
      let eligible = if mode == 4 then 0 else if mode == 5 then 2 else 1
          vout = if mode == 3 then 1 else 0
          matches = mode == 0 || mode > 5
          result | mode == 5 = -1
                 | not matches = 0
                 | capacity < 136 = -1
                 | otherwise = 136
      actual <- elements_hs_checkpoint eligible (castPtr identity) (castPtr prior) vout (buffer `plusPtr` 1) capacity
      output <- B.pack <$> peekArray 138 buffer
      ineligible <- elements_hs_checkpoint 0 nullPtr nullPtr 0 nullPtr 0
      wrongVout <- elements_hs_checkpoint 1 nullPtr nullPtr 1 nullPtr 0
      pure $ conjoin [actual === result, ineligible === 0, wrongVout === 0,
        output === if result == 136 then B.singleton 0xa5 <> record <> B.singleton 0xa5 else B.replicate 138 0xa5]
  where
    gen = (,,) <$> elements Deposit.legacyCheckpoints <*> chooseInt (0,7) <*> elements [0,1,135,136,137,maxBound]

liveSynchronousLifecycle :: Property
liveSynchronousLifecycle = forAll (choose (1,maxBound :: Int64)) $ \value -> ioProperty $ do
  calls <- newIORef []
  let readFields _ step fields = do
        initial <- peekArray 4 fields
        modifyIORef' calls (++ [(step,initial)])
        pokeArray fields (if step == 0 then [0,0,0,0] else [value,8,8,1])
        pure 1
  bracket (wrapPegFields readFields) freeHaskellFunPtr $ \reader -> do
    first <- elements_hs_live_evidence 3 reader nullPtr
    second <- elements_hs_live_evidence 3 reader nullPtr
    invalid <- elements_hs_live_evidence maxBound reader nullPtr
    missing <- elements_hs_live_evidence 3 nullFunPtr nullPtr
    observed <- readIORef calls
    pure $ conjoin [[first,second,invalid,missing] === [0,0,-2,-2],
      observed === [(step,replicate 4 0) | step <- [0,1,0,1]]]

liveEvidenceParity :: Property
liveEvidenceParity = forAll gen $ \(phase,values,failedStep,status) -> ioProperty $
  withArray ([0,0,failedStep,status] ++ values) $ \context -> do
    let call f = f phase referenceLive (castPtr context)
    actual <- call elements_hs_live_evidence
    trace <- peekArray 2 context
    pokeByteOff context 0 (0 :: Int64)
    pokeByteOff context 8 (0 :: Int64)
    expected <- call reference_live_evidence
    expectedTrace <- peekArray 2 context
    invalid <- elements_hs_live_evidence maxBound nullFunPtr nullPtr
    pure $ conjoin [(actual,trace) === (expected,expectedTrace), invalid === -2]
  where
    gen :: Gen (Word32, [Int64], Int64, Int64)
    gen = do
      phase <- frequency [(5,choose (0,3)), (1,elements [6,maxBound])]
      let valid = take 24 $ (case phase of
            0 -> [24,1,1,0, 1,1,0,0, 1,0,0,0, 1,0,0,0, 1,1,0,0, 1,100,100,0]
            1 -> [1,0,0,0, 6,90,90,0, 1,1,0,0]
            2 -> [1,0,0,0, 2,0,0,0, 1,100,100,0]
            _ -> [0,0,0,0, 100,8,8,1]) ++ repeat 0
      index <- chooseInt (0,23)
      value <- edge [-1,0,1,255,256]
      values <- elements [valid, take index valid ++ [value] ++ drop (index+1) valid]
      failedStep <- frequency [(3,pure (-1)), (1,choose (0,5))]
      status <- elements [0,-1,2]
      pure (phase,values,failedStep,status)

selectionParity :: Property
selectionParity = forAll gen $ \(phase,responses) -> ioProperty $
  withArray ([0,fromIntegral (length responses)] ++ concat responses) $ \context -> do
    let call f = f phase referenceScripted (castPtr context)
    actual <- call elements_hs_live_evidence
    calls <- peek context
    poke context (0 :: Int64)
    expected <- call reference_live_evidence
    expectedCalls <- peek context
    pure $ tabulate "selection result" [show actual] ((actual,calls) === (expected,expectedCalls))
  where
    reply step values = [step,1] ++ take 4 (values ++ repeat 0)
    gen :: Gen (Word32, [[Int64]])
    gen = do
      phase <- elements [4,5]
      responses <- if phase == 4 then do
        matches <- chooseInt (0,5) >>= \n -> vectorOf n arbitrary
        pure $ [reply 0 [fromIntegral (length matches)]] ++
          concat [reply 1 [1,if match then 24 else 25,24] : [reply 2 [] | match] | match <- matches] ++
          [reply 3 [50,100],reply 4 [1],reply 5 [1],reply 6 [1]]
        else do
          blocks <- chooseInt (0,4) >>= \n -> vectorOf n (chooseInt (0,4) >>= \m -> vectorOf m (chooseInt (0,2)))
          let event kind = [reply 3 [1],reply 4 [if kind == 0 then 0 else 1,1]] ++
                (if kind == 0 then [] else [reply 5 [if kind == 1 then 0 else 1]]) ++
                (if kind == 2 then [reply 6 [2000,2000,8],reply 7 [5],reply 9 [65,66,67,68],reply 9 [69],reply 8 [1],reply 10 []] else [])
          pure $ [reply 0 [fromIntegral (length blocks)]] ++
            concat [[reply 1 [1],reply 2 [1,fromIntegral (length events)]] ++ concatMap event events | events <- blocks]
      index <- chooseInt (0,length responses-1)
      field <- chooseInt (0,5)
      value <- edge [-1,0,1,2]
      let row = responses !! index
          changed = take index responses ++ [take field row ++ [value] ++ drop (field+1) row] ++ drop (index+1) responses
      result <- elements [responses,changed]
      pure (phase,result)

foreign import ccall "&reference_accumulator_hash" accumulatorHasher :: FunPtr HashTransaction

nextBlockHeight :: Property
nextBlockHeight = forAll ((,) <$> elements [0,1,2,3,maxBound] <*>
  frequency [(1,elements [minBound,-1,0,maxBound-1,maxBound]),(3,arbitrary)]) $ \(present,height) -> ioProperty $ do
  actual <- elements_hs_next_block_height present height
  let expected | present == 0 = -1
               | present == 2 = fromInteger (toInteger height + 1)
               | present == 1 && toInteger height < 2147483647 = fromInteger (toInteger height + 1)
               | otherwise = -2147483649
  pure $ conjoin [actual===expected,validate (Bmm.NextBlockHeight present height)===expected]

extraNonce :: Property
extraNonce = forAll ((,) <$> elements [0,1,2,maxBound] <*>
  frequency [(1,elements [0,1,maxBound-1,maxBound]),(3,arbitrary)]) $ \(sameParent,current) -> ioProperty $ do
  actual <- elements_hs_extra_nonce sameParent current
  let expected | sameParent==0 = 1
               | sameParent==1 = fromInteger ((toInteger current+1) `mod` 4294967296)
               | otherwise = -1
  pure $ conjoin [actual===expected,validate (Bmm.ExtraNonce sameParent current)===expected]

peerStrikes :: Property
peerStrikes = forAll ((,) <$> choose (0,7) <*> frequency [(1,elements [0,1,maxBound-1,maxBound]),(3,arbitrary)]) $ \(flags,count) -> ioProperty $ do
  actual <- elements_hs_peer_strikes flags count
  let expected | flags > 3 = -1
               | not (testBit flags 0) = 0
               | testBit flags 1 && count /= 0 = fromInteger (min 4294967295 (toInteger count + 1))
               | otherwise = 1
  pure (actual === expected)

withdrawalStatusParity :: Property
withdrawalStatusParity = forAll ((,) <$> state <*> statusBytes) $ \(prior,status) -> ioProperty $
  B.useAsCStringLen status $ \(ptr,size) -> do
    actual <- elements_hs_withdrawal_status prior (castPtr ptr) (fromIntegral size)
    let ordinal = case C.unpack status of
          "submitted" -> 0
          "succeeded" -> 1
          "failed" -> 2
          _ -> 3
    expected <- reference_peg_event 2 prior ordinal 0
    pure $ counterexample (show (prior,status)) (actual === expected)
  where
    state = frequency [(4,elements [0,1,2,3]),(1,arbitrary)]
    statusBytes = frequency [(4,C.pack <$> elements ["submitted","succeeded","failed"]),
      (3,C.pack <$> elements ["", "Submitted", "failed\0", "succeeded ", " submitted", "unknown"]),
      (2,B.pack <$> arbitrary)]

pegEventParity :: Property
pegEventParity = forAll ((,,,) <$> elements [0,1,2,3,maxBound] <*> scalar <*> scalar <*> scalar) $
  \(kind,a,b,c) -> ioProperty $ do
    actual <- elements_hs_peg_event kind a b c
    expected <- reference_peg_event kind a b c
    pure $ counterexample (show (kind,a,b,c)) (actual === expected)
  where scalar = frequency [(3,chooseInt (0,7) >>= pure . fromIntegral),
                           (2,elements [minBound,maxBound,-1,0,1,4294967296]),(1,arbitrary)]

bmmHeaderParity :: Property
bmmHeaderParity = forAll (frequency [(9,choose (0,511)),(1,arbitrary)]) $ \facts -> ioProperty $ do
  actual <- elements_hs_bmm_header facts
  expected <- reference_bmm_header facts
  pure (actual === expected)

foreign import ccall unsafe reference_bmm_decode_flow :: Word32 -> Word32 -> Word32 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_extension_flow :: Word32 -> Ptr Word64 -> IO Int32
foreign import ccall unsafe reference_bmm_selection_flow :: Word32 -> Word32 -> Ptr Word64 -> IO Int32

bmmWorkFlowParity :: Property
bmmWorkFlowParity = forAll ((,,) <$> arbitrary <*> arbitrary <*> arbitrary) $ \(pow,targetOk,hashOk) -> ioProperty $ do
  first <- elements_hs_bmm_state_flow (if pow then 84 else 81) 0
  let run step trace
        | step <= 0 = pure (step,trace)
        | length trace >= 2 = error "work flow did not terminate"
        | otherwise = do
            let reply = case step of
                  82 -> if targetOk then 1 else 0
                  83 -> 1
                  85 -> if targetOk then 1 else 0
                  86 -> if hashOk then 1 else 0
                  _ -> error "unexpected work action"
            next <- elements_hs_bmm_state_flow (fromIntegral step) reply
            run next (trace ++ [step])
      expected | pow = (if targetOk && hashOk then 0 else -1, [85] ++ [86 | targetOk])
               | otherwise = (0,[82] ++ [83 | targetOk])
  actual <- run first []
  pure (actual === expected)

bmmModeFlowParity :: Property
bmmModeFlowParity = forAll ((,,) <$> arbitrary <*> arbitrary <*> arbitrary) $ \(consensus,eligible,private) -> ioProperty $ do
  first <- elements_hs_bmm_state_flow (if consensus then 80 else 75) 0
  let run step trace
        | step == 0 = pure trace
        | length trace >= 3 = error "mode flow did not terminate"
        | otherwise = do
            let reply = case step of
                  76 -> if eligible then 2 else 0
                  77 -> if private then 1 else 0
                  78 -> 1
                  79 -> 1
                  _ -> error "unexpected mode action"
            next <- elements_hs_bmm_state_flow (fromIntegral step) reply
            run next (trace ++ [step])
      expected = (if consensus then [] else [76]) ++
        (if consensus || eligible then [77,if private then 78 else 79] else [])
  actual <- run first []
  invalid <- sequence [elements_hs_bmm_state_flow 76 1, elements_hs_bmm_state_flow 77 2]
  pure $ conjoin [actual === expected,invalid === [-2,-2]]

bmmSelectionFlowParity :: Property
bmmSelectionFlowParity = forAll ((,) <$> elements [0,1] <*> choose (0,31)) $ \(mode,facts) -> ioProperty $
  withArray [0] $ \out -> do
    expected <- reference_bmm_selection_flow mode facts out
    expectedTrace <- peekArray 1 out
    first <- elements_hs_bmm_state_flow (if mode == 0 then 63 else 68) 0
    let flag = testBit facts
        yes valid = if valid then 1 else 0
        reply step = case step of
          64 -> yes (flag 0)
          65 -> yes (flag 1)
          66 -> yes (flag 1 && flag 2)
          67 -> yes (flag 3)
          69 -> if flag 0 then 1 else -1
          70 -> if flag 1 then 0 else if flag 2 then -2 else 2
          71 -> if flag 3 then 3 else 4
          72 -> 1
          73 -> if flag 4 then 5 else -3
          74 -> 1
          _ -> error "invalid state selection action"
        run step trace fuel
          | step <= 0 = pure (step,[trace])
          | fuel == (0 :: Int) = error "state selection did not terminate"
          | otherwise = do
              next <- elements_hs_bmm_state_flow (fromIntegral step) (reply step)
              run next (trace * 79 + fromIntegral step) (fuel - 1)
    actual <- run first 0 7
    pure (actual === (expected,expectedTrace))

bmmExtensionFlowParity :: Property
bmmExtensionFlowParity = forAll (choose (0,15)) $ \facts -> ioProperty $ withArray [0] $ \out -> do
  expected <- reference_bmm_extension_flow facts out
  expectedTrace <- peekArray 1 out
  first <- elements_hs_bmm_state_flow 49 0
  let run step trace fuel
        | step <= 0 = pure (step,[trace])
        | fuel == (0 :: Int) = error "BMM extension did not terminate"
        | otherwise = do
            let accepted = case step of
                  50 -> testBit facts 0
                  51 -> testBit facts 1
                  52 -> testBit facts 2
                  53 -> all (testBit facts) [0,1,2]
                  54 -> testBit facts 3
                  _ -> error "invalid extension action"
            next <- elements_hs_bmm_state_flow (fromIntegral step) (if accepted then 1 else 0)
            run next (trace * 59 + fromIntegral step) (fuel - 1)
  actual <- run first 0 6
  invalid <- mapM (\phase -> elements_hs_bmm_state_flow phase 2) [50..54]
  pure (conjoin [actual === (expected,expectedTrace), invalid === replicate 5 (-2)])

bmmNativeLookupParity :: Property
bmmNativeLookupParity = forAll arbitrary $ \(proof,stored) -> ioProperty $ do
  first <- elements_hs_bmm_state_flow 107 0
  let run phase seen
        | phase <= 0 = pure (phase,reverse seen)
        | otherwise = do
            let reply = case phase of
                  108 -> if proof then 1 else 0
                  109 -> if stored then 1 else 0
                  110 -> if proof || stored then -1 else 0
                  _ -> error "unexpected lookup phase"
            next <- elements_hs_bmm_state_flow (fromIntegral phase) reply
            run next (phase:seen)
  actual <- run first []
  bad <- mapM (\phase -> elements_hs_bmm_state_flow phase 2) [108..110]
  pure (conjoin [actual === (if proof || stored then -1 else 0, if proof then [108,110] else [108,109,110]),
                 bad === replicate 3 (-2)])

parentSignatureFlow :: Property
parentSignatureFlow = forAll (choose (0,6 :: Int)) $ \failure -> ioProperty $ do
  first <- elements_hs_bmm_state_flow 111 0
  let steps = [112,113,97,98,99,100] :: [Int32]
      run step trace
        | step <= 0 = pure (step,trace)
        | length trace >= 6 = error "parent signature flow did not terminate"
        | otherwise = do
            next <- elements_hs_bmm_state_flow (fromIntegral step) (if length trace == failure then 0 else 1)
            run next (trace ++ [step])
  actual <- run first []
  invalid <- mapM (\step -> elements_hs_bmm_state_flow step 2) [112,113]
  modes <- mapM (elements_hs_bmm_state_flow 114) [0,1,2,-1]
  pure (conjoin [actual === (if failure < 6 then -1 else 0, take (failure + 1) steps),
                 invalid === [-2,-2], modes === [95,111,-2,-2]])

bmmDecodeFlowParity :: Property
bmmDecodeFlowParity = forAll generator $ \(begin,end,failure) -> ioProperty $
  withArray [0] $ \out -> do
    expected <- reference_bmm_decode_flow begin end failure out
    expectedTrace <- peekArray 1 out
    first <- elements_hs_bmm_state_flow (begin - 1) 0
    let run step trace fuel
          | step <= 0 = pure (step,[trace])
          | fuel == (0 :: Int) = error "BMM decoder did not terminate"
          | otherwise = do
              next <- elements_hs_bmm_state_flow (fromIntegral step) (if fromIntegral step == failure then 0 else 1)
              run next (trace * 43 + fromIntegral step) (fuel - 1)
    actual <- run first 0 8
    invalid <- mapM (\phase -> elements_hs_bmm_state_flow phase 2) [begin..end]
    pure (conjoin [actual === (expected,expectedTrace), invalid === replicate (fromIntegral (end - begin + 1)) (-2)])
  where generator = do
          (begin,end) <- elements [(34,40),(42,45),(47,48),(56,58),(60,62),(88,91),(93,94),(96,100),(102,106)]
          failure <- elements (0:[begin..end])
          pure (begin,end,failure)

bmmStateFlowParity :: Property
bmmStateFlowParity = forAll gen $ \(disconnect,replies) -> ioProperty $
  withArray replies $ \input -> withArray [0,0] $ \out -> do
    expected <- reference_bmm_state_flow disconnect input out
    expectedTrace <- peekArray 2 out
    first <- elements_hs_bmm_state_flow (if disconnect == 0 then 0 else 12) 0
    let run step trace writes fuel
          | step <= 0 = pure (step,[trace,writes])
          | fuel == (0 :: Int) = error "BMM state flow did not terminate"
          | otherwise = do
              next <- elements_hs_bmm_state_flow (fromIntegral step) (replies !! fromIntegral step)
              run next ((trace * 29 + fromIntegral step) `mod` 1000000007)
                (writes + if step `elem` [6,11,15,20] then 1 else 0) (fuel - 1)
    actual <- run first 0 0 24
    unknown <- elements_hs_bmm_state_flow maxBound 0
    badReply <- elements_hs_bmm_state_flow 1 3
    let start = if disconnect == 0 then 0 else 12
        shared entry = do
          observed <- newIORef [0,0]
          let action step = do
                modifyIORef' observed (\fields -> case fields of
                  [trace,writes] -> [(trace*29+fromIntegral step) `mod` 1000000007,
                    writes + if step `elem` [6,11,15,20] then 1 else 0]
                  _ -> error "invalid BMM test transcript")
                pure (fromIntegral (replies !! fromIntegral step))
          outcome <- entry action
          fields <- readIORef observed
          pure (outcome,fields)
    direct <- shared (validate . Bmm.StateExecution start)
    abi <- shared (\action -> bracket (wrapMatchFact (\_ -> action)) freeHaskellFunPtr $ \callback ->
      elements_hs_bmm_state_run start callback nullPtr)
    pure (conjoin [actual === (expected,expectedTrace), unknown === -2, badReply === -2,
      direct === (-expected,expectedTrace),abi === direct])
  where
    gen = (,) <$> elements [0,1] <*> mapM elements
      [[0],[1,2],[0,1],[0,-1],[3,4],[5,-2,-3],[1],[0,6],[0,7],[0,1],[0,1],[1],
       [0],[1,2],[3,-3,-4],[0,-5],[0,4],[0,1],[5,-3,-6],[0,1],[1],[0,1],[6,-7],[-7]]

bmmStateRunBoundaries :: Property
bmmStateRunBoundaries = forAll ((,) <$> frequency [(9,choose (0,116)),(1,arbitrary)] <*>
    elements [minBound,-2147483649,-2147483648,-7,-3,-2,-1,0,1,2,3,4,5,6,7,2147483647,2147483648,maxBound]) $ \(start,reply) -> ioProperty $ do
  first <- elements_hs_bmm_state_flow start 0
  let legacy phase trace
        | phase < -1 || phase > 114 = pure (-1,trace)
        | phase <= 0 = pure (-phase,trace)
        | reply < -2147483648 || reply > 2147483647 = pure (-1,trace ++ [fromIntegral phase])
        | otherwise = elements_hs_bmm_state_flow (fromIntegral phase) (fromIntegral reply) >>=
            \next -> legacy next (trace ++ [fromIntegral phase])
  expected <- legacy first []
  observed <- newIORef []
  actual <- bracket (wrapMatchFact (\_ step -> modifyIORef' observed (++[step]) >> pure reply)) freeHaskellFunPtr $ \callback ->
    elements_hs_bmm_state_run start callback nullPtr
  trace <- readIORef observed
  missing <- elements_hs_bmm_state_run start nullFunPtr nullPtr
  pure (conjoin [(actual,trace) === expected,missing === -1])

bmmStateRunLong :: Property
bmmStateRunLong = once $ ioProperty $ do
  nonces <- newIORef (0 :: Int)
  published <- newIORef (0 :: Int)
  let action phase = case phase of
        29 -> readIORef nonces >>= \n -> pure (if n < 100000 then 0 else 1)
        30 -> modifyIORef' nonces (+1) >> pure 1
        31 -> modifyIORef' published (+1) >> pure 1
        _ -> pure 1
  actual <- validate (Bmm.StateExecution 24 action)
  tries <- readIORef nonces
  writes <- readIORef published
  pure (conjoin [actual === 0,tries === 100000,writes === 1])

bmmProofRunBoundaries :: Property
bmmProofRunBoundaries = forAll gen $ \(kind,start,fields,status) -> ioProperty $ do
  let transition phase = case (kind,fields) of
        (0,[a,b,c,d]) -> do
          next <- elements_hs_signet_validation phase a b c d
          pure (if next == -7 then minBound else next)
        (1,[a,b,_,_]) -> do
          next <- elements_hs_bmm_traversal phase a b
          pure (if next == -3 then minBound else next)
        _ -> pure minBound
      initial | kind == 0 = elements_hs_signet_validation start 0 0 0 0 >>= \n -> pure (if n == -7 then minBound else n)
              | kind == 1 = elements_hs_bmm_traversal start 0 0 >>= \n -> pure (if n == -3 then minBound else n)
              | otherwise = pure minBound
      legacy phase trace
        | phase <= 0 = pure (phase,trace)
        | otherwise = do
            let observed = trace ++ [fromIntegral phase]
            if status /= 1 || length observed >= 128 then pure (minBound,observed)
            else if kind == 1 && phase == 19 then pure (0,observed)
            else transition (fromIntegral phase) >>= \next -> legacy next observed
  expected <- initial >>= \first -> legacy first []
  observed <- newIORef []
  cleared <- newIORef True
  actual <- bracket (wrapProofFacts (\_ phase output -> do
      prior <- peekArray 4 output
      modifyIORef' cleared (&& all (==0) prior)
      modifyIORef' observed (++[phase])
      trace <- readIORef observed
      pokeArray output fields
      pure (if length trace >= 128 then -1 else status))) freeHaskellFunPtr $ \callback ->
        elements_hs_bmm_proof_run kind start callback nullPtr
  trace <- readIORef observed
  zeroed <- readIORef cleared
  missing <- elements_hs_bmm_proof_run kind start nullFunPtr nullPtr
  pure (conjoin [(actual,trace) === expected, property zeroed, missing === minBound])
  where
    gen = (,,,) <$> frequency [(9,elements [0,1]),(1,elements [2,maxBound])] <*>
      frequency [(9,choose (0,22)),(1,pure maxBound)] <*>
      vectorOf 4 (edge [0,1,2,3,9223372036854775808,maxBound]) <*>
      frequency [(9,pure 1),(1,elements [-1,0,2,minBound,maxBound])]

bmmProofRunLong :: Property
bmmProofRunLong = once $ ioProperty $ do
  position <- newIORef (0 :: Word64)
  published <- newIORef (0 :: Int)
  let action phase = case phase of
        7 -> do
          index <- readIORef position
          writeIORef position (index+1)
          pure [index,100000,0,0]
        19 -> modifyIORef' published (+1) >> pure [0,0,0,0]
        _ -> pure [1,0,0,0]
  actual <- validate (Bmm.ProofExecution 1 0 action)
  count <- readIORef position
  writes <- readIORef published
  invalid <- validate (Bmm.ProofExecution 2 0 (\_ -> error "unknown kind forced action"))
  pure (conjoin [actual === 0,count === 100000,writes === 1,invalid === minBound])

bmmProofWorkflow :: Property
bmmProofWorkflow = forAll generator $ \(start,count,signet,fault,replacement) -> ioProperty $ do
  let run interpreter = do
        seen <- newIORef []
        position <- newIORef 0
        let action step = do
              modifyIORef' seen (++[step])
              index <- readIORef position
              when (step == 7) (writeIORef position (index+1))
              pure $ if step == fault then replacement else case step of
                1 -> [1,count,8,0]
                2 -> [0,1,1,100]
                3 -> [1,1,1,0]
                7 -> [index,count,0,0]
                12 -> [3,1,100,0]
                154 -> [0,if signet then 1 else 0,0,0]
                205 -> [1,1,0,0]
                _ -> [1,0,0,0]
        result <- interpreter action
        trace <- readIORef seen
        pure (result,trace)
      -- The former native nesting, expressed independently of ProofWorkflow.
      reference action = either id id <$> runExceptT (case start of
        0 -> do
          check 0 1
          gate (-1) 147
          gate (-1) 18
          mapM_ entry [1..count]
          check 5 8
          gate (-1) 9
          check 6 10
          _ <- fields 19
          pure 0
        11 -> do
          check 7 12
          check 8 13
          gate (-1) 14
          check 9 15
          gate (-1) 16
          gate (-1) 17
          pure 0
        21 -> check 13 22 >> gate (-1) 23 >> pure 0
        _ -> throwE minBound)
        where
          fields = lift . action
          gate code step = fields step >>= \values -> when (head values == 0) (throwE code)
          proof phase [flags,a,b,c] = case validate (Bmm.Proof phase (fromIntegral flags) a b c) of
            0 -> pure ()
            code -> throwE (100+code)
          proof _ _ = throwE minBound
          check phase step = fields step >>= proof phase
          decode [] bits = pure bits
          decode (step:rest) bits = do
            values <- fields step
            if head values == 0 then pure bits
              else decode rest (bits .|. (1 `shiftL` fromIntegral (step-201)))
          extension [] = pure ()
          extension (step:rest) = fields step >>= \values ->
            if head values == 0 then throwE 105 else extension rest
          entry _ = do
            check 1 2
            _ <- fields 200
            bits <- decode [201..204] 0
            shape <- fields 205
            proof 2 [bits .|. (head shape `shiftL` 4),shape !! 1,0,0]
            check 3 3
            check 10 4
            extension [150..152]
            pow <- fields 154
            proof 11 [head pow,0,0,0]
            check 12 155
            when (pow !! 1 /= 0) (gate (-2) 6)
            _ <- fields 7
            pure ()
  expected <- run reference
  direct <- run (validate . Bmm.ProofWorkflow start)
  actual <- run $ \action -> bracket (wrapProofFacts (\_ step out -> action step >>= pokeArray out >> pure 1))
    freeHaskellFunPtr $ \callback -> elements_hs_bmm_proof_workflow start callback nullPtr
  missing <- elements_hs_bmm_proof_workflow start nullFunPtr nullPtr
  malformed <- validate (Bmm.ProofWorkflow start (\_ -> pure [1,2,3]))
  pure (conjoin [direct === expected,actual === expected,missing === minBound,malformed === minBound])
  where
    generator = do
      start <- elements [0,0,11,21]
      count <- choose (0,8)
      signet <- arbitrary
      fault <- elements [0,1,2,3,4,6,8,9,10,12,13,14,15,16,17,22,23,147,150,151,152,154,155,201,202,203,204,205]
      -- Native booleans remain booleans; malformed transport is tested separately.
      replacement <- case fault of
        1 -> elements [[0,count,8,0],[1,0,8,0],[1,9,8,0]]
        2 -> elements [[0,0,1,100],[0,1,101,100]]
        3 -> elements [[0,1,1,0],[1,2,1,0],[1,1,1,1]]
        12 -> elements [[0,1,100,0],[3,0,100,0],[3,101,100,0]]
        154 -> pure [1,if signet then 1 else 0,0,0]
        205 -> elements [[0,1,0,0],[1,2,0,0]]
        _ -> pure [0,0,0,0]
      pure (start,count,signet,fault,replacement)

bmmPrivateBuildParity :: Property
bmmPrivateBuildParity = forAll ((,) <$> elements [0,25,26,32] <*> choose (0,100)) $ \(failure,retries) -> ioProperty $
  withArray [0,0] $ \out -> do
    expected <- reference_private_build failure retries out
    expectedTrace <- peekArray 2 out
    first <- elements_hs_bmm_state_flow 24 0
    let run step remaining trace writes fuel
          | step <= 0 = pure (step,[trace,writes])
          | fuel == (0 :: Int) = error "private construction did not terminate"
          | otherwise = do
              let reply = if step == 29 then if remaining == 0 then 1 else 0
                          else if fromIntegral step == failure then 0 else 1
              next <- elements_hs_bmm_state_flow (fromIntegral step) reply
              run next (if step == 30 then remaining - 1 else remaining)
                ((trace * 37 + fromIntegral step) `mod` 1000000007)
                (writes + if step == 31 then 1 else 0) (fuel - 1)
    actual <- run first retries 0 0 210
    pure (actual === (expected,expectedTrace))

bmmLifecycleParity :: Property
bmmLifecycleParity = forAll ((,) <$> small [0..12] <*> small [0..16]) $ \(phase,facts) -> ioProperty $ do
  actual <- elements_hs_bmm_lifecycle phase facts
  expected <- reference_bmm_lifecycle phase facts
  pure (actual === expected)
  where small xs = frequency [(9,elements xs),(1,arbitrary)]

bmmStateSourceParity :: Property
bmmStateSourceParity = forAll ((,) <$> small [0..6] <*> small [0..7]) $ \(phase,facts) -> ioProperty $ do
  actual <- elements_hs_bmm_state_source phase facts
  expected <- reference_bmm_state_source phase facts
  pure (actual === expected)
  where small xs = frequency [(9,elements xs),(1,arbitrary)]

bmmWrapperParity :: Property
bmmWrapperParity = forAll (elements [0,12,13,14,15,16,17,maxBound]) $ \failure -> ioProperty $
  withArray [0] $ \traceOut -> do
    expected <- reference_bmm_wrapper failure traceOut
    expectedTrace <- peekArray 1 traceOut
    first <- elements_hs_bmm_traversal 11 0 0
    let run step trace fuel
          | step <= 0 = pure (step,[trace])
          | fuel == (0 :: Int) = error "BMM wrapper did not terminate"
          | otherwise = do
              next <- elements_hs_bmm_traversal (fromIntegral step) (if fromIntegral step == failure then 0 else 1) 0
              run next (trace * 19 + fromIntegral step) (fuel - 1)
    actual <- run first 0 7
    pure (actual === (expected,expectedTrace))

bmmAdvanceParity :: Property
bmmAdvanceParity = forAll gen $ \(interval,time,bits,fields) -> ioProperty $
  withArray (sentinel : fields ++ [sentinel]) $ \actual -> withArray fields $ \expected -> do
    result <- elements_hs_bmm_advance interval time bits 16 (actual `plusPtr` 4)
    reference <- reference_bmm_advance interval time bits expected
    output <- peekArray 18 actual
    expectedFields <- peekArray 16 expected
    invalidCount <- elements_hs_bmm_advance interval time bits 15 (actual `plusPtr` 4)
    missing <- elements_hs_bmm_advance interval time bits 16 nullPtr
    unchanged <- peekArray 18 actual
    pure (conjoin [result === reference, output === sentinel : expectedFields ++ [sentinel],
                  invalidCount === -1, missing === -1, unchanged === output])
  where
    sentinel = 0xa5a5a5a5
    gen = do
      interval <- frequency [(4,elements [-1,0,1,2016,4294967296,maxBound]),(1,arbitrary)]
      height <- frequency [(4,elements [0,1,2014,2015,2016,maxBound]),(1,arbitrary)]
      time <- arbitrary
      bits <- arbitrary
      rest <- vectorOf 15 arbitrary
      pure (interval,time,bits,height:rest)

bmmTraversalParity :: Property
bmmTraversalParity = forAll ((,,,) <$> choose (0,8) <*> elements [0,1] <*> choose (0,8) <*> elements ([0..10] ++ [18,19,20])) $
  \(count,signet,failEntry,failPhase) -> ioProperty $ withArray [0,0] $ \out -> do
    expected <- reference_bmm_traversal count signet failEntry failPhase out
    expectedTrace <- peekArray 2 out
    first <- elements_hs_bmm_traversal 0 0 0
    let run step index trace fuel
          | step <= 0 = pure (step,[trace,index])
          | fuel == (0 :: Int) = error "BMM traversal did not terminate"
          | otherwise = do
              let phase = fromIntegral step
                  passed = not (phase == failPhase && (phase `elem` [1,8,9,10,18,19] || index == failEntry))
                  a = if phase == 7 then index else if passed && (phase /= 1 || count > 0) then 1 else 0
                  b = if phase == 7 then count else if phase == 5 then signet else 0
              next <- elements_hs_bmm_traversal phase a b
              run next (if phase == 7 then index + 1 else index) ((trace * 13 + fromIntegral step) `mod` 1000000007) (fuel - 1)
    actual <- run first 0 0 64
    boundary <- elements_hs_bmm_traversal 7 (maxBound - 1) maxBound
    invalid <- elements_hs_bmm_traversal 7 maxBound maxBound
    unknown <- elements_hs_bmm_traversal maxBound 0 0
    let shared entry = do
          observed <- newIORef [0,0]
          let action phase = do
                prior <- readIORef observed
                case prior of
                  [trace,index] -> do
                    let passed = not (phase == failPhase && (phase `elem` [1,8,9,10,18,19] || index == failEntry))
                        a = if phase == 7 then index else if passed && (phase /= 1 || count > 0) then 1 else 0
                        b = if phase == 7 then count else if phase == 5 then signet else 0
                    writeIORef observed [(trace*13+fromIntegral phase) `mod` 1000000007,index+if phase==7 then 1 else 0]
                    pure [a,b,0,0]
                  _ -> error "invalid proof traversal transcript"
          outcome <- entry action
          trace <- readIORef observed
          pure (outcome,trace)
    direct <- shared (validate . Bmm.ProofExecution 1 0)
    abi <- shared (\action -> bracket (wrapProofFacts (\_ phase ptr -> action phase >>= pokeArray ptr >> pure 1)) freeHaskellFunPtr $ \callback ->
      elements_hs_bmm_proof_run 1 0 callback nullPtr)
    pure (conjoin [actual === (expected,expectedTrace), boundary === 8, invalid === -3, unknown === -3,
      direct === (if failPhase==19 && count>0 then 0 else expected,expectedTrace),abi === direct])

bmmCodecParity :: Property
bmmCodecParity = forAll gen $ \(phase,facts,a,b) -> ioProperty $ do
  actual <- elements_hs_bmm_codec phase facts a b
  expected <- reference_bmm_codec phase facts a b
  pure (actual === expected)
  where
    small xs = frequency [(4,elements xs),(1,arbitrary)]
    gen = (,,,) <$> small [0..11] <*> small [0,1,2,3,15,31,32] <*>
      small [0,1,76,77,78,79,117,128,129,1000000,1000001,maxBound] <*>
      small [0,1,128,1000000,maxBound]

bmmProofParity :: Property
bmmProofParity = forAll gen $ \(phase,facts,a,b,c) -> ioProperty $ do
  actual <- elements_hs_bmm_proof phase facts a b c
  expected <- reference_bmm_proof phase facts a b c
  pure (actual === expected)
  where
    gen = (,,,,) <$> frequency [(9,choose (0,13)),(1,elements [14,maxBound])] <*>
      edge [0,1,3,7,31] <*> edge [0,1,1000000,1000001] <*>
      edge [0,1,1000000,1000001] <*> edge [0,1,1000000,1000001]

signetValidationParity :: Property
signetValidationParity = forAll gen $ \facts -> ioProperty $
  withArray facts $ \input -> withArray [0] $ \traceOut -> do
    expected <- reference_signet_validation input traceOut
    expectedTrace <- peekArray 1 traceOut
    first <- elements_hs_signet_validation 0 0 0 0 0
    (actual,trace) <- run facts first 0 (8 :: Int)
    faults <- mapM (\phase -> elements_hs_signet_validation phase 0 0 0 0) [8,9,maxBound]
    let shared entry = do
          observed <- newIORef 0
          let action phase = do
                modifyIORef' observed (\n -> n*10+fromIntegral phase)
                pure $ case phase of
                  1 -> [facts !! 0,0,0,0]
                  2 -> [facts !! 1,0,0,0]
                  3 -> [facts !! 2,0,0,0]
                  4 -> [facts !! 3,0,0,0]
                  5 -> take 4 (drop 4 facts)
                  6 -> [facts !! 8,0,0,0]
                  7 -> [facts !! 9,0,0,0]
                  _ -> error "invalid signet runner action"
          outcome <- try (entry action) :: IO (Either SomeException Int32)
          seen <- readIORef observed
          pure (either (const minBound) id outcome,[seen])
    direct <- shared (validate . Bmm.ProofExecution 0 0)
    abi <- shared (\action -> bracket (wrapProofFacts (\_ phase ptr -> action phase >>= pokeArray ptr >> pure 1)) freeHaskellFunPtr $ \callback ->
      elements_hs_bmm_proof_run 0 0 callback nullPtr)
    pure (conjoin [actual === expected, [trace] === expectedTrace, faults === replicate 3 (-7),
      direct === (if expected == -7 then minBound else expected,expectedTrace),abi === direct])
  where
    gen = frequency [(1,randomFacts),(3,do
      hasSolution <- elements [0,1]
      let good = [1,1,hasSolution,0,1,1,1,0,1,1]
      (index,value) <- elements [(0,1),(0,0),(1,0),(3,1),(3,2),(3,3),
                                (4,0),(5,0),(5,2),(6,0),(6,2),(7,1),(8,0),(9,0)]
      pure (take index good ++ [value] ++ drop (index + 1) good))]
    randomFacts = sequence [edge [0,1], edge [0,1], edge [0,1], edge [0,1,2,3],
                            edge [0,1], edge [0,1,2], edge [0,1,2], edge [0,1], edge [0,1], edge [0,1]]
    run facts step trace fuel
      | step <= 0 = pure (step,trace)
      | fuel == 0 = error "signet planner did not terminate"
      | otherwise = do
          let (a,b,c,d) = case step of
                1 -> (facts !! 0,0,0,0)
                2 -> (facts !! 1,0,0,0)
                3 -> (facts !! 2,0,0,0)
                4 -> (facts !! 3,0,0,0)
                5 -> (facts !! 4,facts !! 5,facts !! 6,facts !! 7)
                6 -> (facts !! 8,0,0,0)
                7 -> (facts !! 9,0,0,0)
                _ -> error "invalid signet action"
          next <- elements_hs_signet_validation (fromIntegral step) a b c d
          run facts next (trace * 10 + fromIntegral step) (fuel - 1)

replayMaintenanceExpiry :: Property
replayMaintenanceExpiry = forAll gen $ \(height,entries,fault) -> ioProperty $ do
  seen <- newIORef []
  let slots = zip (24:[0..] :: [Word8]) entries
      inventory = B.pack (concatMap (\(slot,(used,_,_)) -> [slot,if used then 1 else 0]) slots)
      windows = 10 + 5*65536 + 20*4294967296 + 15*281474976710656
      event step slot payload = (step,fromIntegral slot,payload)
      erase step slot selected = [event step slot (B.concat (map (wordLE 8) selected)) | not (null selected)]
      prefix decide = go 0 []
        where
          go _ selected [] = (0,reverse selected)
          go index selected (entry:rest) = case decide entry of
            Left code -> (code,reverse selected)
            Right expired -> go (index+1) (if expired then index:selected else selected) rest
      proposal used (proposed,votes)
        | proposed > height = Left 1
        | votes > 65535 = Left (-1)
        | votes > age = Left 2
        | otherwise = Right (age > maxAge || (age > maxFails && age-votes >= maxFails))
        where
          age = height-proposed
          (maxAge,maxFails) = if used then (20,5) else (10,5)
      withdrawals [] = (0,[])
      withdrawals ((slot,(_,_,rows)):rest) =
        let decide proposed | proposed > height = Left (1 :: Int32)
                            | otherwise = Right (height-proposed > 12)
            (status,selected) = prefix decide rows
            current = event 3 slot B.empty : erase 4 slot selected
            (later,following) = withdrawals rest
        in if status /= 0 then (0x300,current) else (later,current++following)
      proposals [] = withdrawals (List.sortOn fst (filter (\(_, (used,_,_)) -> used) slots))
      proposals ((slot,(used,rows,_)):rest) =
        let (status,selected) = prefix (proposal used) rows
            current = event 1 slot B.empty : erase 2 slot selected
            (later,following) = proposals rest
        in if status /= 0 then (if status < 0 then status else status*256+fromIntegral slot,current)
          else (later,current++following)
      (expected,restTrace) = proposals slots
      trace = (0,0,B.empty):restTrace
      native step slot payload = do
        calls <- readIORef seen
        modifyIORef' seen (++[(step,slot,payload)])
        pure $ if length calls == fault then B.singleton 255 else case step of
          0 -> inventory
          1 -> let (_,rows,_) = fromMaybe (error "unknown proposal slot") (lookup (fromIntegral slot) slots)
               in B.concat [wordLE 4 (fromIntegral proposed) <> wordLE 4 (fromIntegral votes) | (proposed,votes) <- rows]
          3 -> let (_,_,rows) = fromMaybe (error "unknown withdrawal slot") (lookup (fromIntegral slot) slots)
               in B.concat (map (wordLE 4 . fromIntegral) rows)
          _ -> B.empty
      failed = fault >= 0 && fault < length trace
  actual <- execute (ParentReplay.Maintenance height windows 12 0 native) ParentReplay.BeforeTreasury
  observed <- readIORef seen
  pure $ conjoin [actual === if failed then -1 else expected,
    observed === if failed then take (fault+1) trace else trace,
    property ((() <$ interpret (SomeOperation (undefined :: Withdrawal.WithdrawalRequest))
      (error "mismatched maintenance DSL forced" `asTypeOf` ParentReplay.BeforeTreasury)) == Nothing)]
  where
    gen = (,,) <$> choose (0,110 :: Word32) <*>
      resize 6 (listOf ((,,) <$> arbitrary <*>
        resize 8 (listOf ((,) <$> choose (0,110) <*> frequency [(9,choose (0,25)),(1,elements [65535,65536,maxBound])])) <*>
        resize 8 (listOf (choose (0,110))))) <*> choose (-1,35 :: Int)

replayMaintenancePublication :: Property
replayMaintenancePublication = forAll gen $ \(flags,occupied,clockFacts,fault) -> ioProperty $ do
  seen <- newIORef []
  let slots = zip [0..] occupied :: [(Word8,Word8)]
      retired = B.pack [slot | (slot,0) <- slots]
      prefix = [(10,0,B.empty)] ++ [(11,0,retired) | not (B.null retired)]
      accepted = flags <= 15 && (not (testBit flags 0) || testBit flags 1)
      budget = [27] ++ if clockFacts !! 4 then [28] ++ [29 | clockFacts !! 5] else []
      afterInterrupt = [25] ++ if clockFacts !! 3 then [26] else budget
      clockSteps = 21 : if not (head clockFacts) then budget else
        22 : if not (clockFacts !! 1) then afterInterrupt else
          23 : if clockFacts !! 2 then [24] else afterInterrupt
      clockFailed = last clockSteps `elem` [24,26,29]
      trace = prefix ++ (if accepted then [(step,0,B.empty) |
        step <- [12 | testBit flags 2] ++ [13 | testBit flags 3] ++ clockSteps] else [])
      native step slot payload = do
        calls <- readIORef seen
        modifyIORef' seen (++[(step,slot,payload)])
        pure $ if length calls == fault then B.singleton 255
          else if step == 10 then B.pack (concatMap (\(a,b) -> [a,b]) slots)
          else if step `elem` [24,26,29] then B.singleton 255
          else case lookup step (zip [21,22,23,25,27,28] clockFacts) of
            Just present -> B.singleton (if present then 1 else 0)
            Nothing -> B.empty
      failed = fault >= 0 && fault < length trace
      expected = if flags > 15 then -1 else if not accepted then 1 else if clockFailed then -1 else 0
  actual <- execute (ParentReplay.Maintenance 0 0 0 flags native) ParentReplay.AfterTreasury
  observed <- readIORef seen
  pure $ conjoin [actual === if failed then -1 else expected,
    observed === if failed then take (fault+1) trace else trace]
  where gen = (,,,) <$> choose (0,31) <*> resize 10 (listOf (choose (0,63))) <*>
          vectorOf 6 arbitrary <*> choose (-1,15 :: Int)

replayComposedStages :: Property
replayComposedStages = forAll (elements [327,328]) $ \kind ->
  forAll ((,) <$> vectorOf (if kind == 327 then 7 else 5) arbitrary <*> choose (-1,8 :: Int)) $ \(accepted,fault) -> ioProperty $
  let replies = zip (if kind == 327 then [1,2,3,4,5,7,8] else [1,4,5,7,8]) (map (\good -> if good then 1 else 0) accepted)
      script = take (1+length (takeWhile id accepted)) replies
  in commandTrace kind 8 (\phase result -> validate (ParentReplay.StoreFlow kind phase result))
    script fault (if and accepted then 1 else 0)

bitcoinSignatureWorkflow :: Property
bitcoinSignatureWorkflow = forAll gen $ \(mode,isWitness,index,inputs,outputs,hashType,signature,encoding,key,verified,fault) -> ioProperty $ do
  calls <- newIORef []
  let bool step = if step == 0 then encoding else if step == 1 then key else verified
      native step value payload = do
        seen <- readIORef calls
        modifyIORef' calls (++ [(step,value,payload)])
        pure $ if length seen == fault then B.pack [19,23]
          else if step `elem` [0,1,3] then B.singleton (if bool step then 1 else 0) else B.empty
      request = if mode == 2 then Bmm.SignatureHashWorkflow hashType index outputs native
        else Bmm.SignatureVerifyWorkflow mode isWitness index inputs outputs (B.pack signature) native
      effectiveType = if mode == 2 then hashType else fromIntegral (last signature)
      effect step = (step,0,B.empty)
      -- Independent pre-refactor branches, rather than the new capability methods.
      base = effectiveType `mod` 32
      anyone = testBit effectiveType 7
      allOutputs = base /= 2 && base /= 3
      hashing = [(4,0,B.pack ([100 | not anyone] ++ [101 | not anyone && allOutputs] ++
        (if allOutputs then [102] else [103 | base == 3 && fromIntegral index < outputs]) ++ [200..210]))]
      (expected,trace)
        | mode == 2 = (1,hashing)
        | mode > 1 = (-1,[])
        | isWitness == 0 || null signature || (mode == 0 && fromIntegral index >= inputs) = (0,[])
        | mode == 1 && not encoding = (0,[effect 0])
        | not key = (0,[effect 0 | mode == 1] ++ [effect 1])
        | otherwise = (if verified then 1 else 0,[effect 0 | mode == 1] ++ [effect 1] ++
            [(2,fromIntegral (last signature),B.pack (init signature))] ++ hashing ++ [effect 3])
      failed = fault >= 0 && fault < length trace
      mismatch = (() <$ interpret (SomeOperation (undefined :: Withdrawal.WithdrawalRequest))
        (error "mismatched signature DSL forced" `asTypeOf` Bmm.RunSignature)) == Nothing
  actual <- execute request Bmm.RunSignature
  observed <- readIORef calls
  pure (conjoin [actual === if failed then -1 else expected,
    observed === if failed then take (fault+1) trace else trace, property mismatch])
  where
    gen = (,,,,,,,,,,) <$> elements [0,1,2,3,maxBound] <*> elements [0,1] <*>
      choose (0,4) <*> choose (0,4) <*> choose (0,4) <*> arbitrary <*>
      resize 80 arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> choose (-1,5)

bmmSignatureParity :: Property
bmmSignatureParity = forAll gen $ \(hashType,index,count,isWitness,size) -> ioProperty $ do
  actualPlan <- elements_hs_bmm_sighash_plan hashType index count
  expectedPlan <- reference_bmm_sighash_plan hashType index count
  actualGate <- elements_hs_bmm_signature_gate isWitness size index count
  expectedGate <- reference_bmm_signature_gate isWitness size index count
  pure (conjoin [actualPlan === expectedPlan, actualGate === expectedGate])
  where
    gen = (,,,,) <$> frequency [(8,choose (0,255)),(2,arbitrary)] <*> edge [0,1,maxBound] <*>
      edge [0,1,2,4294967295,4294967296,maxBound] <*> edge [0,1] <*> edge [0,1,72,maxBound]

signetExtractionParity :: Property
signetExtractionParity = forAll gen $ \rows -> ioProperty $
  withArray ([fromIntegral (length rows),0,0,0] ++ concat rows) $ \context -> do
    actual <- elements_hs_signet_extract signetStep (castPtr context)
    trace <- peekArray 4 context
    pokeByteOff context 8 (0 :: Int64)
    pokeByteOff context 16 (0 :: Int64)
    pokeByteOff context 24 (0 :: Int64)
    expected <- reference_signet_extract (castPtr context)
    expectedTrace <- peekArray 4 context
    missing <- elements_hs_signet_extract nullFunPtr nullPtr
    (failed,failedTrace) <- withArray ([1,0,0,0,1,0,5,0xa2dac7ec] :: [Int64]) $ \fault -> do
      result <- elements_hs_signet_extract signetFailWrite (castPtr fault)
      transcript <- peekArray 4 fault
      pure (result,transcript)
    pure (conjoin [actual === expected, trace === expectedTrace, missing === -1,
                  failed === -1, failedTrace === [1,1,2,9]])
  where
    gen :: Gen [[Int64]]
    gen = listOf $ frequency
      [(6,sequence [pure 1,pure 0,elements [0,1,4,5,36,100],elements [0,0xa2dac7ec]]),
       (1,sequence [pure 0,elements [0,1],pure 0,pure 0]),
       (1,pure [-1,0,0,0]),(1,pure [2,0,0,0])]

bmmActivationParity :: Property
bmmActivationParity = forAll gen $ \(phase,facts,height,activation) -> ioProperty $ do
  actual <- elements_hs_bmm_activation phase facts height activation
  expected <- reference_bmm_activation phase facts height activation
  pure (actual === expected)
  where
    gen = (,,,) <$> elements [0,1,2,3,4,5,maxBound] <*> edge [0,1,2,3,4] <*>
      edge [minBound,-1,0,1,2147483645,2147483646,2147483647,maxBound] <*>
      edge [minBound,-1,0,1,2,2147483646,2147483647,maxBound]

bmmRetargetParity :: Property
bmmRetargetParity = forAll gen $ \(height,interval,target,time,start) -> ioProperty $ do
  actual <- elements_hs_bmm_retarget height interval target time start
  expected <- reference_bmm_retarget height interval target time start
  pure (actual === expected)
  where
    gen = (,,,,) <$> edge [0,1,2014,2015,2016,maxBound] <*>
      edge [-1,0,1,2016,4294967296,maxBound] <*>
      edge [minBound,-1,0,1,3,4,1209600,maxBound `quot` 4,maxBound] <*>
      edge [0,1,302399,302400,1209600,4838400,maxBound] <*> edge [0,1,maxBound]

bmmRetargetWorkflowParity :: Property
bmmRetargetWorkflowParity = forAll gen $ \(height,interval,target,time,start,payload) -> ioProperty $ do
  spanTime <- reference_bmm_retarget height interval target time start
  expectedBytes <- if spanTime < 0 || B.length payload /= 64 then pure B.empty else
    withArray (B.unpack (B.take 32 payload)) $ \output ->
    withArray (B.unpack (B.drop 32 payload)) $ \limit -> do
      status <- reference_bmm_scale_target 32 (fromIntegral spanTime) (fromIntegral target) output limit
      if status /= 0 then fail "invalid reference target scale" else B.pack <$> peekArray 32 output
  calls <- newIORef []
  let native step index input = do
        modifyIORef' calls (++ [(step,index,input)])
        pure (if step == 0 then payload else B.empty)
      expected = if spanTime == -1 then 0 else if spanTime < -1 then -2
        else if B.length payload /= 64 then -1 else 0
      expectedCalls = if spanTime < 0 then [] else
        [(0,0,B.empty)] ++ [(1,0,expectedBytes) | B.length payload == 64]
  actual <- validate (Bmm.RetargetWorkflow height interval target time start native)
  trace <- readIORef calls
  missing <- elements_hs_bmm_retarget_workflow height interval target time start nullFunPtr nullPtr
  pure $ conjoin [actual === expected,trace === expectedCalls,
    missing === (if spanTime < 0 then expected else -1)]
  where
    gen = do
      interval <- elements [-1,0,1,2016,4294967296,maxBound]
      height <- oneof [arbitrary,pure (fromIntegral interval - 1)]
      target <- edge [minBound,-1,0,1,3,4,1209600,4294967296,maxBound `quot` 4,maxBound]
      time <- edge [0,1,1209600,4838400,maxBound]
      start <- edge [0,1,maxBound]
      size <- frequency [(4,pure 64),(1,elements [0,32,63,65])]
      payload <- B.pack <$> vectorOf size arbitrary
      pure (height,interval,target,time,start,payload)

bmmMedianParity :: Property
bmmMedianParity = forAll (listOf (edge [0,1,maxBound])) $ \times -> ioProperty $
  withArray times $ \ptr -> do
    let count = fromIntegral (length times)
    actual <- elements_hs_bmm_median count ptr
    expected <- reference_bmm_median count ptr
    missing <- elements_hs_bmm_median 1 nullPtr
    parent <- elements_hs_bmm_parent_median count ptr
    missingParent <- elements_hs_bmm_parent_median 1 nullPtr
    pure (conjoin [actual === expected, missing === -2,
      parent === (if expected == 0 then -1 else expected), missingParent === -2])

foreign import ccall "wrapper" wrapCommitmentScript :: Bmm.ReadScript -> IO (FunPtr Bmm.ReadScript)

taggedParentParity :: Property
taggedParentParity = forAll (listOf (elements [0,1,2,3 :: Int])) $ \rows -> ioProperty $ do
  published <- newIORef []
  let model _ found [] = (maybe (-1) fromIntegral found,maybe [] (:[]) found)
      model index found (row:rest)
        | row == 0 = model (index+1) found rest
        | row /= 1 = (-4,maybe [] (:[]) found)
        | otherwise = case found of
            Just _ -> (-2,maybe [] (:[]) found)
            Nothing -> model (index+1) (Just index) rest
      (expected,selected) = model (0 :: Word32) Nothing rows
      readFields _ index action output = do
        let row = rows !! fromIntegral index
        pokeArray output (case action of
          1 -> [106,0,0,0]
          2 -> [if row == 3 then 76 else 37,0,0,0]
          _ -> [if row == 2 then 0 else 1,37,if row == 0 then 0 else 0x544d4c45,0x50])
        if action == 4 then modifyIORef' published (++[index]) else pure ()
        pure 1
  bracket (wrapCommitmentScript readFields) freeHaskellFunPtr $ \reader -> do
    actual <- elements_hs_bmm_commitment 3 0 (fromIntegral (length rows)) reader nullPtr
    observed <- readIORef published
    pure (conjoin [actual === expected,observed === selected])

bmmCommitmentParity :: Property
bmmCommitmentParity = forAll gen $ \(kind,slot,rows) -> ioProperty $
  withArray (0 : concat rows) $ \context -> do
    let count = fromIntegral (length rows)
    actual <- elements_hs_bmm_commitment kind slot count bmmFields (castPtr context)
    actualCalls <- peek context
    poke context 0
    expected <- reference_bmm_commitment kind slot count (castPtr context)
    expectedCalls <- peek context
    missing <- elements_hs_bmm_commitment 0 24 1 nullFunPtr nullPtr
    empty <- elements_hs_bmm_commitment 0 24 0 nullFunPtr nullPtr
    pure (conjoin [actual === expected, actualCalls === expectedCalls, missing === -3, empty === -1])
  where
    gen :: Gen (Word32, Int32, [[Int64]])
    gen = do
      kind <- elements [0,1,2,4,maxBound]
      slot <- elements [-1,0,24,255,256]
      rows <- listOf $ frequency
        [(4,pure [106 + 37*512 + 262144,37,0x687361d1,fromIntegral slot]),
         (4,sequence [elements [0,37,38,39,100],elements [0,0xeda921aa246a,0xeda921aa246b],pure 0,pure 0]),
         (3,pure [106 + 32*512 + 262144,32,0,0]),
         (1,pure [-1,0,0,0]),
         (4,sequence [elements [106,107,256,524288,106+79*512+262144,106+78*512+262144],
                       elements [-1,0,31,32,36,37,38],elements [0,0x687361d1],elements [0,24,255]])]
      pure (kind,slot,rows)

bmmStateParity :: Property
bmmStateParity = forAll gen $ \(present,interval,height,time,bits,start,startTime,count,latest) -> ioProperty $ do
  actual <- elements_hs_bmm_state present interval height time bits start startTime count latest
  expected <- reference_bmm_state present interval height time bits start startTime count latest
  pure (actual === expected)
  where
    gen = do
      h <- edge [0,1]
      i <- edge [0,-1,1,2016,4294967296,4294967297]
      height <- edge [0,1,2016,4031,4032]
      time <- edge [0,1]
      bits <- edge [0,1]
      start <- edge [0,2016]
      startTime <- edge [0,1]
      count <- edge [0,10,11,12]
      latest <- elements [0,time]
      elements [(h,i,height,time,bits,start,startTime,count,latest), (1,2016,4031,1,1,2016,1,11,1)]
main :: IO ()
main = do
  results <- mapM (\(name,prop) -> putStrLn name >> quickCheckWithResult
    stdArgs { maxSuccess = 10000, replay = Just (mkQCGen 20261009, 0) } prop) $ SignetSessionTests.properties ++ CommitmentTests.properties ++ BmmChainTests.properties ++ ProofSessionTests.properties ++ StateStorageTests.properties ++ BmmStateAccessTests.properties ++ BmmHeaderPolicyTests.properties ++ JournalWorkflowTests.properties ++ WalletWithdrawalTests.properties ++ BmmContextTests.properties ++ LocalBidTests.properties ++ ConfirmationDepthTests.properties ++ ReplayStoreTests.properties ++ ParentRpcTests.properties ++ ParentHeaderTests.properties ++ NativeDepositTests.properties ++
    [("next block height / missing tip, signed boundaries and overflow",nextBlockHeight),
     ("extra nonce / parent reset, full-width increment and wrap",extraNonce),
     ("fee-free selection / raw values, signed age and clock laziness",feeFreeSelectionValues),
     ("fee-free selection / multi-row lazy reads and fault prefixes",feeFreeSelectionOrder),
     ("template commitments / lazy BMM marking",templateCommitmentOrder),
     ("template selection / reset, optional authentication and publication",templateSelectionOrder),
     ("template admission / replay fence precedes mandatory native validity",templateAdmissionOrder),
     ("template parent / authentication, fallback and publication order",templateParentOrder),
     ("child checkpoint / pre-flush checks, cursor ordering and failures",childCheckpointOrder),
     ("checkpoint metadata / lazy reads, precedence and failures",checkpointMetadataOrder),
     ("checkpoint records / prefix boundaries, lazy decoders and failures",checkpointKeyOrder),
     ("BMM RPC authentication / ordered effects and no early publication",bmmRpcAuthenticationOrder),
     ("BMM RPC source / lazy native and legacy selection",bmmRpcSourceOrder),
     ("generated block preparation / mode selection and failure precedence",blockPreparationOrder),
     ("withdrawal history / continuity, monotonicity and selected blocks",withdrawalHistoryOrder),
     ("child preflight / lazy cancellation and fault order",childPreflightOrder),
     ("periodic reverification / activation survives warm-up and refresh rejection",reverificationOrder),
     ("sync preflight / first rejection and fault order",syncPreflightOrder),
     ("sync loop / shutdown, sleep interruption and fault order",syncLoopOrder),
     ("bid parent / fetch ordering and stale rejection",bidParentOrder),
     ("wallet command / timeout, stderr fallback and JSON admission",walletCommandOrder),
     ("mined commitment / slot before null hash before lookup",minedPreflightOrder),
     ("configured slot / missing before mismatched identity",configuredSlotOrder),
     ("mempool sweep / epoch fence before publication or locked traversal",mempoolSweepPreflightOrder),
     ("parent RPC host / lazy numeric lookup and family selection",parentRpcHostOrder),
     ("unknown full block / preflight before index mutation",blockAdmissionOrder 312 22 Bmm.FullBlockPreflight),
     ("indexed full block / BMM then deposits before anchor publication",blockAdmissionOrder 313 31 Bmm.BlockAnchorAdmission),
     ("stored full block / durable anchor and notification order",blockAdmissionOrder 314 11 Bmm.BlockAnchorPublication),
     ("BMM cache routing / cached, indexed and negative paths",cacheRoutingOrder),
     ("required facts / proposal, snapshot and marker ordering",requiredFactsOrder),
     ("native deposit admission / ordered checks, status and unavailable publication",nativeDepositAdmissionOrder),
     ("bid input / default selection and parse publication ordering",bidInputOrder),
     ("funded submission and template creation / admission and reporting order",fundedSubmissionOrder),
     ("BMM wait probes / lazy status classification",waitProbeOrder),
     ("reward wallets / first spendable private wallet",rewardWalletOrder),
     ("producer preparation / signed, nonce, witness and rejection order",producerPreparationOrder),
     ("producer routing / exactly one native or ECX path",producerRoutingOrder),
     ("producer acceptance / reject once without changing the result",producerAcceptanceOrder),
     ("parent request / reset optional error slot and exception boundary",parentRequestOrder),
     ("bundle event / verification errors and final-event clearing",bundleEventOrder),
     ("parent report / native, authenticated and isolated-regtest context selection",parentReportOrder),
     ("pegin confirmation policy / pinned identity order and height boundary",peginConfirmationPolicy),
     ("startup arguments / ordered native-width reads, effects and rejection",startupArgsOrder),
     ("peer rejection / edge identity and saturating strikes",peerStrikes),
     ("domain ABI / scalar and pointer roundtrip",abiRoundTrip),
     ("domain ABI / rejection before effects",abiRejectsBeforeEffects),
     ("domain ABI / signed canonicality before effects",abiSignedCanonical),
     ("domain ABI / exceptions preserve result canary",abiExceptionsPreserveResult),
     ("family ABI / section isolation, canonical arguments and no effects on rejection",abiFamilyRouting),
     ("parent messages / ordered M1-M4 composition, errors and fault prefixes",wholeReplayMessages),
     ("parent messages / framing rejects before later effects",replayMessageFraming),
     ("M4 whole workflow / modes, saturation, lazy reads and publication",wholeM4Voting),
     ("deposit state workflow / legacy decisions, publication order and exceptions",depositStateWorkflowParity),
     ("pruned parent recovery / first full peer, service order and failed callbacks",recoveryPeerOrder),
     ("pruned parent recovery / reply and header admission order",recoveryValidationOrder),
     ("pruned parent recovery / outer deadline, retry and active-height order",recoveryBodyOrder),
     ("pruned parent recovery / composed capabilities, retry trace and failure prefix",recoveryComposedOrder),
     ("pruned parent recovery / null callback and invalid composed selector",recoveryComposedBoundary),
     ("configuration field parser / byte ABI, lengths and canaries",configurationFieldAbi),
     ("payment URI / selection, admission and invalid ABI",paymentUriAbi),
     ("address aliases / network, parent exclusion, prefix and invalid ABI",addressAliasAbi),
     ("network selection / names, precedence and invalid ABI",networkSelectionAbi),
     ("Peer admission / request lookup, sync backoff and callback order",peerAdmissionOrder),
     ("deposit input limit / nested traversal, cap and callback failures",depositInputLimitAbi),
     ("cursor transport / shared reads, reset, publication and null guards",cursorTransportAbi),
     ("CTV admission / flag precedence, stack shapes and invalid ABI",ctvAdmissionAbi),
     ("proposal description / frozen prefix and output boundaries",proposalDescriptionBoundaries),
     ("Replay bounds / all kinds and unchanged transitions",parentReplayBounds),
     ("Header admission / bounded callbacks and malformed replies",headerAdmissionBounds),
     ("Shared command runner / framing, terminal and committing actions",commandFlowFraming),
     ("Shared command runner / long traversal and null callback",commandFlowLongRun),
     ("Shared predicate runner / framing and terminal replies",predicateFlowFraming),
     ("Shared predicate runner / faults and long traversal",predicateFlowFaults),
     ("Replay block admission / ordered gates and loops",parentReplayAdmissionTransitions),
     ("Composed block, transaction and accumulator admission stages",parentReplayStageTransitions),
     ("depth / old C++",depthParity), ("treasury / old C++",treasuryParity),
     ("treasury matching / slot range, decoder reuse and lazy reads",treasuryMatchParity),
     ("payout / old C++",payoutParity), ("payout conservation",conservation),
     ("withdrawal state anchor / independent bytes and ABI bounds",anchorPayload),
     ("withdrawal destination / boundaries and invalid stage results",destinationTransitions),
     ("wallet withdrawal plan / monetary bounds, fee bytes and ABI",walletBundlePlan),
     ("wallet bundle workflow / post-Refl planning and construction",walletBundleWorkflow),
     ("wallet bundle workflow / malformed frames, exceptions and lazy mismatch",walletBundleWorkflowFailures),
     ("anchored wallet workflow / exact preimages and effect prefixes",property walletAnchoredWorkflow),
     ("anchored wallet workflow / strict v3 framing",walletAnchoredFraming),
     ("wallet marker / null commitments and canonical script bytes",walletMarker),
     ("wallet transport / large buffers, insertion and canaries",walletTransport),
     ("wallet event lookup / stage table and malformed replies",walletEventTransitions),
     ("wallet submission / stage table and malformed replies",walletSubmissionTransitions),
     ("wallet native output / stage table and malformed replies",walletOutputTransitions),
     ("wallet RPC policy / fee boundaries and status classification",walletRpcPolicies),
     ("wallet native amounts / signed boundaries and malformed ABI",walletNativeAmounts),
     ("wallet native payout / combined monetary and dust admission",walletNativePayout),
     ("wallet native burn plan / prior monetary and script sequence",walletNativeBurnPlan),
     ("wallet native output selection / candidates, duplicates, malformed framing",walletNativeOutputSelection),
     ("withdrawal journal admission / ordered errors and framing",withdrawalJournalAdmission),
     ("withdrawal journal prefix / framing and error precedence ABI parity",withdrawalJournalPrefix),
     ("withdrawal journal identity / exact hash match and ABI framing",withdrawalJournalIdentity),
     ("withdrawal journal legacy / marker stripping and malformed ABI inputs",withdrawalJournalLegacy),
     ("withdrawal journal read / ordered verification and delayed publication",withdrawalJournalRead),
     ("withdrawal journal persistence / commit-close-rename and removal ordering",withdrawalJournalPersist),
     ("withdrawal parent policy / wallet-RPC parity and malformed framing",withdrawalParentPolicy),
     ("withdrawal RPC admission / options, pruning, reorg and depth precedence",withdrawalRpcAdmission),
     ("withdrawal proof bounds / signed index, leaf limit and precedence",withdrawalProofBounds),
     ("withdrawal submission policy / platform, process failures and duplicate precedence",withdrawalSubmissionPolicy),
     ("gRPC duplicate text / native substring parity and failure precedence",grpcDuplicateTextPolicy),
     ("withdrawal RPC burn scan / duplicates, malformed outputs and policy order",withdrawalRpcBurnScan),
     ("withdrawal RPC claim / canonical round trip, anchors and parent replay order",withdrawalRpcClaim),
     ("withdrawal RPC external verification / domain, authentication and publication order",withdrawalRpcVerify),
     ("ordered admission pair / ECX and withdrawal checks, errors and effect order",requiredPairAdmission),
     ("connection parent context / candidate, finalized and live authentication",connectionContextOrder),
     ("snapshot preparation / interruption, reuse and publish ordering",snapshotPrepareOrder),
     ("snapshot backlog / count threshold and locked cache reset",snapshotBacklogOrder),
     ("anchor cache / epoch fence before cache reuse",anchorCacheOrder),
     ("anchor publication / persist before candidate readmission",anchorPublishOrder),
     ("anchor replacement / checkpoint, evidence and authorization order",anchorReplacementOrder),
     ("reconciliation gate / budget before snapshot authentication",reconciliationGateOrder),
     ("anchor ordering / height first and lazy hash tie-break",anchorOrdering),
     ("anchor disconnection / unavailable stalls and failure stops",anchorDisconnectOrder),
     ("candidate admission / lazy work comparison and header authentication",candidateAdmissionOrder),
     ("anchor collection / optional copy and shared ancestry stopping",anchorCollectionOrder),
     ("Retired BMM submission / no transitions or effects",retiredBmmSubmission),
     ("BMM replacement / indexed capabilities, parser order and bounded adjustment",bmmReplacementWorkflow),
     ("BMM initial bid / range boundaries, failure precedence and selected fees",bmmSelectedBid),
     ("BMM replacement limit / old subtraction cap and overflow boundaries",bmmReplacementLimit),
     ("anchor rules / native encoding, 256-bit work, wrapped heights and predecessor checks",anchorRules),
     ("bounded output / mathematical capacity and signed count parity",boundedAppendRule),
     ("bounded waits / signed limits and native clamp parity",boundedWaitRule),
     ("approving parent height / unsigned successor limits",approvingParentHeightRule),
     ("child height comparison / full signed domain",childBehindRule),
     ("unsigned 32-bit fields / signed conversion, lengths and malformed ABI",unsigned32Fields),
     ("peg event range / start-first errors, bounds, overflow and canaries",pegEventRange),
     ("peg event default start / widened window, reserved inputs and canaries",pegEventDefaultStart),
     ("anchor rules / malformed framing and null ABI inputs",anchorFraming),
     ("anchor checkpoint / rejected frames preserve output and canaries",anchorCheckpointFraming),
     ("BMM work quote / pricing, partial rejection output and ABI bounds",bmmWorkQuote),
     ("script cache endpoint / fixed domain, revision, absent and present bytes",scriptCacheEndpoint),
     ("script cache / truncated, noncanonical, trailing and invalid ABI rejection",scriptCacheMalformed),
     ("consensus parameter gates / signed heights, boolean facts and invalid modes",parameterGateParity),
     ("wallet issuance amount / native double comparison and null boundary",walletIssueAmountParity),
     ("ECX required height / presence and full Word64 range",jetHeightParity),
     ("optional Simplicity environment / exact presence and nonzero-field combinations",optionalEnvironmentParity),
     ("optional checkpoint / absent bytes, null pointer and zero-height compatibility",optionalCheckpointParity),
     ("Merkle replacement / sentinel, matching and required index",merkleReplacementParity),
     ("Simplicity work budget / lazy witness reads, overflow and callback faults",bmmWorkBudget),
     ("Block work total / rejecting and saturating modes, lazy reads and nested ABI",bmmWorkTotal),
     ("Credential read / retries, EOF, overflow probe, offsets and ABI canaries",credentialRead),
     ("Private credential admission / guarded metadata, failure order and ABI",privateFileAdmission),
     ("mTLS credential admission / ordered metadata, Windows branch and file identity",tlsFileAdmission),
     ("Credential file / platform branches, nested read results, normalization and failure order",credentialFileOrder),
     ("Credential record / read failure, validation and rejection effects",credentialRecordOrder),
     ("Peer block dispatch / request, discouragement and missing peer",peerBlockDispatchOrder),
     ("Mempool witnesses / ordered validation, availability and error retention",mempoolWitnessOrder),
     ("Retired preliminary witness selector / fail closed",retiredPreliminaryWitness),
     ("Canonical M7 / count rejection and publication ordering",canonicalMatchOrder),
     ("Explicit M4 / abstention, vote publication and error ordering",explicitVoteOrder),
     ("Block deposit preflight / traversal, rejection and unavailable ordering",blockDepositPreflightOrder),
     ("Branch replay / fork boundaries, nested scans and early failure",branchReplayOrder),
     ("Recovery ancestor / ordered alignment, forests and callback faults",recoveryAncestorOrder),
     ("Recovery admission / branch reads before persisted-state screening",recoveryAdmissionOrder),
     ("Ephemeral header / native admission, predecessor and publication order",ephemeralHeaderOrder),
     ("Connection anchor / dry-run exceptions and persisted predecessor order",connectionAnchorOrder),
     ("Connection state / prior context, BMM, exchange and bundle order",connectionStateOrder),
     ("Startup parent / authentication before databases",startupParentOrder ParentReplay.ParentLoad),
     ("Startup parent / reconciliation before verification",startupParentOrder ParentReplay.ParentVerify),
     ("Startup parent / fatal gates and nonfatal mempool sweep",startupParentOrder ParentReplay.ParentServe),
     ("Startup bundle / lazy tip and ordered restoration",startupBundleOrder),
     ("Contextual header / BMM before exchange",blockValidationOrder ParentReplay.ContextualHeader),
     ("Contextual outputs / configured then active passes",blockValidationOrder ParentReplay.ContextualOutputs),
     ("Candidate self-check / budget and authenticated context",blockValidationOrder ParentReplay.CandidateSelfCheck),
     ("Branch choice / lazy condition and selected result",blockValidationOrder ParentReplay.BranchChoice),
     ("Startup reconciliation / locks, failure and stalled result",blockValidationOrder ParentReplay.StartupReconcile),
     ("Final BMM / invalid versus retryable parent evidence",blockValidationOrder ParentReplay.FinalBmm),
     ("BMM failure / permanent versus transient state",blockValidationOrder ParentReplay.BmmFailure),
     ("BMM reward admission / ordered facts, short circuit and invalid callback",bmmRewardAdmission),
     ("fee asset / shared hex decoder, immutable identity and output preservation",feeAssetResolution),
     ("BMM wait / reset versus retained failures, cadence and interruption",bmmWaitWorkflow),
     ("native and ECX production / stage order, short circuit and malformed responses",productionStages),
     ("BMM sync heights / comparison, short circuit and malformed responses",bmmSyncHeights),
     ("policy callback boundary / lazy null rejection and exception conversion",policyCallBoundary),
     ("parent RPC address / exact IPv4 and IPv6 loopback policy",parentRpcAddress),
     ("result publication / lazy rejection and write exception preservation",resultPublication),
     ("BMM proof build / bounded headers and ordered short-circuiting",proofBuildWorkflow),
     ("deposit CTIP search / uniqueness, recoverable misses and exact effects",ctipSearchWorkflow),
     ("deposit headers / inclusive bounded window and publication order",depositHeaderWorkflow),
     ("indexed callback boundary / lazy rejection and full-width arguments",indexedCallbackBoundary),
     ("replay leader / ranking, ties, margin and saturation",replayLeaderParity),
     ("proposal expiry / ordered mutation and malformed-entry stop",proposalExpiryWorkflowParity),
     ("withdrawal expiry / strict age and effect rejection",withdrawalExpiryWorkflowParity),
     ("parent maintenance / slot order, snapshots, partial effects and malformed replies",replayMaintenanceExpiry),
     ("parent maintenance / pruning before ordered publication",replayMaintenancePublication),
     ("parent maintenance / composed block stages and short circuit",replayComposedStages),
     ("deposit claims / three complete workflows",DepositClaimTests.whole),
     ("deposit claims / checkpoint admission and publication",DepositClaimTests.lookupOrder),
     ("deposit claims / projected transaction rule parity and order",DepositClaimTests.transaction),
     ("deposit claims / legacy witness and destination precedence",DepositClaimTests.legacy),
     ("deposit claims / callback exception prefixes",DepositClaimTests.faults),
     ("deposit claims / malformed replies fail closed",DepositClaimTests.malformed),
     ("deposit claims / lazy mismatches and missing input",DepositClaimTests.lazyDispatch),
     ("deposit parsing / complete ordered workflow",DepositParsingTests.whole),
     ("deposit parsing / domain rejection and publication gates",DepositParsingTests.rejections),
     ("deposit parsing / callback fault prefixes",DepositParsingTests.faults),
     ("deposit parsing / malformed frames and scalar widths",DepositParsingTests.malformed),
     ("deposit parsing / lazy payload mismatch and index admission",DepositParsingTests.lazyDispatch),
     ("deposit parsing / generic capability composition",DepositParsingTests.stages),
     ("deposit construction / ordered reconstruction and partial publication",DepositConstructionTests.transcript),
     ("deposit construction / signed and header-window boundaries",DepositConstructionTests.boundaries),
     ("deposit construction / callback failure prefixes",DepositConstructionTests.exceptions),
     ("deposit construction / candidate recovery and fatal exception preservation",DepositConstructionTests.recovery),
     ("deposit construction / malformed callback replies",DepositConstructionTests.malformed),
     ("deposit construction / payload equality precedes DSL and effects",DepositConstructionTests.lazyDispatch),
     ("deposit construction / generic capability stage composition",DepositConstructionTests.stages),
     ("parent prelude / ordered messages, duplicates, hash order and M8 rejection",ParentBlockTests.preludeMessages),
     ("parent prelude / callback failure prefixes",ParentBlockTests.preludeFaults),
     ("parent prelude / admission priority and safe snapshots",ParentBlockTests.preludeAdmission),
     ("parent prelude / exact M8 encoding",ParentBlockTests.preludeM8),
     ("parent prelude / payload equality precedes DSL and effects",ParentBlockTests.preludeLazy),
     ("parent prelude / malformed snapshots and hash replies",ParentBlockTests.preludeMalformed),
     ("parent block / generic capability stage ordering and short circuit",ParentBlockTests.blockStages),
     ("parent block / payload equality precedes DSL and effects",ParentBlockTests.blockLazy),
     ("parent block / complete grouped workflow and publication order",ParentBlockTests.blockWhole),
     ("parent block / native exception prefixes",ParentBlockTests.blockFaults),
     ("parent block / malformed callback replies",ParentBlockTests.blockMalformed),
     ("parent block / domain rejection stops later stages",ParentBlockTests.blockRejections),
     ("parent block / M5 parsing and block scoped M6 policy",ParentBlockTests.blockTreasury),
     ("CTIP ownership / balance checks, duplicate rejection and order",ctipOwnersWorkflowParity),
     ("CTIP spends / duplicate tracking and indexed effects",ctipSpendsWorkflowParity),
     ("CTIP outputs / active treasury validation and insertion ordering",ctipOutputsWorkflowParity),
     ("CTIP replacements / lazy checks and exact early exit",ctipReplacementsWorkflowParity),
     ("entry traversal / exact count, lazy empty and unchanged errors",repeatEntriesParity),
     ("CTIP changes / value branching and publication order",ctipChangesWorkflowParity),
     ("coinbase collection / ordered duplicate rejection and publication",coinbaseWorkflowParity),
     ("BMM typed submission / retries, caps, parent recheck and publication",bmmSubmissionWorkflow),
     ("M4 repeat / inactive, missing, unchanged and published votes",m4RepeatWorkflowParity),
     ("M8 acceptance / deadline, recognition, commitment and parent order",m8AcceptanceWorkflowParity),
     ("M2 activation / votes, windows, mutations and short-circuiting",m2ProposalWorkflowParity),
     ("M4 mode / lazy slot lookup and full-width counts",m4ModeWorkflowParity),
     ("M3 proposal / first duplicate and ordered publication",m3ProposalWorkflowParity),
     ("M6 id / ordered checks, bounded sum and fee",m6IdWorkflowParity),
     ("active slots / sorted multiset and bounded publication",activeSlotsParity),
     ("block publication / admission and optional output order",blockPublishWorkflowParity),
     ("slot pruning / occupancy and ordered mutations",pruneSlotsWorkflowParity),
     ("M6 withdrawal / ordered guards and publication",m6WithdrawalWorkflowParity),
     ("Treasury transaction / legacy rule composition, fault prefixes and effects",treasuryTransactionParity),
     ("Treasury transaction / invalid modes, null callback and negative counts",treasuryTransactionBoundary),
     ("BMM state workflow / lifecycle and source decisions preserve ordered native effects",bmmStateWorkflowParity),
     ("M5 deposit / address-first validation and gated publication",m5DepositWorkflowParity),
     ("replay leading workflow / duplicate identities and publication",replayLeadingParity),
     ("replay explicit workflow / abstain, alarm and duplicate identities",replayExplicitParity),
     ("replay alarm / batch decrement, no-op and output canaries",replayAlarmParity),
     ("replay upvote / batch parity, saturation and output canaries",replayUpvoteParity),
     ("raw deposit match / preflight and rejection ordering",rawDepositMatchParity),
     ("match scan / ordered counting and failure short-circuit",matchScanParity),
     ("deposit treasury / exact delta without signed overflow",treasuryDeltaParity),
     ("reported effects / lazy mapping and terminal rejection",reportedEffects),
     ("ordered facts / rejection codes, wide status and lazy tails",orderedFactsParity),
     ("live deposit / index preflight and ordered verification",liveVerifyWorkflow),
     ("deposit evidence / preflight, ordered effects and lazy tails",evidenceBuildWorkflow),
     ("child monitor / drain, reap, cancellation, deadline and polling order",childMonitorWorkflow),
     ("child termination grace / deadline, reaping and nonblocking drain order",childGraceWorkflow),
     ("child reaping / interrupted waits, already reaped and native error ordering",childReapWorkflow),
     ("child output / interrupted reads, EOF, truncation and native error ordering",childDrainWorkflow),
     ("wallet parent dust / uint32 sizing and malformed ABI",walletParentDust),
     ("wallet native guards / complete policy table and malformed ABI",walletNativeGuards),
     ("deposit broadcast / branch table and malformed replies",depositBroadcastTransitions),
     ("enforcer TLS / ordered fail-closed configuration",grpcConfigTransitions),
     ("enforcer TLS / endpoint facts and optional argument short circuit",grpcEndpointAdmission),
     ("enforcer request / fail before process execution",grpcRequestTransitions),
     ("enforcer request / length admission boundaries",grpcRequestAdmission),
     ("enforcer executable / platform and permission ordering",grpcExecutableTransitions),
     ("RPC server / ordered loopback checks",rpcServerTransitions),
     ("RPC binds / raw facts, lazy loopback check and first invalid binding",rpcBindAdmission),
     ("credentials / platform, ownership and open ordering",tlsCredentialTransitions),
     ("enforcer argument plan / byte-preserving direct argv",grpcArgumentPlan),
     ("enforcer argument plan / rejection precedence",grpcArgumentRejections),
     ("enforcer argument plan / FFI canaries",grpcPlanFfiBounds),
     ("enforcer text admission / bytes, scheme and size",grpcTextAdmission),
     ("enforcer text admission / null and oversized ABI",grpcTextBounds),
     ("withdrawal preflight / fail before submission",withdrawalPreflightTransitions),
     ("native withdrawal submission / exactly-once send and guarded result",nativeWithdrawalSubmissionOrder),
     ("withdrawal preflight / lazy individual facts and faults",withdrawalPreflightOrder),
     ("replay workflows / exact initial action domain",replayInitialActions),
     ("configured sidechain slot / signed bounds and exact identity",configuredSlotPolicy),
     ("BMM wait errors / byte-substring parity and ABI bounds",definitiveWaitError),
     ("BMM duplicate requests / byte-substring parity and ABI bounds",duplicateRequest),
     ("explicit amount accumulation / non-wrapping bounds",amountSumPolicy),
     ("wallet balance / nonnegative non-wrapping total",walletBalanceTotal),
     ("deposit predecessor / positive sequence and signed boundaries",depositPreviousSequence),
     ("deposit broadcast messages / byte-exact recognition and ABI bounds",depositBroadcastMessage),
     ("work bid admission / pricing reuse, lazy rate and output canaries",workBidAdmission),
     ("transaction total modes and unavailable parent rejection",transactionAdmissionModes),
     ("header layout / version bits, field selection and ABI bounds",headerLayoutPolicy),
     ("default wallet / load before missing-only create",defaultWalletTransitions),
     ("deposit preflight / full-width signed amounts and bounds",depositPreflightBounds),
     ("native deposit import / authentication before nested sponsorship",depositNativeImportTransitions),
     ("deposit import / authenticated witness sequencing",depositImportTransitions),
     ("deposit sponsorship / sequencing and malformed replies",depositSponsorshipTransitions),
     ("deposit satoshis / parsing branch table and malformed replies",depositSatoshiTransitions),
     ("wallet bundle admission / reservation and identity",walletBundleAdmission),
     ("six-confirmation boundary",sixConfirmations), ("withdrawal script round trip",scriptRoundTrip),
     ("noncanonical withdrawal script rejection",scriptMutations), ("M6 reference round trip",referenceRoundTrip),
     ("M6 allocation preflight / old C++",legacyFrameParity), ("fee bounds",feeBounds),
     ("byte ABI capacity and canaries",byteAbi), ("explicit burn output round trip / blinded rejection",outputRoundTrip),
     ("M6 round trip / replay and shape rejection",m6RoundTrip),
     ("deposit witness formats / old C++",depositWitnessParity),
     ("deposit recipient policy / old C++",depositOutputParity),
     ("class-constrained dispatch / all payload pairs",dispatchMatrix),
     ("mismatched dispatch never evaluates payload",mismatchIsLazy),
     ("typed withdrawal dispatch / all ABI tags",withdrawalDispatch),
     ("ELMTP tagged parent / canonicality and partial publication",taggedParentParity),
     ("BMM commitment selection / callback order / frozen native rules",bmmCommitmentParity),
     ("BMM retarget boundaries and timespan clamps",bmmRetargetParity),
     ("BMM retarget workflow / native parity, lazy reads and publication",bmmRetargetWorkflowParity),
     ("BMM upper-middle median / unsigned times",bmmMedianParity),
     ("BMM storage / ordered effects and height normalization",bmmStoreParity),
     ("BMM encoding / ordered native primitives",bmmEncodingParity),
     ("BMM target scaling / independent byte arithmetic and canaries",bmmScaleParity),
     ("BMM fingerprint / frozen encoding and short circuit",bmmFingerprintParity),
     ("BMM fingerprint finalization / force bytes before return",fingerprintFinalization),
     ("BMM activation preflight / private bounds / public ancestry",bmmActivationParity),
     ("signet extraction callback transcript / native rules",signetExtractionParity),
     ("post-Refl signet orchestration / reusable capabilities",property signetCapabilities),
     ("BMM signature hash mode plan / frozen native branches",bmmSignatureParity),
     ("Bitcoin signature workflow / class dispatch and exact native-effect prefixes",bitcoinSignatureWorkflow),
     ("signet validation / frozen control flow and short-circuit trace",signetValidationParity),
     ("BMM proof and state codecs / frozen native guards",bmmCodecParity),
     ("BMM traversal / frozen loop and short-circuit transcript",bmmTraversalParity),
     ("BMM advancement / native wrap, retarget, history and ABI canaries",bmmAdvanceParity),
     ("BMM wrapper / ordered short-circuit transcript",bmmWrapperParity),
     ("BMM state source / corrupt storage before fallback",bmmStateSourceParity),
     ("BMM connect/disconnect gates / frozen branch rules",bmmLifecycleParity),
     ("BMM proof/effective state / failure and fallback order",bmmSelectionFlowParity),
     ("BMM consensus/activation mode / short-circuit read order",bmmModeFlowParity),
     ("BMM retarget/PoW flow / original branch order",bmmWorkFlowParity),
     ("BMM extension / conditional checks and PoW ordering",bmmExtensionFlowParity),
     ("BMM persisted decode / action order and short circuit",bmmDecodeFlowParity),
     ("BMM native-state lookup / short circuit",bmmNativeLookupParity),
     ("BMM state flow / frozen action trace and write attempts",bmmStateFlowParity),
     ("BMM state runner / signed replies, phases and ABI faults",bmmStateRunBoundaries),
     ("BMM state runner / long nonce traversal",bmmStateRunLong),
     ("BMM proof runner / unsigned replies, null callbacks and malformed frames",bmmProofRunBoundaries),
     ("BMM proof runner / long traversal and publication",bmmProofRunLong),
     ("BMM proof workflow / nested reference, effects and ABI",bmmProofWorkflow),
     ("parent signet signature / encoding before key and split",parentSignatureFlow),
     ("Private BMM construction / retries and publication",bmmPrivateBuildParity),
     ("Private BMM template / integer wrap and byte order",bmmPrivateTemplateParity),
     ("BMM preimage / field ordering and writer failures",bmmPreimageParity),
     ("BMM signature hash actions / old branches and writer faults",bmmSignatureActionsParity),
     ("BMM signature split / prefix and hash type",bmmSignatureBytesParity),
     ("Signet template / fixed fields and ABI bounds",bmmSignetTemplateBounds),
     ("BMM consensus presets / frozen values and guarded outputs",bmmPresetParity),
     ("BMM checkpoint presets / frozen records and guarded outputs",bmmCheckpointParity),
     ("BMM fixed identities / frozen bytes and output canaries",bmmIdentityParity),
     ("BMM difficulty interval / signed native division and output faults",bmmIntervalParity),
     ("BMM commitment payload / byte order and fault canaries",bmmCommitmentBytesParity),
     ("parent commitment payload / parser-selected byte order",parentCommitmentBytes),
     ("Signet assembly/decode / primitive order and faults",bmmSignetActionsParity),
     ("withdrawal capability orchestration / frame before body",withdrawalCapabilities),
     ("dispatch faults preserve ABI sentinel and output",dispatchFaults),
     ("existential packing defers effects",deferredEffects),
     ("direct workflows / lazy payload gates and deferred effects",lazyWorkflows),
     ("authenticated deposit shape and accounting / old C++",authenticatedDepositParity),
     ("authenticated deposit overflow and error priority",authenticatedDepositBounds),
     ("deterministic deposit evidence / old C++ and callback ordering",evidenceParity),
     ("deterministic evidence faults and early pointer rejection",evidenceFaults),
     ("deposit inclusion / old C++ and lazy header ordering",inclusionParity),
     ("deposit inclusion faults and bounded callbacks",inclusionFaults),
     ("authenticated CTIP increase / old C++ and full-width amounts",ctipParity),
     ("persisted CTIP / old C++, decode faults and callback ordering",persistedCtipParity),
     ("CTIP script / native packing and read order",ctipScriptPacking),
     ("Persisted CTIP workflow / old C++, cursor and decoder order",persistedCtipWorkflow),
     ("deposit verification / original branch transcript",depositVerificationFlow),
     ("deposit anchor / original branch transcript",depositAnchorFlow),
     ("deposit lifecycle / original branch transcript and terminal publication",depositLifecycleFlow),
     ("deposit parsing / original short circuit and publication order",depositParsingFlow),
     ("CTIP input scan / ordered guards and last match",ctipInputScanFlow),
     ("deposit authentication / ordered checks and publication",depositAuthenticationFlow),
     ("deposit access / checkpoint claim and CTIP short circuit",depositAccessFlow),
     ("deposit projection / shape gates and bounded output reads",depositProjectionFlow),
     ("peg read runner / unsigned values, failure traces and invalid modes",pegReadRunnerParity),
     ("withdrawal status / event filtering and failure order",withdrawalStatusTraversal),
     ("L1 normalization / transition and adapter fault table",l1NormalizationTransitions),
     ("sidechain events / transition and adapter fault table",sidechainEventTransitions),
     ("L1 location / transition and adapter fault table",l1LocationTransitions),
     ("peg schema / guards, widths and phase faults",pegSchemaTransitions),
     ("parent epoch / nonzero equality and shared anchor fence",currentEpochRule),
     ("parent replay records / frozen C++ and numeric boundaries",parentReplayRecordParity),
     ("signed predecessor / full-width adjacency",signedPredecessorRule),
     ("replay distance / full-width subtraction and underflow",replayDistanceRule),
     ("nonempty bounded size / scalar ABI and full-width boundaries",nonEmptyBoundedRule),
     ("deposit routing / format, network and malformed scalar flags",depositRoutingRule),
     ("legacy witness shape / shallow recognition and untouched outputs",legacyWitnessShapePolicy),
     ("parent replay constants / frozen storage contract",parentReplayConstantsFrozen),
     ("parent cache / epoch mismatch and timeout retention",cacheExpiryRule),
     ("resource lanes / shared overflow-safe cumulative limit",laneLimitRule),
     ("parent rule catalog / exact versions and native schema",parentRuleCatalog),
     ("parent replay tip / transitions and invalid snapshots",parentReplayTipTransitions),
     ("parent replay store / status and terminal diagnostics",parentReplayStoreTransitions),
     ("parent replay append / ordered validation and atomic commit",parentReplayAppendTransitions),
     ("parent replay identity / preimage and terminal hash order",parentReplayIdentityTransitions),
     ("parent replay cache / preflight and identity sequencing",parentReplayCacheTransitions),
     ("parent replay cache / durable tip selection",parentReplayCacheLoadTransitions),
     ("parent replay bootstrap / preimage and reconstruction transitions",parentReplayBootstrapTransitions),
     ("parent replay boundaries / reorg preflight and terminal publication",parentReplayBoundaryTransitions),
     ("parent replay advancement / durable ordering and loop transitions",parentReplayAdvanceTransitions),
     ("parent replay wrappers / budget snapshot and lock transitions",parentReplayWrapperTransitions),
     ("parent deadlines / interrupt timeout and backoff transitions",parentDeadlineTransitions),
     ("parent milestones / guarded state and message tags",parentMilestoneTransitions),
     ("parent messages / decoding traversal and pinned guards",parentMessageTransitions),
     ("parent RPC parsing / short circuit and publication",parentRpcParseTransitions),
     ("parent work / guarded targets and chainwork order",parentWorkTransitions),
     ("parent raw headers / request decode and deadline order",parentRawHeaderTransitions),
     ("parent median time / traversal and overflow boundaries",parentMedianTimeTransitions),
     ("parent header metadata / lazy reads and diagnostic order",parentHeaderMetadataTransitions),
     ("parent predecessor / guarded RPC and chainwork branches",parentPredecessorTransitions),
     ("verified parent header / request and publication ordering",parentVerifiedHeaderTransitions),
     ("parent block transactions / scan and periodic deadline order",parentBlockTransactionTransitions),
     ("parent block wrappers / lazy signet and output ordering",parentBlockWrapperTransitions),
     ("parent recovery / tighter limit and stable duration",parentRecoveryTransitions),
     ("parent signet Merkle / ordered traversal and terminal hash",parentSignetMerkleTransitions),
     ("parent signet / lazy validation and diagnostics",parentSignetTransitions),
     ("parent warmup / RPC ordering and failure gates",parentWarmupTransitions),
     ("RPC reply / error priority and lazy result",rpcReplyTransitions),
     ("RPC cookie retry / invalidation and budget gate",authRetryTransitions),
     ("RPC timeout / deadline precedence and lazy clamping",rpcTimeoutTransitions),
     ("signed positive / full-width bounds",signedPositiveParity),
     ("cookie cache / nonblocking budget and protected copy",cookieCacheTransitions),
     ("credential sources / conflicts and validation file guard",credentialTransitions),
     ("checkpoint identity / lazy absent and present branches",checkpointIdentityTransitions),
     ("checkpoint CTIP / frozen money and outpoint bounds",checkpointCtipParity),
     ("activation windows / original predicate and full-width bounds",activationWindowParity),
     ("CTIP balances / optional treasury and full-width money bounds",ctipBalanceParity),
     ("proposal expiry / age, misses and guarded subtraction",proposalExpiryParity),
     ("parent header MTP / lazy JSON and parse boundary",headerMtpTransitions),
     ("parent preflight / lazy branches and malformed replies",parentPreflightTransitions),
     ("M8 acceptance / traversal, skip and rejection boundaries",m8AcceptanceTransitions),
     ("coinbase messages / ordered collection and duplicate rejection",coinbaseMessagesTransitions),
     ("proposal ACK / lazy activation and partial mutations",proposalAckTransitions),
     ("proposal admission / lazy insert, scan and append order",proposalAdmissionTransitions),
     ("M4 voting / saturation, competing downvotes and alarm effects",m4VoteTransitions),
     ("M4 leader / ordered scan, fifty-vote gap and guarded submission",m4LeaderTransitions),
     ("M4 explicit/repeat / skip, guards and effective publication",m4DispatchTransitions),
     ("expiry loops / lazy checks, errors and iterator transitions",expiryTransitions),
     ("CTIP scans / ownership, deadlines and duplicate spends",ctipScanTransitions),
     ("CTIP outputs / lazy script, value and replacement checks",ctipOutputTransitions),
     ("CTIP changes / old-value selection and ordered publication",ctipChangeTransitions),
     ("M5 deposits / validation, CTIP updates and optional mint record",m5DepositTransitions),
     ("M6 withdrawals / approval gates and ordered treasury mutation",m6WithdrawalTransitions),
     ("replay finish / lazy slot pruning and output publication",replayFinishTransitions),
     ("M6 identity / payout loop, serialization and publication order",m6IdTransitions),
     ("M4 mode / validation and active-slot traversal",m4ModeTransitions),
     ("snapshot membership / admission and guarded lookup",snapshotMembershipTransitions),
     ("snapshot epochs / signed slots and full-width generations",snapshotEpochParity),
     ("cache epoch inequality / full-width generations",cacheEpochParity),
     ("signed height windows / no overflow or narrowing",signedHeightWindowParity),
     ("cache capacity / full-width unsigned sizes",cacheCapacityParity),
     ("parent probe metadata / ordered parsing and status",parentProbeMetadataTransitions),
     ("BMM edge recheck / mismatch-only invalidation",bmmEdgeRecheckTransitions),
     ("BMM cache preflight / budget locking and invalidation",bmmCachePreflightTransitions),
     ("BMM cache hit / cheap rejection and exact publication",bmmCacheHitTransitions),
     ("BMM cache key / lazy hash and slot match",bmmCacheKeyTransitions),
     ("untrusted BMM admission / indexed evidence only",bmmAdmissionTransitions),
     ("BMM probe result / rejection cache ordering",bmmProbeResultTransitions),
     ("BMM publication / partial output and cache ordering",bmmPublicationTransitions),
     ("BMM successor / preparation and chainwork ordering",bmmSuccessorTransitions),
     ("authenticated JSON / transport admission and output clearing",authenticatedJsonTransitions),
     ("BMM bid / preflight and transaction id admission",bmmBidTransitions),
     ("anchor reconciliation / orphaning versus unavailability",anchorReconcileTransitions),
     ("block contexts / reset, preflight and guarded publication",blockContextTransitions),
     ("parent contexts / shared tip guards and publication",parentContextTransitions),
     ("withdrawal lookup / ordered invalidation and publication",withdrawalLookupTransitions),
     ("deposit preflight / diagnostics and guarded identity",depositPreflightTransitions),
     ("confirmed deposit / lazy state and RPC ordering",confirmedDepositTransitions),
     ("parent message parser / original C++ and ABI canaries",parentMessageParity),
     ("M8 parser / ordered guarded extraction",m8ParseTransitions),
     ("replay message dispatch / lazy handler selection",messageDispatchTransitions),
     ("replay each / shared short-circuiting traversal",eachTransitions),
     ("parent bootstrap / versioned catalog and activation height",parentBootstrapCatalog),
     ("parent lifecycle / generated nonthrowing action plans",parentLifecyclePlans),
     ("event identity / old C++ bytes and output canaries",eventIdentityParity),
     ("event layout / frozen schema and ABI canaries",eventLayoutAbi),
     ("CTIP state and anchor phases / old C++ and invalid phases",stateRuleParity),
     ("legacy claim / old C++ and full-width values",legacyClaimParity),
     ("destination selection / old C++ and callback ordering",destinationParity),
     ("checkpoint ABI bounds, immutable lookup and output canaries",checkpointAbi),
     ("live evidence / old C++, ordered field reads and parser faults",liveEvidenceParity),
     ("live evidence / synchronous isolation and initialized callbacks",liveSynchronousLifecycle),
     ("declaration and deposit selection / old C++ and lazy read traces",selectionParity),
     ("peg event lifecycle and amounts / old C++",pegEventParity),
     ("withdrawal status bytes / old C++ and exact matching",withdrawalStatusParity),
     ("BMM parent state / old C++ and interval truncation",bmmStateParity),
     ("BMM header preflight/final phases / old C++",bmmHeaderParity),
     ("BMM proof bounds and authentication / old C++",bmmProofParity)]
  unless (all isSuccess results) exitFailure
