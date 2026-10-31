{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module ParentHeaderTests (properties) where

import Control.Exception (SomeException, bracket_, throwIO, try)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT)
import Control.Operation
import Control.Operation.Validation (validate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef
import Data.List (sort)
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import qualified NativeDeposit as N
import Foreign.Ptr (nullFunPtr, nullPtr)
import qualified ParentHeader as H
import qualified ParentReplay as Replay
import qualified ParentRpcTests as RPC
import qualified Bmm
import Test.QuickCheck
import Withdrawal (wordLE, readLE)
import Workflow (NativeBytes)

type Event = (Word32,Word64)

header :: Word32 -> Bool -> NativeBytes -> H.Header
header height rpc = H.Header height rpc H.HookDeadline

capture :: Int -> (Event -> B.ByteString) -> (NativeBytes -> IO Int32) -> IO (Int32,[Event])
capture failure reply action = do
  events <- newIORef []
  let native step index input = do
        prior <- readIORef events
        modifyIORef' events (++ [(step,index)])
        when (not (B.null input) || length prior == failure) (ioError (userError "header callback fault"))
        pure (reply (step,index))
  result <- try (action native) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) <$> readIORef events

defaults :: Event -> B.ByteString
defaults (step,_) = wordLE 8 $ if step `elem` [2,3,4,5,6,9,40] then 0 else 1

proof :: Property
proof = forAll (vectorOf 5 arbitrary) $ \flags -> ioProperty $ do
  let replies event@(step,_) = case lookup step (zip [2,3,4,5,6] flags) of
        Just value -> wordLE 8 (if value then 1 else 0)
        _ -> defaults event
      prior = takeWhile not flags
      checks = take (min 5 (length prior+1)) [2,3,4,5,6]
      reject = if length prior < 4 then [(40,1)] else if length prior == 4 then [(40,2)] else []
  (status,events) <- capture (-1) replies (\native -> execute (header 0 False native) H.CheckProof)
  pure $ conjoin [status === if or flags then 0 else 1,
    events === ([(1,0)] ++ [(step,0) | step <- checks] ++ reject)]

work :: Property
work = forAll (vectorOf 3 arbitrary) $ \flags -> forAll arbitrary $ \empty ->
  forAll arbitrary $ \matches -> ioProperty $ do
    let replies event@(step,_) = case lookup step (zip [2,4,3,9,10] (flags ++ [empty,matches])) of
          Just value -> wordLE 8 (if value then 1 else 0)
          _ -> defaults event
        checks = take (min 3 (length (takeWhile not flags)+1)) [2,4,3]
        prefix = [(1,0)] ++ [(step,0) | step <- checks] ++ [(if or flags then 8 else 7,0)]
    (status,events) <- capture (-1) replies (\native -> execute (header 0 False native) H.CheckChainwork)
    pure $ conjoin [status === if empty || not matches then 0 else 1,
      events === (prefix ++ [(9,0)] ++ (if empty then [] else [(10,0)]) ++
        (if empty || not matches then [(40,3)] else []))]

rawPrefix :: [Event]
rawPrefix = [(20,0),(21,0),(22,0),(23,0),(22,0),(24,0),(1,0),(2,0),(3,0),(4,0),(5,0),(6,0)]

raw :: Property
raw = ioProperty $ do
  results <- mapM (\(stage,tailEvents) -> do
      let replies event@(step,_) = if step == stage then wordLE 8 0 else defaults event
      (status,events) <- capture (-1) replies (\native -> execute (header 0 False native) H.AuthenticateRaw)
      let prefix = takeWhile ((/= stage) . fst) rawPrefix ++ [(stage,0)]
      pure $ conjoin [status === 0,events === prefix ++ tailEvents])
    [(20,[(40,4)]),(21,[(40,4)]),(23,[]),(24,[(40,5)])]
  pure (conjoin results)

median :: Property
median = forAll arbitrary $ \height -> forAll arbitrary $ \rpc ->
  forAll (vectorOf 11 arbitrary) $ \times -> ioProperty $ do
    index <- newIORef (0 :: Int)
    events <- newIORef []
    let native step offset input = do
          when (not (B.null input)) (ioError (userError "unexpected header input"))
          modifyIORef' events (++ [(step,offset)])
          i <- readIORef index
          when (step == 34) (modifyIORef' index (+1))
          pure $ if step == 33 then wordLE 8 (fromIntegral (times !! i :: Word32)) else defaults (step,offset)
        count = fromIntegral (min 11 (toInteger (height :: Word32)+1))
        expected = sort (take count times) !! (count `div` 2)
        sampleEvents = [(31,0),(32,0)] ++ (if rpc then rawPrefix else []) ++ [(33,0),(34,0)]
    status <- execute (header height rpc native) H.AncestorMedian
    trace <- readIORef events
    pure $ conjoin [status === 1,
      trace === [(30,0)] ++ concat (replicate count sampleEvents) ++ [(31,0),(35,fromIntegral expected)]]

faults :: Property
faults = ioProperty $ do
  let action native = execute (header 2 True native) H.AncestorMedian
  (success,whole) <- capture (-1) defaults action
  failures <- mapM (\offset -> do
      (status,events) <- capture offset defaults action
      pure $ conjoin [status === (-1), events === take (offset+1) whole]) [0..length whole-1]
  pure (conjoin ((success === 1):failures))

malformed :: Property
malformed = ioProperty $ do
  let action native = execute (header 0 True native) H.AncestorMedian
  results <- mapM (\(stage,bytes) -> do
      (status,events) <- capture (-1) (\event@(step,_) -> if step == stage then bytes else defaults event) action
      pure $ conjoin [status === (-1), property (not (any ((==35) . fst) events))])
    ([(step,B.empty) | step <- [30,31,32,20,21,22,23,24,1,2,3,4,5,6,33,34]] ++
      [(step,wordLE 8 2) | step <- [30,31,32,20,21,22,23,24,1,2,3,4,5,6,34]] ++ [(33,wordLE 8 0x100000000)])
  pure (conjoin results)

newtype Probe = Probe (IORef [String])
instance H.ProofTarget Probe where
  checkProof (Probe events) = liftIO (modifyIORef' events (++ ["proof"]))
  calculateWork (Probe events) = liftIO (modifyIORef' events (++ ["work"]))
  checkWorkIncrement (Probe events) = liftIO (modifyIORef' events (++ ["increment"]))
instance H.RawHeader Probe where
  decodeRaw (Probe events) = liftIO (modifyIORef' events (++ ["decode"]))
instance H.HeaderMetadata Probe where
  readMetadata (Probe events) = liftIO (modifyIORef' events (++ ["metadata"])) >> pure 10
instance H.HeaderPredecessor Probe where
  checkPredecessor (Probe events) = liftIO (modifyIORef' events (++ ["predecessor"]))
instance H.HeaderAuthentication Probe where
  prepareHeader (Probe events) = liftIO (modifyIORef' events (++ ["prepare"]))
  readCurrentHeader (Probe events) = liftIO (modifyIORef' events (++ ["current"]))
  readHeaderMedian (Probe events) height = liftIO (modifyIORef' events (++ ["median:" ++ show height]))
  publishHeader (Probe events) = liftIO (modifyIORef' events (++ ["publish"]))
instance H.ParentNetwork Probe where
  checkParentNetwork (Probe events) = liftIO (modifyIORef' events (++ ["network"]))
instance H.ActiveParentHash Probe where
  readActiveHash (Probe events) = liftIO (modifyIORef' events (++ ["active-hash"]))
instance H.VerifiedParentHeader Probe where
  readVerifiedParentHeader (Probe events) = liftIO (modifyIORef' events (++ ["verified-header"]))
instance H.AuthenticatedParentBody Probe where
  readAuthenticatedBody (Probe events) = liftIO (modifyIORef' events (++ ["authenticated-body"]))
instance H.ParentBlockBinding Probe where
  bindParentBlock (Probe events) = liftIO (modifyIORef' events (++ ["bind-block"]))

capabilities :: Property
capabilities = ioProperty $ do
  events <- newIORef []
  result <- runExceptT (H.authenticateRaw (Probe events) >> H.authenticateChainwork (Probe events) >>
    H.authenticateHeader (Probe events) >> H.authenticateActiveHash (Probe events) >>
    H.authenticateNetworkHeader (Probe events) >> H.authenticateParentBlock (Probe events))
  trace <- readIORef events
  pure $ conjoin [result === Right (), trace === ["decode","proof","work","increment",
    "prepare","metadata","current","predecessor","median:10","publish","network","active-hash",
    "network","verified-header","network","verified-header","authenticated-body","bind-block"]]

type NetworkEvent = (Word32,B.ByteString)

networkCapture :: DSL H.Header -> (Word32 -> IO B.ByteString) -> IO (Either SomeException Int32,[NetworkEvent])
networkCapture request reply = do
  events <- newIORef []
  let native step index input = do
        when (index /= 0 || (step /= 5 && not (B.null input))) (fail "invalid network request")
        modifyIORef' events (++[(step,input)])
        reply step
  status <- try (execute (H.networkHeader native) request)
  (,) status <$> readIORef events

networkReply :: Word32 -> B.ByteString
networkReply step = B.singleton 1 <> wordLE 8 (case step of 42 -> 64; 8 -> 100; _ -> 1)

networkSteps, activeSteps :: [Word32]
networkSteps = [0,1,2,41,42,43,44,45,3]
activeSteps = [7,41,42,43,44,45]

networkWorkflow :: Property
networkWorkflow = forAll arbitrary $ \selected -> forAll (elements [0,2,41,42,43,45,3]) $ \bad -> ioProperty $ do
  let reply step = pure $ if step == 0 then B.singleton 1 <> wordLE 8 (if selected then 1 else 0)
        else if selected && step == bad then if bad == 2 then B.singleton 0 <> C.pack "offline"
          else B.singleton 1 <> wordLE 8 0 else networkReply step
      rejected = selected && bad /= 0
      prefix = if not selected then [0] else if rejected
        then takeWhile (/=bad) networkSteps ++ [bad] else networkSteps
      expected = prefix ++ if rejected then [4,5] else activeSteps
      diagnostic = if bad == 2 then "cannot verify mainnet parent RPC identity: offline"
        else "parent RPC does not serve the mainnet parent post-fork block at height 967680"
  (status,trace) <- networkCapture H.AuthenticateActiveHash reply
  pure $ conjoin [either (const (-1)) id status === if rejected then 0 else 1,
    map fst trace === expected,
    [C.unpack input | (5,input) <- trace] === if rejected then [diagnostic] else []]

networkRecovery :: Property
networkRecovery = once $ ioProperty $ do
  failures <- mapM (\step -> do
    (status,trace) <- networkCapture H.CheckParentNetwork (\at -> pure $
      if at == step then B.singleton 0 <> C.pack "native fault" else networkReply at)
    let prefix = takeWhile (/=step) networkSteps ++ [step]
    pure $ conjoin [either (const (-1)) id status === if step < 2 then (-1) else 0,
      map fst trace === prefix ++ if step < 2 then [] else [4,5]]) networkSteps
  -- A fault in the recovery handler must escape, not recurse or claim success.
  handlers <- mapM (\handler -> do
    (status,trace) <- networkCapture H.CheckParentNetwork (\at ->
      if at == handler then fail "handler fault"
      else pure $ if at == 2 then B.singleton 0 <> C.pack "rpc fault" else networkReply at)
    pure $ conjoin [property (either (const True) (const False) status),
      map fst trace === [0,1,2,4] ++ if handler == 5 then [5] else []]) [4,5]
  pure (conjoin (failures ++ handlers))

networkFrames :: Property
networkFrames = once $ ioProperty $ do
  failures <- mapM (\(step,bytes) -> do
    (status,trace) <- networkCapture H.CheckParentNetwork (\at -> pure $
      if at == step then bytes else networkReply at)
    pure $ conjoin [property (either (const True) (<0) status),
      map fst trace === takeWhile (/=step) networkSteps ++ [step]])
    [(step,bytes) | step <- networkSteps, bytes <- [B.empty,B.singleton 1,B.singleton 2,
      B.snoc (networkReply step) 0]]
  pure (conjoin failures)

activeHashWorkflow :: Property
activeHashWorkflow = forAll (elements [0,41,42,43,45]) $ \bad -> ioProperty $ do
  let reply step = pure $ if step == bad then B.singleton 1 <> wordLE 8 0 else networkReply step
      expected = if bad == 0 then activeSteps else takeWhile (/=bad) activeSteps ++ [bad,8,5]
  (status,trace) <- networkCapture H.ReadActiveHash reply
  injected <- mapM (\step -> do
    (failed,prefix) <- networkCapture H.ReadActiveHash (\at -> if at == step then fail "read fault" else reply at)
    pure $ conjoin [property (either (const True) (const False) failed),
      map fst prefix === takeWhile (/=step) expected ++ [step]]) expected
  pure $ conjoin ([either (const (-1)) id status === if bad == 0 then 1 else 0,
    map fst trace === expected,
    [C.unpack input | (5,input) <- trace] === if bad == 0 then [] else ["getblockhash(100) returned a noncanonical hash"]] ++ injected)

networkTransportCapture :: Bool -> Bool -> Bool -> Int -> Int -> Bool -> Word32 -> Int
  -> IO (Int32,[Word32],[Word32])
networkTransportCapture legacy active budget source fault auth badFrame size = do
  outer <- newIORef []
  poisoned <- newIORef Nothing
  let run rpc = do
        let native step index input = do
              -- ReadWorkflow retains escaping native exceptions and refuses all
              -- later callbacks, even if Haskell attempts cleanup or recovery.
              readIORef poisoned >>= maybe (pure ()) throwIO
              modifyIORef' outer (++[step])
              let body
                    | step >= 1000 = B.cons 1 <$> rpc (step-1000) index input
                    | step == 9 = fail "Haskell replay store workflow failed"
                    | step == 2 || step == 7 =
                        if legacy then do
                          status <- execute (Bmm.RpcSession rpc) Bmm.CallCheckedTransport
                          when (status /= 1) (fail "Haskell replay store workflow failed")
                          modifyIORef' outer (++[6])
                          pure (networkReply step)
                        else pure (B.singleton 1 <> wordLE 8 2)
                    | otherwise = pure (networkReply step)
              result <- try body :: IO (Either SomeException B.ByteString)
              case result of
                Left err -> if active then writeIORef poisoned (Just err) >> throwIO err
                  else pure (B.singleton 0 <> C.pack "native fault")
                Right reply -> pure reply
        execute (H.networkHeader native) (if active then H.ReadActiveHash else H.CheckParentNetwork)
  (status,inner) <- RPC.transportWith (Just run) (C.pack "elementsregtest")
    (B.cons 4 (wordLE 4 0x7f000001)) False True budget source fault auth badFrame size
  trace <- filter (<1000) <$> readIORef outer
  pure (status,inner,trace)

networkTransport :: Property
networkTransport = once $ ioProperty $ do
  checks <- mapM (\(active,budget,source) -> do
    expected@(_,events,_) <- networkTransportCapture True active budget source (-1) False 0 0
    actual <- networkTransportCapture False active budget source (-1) False 0 0
    injected <- mapM (\(fault,auth) -> do
      old <- networkTransportCapture True active budget source fault auth 0 0
      new <- networkTransportCapture False active budget source fault auth 0 0
      pure (counterexample (show (active,budget,source,fault,auth)) (old === new)))
      [(i,auth) | (i,step) <- zip [0..] events,step `notElem` [11,480],auth <- [False,True]]
    pure (conjoin ((expected === actual):injected)))
    [(active,budget,source) | active <- [False,True],budget <- [False,True],source <- [0..3]]
  pure (conjoin checks)

networkTransportFrames :: Property
networkTransportFrames = once $ ioProperty $ do
  checks <- mapM (\(active,source) -> do
    (_,events,_) <- networkTransportCapture False active False source (-1) False 0 0
    mapM (\(step,size) -> do
      (status,_,outer) <- networkTransportCapture False active False source (-1) False step size
      pure (counterexample (show (active,source,step,size)) (conjoin
        [status === if active then (-1) else 0,
         property (6 `notElem` outer),
         property (if active then 4 `notElem` outer else drop (length outer-2) outer == [4,5])])))
      [(step,size) | step <- events,step >= 100,step `notElem` [483,550],size <- [0,1,8,10]])
    [(active,source) | active <- [False,True],source <- [0..2]]
  pure (conjoin (concat checks))

headerTransportCapture :: Bool -> Bool -> Int -> Int -> Bool -> Word32 -> Int
  -> IO (Int32,[Word32],[Event])
headerTransportCapture legacy budget source fault auth badFrame size = do
  outer <- newIORef []
  poisoned <- newIORef Nothing
  let run rpc = do
        let native step index input = do
              readIORef poisoned >>= maybe (pure ()) throwIO
              modifyIORef' outer (++[(step,index)])
              let body
                    | step >= 1000 = rpc (step-1000) index input
                    | not (B.null input) = fail "unexpected header request input"
                    | step == 609 = fail "Haskell replay store workflow failed"
                    | step `elem` [81,83,84,86,65,132] =
                        if legacy then do
                          status <- execute (Bmm.RpcSession rpc) Bmm.CallCheckedTransport
                          when (status /= 1) (fail "Haskell replay store workflow failed")
                          modifyIORef' outer (++[(600,0)])
                          pure (wordLE 8 1)
                        else pure (wordLE 8 2)
                    | step == 55 || step == 60 = pure (wordLE 8 1)
                    | step == 70 = pure (wordLE 8 0)
                    | otherwise = pure (authenticationReplies (step,index))
              result <- try body :: IO (Either SomeException B.ByteString)
              case result of
                Left err -> writeIORef poisoned (Just err) >> throwIO err
                Right reply -> pure reply
        execute (header 0 True native) H.AuthenticateHeader
  (status,inner) <- RPC.transportWith (Just run) (C.pack "elementsregtest")
    (B.cons 4 (wordLE 4 0x7f000001)) False True budget source fault auth badFrame size
  trace <- filter ((<1000) . fst) <$> readIORef outer
  pure (status,inner,trace)

headerTransport :: Property
headerTransport = once $ ioProperty $ do
  checks <- mapM (\(budget,source) -> do
    expected@(status,events,trace) <- headerTransportCapture True budget source (-1) False 0 0
    actual <- headerTransportCapture False budget source (-1) False 0 0
    injected <- mapM (\(fault,auth) -> do
      old <- headerTransportCapture True budget source fault auth 0 0
      new <- headerTransportCapture False budget source fault auth 0 0
      pure (counterexample (show (budget,source,fault,auth)) (old === new)))
      [(i,auth) | i <- [0..length events-1],auth <- [False,True]]
    let denied = budget && source `elem` [1,2]
    pure (counterexample (show (budget,source,status,trace)) (conjoin ([expected === actual,
      status === if denied then (-1) else 1,
      length (filter (==(600,0)) trace) === if denied then 0 else 7,
      last trace === if denied then (81,0) else (91,0)] ++ injected))))
    [(budget,source) | budget <- [False,True],source <- [0..3]]
  pure (conjoin checks)

headerTransportFrames :: Property
headerTransportFrames = once $ ioProperty $ do
  checks <- mapM (\source -> do
    (_,events,_) <- headerTransportCapture False False source (-1) False 0 0
    mapM (\(step,size) -> do
      (status,_,trace) <- headerTransportCapture False False source (-1) False step size
      pure (counterexample (show (source,step,size)) (conjoin
        [status === (-1),property ((600,0) `notElem` trace),property ((90,0) `notElem` trace)])))
      [(step,size) | step <- takeWhile (/=105) events ++ [105],step >= 100,
        step `notElem` [483,550],size <- [0,1,8,10]]) [0..2]
  pure (conjoin (concat checks))

authenticationReplies :: Event -> B.ByteString
authenticationReplies event@(step,index)
  | step >= 200 = defaults (step-200,index)
  | step >= 100 = defaults (step-100,index)
  | otherwise = case step of
      42 -> wordLE 8 64
      55 -> wordLE 8 10
      56 -> wordLE 8 6
      57 -> wordLE 8 6
      60 -> wordLE 8 10
      70 -> wordLE 8 9
      91 -> wordLE 8 0
      _ -> defaults event

canonical :: Property
canonical = forAll arbitrary $ \string -> forAll (elements [0,63,64,65,maxBound :: Word64]) $ \size ->
  forAll arbitrary $ \hex -> forAll arbitrary $ \exact -> ioProperty $ do
    let replies event@(step,_) = case lookup step [(41,if string then 1 else 0),(42,size),
          (43,if hex then 1 else 0),(45,if exact then 1 else 0)] of
            Just value -> wordLE 8 value
            Nothing -> authenticationReplies event
        expected = [41] ++ if not string then [] else [42] ++
          if size /= 64 then [] else [43] ++ if not hex then [] else [44,45]
    (status,trace) <- capture (-1) replies (\native -> execute (header 0 False native) H.CanonicalHash)
    pure $ conjoin [status === if string && size == 64 && hex && exact then 1 else 0,
      trace === [(step,0) | step <- expected]]

metadata :: Property
metadata = forAll (elements [minBound,-1,0,1,0xffffffff,0x100000000,maxBound :: Int64]) $ \height ->
  forAll arbitrary $ \confirmations -> forAll arbitrary $ \minimumConfirmations -> ioProperty $ do
    let replies event@(step,_) = case lookup step [(55,height),(56,confirmations),(57,minimumConfirmations)] of
          Just value -> wordLE 8 (fromIntegral value)
          Nothing -> authenticationReplies event
        valid = height >= 0 && height <= 0xffffffff && confirmations >= (minimumConfirmations :: Int64)
    (status,trace) <- capture (-1) replies (\native -> execute (header 0 False native) H.ReadMetadata)
    pure $ conjoin [status === if valid then 1 else 0,
      property (all (`elem` trace) [(55,0),(56,0),(57,0)]),
      property (valid || last trace == (40,9))]

authentication :: Property
authentication = once $ conjoin [authenticationMode rpc | rpc <- [False,True]]

authenticationMode :: Bool -> Property
authenticationMode rpc = ioProperty $ do
  let action native = execute (header 0 rpc native) H.AuthenticateHeader
  (success,whole) <- capture (-1) authenticationReplies action
  failures <- mapM (\position -> do
      (status,trace) <- capture position authenticationReplies action
      pure $ conjoin [status === (-1),trace === take (position+1) whole]) [0..length whole-1]
  pure $ conjoin ((success === 1) : (drop (length whole-3) whole === [(89,0),(90,0),(91,0)]) :
    (length (filter ((==132) . fst) whole) === if rpc then 11 else 0) : failures)

authenticationRejections :: Property
authenticationRejections = once $ ioProperty $ do
  results <- mapM (\(event,value,code) -> do
    let replies at = if at == event then wordLE 8 value else authenticationReplies at
    (status,trace) <- capture (-1) replies (\native -> execute (header 0 False native) H.AuthenticateHeader)
    pure $ conjoin [status === 0,last trace === (40,code),
      property (code == 19 || (90,0) `notElem` trace)])
    [((57,0),0,16),((41,5),0,17),((82,0),0,17),((50,0),0,6),((51,0),0,7),
     ((54,0),0,8),((55,0),maxBound,9),((85,0),0,18),((64,0),0,12),
     ((66,0),0,13),((69,0),0,14),((70,0),10,14),((9,0),1,15),((10,0),0,15),((91,0),1,19)]
  pure (conjoin results)

authenticationMalformed :: Property
authenticationMalformed = once $ ioProperty $ do
  let action native = execute (header 0 True native) H.AuthenticateHeader
  (_,whole) <- capture (-1) authenticationReplies action
  results <- mapM (\event -> do
    (status,trace) <- capture (-1) (\at -> if at == event then B.empty else authenticationReplies at) action
    pure $ conjoin [status === (-1),last trace === event]) whole
  pure (conjoin results)

deadlineTrace :: [Bool] -> [Word64]
deadlineTrace [warm,interruptPresent,interrupted,expired,budget,budgetExpired] =
  (if warm then [1,2] ++ (if interruptPresent then [3] else []) ++
    (if interruptPresent && interrupted then [4] else [5] ++ if expired then [6] else budgetTrace)
   else 1:budgetTrace)
  where budgetTrace = [7] ++ if budget then [8] ++ if budgetExpired then [9] else [] else []
deadlineTrace _ = error "invalid deadline fixture"

deadlinePolicy :: Property
deadlinePolicy = once $ ioProperty $ do
  checks <- mapM (\flags -> do
    let expected = deadlineTrace flags
        replies (_,phase) = wordLE 8 (if maybe False id (lookup phase (zip [1,2,3,5,7,8] flags)) then 1 else 0)
        action native = fmap (either id (const 1)) $ runExceptT $
          H.checkDeadline (H.Header 0 False H.NativeDeadline (\step phase bytes ->
            if phase `elem` [4,6,9] then native step phase bytes >> ioError (userError "deadline exceeded")
            else native step phase bytes)) 22
        rejected = last expected `elem` [4,6,9]
    (status,trace) <- capture (-1) replies action
    faultsAt <- mapM (\position -> do
        (failed,prefix) <- capture position replies action
        pure $ conjoin [failed === (-1), prefix === take (position+1) trace]) [0..length expected-1]
    pure $ conjoin ((status === if rejected then (-1) else 1) :
      (trace === [(36,phase) | phase <- expected]) : faultsAt))
    (sequence (replicate 6 [False,True]))
  pure (conjoin checks)

composedDeadlines :: Property
composedDeadlines = once $ ioProperty $ do
  (_,hookTrace) <- capture (-1) authenticationReplies
    (\native -> execute (header 0 True native) H.AuthenticateHeader)
  let replies event@(step,_) = if step `elem` [36,136,236] then wordLE 8 0 else authenticationReplies event
      expand event@(step,_)
        | step == 89 = [(36,1),(36,7)]
        | step `elem` [122,131] = [(136,1),(136,7)]
        | step == 222 = [(236,1),(236,7)]
        | otherwise = [event]
      action native = execute (H.Header 0 True H.NativeDeadline native) H.AuthenticateHeader
  (status,trace) <- capture (-1) replies action
  malformedAt <- mapM (\event -> do
      (failed,prefix) <- capture (-1) (\at -> if at == event then B.empty else replies at) action
      pure $ conjoin [failed === (-1),last prefix === event])
    [(36,1),(36,7),(136,1),(136,7),(236,1),(236,7)]
  pure $ conjoin ((status === 1) : (trace === concatMap expand hookTrace) :
    (length [() | (step,phase) <- trace, step `elem` [36,136,236],phase == 1] === 37) : malformedAt)

-- The reference retains the old two-entry sequencing. Scope events model the
-- native owners; poisoned callbacks model the checked C ABI's exception latch.
networkHeaderCapture :: Bool -> Bool -> Int -> Int -> Maybe (Event,B.ByteString)
  -> IO (Int32,[(Word32,Word64,B.ByteString)],Word64)
networkHeaderCapture legacy deadlines scenario failure malformedAt = do
  events <- newIORef []
  owner <- newIORef (0 :: Word64)
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        prior <- readIORef events
        modifyIORef' events (++[(step,index,input)])
        result <- try $ do
          when (length prior == failure) (fail "injected native callback failure")
          active <- readIORef owner
          when (step /= 5 && not (B.null input)) (fail "unexpected workflow input")
          case step of
            10000 -> do
              when (active /= 0 || index `notElem` [1,2]) (fail "overlapping native owners")
              writeIORef owner index
            10001 -> do
              when (active /= index || index `notElem` [1,2]) (fail "wrong owner released")
              writeIORef owner 0
            10002 -> when (active /= 2 || index /= 0) (fail "deadline mode outside header scope")
            _ -> when (if step < 2000 then active /= 1 else step >= 4000 || active /= 2)
                   (fail "native action outside its scope")
          pure $ case malformedAt of
            Just (event,bytes) | event == (step,index) -> bytes
            _ | step == 10002 -> wordLE 8 (if deadlines then 1 else 0)
              | step >= 10000 -> wordLE 8 1
              | step < 2000 -> case (scenario,step) of
                  (1,0) -> B.singleton 1 <> wordLE 8 0
                  (2,3) -> B.singleton 1 <> wordLE 8 0
                  (3,2) -> B.singleton 0 <> C.pack "network offline"
                  _ -> networkReply step
              | otherwise -> let part = step-2000 in
                  if (scenario == 4 && part == 57) || (scenario == 5 && part == 85)
                    || part `elem` [55,60,36,136,236] then wordLE 8 0
                  else authenticationReplies (part,index)
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right reply -> pure reply
      scoped scope action = bracket_ (native 10000 scope B.empty) (do
          bytes <- native 10001 scope B.empty
          when (bytes /= wordLE 8 1) (fail "invalid reference release")) action
      reference = do
        status <- scoped 1 (execute (H.networkHeader native) H.CheckParentNetwork)
        if status /= 1 then pure status else scoped 2 $ do
          mode <- native 10002 0 B.empty
          when (mode /= wordLE 8 0 && mode /= wordLE 8 1) (fail "invalid reference deadline mode")
          execute (H.Header 0 True (if readLE mode == 1 then H.NativeDeadline else H.HookDeadline)
            (H.offset 2000 native)) H.AuthenticateHeader
  result <- try (if legacy then reference else execute (H.NetworkHeader native) H.AuthenticateNetworkHeader)
    :: IO (Either SomeException Int32)
  trace <- readIORef events
  remaining <- readIORef owner
  pure (either (const (-1)) id result,trace,remaining)

networkHeaderWorkflow :: Property
networkHeaderWorkflow = once $ ioProperty $ do
  checks <- mapM (\(deadlines,scenario) -> do
    old@(status,trace,remaining) <- networkHeaderCapture True deadlines scenario (-1) Nothing
    new <- networkHeaderCapture False deadlines scenario (-1) Nothing
    faultsAt <- mapM (\position -> do
      expected <- networkHeaderCapture True deadlines scenario position Nothing
      actual <- networkHeaderCapture False deadlines scenario position Nothing
      pure (counterexample (show (deadlines,scenario,position)) (expected === actual))) [0..length trace-1]
    pure $ conjoin ([old === new,status === if scenario < 2 then 1 else 0,remaining === 0,
      property (scenario `notElem` [2,3] || all (\(step,_,_) -> step < 2000 || step == 10000 || step == 10001) trace)] ++ faultsAt))
    [(deadlines,scenario) | deadlines <- [False,True],scenario <- [0..5]]
  pure (conjoin checks)

networkHeaderFrames :: Property
networkHeaderFrames = once $ ioProperty $ do
  (_,trace,_) <- networkHeaderCapture False True 0 (-1) Nothing
  checks <- mapM (\(step,index,_) -> mapM (\bytes -> do
      (status,seen,remaining) <- networkHeaderCapture False True 0 (-1) (Just ((step,index),bytes))
      pure $ counterexample (show (step,index,bytes)) $ conjoin [status === (-1),
        property (step `elem` [2090,2091,10001] || all (\(at,_,_) -> at /= 2090) seen),
        property (step == 10000 || remaining == 0)])
      ([B.empty,B.singleton 1] ++ [wordLE 8 2 | step `elem` [10000,10001,10002,2082,2090,2091]]))
    [(step,index,input) | (step,index,input) <- trace,
      step `elem` [0,41,10000,10001,10002,2057,2082,2090,2091,2036,2136,2236]]
  nullCallback <- FFI.elements_hs_parent_header 23 0 nullFunPtr nullPtr
  pure (conjoin ((nullCallback === (-1)):concat checks))

lazyMismatch :: Property
lazyMismatch = conjoin [property $ isNothing $ interpret
    (SomeOperation (error "forced wrong payload" :: N.Recipient))
    (error "forced mismatched DSL" :: DSL H.Header),
  property $ isNothing $ interpret
    (SomeOperation (error "forced wrong payload" :: N.Recipient))
    (error "forced mismatched DSL" :: DSL H.NetworkHeader),
  property $ isNothing $ interpret
    (SomeOperation (error "forced wrong payload" :: N.Recipient))
    (error "forced mismatched DSL" :: DSL H.ParentBlockReader)]

unknown :: Property
unknown = forAll (choose (26,maxBound :: Word32)) $ \mode -> ioProperty $ do
  result <- FFI.elements_hs_parent_header mode maxBound nullFunPtr nullPtr
  pure (result === (-1))

blockReply :: Word64 -> Int -> Event -> B.ByteString
blockReply count shape event@(step,index) = wordLE 8 $ case step of
  100 -> count
  101 -> if (shape == 1 && index == 0) || (shape == 3 && index == count-1) then 0 else 1
  102 -> if (index == 0 && shape /= 2) || (shape == 4 && index == count-1) then 1 else 0
  106 -> if shape == 5 then 1 else 0
  107 -> if shape == 6 then 1 else 0
  110 -> if shape == 7 || shape == 8 then 0 else 1
  112 -> if shape == 8 then 0 else 1
  _ -> readLE (defaults event)

blockTrace :: Word64 -> Int -> (Int32,[Event])
blockTrace count shape =
  let die code prefix = (0,prefix ++ [(140,code)])
      tick i = [(108,0) | i `mod` 256 == 0]
      scan i prefix
        | i == count = finish (prefix ++ [(103,0)] ++ concat [tick n ++ [(104,n)] | n <- [0..count-1]] ++ [(105,0),(106,0)])
        | otherwise = let seen = prefix ++ tick i ++ [(101,i)] in
            if shape == 3 && i == count-1 then die 1 seen else
              if shape == 4 && i == count-1 then die 1 (seen ++ [(102,i)]) else scan (i+1) (seen ++ [(102,i)])
      finish prefix | shape == 5 = die 2 prefix
                    | shape == 6 = die 2 (prefix ++ [(107,0)])
                    | otherwise = (1,prefix ++ [(107,0),(108,0)])
  in if count == 0 then die 0 [(100,0)] else
     if shape == 1 || (shape == 3 && count == 1) then die 0 [(100,0),(101,0)] else
     if shape == 2 then die 0 [(100,0),(101,0),(102,0)] else
     scan 1 [(100,0),(101,0),(102,0)]

blockTransactions :: Property
blockTransactions = once $ ioProperty $ do
  checks <- mapM (\(count,shape) -> do
    let expected = blockTrace count shape
        action native = execute (header 0 False native) H.CheckBlockTransactions
        reply = blockReply count shape
    actual <- capture (-1) reply action
    let trace = snd expected
        positions = if count < 4 then [0..length trace-1] else [0,length trace `div` 2,length trace-1]
    faultsAt <- mapM (\position -> do
      failed <- capture position reply action
      pure (failed === (-1,take (position+1) trace))) positions
    pure (counterexample (show (count,shape)) (conjoin ((actual === expected):faultsAt))))
    [(count,shape) | count <- [0,1,2,3,255,256,257,511,512,513],shape <- [0..6]]
  pure (conjoin checks)

blockComposition :: Property
blockComposition = once $ ioProperty $ do
  checks <- mapM (\(nativeDeadline,shape) -> do
    let (txStatus,txTrace) = blockTrace 3 shape
        signetTrace = [(109,0),(110,0)] ++ if shape `elem` [7,8]
          then [(111,0),(112,0)] ++ [(108,0) | shape == 7] else []
        expectedStatus = if txStatus == 0 || shape == 8 then 0 else 1
        expand event@(step,_) = if nativeDeadline && step `elem` [22,108] then [(36,1),(36,7)] else [event]
        expected = concatMap expand (rawPrefix ++ txTrace ++ if txStatus == 1 then signetTrace else [])
        reply event@(step,_) = if step == 36 then wordLE 8 0 else blockReply 3 shape event
        action native = execute (H.Header 0 False (if nativeDeadline then H.NativeDeadline else H.HookDeadline) native) H.AuthenticateBlock
    actual <- capture (-1) reply action
    faultsAt <- mapM (\position -> do
      failed <- capture position reply action
      pure (failed === (-1,take (position+1) expected))) [0..length expected-1]
    malformedAt <- mapM (\event -> do
      failed <- capture (-1) (\at -> if at == event then B.empty else reply at) action
      pure (failed === (-1,takeWhile (/=event) expected ++ [event]))) expected
    pure (counterexample (show (nativeDeadline,shape)) (conjoin
      ((actual === (expectedStatus,expected)):faultsAt ++ malformedAt))))
    [(nativeDeadline,shape) | nativeDeadline <- [False,True],shape <- [0..8]]
  pure (conjoin checks)

blockBoundaryCount :: Property
blockBoundaryCount = once $ ioProperty $ do
  checks <- mapM (\count -> do
    calls <- newIORef (0 :: Int)
    index <- newIORef (0 :: Word64)
    legacy <- Replay.runStore 47 $ \step -> do
      modifyIORef' calls (+1)
      i <- readIORef index
      let bit value = if value then 1 else 0
      case step of
        1 -> pure 0
        5 -> writeIORef index 1 >> pure 1
        17 -> writeIORef index 0 >> pure 1
        6 -> pure (bit (i < count))
        18 -> pure (bit (i < count))
        7 -> pure (fromIntegral (validate (Replay.Record 14 0 0 i 0)))
        19 -> pure (fromIntegral (validate (Replay.Record 14 0 0 i 0)))
        12 -> modifyIORef' index (+1) >> pure 1
        22 -> modifyIORef' index (+1) >> pure 1
        10 -> pure 0
        25 -> pure 0
        26 -> pure 0
        _ -> pure 1
    before <- readIORef calls
    (status,trace) <- capture (-1) (blockReply count 0)
      (\native -> execute (header 0 False native) H.CheckBlockTransactions)
    pure (counterexample (show (count,before,length trace)) (conjoin
      [legacy === 1,status === 1,before-length trace === fromIntegral (6*count+3)]))) [1,2,255,256,257,513]
  pure (conjoin checks)

signetReply :: Word64 -> Int -> Event -> B.ByteString
signetReply count shape (step,index)
  | step == 501 = wordLE 8 38 <> wordLE 8 (if shape == 4 then 0 else 0xeda921aa246a)
  | step >= 420 && step <= 424 = if (shape == 6 && step == 421) || (shape == 7 && step == 422)
      then B.singleton 0 else B.singleton 1 <> wordLE 8 (if step == 424 || (step == 423 && shape /= 8) then 0 else 1)
  | otherwise = wordLE 8 $ case step of
      400 -> if shape == 1 then 1 else 0
      401 -> if shape == 2 then 1 else 0
      402 -> if shape == 3 then 0 else 1
      500 -> 3
      502 -> if index == maxBound then 0 else 1
      410 -> if shape == 5 then 1 else 0
      416 -> if shape == 9 then 0 else 1
      603 -> count
      440 -> 0
      425 -> 0
      _ -> 1

signetExpected :: Word64 -> Int -> (Int32,[Event])
signetExpected count shape = (if shape `elem` [0,1,5] then 1 else 0, trace)
  where
    steps = map (\step -> (step,0))
    opening = steps [400,401,402]
    select = [(500,0),(501,0),(501,1),(501,2),(502,if shape == 4 then maxBound else 2)]
    assemble = steps ([407,408,409] ++ [200..205] ++ [410])
    decoded = steps $ if shape == 5 then [] else if shape == 6 then [420,421,425]
      else if shape == 7 then [420,421,422,425]
      else [420,421,422,423] ++ [424 | shape == 8]
    merkle = steps [412,601,602,603] ++ [(604,index) | index <- [1..max 1 count-1]] ++ steps [605,413]
    ending = steps ([300..303] ++ [414,415,416]) ++ [(440,2) | shape == 9]
    trace | shape == 1 = steps [400]
          | shape == 2 = steps [400,401] ++ [(440,0)]
          | shape == 3 = opening ++ [(440,0)]
          | shape == 4 = opening ++ select ++ [(440,1)]
          | shape `elem` [6,7,8] = opening ++ select ++ assemble ++ decoded
          | otherwise = opening ++ select ++ assemble ++ decoded ++ merkle ++ ending

captureSignet :: Int -> (Event -> B.ByteString) -> (NativeBytes -> IO Int32) -> IO (Int32,[Event])
captureSignet failure reply action = do
  events <- newIORef []
  let native step index input = do
        prior <- readIORef events
        modifyIORef' events (++ [(step,index)])
        let part = if step >= 2000 then step-2000 else step
            expectedInput = if part >= 200 && part <= 205
              then B.concat (map (wordLE 4 . fromIntegral) (validate Bmm.SignetTemplate)) else B.empty
        when (input /= expectedInput || length prior == failure) (ioError (userError "signet callback fault"))
        pure (reply (step,index))
  result <- try (action native) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) <$> readIORef events

signetWorkflow :: Property
signetWorkflow = once $ ioProperty $ do
  checks <- mapM (\(count,shape) -> do
    let expected@(_,trace) = signetExpected count shape
        action native = execute (header 0 False native) H.AuthenticateSignet
    actual <- captureSignet (-1) (signetReply count shape) action
    faultsAt <- mapM (\position -> do
      failed <- captureSignet position (signetReply count shape) action
      pure (failed === (-1,take (position+1) trace))) [0..length trace-1]
    pure (counterexample (show (count,shape)) (conjoin ((actual === expected):faultsAt))))
    [(count,shape) | count <- [1,2,3,257],shape <- [0..9]]
  pure (conjoin checks)

signetFrames :: Property
signetFrames = once $ ioProperty $ do
  let (_,trace) = signetExpected 2 0
      action native = execute (header 0 False native) H.AuthenticateSignet
  checks <- mapM (\event@(step,_) -> do
    failed <- captureSignet (-1) (\at -> if at == event then B.empty else signetReply 2 0 at) action
    let recover = step >= 420 && step <= 424
        expected = (if recover then 0 else -1,takeWhile (/=event) trace ++ [event] ++ [(425,0) | recover])
    pure (counterexample (show event) (failed === expected))) trace
  -- A failed diagnostic in the original catch body must not be caught again.
  diagnostic <- captureSignet 20 (signetReply 2 6) action
  decoderFailures <- mapM (\step -> do
    failed <- captureSignet (-1) (\event -> if event == (step,0) then B.singleton 0 else signetReply 2 8 event) action
    let (_,trailing) = signetExpected 2 8
    pure (failed === (0,takeWhile (/=(step,0)) trailing ++ [(step,0),(425,0)]))) [420..424]
  let (_,badEncoding) = signetExpected 2 6
  pure (conjoin (checks ++ decoderFailures ++ [diagnostic === (-1,badEncoding)]))

signetWitness :: Property
signetWitness = forAll (listOf (elements [(0,0),(37,0xeda921aa246a),(38,0xeda921aa246a),(80,0xeda921aa246a),(38,0)])) $ \facts ->
  ioProperty $ do
    let valid = [i | (i,(size,prefix)) <- zip [0..] facts,size >= 38,prefix == 0xeda921aa246a]
        selected = if null valid then maxBound else last valid
        reply (step,index) = case step of
          500 -> wordLE 8 (fromIntegral (length facts))
          501 -> let (size,prefix) = facts !! fromIntegral index in wordLE 8 size <> wordLE 8 prefix
          502 -> wordLE 8 (if index == maxBound then 0 else 1)
          _ -> B.empty
        action native = execute (header 0 False native) H.SelectSignetCommitment
        trace = [(500,0)] ++ [(501,fromIntegral i) | i <- [0..length facts-1]] ++ [(502,selected)]
    result <- captureSignet (-1) reply action
    invalid <- mapM (\bytes -> captureSignet (-1)
      (\event -> if event == (500,0) then wordLE 8 2 else if event == (501,0) then bytes else reply event) action)
      [wordLE 8 maxBound <> wordLE 8 0,wordLE 8 38 <> wordLE 8 maxBound,wordLE 8 38 <> wordLE 8 0x1000000000000]
    pure (conjoin ((result === (if null valid then 0 else 1,trace)):
      [bad === (-1,[(500,0),(501,0)]) | bad <- invalid]))

signetMerkleCalls :: Property
signetMerkleCalls = once $ ioProperty $ do
  checks <- mapM (\count -> do
    calls <- newIORef (0 :: Int)
    index <- newIORef (1 :: Word64)
    old <- Replay.runStore 51 $ \step -> do
      modifyIORef' calls (+1)
      i <- readIORef index
      case step of
        4 -> pure (if i < count then 1 else 0)
        6 -> modifyIORef' index (+1) >> pure 1
        _ -> pure 1
    before <- readIORef calls
    result <- captureSignet (-1) (signetReply count 0)
      (\native -> execute (header 0 False native) H.ModifiedSignetMerkle)
    let trace = [(601,0),(602,0),(603,0)] ++ [(604,i) | i <- [1..max 1 count-1]] ++ [(605,0)]
    pure (conjoin [old === 1,result === (1,trace),before-length trace === 1+2*fromIntegral (max 1 count-1)]))
    [0,1,2,3,255,256,257,513]
  pure (conjoin checks)

preparedSignetReply :: Word64 -> Int -> Event -> B.ByteString
preparedSignetReply count shape event@(step,index)
  | step >= 2000 = signetReply count shape (step-2000,index)
  | step == 112 = wordLE 8 2
  | step == 36 = wordLE 8 0
  | otherwise = blockReply count 7 event

preparedSignetTrace :: Word64 -> Int -> [Event]
preparedSignetTrace count shape = [(109,0),(110,0),(111,0),(112,0)] ++
  [(2000+step,index) | (step,index) <- snd (signetExpected count shape)] ++ [(113,0)] ++
  [(108,0) | fst (signetExpected count shape) == 1]

preparedSignetWorkflow :: Property
preparedSignetWorkflow = once $ ioProperty $ do
  checks <- mapM (\(whole,nativeDeadline,shape) -> do
    let count = 3
        expand event@(step,_) = if nativeDeadline && step `elem` [22,108] then [(36,1),(36,7)] else [event]
        trace = concatMap expand ((if whole then rawPrefix ++ snd (blockTrace count 0) else []) ++ preparedSignetTrace count shape)
        action native = execute (H.Header 0 False (if nativeDeadline then H.NativeDeadline else H.HookDeadline) native)
          (if whole then H.AuthenticateBlock else H.CheckBlockSignet)
        reply = preparedSignetReply count shape
    actual <- captureSignet (-1) reply action
    faultsAt <- mapM (\position -> do
      failed <- captureSignet position reply action
      let event@(step,_) = trace !! position
          expected = take (position+1) trace ++ [(113,0) | step >= 2000]
      pure (counterexample (show (position,event)) (failed === (-1,expected)))) [0..length trace-1]
    pure (counterexample (show (whole,nativeDeadline,shape)) (conjoin
      ((actual === (fst (signetExpected count shape),trace)):faultsAt))))
    [(whole,nativeDeadline,shape) | whole <- [False,True],nativeDeadline <- [False,True],shape <- [0..9]]
  pure (conjoin checks)

preparedSignetFrames :: Property
preparedSignetFrames = once $ ioProperty $ do
  let trace = preparedSignetTrace 2 0
      action native = execute (header 0 False native) H.CheckBlockSignet
      reply = preparedSignetReply 2 0
  checks <- mapM (\event@(step,_) -> do
    failed <- captureSignet (-1) (\at -> if at == event then B.empty else reply at) action
    let recover = step >= 2420 && step <= 2424
        expected = (if recover then 0 else -1,takeWhile (/=event) trace ++ [event] ++
          [(2425,0) | recover] ++ [(113,0) | step >= 2000])
    pure (counterexample (show event) (failed === expected))) trace
  modes <- mapM (\mode -> do
    failed <- captureSignet (-1) (\event -> if event == (112,0) then wordLE 8 mode else reply event) action
    pure (failed === (-1,take 4 trace))) [3,4,maxBound]
  releases <- mapM (\mode -> do
    failed <- captureSignet (-1) (\event -> if event == (113,0) then wordLE 8 mode else reply event) action
    pure (failed === (-1,init trace))) [0,2,maxBound]
  pure (conjoin (checks ++ modes ++ releases))

completeBlockCapture :: Bool -> Bool -> Int -> Int -> Maybe (Event,B.ByteString)
  -> IO (Int32,[Event])
completeBlockCapture full deadlines shape failure malformedAt = do
  events <- newIORef []
  owners <- newIORef []
  poisoned <- newIORef Nothing
  copied <- newIORef False
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        previous <- readIORef events
        modifyIORef' events (++[(step,index)])
        outcome <- try $ do
          when (length previous == failure) (fail "complete block callback failure")
          when (step /= 5 && not (B.null input)) (fail "unexpected block input")
          active <- readIORef owners
          case step of
            10000 -> do
              when (if index <= 3 then not (null active) else active /= [3]) (fail "invalid owner nesting")
              modifyIORef' owners (index:)
            10001 -> do
              when (null active || head active /= index) (fail "invalid release order")
              modifyIORef' owners tail
            10003 -> do
              when (active /= [4,3]) (fail "result copied outside recovery")
              writeIORef copied True
            10004 -> do
              ready <- readIORef copied
              when (not ready || active /= [5,3]) (fail "authentication without result")
            _ -> pure ()
          pure $ case malformedAt of
            Just (event,bytes) | event == (step,index) -> bytes
            _ | step == 10002 || step == 10004 || step == 4460 -> wordLE 8 (if deadlines then 1 else 0)
              | step == 10005 -> wordLE 8 (if shape == 4 then 0 else 1)
              | step >= 10000 -> wordLE 8 1
              | step == 9002 -> wordLE 8 (if shape >= 5 then 1 else 0)
              | step == 9003 -> wordLE 8 (if shape == 5 then 1 else 0)
              | step >= 9000 -> wordLE 8 1
              | step >= 6000 -> if step == 6036 then wordLE 8 0 else blockReply 2 (if shape == 3 then 5 else 0) (step-6000,index)
              | step >= 4000 -> wordLE 8 (if step == 4101 || step == 4036 then 0 else 1)
              | step >= 2000 -> if (shape == 2 && step == 2057) || step `elem` [2055,2060,2036,2136,2236]
                  then wordLE 8 0 else authenticationReplies (step-2000,index)
              | step == 3 && shape == 1 -> B.singleton 1 <> wordLE 8 0
              | otherwise -> networkReply step
        case outcome of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  outcome <- try (execute (H.ParentBlockReader native)
    (if full then H.AuthenticateParentBlock else H.ReadAuthenticatedBody)) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id outcome) <$> readIORef events

completeBlockWorkflow :: Property
completeBlockWorkflow = once $ ioProperty $ do
  checks <- mapM (\(full,deadlines,shape) -> do
    (status,trace) <- completeBlockCapture full deadlines shape (-1) Nothing
    (_,headerEvents,_) <- networkHeaderCapture True deadlines (if shape == 1 then 2 else if shape == 2 then 4 else 0) (-1) Nothing
    let headerTrace = [(step,index) | (step,index,_) <- headerEvents,full]
        gate = full && shape `elem` [1,2]
        (blockStatus,blockEvents) = blockTrace 2 (if shape == 3 then 5 else 0)
        expand event@(step,_) = if deadlines && step `elem` [22,108]
          then [(36,1),(36,7)] else [event]
        rawTrace = [(6000+step,index) | (step,index) <- concatMap expand
          (rawPrefix ++ blockEvents ++ if blockStatus == 1 then [(109,0),(110,0)] else [])]
        deadlineEvents = if deadlines then [(4036,1),(4036,7)] else [(4450,0)]
        budgetEvents = [(9001,0),(9002,0)] ++ [(9003,0) | shape >= 5] ++ [(9004,0) | shape /= 6] ++ [(9005,0)]
        bodyTrace = [(10000,3)] ++ budgetEvents ++ [(10000,4),(4460,0)] ++ deadlineEvents ++
          [(4001,0),(4101,0),(4003,0),(4004,0),(10003,0),(10001,4),(10000,5),(10004,0)] ++
          rawTrace ++ [(10001,5),(10001,3)]
        binding = [(10005,0) | full && blockStatus == 1] ++ [(10006,0) | full && blockStatus == 1 && shape == 4]
        expected = headerTrace ++ if gate then [] else bodyTrace ++ binding
        expectedStatus = if gate || shape == 3 || (full && shape == 4) then 0 else 1
    injected <- mapM (\position -> do
      failed <- completeBlockCapture full deadlines shape position Nothing
      pure (counterexample (show (full,deadlines,shape,position)) (failed === (-1,take (position+1) trace))))
      [0..length trace-1]
    pure $ counterexample (show (full,deadlines,shape)) $ conjoin
      ([status === expectedStatus,trace === expected] ++ injected))
    [(full,deadlines,shape) | full <- [False,True],deadlines <- [False,True],shape <- [0..6]]
  pure (conjoin checks)

completeBlockFrames :: Property
completeBlockFrames = once $ ioProperty $ do
  (_,trace) <- completeBlockCapture True True 0 (-1) Nothing
  checks <- mapM (\event -> do
    (status,seen) <- completeBlockCapture True True 0 (-1) (Just (event,B.empty))
    pure $ counterexample (show event) $ conjoin
      [status === (-1),property (all (\(step,_) -> step == 10001) (drop 1 (dropWhile (/=event) seen)))])
    [event | event@(step,_) <- trace,step >= 4000]
  nulls <- mapM (\mode -> FFI.elements_hs_parent_header mode 0 nullFunPtr nullPtr) [24,25]
  pure (conjoin ([nulls === [-1,-1]] ++ checks))

bodyTransportCapture :: Bool -> Bool -> Int -> Int -> Bool -> Word32 -> Int
  -> IO (Int32,[Word32],[Event])
bodyTransportCapture legacy budget source fault auth badFrame size = do
  outer <- newIORef []
  poisoned <- newIORef Nothing
  let run rpc = do
        let native step index input = do
              readIORef poisoned >>= maybe (pure ()) throwIO
              modifyIORef' outer (++[(step,index)])
              result <- try $ if step >= 1000 then rpc (step-1000) index input
                else if step == 609 then fail "Haskell replay store workflow failed"
                else if step == 1 then if legacy then do
                  code <- execute (Bmm.RpcSession rpc) Bmm.CallTransport
                  when (code /= 1) (fail "Haskell replay store workflow failed")
                  modifyIORef' outer (++[(600,0)])
                  pure (wordLE 8 1)
                else pure (wordLE 8 2)
                else pure (wordLE 8 (if step `elem` [101,460] then 0 else 1))
              case result of
                Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
                Right bytes -> pure bytes
        execute (H.ParentBlockReader native) H.FetchParentBody
  (status,inner) <- RPC.transportWith (Just run) (C.pack "elementsregtest")
    (B.cons 4 (wordLE 4 0x7f000001)) False False budget source fault auth badFrame size
  trace <- filter ((<1000) . fst) <$> readIORef outer
  pure (status,inner,trace)

bodyTransport :: Property
bodyTransport = once $ ioProperty $ do
  checks <- mapM (\(budget,source) -> do
    old@(status,events,_) <- bodyTransportCapture True budget source (-1) False 0 0
    new <- bodyTransportCapture False budget source (-1) False 0 0
    faultsAt <- mapM (\(position,auth) -> do
      expected <- bodyTransportCapture True budget source position auth 0 0
      actual <- bodyTransportCapture False budget source position auth 0 0
      pure (counterexample (show (budget,source,position,auth)) (expected === actual)))
      [(position,auth) | position <- [0..length events-1],auth <- [False,True]]
    malformedAt <- mapM (\(step,size) -> do
      (failed,_,trace) <- bodyTransportCapture False budget source (-1) False step size
      pure $ conjoin [failed === (-1),property ((600,0) `notElem` trace)])
      [(step,size) | step <- takeWhile (/=105) events ++ [105],step >= 100,step `notElem` [483,550],size <- [0,1,8,10]]
    pure $ conjoin ([old === new,status === if budget && source `elem` [1,2] then (-1) else 1] ++ faultsAt ++ malformedAt))
    [(budget,source) | budget <- [False,True],source <- [0..3]]
  pure (conjoin checks)

properties :: [(String,Property)]
properties = [("parent complete block / scoped composition, ordering and native exception prefixes",completeBlockWorkflow),
  ("parent complete block / framing and fail-closed ABI",completeBlockFrames),
  ("parent complete block / unchecked transport, retry and malformed reply parity",bodyTransport),
  ("parent network/header / composition, scoped lifetime and all fault prefixes",networkHeaderWorkflow),
  ("parent network/header / malformed frames, cleanup and ABI rejection",networkHeaderFrames),
  ("parent block / prepared Signet composition, lifetime and all fault prefixes",preparedSignetWorkflow),
  ("parent block / prepared Signet frames, cleanup and unknown-mode rejection",preparedSignetFrames),
  ("parent signet / complete workflow and every native exception prefix",signetWorkflow),
  ("parent signet / strict frames and scoped decoder failure translation",signetFrames),
  ("parent signet / last witness commitment, shared rule and invalid facts",signetWitness),
  ("parent signet / Merkle traversal and measured legacy callback reduction",signetMerkleCalls),
  ("parent block / transaction scans, rejection and deadline boundaries",blockTransactions),
  ("parent block / composed decode, transactions, signet and all fault prefixes",blockComposition),
  ("parent block / measured native callback reduction against legacy flow",blockBoundaryCount),
  ("parent header / target admission ordering",proof),
  ("parent header / native work and chainwork composition",work),
  ("parent header / raw decode failure priority",raw),
  ("parent header / bounded RPC ancestor traversal and median",median),
  ("parent header / callback exception prefixes",faults),
  ("parent header / malformed replies cannot publish",malformed),
  ("parent header / reusable capability composition",capabilities),
  ("parent network / composed admission and active hash",networkWorkflow),
  ("parent network / scoped exception recovery and revocation",networkRecovery),
  ("parent network / strict recoverable frames",networkFrames),
  ("parent network / active hash failure and exception order",activeHashWorkflow),
  ("parent network / complete native transport parity and every failure",networkTransport),
  ("parent network / malformed transport revokes only in identity scope",networkTransportFrames),
  ("parent header / composed RPC requests and every native failure",headerTransport),
  ("parent header / malformed RPC frames never publish a header",headerTransportFrames),
  ("parent header / canonical hash order and mutation boundary",canonical),
  ("parent header / signed metadata bounds",metadata),
  ("parent header / complete authentication and fault prefixes",authentication),
  ("parent header / authentication rejection and publication order",authenticationRejections),
  ("parent header / malformed authentication replies",authenticationMalformed),
  ("parent header / composed deadline policy and fault prefixes",deadlinePolicy),
  ("parent header / native deadlines remain within authentication",composedDeadlines),
  ("parent header / payload equality before DSL and effects",lazyMismatch),
  ("parent header / unknown ABI modes",unknown)]
