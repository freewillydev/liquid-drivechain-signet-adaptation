{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module ParentRpcTests (properties, transportWith) where

import Control.Exception (Exception, SomeException, finally, throwIO, try)
import Control.Monad (when)
import Control.Monad.Trans.Except (runExceptT)
import Control.Operation
import Control.Operation.Validation (Check(..))
import Control.Operation.Validation (Validation(..))
import qualified Bmm
import qualified NodeRules
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Withdrawal (wordLE, readLE)
import Data.Int (Int32, Int64)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word8, Word32)
import qualified ParentReplay as R
import qualified ParentCache
import Workflow (NativeBytes)
import Test.QuickCheck

capture :: Int -> (Word32 -> Int64) -> (R.RpcPreparation -> IO Int32)
  -> IO (Int32,[Word32])
capture fault reply run = do
  events <- newIORef []
  let action step = do
        prior <- readIORef events
        modifyIORef' events (++ [step])
        when (length prior == fault) (ioError (userError "RPC preparation fault"))
        pure (reply step)
  result <- try (run (R.RpcPreparation action)) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) <$> readIORef events

timeout :: Property
timeout = once $ ioProperty $ do
  let values = [minBound,-1000001,-1,0,1,999999,1000000,1000001,4294967296,maxBound] :: [Int64]
  results <- mapM (\(budget,warm,remaining,configured) -> do
    let remainingSeconds = fromInteger ((toInteger remaining+999999) `div` 1000000)
        reply step = case step of
          1 -> if budget then 1 else 0
          6 -> if warm then 1 else 0
          3 -> remaining
          8 -> remaining
          11 -> configured
          12 -> remainingSeconds
          _ -> 1
        expected = if budget then [1,2,3,if remaining>0 then 5 else 4]
          else if not warm then [1,6,14]
          else [1,6,7,8] ++ if remaining<=0 then [9]
          else [10,11] ++ (if configured>0 then [12] ++ [13 | configured<remainingSeconds] else []) ++ [5]
        status = if (budget || warm) && remaining<=0 then 0 else 1
    checks <- mapM (\fault -> do
      (actual,events) <- capture fault reply (\value -> execute value R.ConfigureTimeout)
      pure (conjoin [actual === if fault<0 then status else -1,
        events === if fault<0 then expected else take (fault+1) expected]))
      [-1..length expected-1]
    pure (conjoin checks)) [(b,w,r,c) | b <- [False,True], w <- [False,True], r <- values, c <- values]
  pure (conjoin results)

credentials :: Property
credentials = forAll (vectorOf 12 arbitrary) $ \flags -> ioProperty $ do
  let flag i = if flags !! i then 1 else 0
      reply step = case lookup step [(1,0),(2,1),(3,2),(7,2),(4,3),(8,3),(6,4),
              (11,5),(21,6),(41,6),(25,7),(22,8),(43,0),(44,9),(45,10),(47,11)] of
        Just i -> flag i
        Nothing -> 1
      legacy (R.RpcPreparation action) = do
        source <- R.runStore 58 action
        if source < 0 then pure source else if source /= 0 then pure 1 else do
          _ <- action 20
          cached <- R.runStore 57 (action . (20+))
          if cached < 0 then pure cached else do
            _ <- action 27
            if cached /= 0 then pure 1 else do
              loaded <- R.runStore 59 (action . (40+))
              pure (if loaded<0 then loaded else 1)
  expected@(_,events) <- capture (-1) reply legacy
  actual <- capture (-1) reply (\value -> execute value R.PrepareCredentials)
  faults <- mapM (\fault -> do
    old <- capture fault reply legacy
    new <- capture fault reply (\value -> execute value R.PrepareCredentials)
    pure (old === new)) [0..length events-1]
  pure (conjoin ((actual === expected):faults))

malformed :: Property
malformed = once $ ioProperty $ do
  let reply step = if step `elem` [1,6,11,21,25,41,43] then 0 else 1
  (_,events) <- capture (-1) reply (\value -> execute value R.PrepareCredentials)
  checks <- mapM (\(step,bad) -> do
    (status,seen) <- capture (-1) (\s -> if s==step then bad else reply s)
      (\value -> execute value R.PrepareCredentials)
    -- The legacy terminal cache-publication action ignores in-range replies.
    pure (conjoin [status === if step==49 && bad==2 then 1 else -1,
      seen === takeWhile (/=step) events ++ [step]]))
    [(step,bad) | step <- events, bad <- [-1,2,4294967296,maxBound]]
  pure (conjoin checks)

data Cached = Cached
instance R.CredentialSource Cached where selectCredential _ = pure False
instance R.CredentialCache Cached where cachedCredential _ = pure True
instance R.CredentialLoader Cached where loadCredential _ = error "cache hit loaded a credential"

dispatch :: Property
dispatch = once $ ioProperty $ do
  reused <- runExceptT (R.prepareCredentials Cached)
  let unrelated = SomeOperation (Check (R.Distance 1 0))
      mismatch = isNothing (interpret unrelated (error "forced mismatched RPC DSL" :: DSL R.RpcPreparation))
  pure (conjoin [reused === Right (),property mismatch])

rpcCalls :: Property
rpcCalls = once $ ioProperty $ do
  checks <- mapM check [(b,c,p,k,e,n,a,z) | b <- [False,True], c <- [False,True],
    p <- [False,True], k <- [False,True], e <- [False,True], n <- [False,True],
    a <- [0..2], z <- [0..2]]
  pure (conjoin checks)
  where
    check (budget,circuit,password,checked,replyError,missing,first,second) = do
      let failed = [12,13]
          retry = [21] ++ if password then failed else [22,23] ++
            if budget then failed else [10] ++ if second==0 then replyTrace else failed
          replyTrace = if not checked then [] else [31] ++
            if replyError then [32] else [33] ++ [34 | missing]
          expected = [1] ++ (if budget then [2] else []) ++
            if budget && circuit then [3] else [10] ++
              case first of 0 -> replyTrace; 1 -> retry; _ -> failed
          rejected = any (`elem` expected) [3,13,32,34]
      results <- mapM (\fault -> do
        events <- newIORef []
        attempts <- newIORef [first,second]
        let action step = do
              prior <- readIORef events
              modifyIORef' events (++ [step])
              when (length prior==fault || step `elem` [3,13,32,34])
                (ioError (userError "RPC lifecycle fault"))
              case step of
                1 -> pure (flag budget)
                2 -> pure (flag circuit)
                10 -> do
                  values <- readIORef attempts
                  case values of
                    x:xs -> writeIORef attempts xs >> pure x
                    [] -> error "third RPC attempt"
                21 -> pure (flag (not password))
                23 -> pure (flag budget)
                31 -> pure (flag (not replyError))
                33 -> pure (flag missing)
                _ -> pure 1
        actual <- try (execute (R.RpcCall action)
          (if checked then R.CallCheckedRpc else R.CallRpc)) :: IO (Either SomeException Int32)
        seen <- readIORef events
        pure (conjoin [either (const (-1)) id actual === if fault>=0 || rejected then -1 else 1,
          seen === if fault<0 then expected else take (fault+1) expected]))
        [-1..length expected-1]
      pure (conjoin results)
    flag value = if value then 1 else 0

rpcMalformed :: Property
rpcMalformed = once $ ioProperty $ do
  checks <- mapM (\bad -> do
    events <- newIORef []
    let action step = modifyIORef' events (++ [step]) >> pure (if step==10 then bad else 0)
    status <- execute (R.RpcCall action) R.CallCheckedRpc
    seen <- readIORef events
    pure (conjoin [status === -1,seen === [1,10]])) [-1,3,4294967296,minBound,maxBound]
  pure (conjoin checks)

data SuccessfulRpc = SuccessfulRpc
instance R.RpcCircuit SuccessfulRpc where admitRpcCall _ = pure ()
instance R.RpcAttempt SuccessfulRpc where attemptRpcCall _ = pure R.RpcSucceeded
instance R.RpcAuthentication SuccessfulRpc where retryRpcCall _ = error "successful call retried"
instance R.RpcFailure SuccessfulRpc where rejectRpcCall _ = error "successful call rejected"

rpcDispatch :: Property
rpcDispatch = once $ ioProperty $ do
  reused <- runExceptT (R.performRpcCall SuccessfulRpc)
  let unrelated = SomeOperation (Check (R.Distance 1 0))
      mismatch = isNothing (interpret unrelated (error "forced mismatched RPC call DSL" :: DSL R.RpcCall))
  pure (conjoin [reused === Right (),property mismatch])

data TransportFault = TransportAuth | TransportError deriving (Eq, Show)
instance Exception TransportFault

-- The reference keeps the old native phase ordering and catch/retry scope.
transportRun :: Bool -> Bool -> Bool -> Int -> Int -> Bool -> Word32 -> Int
  -> IO (Int32,[Word32])
transportRun = transportEnvironment (C.pack "elementsregtest") (B.cons 4 (wordLE 4 0x7f000001))

transportEnvironment :: B.ByteString -> B.ByteString -> Bool -> Bool -> Bool -> Int -> Int -> Bool -> Word32 -> Int
  -> IO (Int32,[Word32])
transportEnvironment = transportWith Nothing

transportWith :: Maybe (NativeBytes -> IO Int32) -> B.ByteString -> B.ByteString -> Bool -> Bool -> Bool -> Int -> Int -> Bool -> Word32 -> Int
  -> IO (Int32,[Word32])
transportWith custom chain host legacy checked budget source fault authFault malformedStep malformedSize = do
  events <- newIORef []
  cached <- newIORef (source == 3)
  failure <- newIORef TransportError
  let flag value = if value then 1 else 0
      raw step = do
        prior <- readIORef events
        modifyIORef' events (++[step])
        when (length prior == fault) (throwIO (if authFault then TransportAuth else TransportError))
        case step of
          1 -> pure (flag budget)
          2 -> pure 0
          11 -> pure 1
          13 -> readIORef failure >>= throwIO
          21 -> pure (flag (source /= 0))
          22 -> writeIORef cached False >> pure 1
          23 -> pure (flag budget)
          31 -> pure 1
          33 -> pure 0
          201 -> pure 0
          207 -> pure (flag budget)
          208 -> pure 0
          301 -> pure (flag budget)
          303 -> pure 1500000
          306 -> pure 0
          401 -> pure (flag (source == 2))
          402 -> pure (flag (source == 1 || source == 3))
          403 -> pure (flag (source == 0))
          404 -> pure (flag (source == 0))
          406 -> pure (flag (source /= 0))
          407 -> pure (flag (source == 0))
          408 -> pure (flag (source == 0))
          411 -> pure (flag (source == 0))
          421 -> pure (flag budget)
          425 -> flag <$> readIORef cached
          441 -> pure (flag budget)
          442 -> throwIO TransportError
          443 -> pure (flag (source == 2))
          449 -> writeIORef cached True >> pure 1
          533 -> pure 42
          534 -> pure 42
          536 -> pure 0
          523 -> pure 256
          525 -> pure 256
          _ -> pure 1
      record = C.pack (if source == 2 then "user:password" else "__cookie__:" ++ replicate 64 'a')
      body step index input = do
        value <- raw step
        case step of
          447 -> do
            let expected = if chain `elem` map C.pack ["elements","liquidv1"] then ".cookie" else "regtest/.cookie"
            when (index /= 0 || input /= C.pack expected) (error "unexpected default cookie path")
            pure (wordLE 8 (fromIntegral value))
          540 -> do
            when (index `notElem` [0,fromIntegral (B.length record)] || input /= wordLE 8 (4097-index))
              (error "unexpected credential read bounds")
            pure (wordLE 8 (if index == 0 then fromIntegral (B.length record) else 0))
          511 -> do
            when (index /= fromIntegral (B.length record) || not (B.null input))
              (error "unexpected credential publication")
            pure (wordLE 8 (fromIntegral value))
          _ -> do
            when (index /= 0 || not (B.null input)) (error "unexpected RPC transport input")
            pure (case step of
              444 -> host
              483 -> chain
              550 -> record
              _ -> wordLE 8 (fromIntegral value))
      framed step index input =
        if step < 100 then body step index input else do
          result <- try (body step index input)
          case result of
            Left err -> writeIORef failure err >> pure (B.singleton (if err == TransportAuth then 2 else 0))
            Right bytes -> pure (if step == malformedStep then B.replicate malformedSize 1 else B.cons 1 bytes)
      legacyCredential step
        | step == 44 = do
            _ <- raw 444
            let accepted = case B.uncons host of
                  Just (4,rest) -> readLE rest `div` 16777216 == 127
                  Just (6,rest) -> rest == B.replicate 15 0 <> B.singleton 1
                  _ -> False
            pure (if accepted then 1 else 0)
        | step == 45 || step == 47 = do
            when (step == 47) (raw 483 >> pure ())
            ready <- raw (400+step)
            if ready == 0 then pure 0 else do
              status <- execute (Bmm.AuthFile (\part -> body (500+part)))
                (if step == 45 then Bmm.ReadStaticAuthRecord else Bmm.ReadCookieAuthRecord)
                `finally` (raw 480 >> pure ())
              when (status < 0 || status > 1) (throwIO TransportError)
              when (step == 47) (raw (if status == 1 then 482 else 481) >> pure ())
              pure (fromIntegral status)
        | otherwise = raw (400+step)
      oldAttempt :: IO Int32
      oldAttempt = do
        result <- try ((do
          _ <- R.runDeadline (raw . (200+))
          _ <- raw 100
          _ <- execute (R.RpcPreparation (raw . (300+))) R.ConfigureTimeout
          _ <- raw 101
          _ <- execute (R.RpcPreparation legacyCredential) R.PrepareCredentials
          _ <- raw 102
          _ <- R.runDeadline (raw . (200+))
          _ <- raw 103
          _ <- R.runDeadline (raw . (200+))
          _ <- raw 104
          _ <- raw 105
          pure ()) `finally` (raw 11 >> pure ()))
        case result of
          Left err -> writeIORef failure err >> pure (if err == TransportAuth then 1 else 2)
          Right () -> pure 0
      oldCall = do
        active <- raw 1
        when (active /= 0) $ do
          unavailable <- raw 2
          when (unavailable /= 0) (raw 3 >> pure ())
        first <- oldAttempt
        let reject = raw 12 >> raw 13 >> pure ()
        if first == 0 then pure () else if first /= 1 then reject else do
          noPassword <- raw 21
          if noPassword == 0 then reject else do
            _ <- raw 22
            locked <- raw 23
            if locked /= 0 then reject else do
              second <- oldAttempt
              when (second /= 0) reject
        when checked $ do
          noError <- raw 31
          if noError == 0 then raw 32 >> pure () else do
            missing <- raw 33
            when (missing /= 0) (raw 34 >> pure ())
        pure 1
      run = case custom of
        Just runCustom -> runCustom framed
        Nothing -> if legacy then oldCall else execute (Bmm.RpcSession framed)
          (if checked then Bmm.CallCheckedTransport else Bmm.CallTransport)
  actual <- try run :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id actual) <$> readIORef events

transport :: Property
transport = once $ ioProperty $ do
  checks <- mapM (\(checked,budget,source) -> do
    expected@(_,events) <- transportRun True checked budget source (-1) False 0 0
    actual <- transportRun False checked budget source (-1) False 0 0
    faults <- mapM (\(fault,auth) -> do
      old <- transportRun True checked budget source fault auth 0 0
      new <- transportRun False checked budget source fault auth 0 0
      pure (counterexample (show (checked,budget,source,fault,auth)) (old === new)))
      [(fault,auth) | (fault,step) <- zip [0..] events, step `notElem` [11,480], auth <- [False,True]]
    let readsFile = not budget && source `elem` [1,2]
        coverage = conjoin
          [property ((550 `elem` events) == readsFile),
           property ((444 `elem` events) == (readsFile && source == 2)),
           property ((483 `elem` events) == (readsFile && source == 1))]
    pure (conjoin (coverage:(expected === actual):faults)))
    [(checked,budget,source) | checked <- [False,True],budget <- [False,True],source <- [0..3]]
  pure (conjoin checks)

transportMalformed :: Property
transportMalformed = once $ ioProperty $ do
  (_,events) <- transportRun False True False 0 (-1) False 0 0
  checks <- mapM (\(step,size) -> do
    (status,seen) <- transportRun False True False 0 (-1) False step size
    pure (conjoin [status === -1,seen === takeWhile (/=step) events ++ [step,11]]))
    [(step,size) | step <- events,step >= 100,size <- [0,1,8,10]]
  let unrelated = SomeOperation (R.RpcCall (error "forced unrelated transport payload"))
      mismatch = isNothing (interpret unrelated
        (error "forced mismatched transport DSL" :: DSL Bmm.RpcSession))
  pure (conjoin (property mismatch:checks))

transportFileMalformed :: Property
transportFileMalformed = once $ ioProperty $ do
  checks <- mapM (\source -> do
    (_,events) <- transportRun False True False source (-1) False 0 0
    mapM (\(step,size) -> do
      (status,seen) <- transportRun False True False source (-1) False step size
      pure (counterexample (show (source,step,size)) (conjoin
        [status === -1,seen === takeWhile (/=step) events ++ [step,480,11]])))
      [(step,size) | step <- events,step >= 500,step /= 550,size <- [0,1,8,10]]) [1,2]
  pure (conjoin (concat checks))

hostAdmission :: Word32 -> [Word8] -> Property
hostAdmission ipv4 input = ioProperty $ do
  let ipv6 = B.pack (take 16 (input ++ repeat 0))
      samples = [(B.singleton 0,False),(B.cons 4 (wordLE 4 (fromIntegral ipv4)),ipv4 `div` 16777216 == 127),
                 (B.cons 6 ipv6,ipv6 == B.replicate 15 0 <> B.singleton 1),
                 (B.cons 6 (B.replicate 15 0 <> B.singleton 1),True)]
  checks <- mapM (\(snapshot,expected) -> do
    events <- newIORef []
    let native step index bytes = do
          modifyIORef' events (++[step])
          when (index /= 0 || not (B.null bytes)) (error "unexpected host input")
          pure (if step == 1 then wordLE 8 1 else snapshot)
    actual <- execute (Bmm.RpcHost native) Bmm.CheckRpcHost
    trace <- readIORef events
    pure (conjoin [actual === if expected then 1 else 0,trace === [1,2]])) samples
  pure (conjoin checks)

hostMalformed :: Property
hostMalformed = once $ ioProperty $ do
  let bad = [B.empty,B.pack [0,0],B.pack [1],B.pack [5]] ++
            [B.cons family (B.replicate size 0) | (family,valid) <- [(4,4),(6,16)],size <- [0..18],size /= valid]
  checks <- mapM (\snapshot -> do
    result <- try (Bmm.admitHostSnapshot snapshot) :: IO (Either SomeException Bool)
    pure (property (either (const True) (const False) result))) bad
  modes <- mapM (\mode -> do
    events <- newIORef []
    result <- try (execute (Bmm.RpcHost (\step _ _ -> modifyIORef' events (++[step]) >> pure mode)) Bmm.CheckRpcHost)
      :: IO (Either SomeException Int32)
    trace <- readIORef events
    pure (conjoin [property (either (const True) (const False) result),trace === [1]]))
    [B.empty,wordLE 8 2,B.replicate 7 0,B.replicate 9 0]
  nonNative <- execute (Bmm.RpcHost (\step _ _ -> if step == 1 then pure (wordLE 8 0)
    else error "non-native host was parsed")) Bmm.CheckRpcHost
  let unrelated = SomeOperation (Check (R.Distance 1 0))
      mismatch = isNothing (interpret unrelated (error "forced mismatched host DSL" :: DSL Bmm.RpcHost))
  pure (conjoin (property mismatch : (nonNative === 1) : checks ++ modes))

transportEnvironmentRules :: Property
transportEnvironmentRules = once $ ioProperty $ do
  checks <- mapM (\(chain,host,source) -> do
    old <- transportEnvironment chain host True True False source (-1) False 0 0
    new <- transportEnvironment chain host False True False source (-1) False 0 0
    pure (counterexample (show (chain,host,source)) (old === new)))
    [(chain,host,source) | chain <- map C.pack ["elements","liquidv1","elementsregtest","regtest","","Elements","elements\0x"],
      host <- [B.singleton 0,B.cons 4 (wordLE 4 0x7f000001),B.cons 4 (wordLE 4 0xc0a80001),
        B.cons 6 (B.replicate 15 0 <> B.singleton 1),B.cons 6 (B.replicate 16 0)],source <- [0..3]]
  pure (conjoin checks)

transportEnvironmentMalformed :: Property
transportEnvironmentMalformed = once $ ioProperty $ do
  checks <- mapM (\(source,step,size) -> do
    (_,events) <- transportRun False True False source (-1) False 0 0
    (status,seen) <- transportRun False True False source (-1) False step size
    pure (counterexample (show (source,step,size)) (conjoin
      [status === -1,seen === takeWhile (/=step) events ++ [step,11]])))
    ([(2,444,size) | size <- [0,1,8,10]] ++ [(1,447,size) | size <- [0,1,8,10]] ++ [(1,483,0)])
  pure (conjoin checks)

data MemoryAuthFile = MemoryAuthFile
instance Bmm.CredentialMetadata MemoryAuthFile where inspectCredentialFile _ = pure 1
instance Bmm.CredentialContents MemoryAuthFile where readCredentialFile _ = pure (0,0)
instance Bmm.CredentialFileEffects MemoryAuthFile where
  credentialFileEffect _ step _ = pure (if step `elem` [23,25] then 256 else 1)

authFileDispatch :: Property
authFileDispatch = once $ ioProperty $ do
  reused <- Bmm.loadAuthFile MemoryAuthFile
  let unrelated = SomeOperation (Check (R.Distance 1 0))
      mismatch = isNothing (interpret unrelated (error "forced mismatched auth file DSL" :: DSL Bmm.AuthFile))
  pure (conjoin [reused === 1,property mismatch])

authFileFraming :: Property
authFileFraming = once $ ioProperty $ do
  let expected = [1,3,4,31,38,33,34,36,40,9,11,23,25]
      result step | step `elem` [33,34] = 42
                  | step `elem` [36,40] = 0
                  | step `elem` [23,25] = 256
                  | otherwise = 1
  checks <- mapM (\(badStep,size) -> do
    seen <- newIORef []
    let action step index request = do
          modifyIORef' seen (++ [step])
          when (index/=0 || request/=(if step==40 then wordLE 8 4097 else B.empty))
            (error "invalid native credential request")
          pure (if step==badStep then B.replicate size 0 else wordLE 8 (result step))
    actual <- try (execute (Bmm.AuthFile action) Bmm.ReadRawAuthFile) :: IO (Either SomeException Int32)
    events <- readIORef seen
    pure (conjoin [either (const (-1)) id actual === if badStep==0 then 1 else -1,
      events === if badStep==0 then expected else takeWhile (/=badStep) expected ++ [badStep]]))
    ((0,0):[(step,size) | step <- expected,size <- [0,1,7,9]])
  pure (conjoin checks)

authRecord :: Property
authRecord = forAll (oneof [B.pack <$> resize 120 (listOf (arbitrary :: Gen Word8)),
    elements (map C.pack ["u:p","u:p\n","__cookie__:"++replicate 64 'a',replicate 4097 'a'])]) $
  \bytes -> forAll arbitrary $ \rotating -> forAll (elements [0,1,2]) $ \ack -> ioProperty $ do
    seen <- newIORef []
    let action step index request = do
          when (index/=0 || not (B.null request)) (error "invalid record request")
          modifyIORef' seen (++ [step])
          pure (if step==50 then bytes else wordLE 8 ack)
        valid = validate (NodeRules.ConfigurationField (if rotating then 7 else 8) bytes)==Right (B.singleton 1)
        oversized = B.length bytes>4096
    status <- Bmm.validateCredentialRecord (Bmm.AuthFile action) rotating
    events <- readIORef seen
    pure (conjoin [status === if oversized then -1 else if valid then 1 else if ack==1 then 0 else -1,
      events === [50] ++ [60 | not oversized && not valid]])

newtype CachePlan = CachePlan (Word32 -> IO Int32)
instance ParentCache.CacheAdmission CachePlan where admitReplayCache (CachePlan action) = action 1
instance ParentCache.CacheConfiguration CachePlan where configureReplayCache (CachePlan action) = action 2
instance ParentCache.CacheStorage CachePlan where loadReplayCache (CachePlan action) = action 3
instance ParentCache.CacheBootstrap CachePlan where rebuildReplayCache (CachePlan action) = action 4

cacheDispatch :: Property
cacheDispatch = forAll (vectorOf 4 (elements [-1,0,1,2])) $ \results -> ioProperty $ do
  events <- newIORef []
  let plan = CachePlan (\step -> modifyIORef' events (++ [step]) >> pure (results !! (fromIntegral step-1)))
      expected = case results of
        [0,_,_,_] -> (1,[1])
        [2,_,_,_] -> (0,[1])
        [1,1,0,result] -> (result,[1,2,3,4])
        [1,1,1,_] -> (1,[1,2,3])
        [1,1,_,_] -> (-1,[1,2,3])
        [1,_,_,_] -> (-1,[1,2])
        _ -> (-1,[1])
      unrelated = SomeOperation (Check (R.Distance 1 0))
      mismatch = isNothing (interpret unrelated
        (error "forced mismatched cache DSL" :: DSL ParentCache.CacheInitialization))
  actual <- ParentCache.initializeReplayCache plan
  seen <- readIORef events
  pure (conjoin [(actual,seen) === expected,property mismatch])

cacheFields :: Property
cacheFields = forAll (oneof [arbitrary,elements [minBound,-1,0,1,4294967295,4294967296,maxBound]]) $
  \value -> ioProperty $ do
    events <- newIORef []
    let action step = modifyIORef' events (++ [step]) >> pure value
    result <- try (ParentCache.cacheValue action 8 >>= pure . toInteger) :: IO (Either SomeException Integer)
    seen <- readIORef events
    pure (conjoin [either (const (-1)) id result ===
      if value < 0 || value > 4294967295 then -1 else toInteger value,seen === [8]])

properties :: [(String,Property)]
properties =
  [ ("RPC credentials / composed legacy traces and faults",credentials)
  , ("RPC timeout / signed bounds, precedence and exact effects",timeout)
  , ("RPC credentials / malformed callback rejection",malformed)
  , ("RPC preparation / lazy payload mismatch and generic capability reuse",dispatch)
  , ("RPC lifecycle / retry, circuit, reply order and every effect fault",rpcCalls)
  , ("RPC lifecycle / malformed attempt results stop effects",rpcMalformed)
  , ("RPC lifecycle / lazy mismatch and minimal capability reuse",rpcDispatch)
  , ("RPC transport / native phase parity and every effect failure",transport)
  , ("RPC transport / malformed framing cleanup and lazy mismatch",transportMalformed)
  , ("RPC transport / file framing rejects before send with both cleanups",transportFileMalformed)
  , ("RPC host / native snapshots preserve address admission",property hostAdmission)
  , ("RPC host / malformed frames, lazy mismatch and non-native short circuit",hostMalformed)
  , ("RPC transport / composed host and cookie selection parity",transportEnvironmentRules)
  , ("RPC transport / environment framing fails before file open",transportEnvironmentMalformed)
  , ("Auth file / lazy mismatch and reusable file capabilities",authFileDispatch)
  , ("Auth file / malformed scalar framing and short-circuiting",authFileFraming)
  , ("Auth record / bounded format checks and rejection effect",authRecord)
  , ("Replay cache / reusable capability orchestration and lazy mismatch",cacheDispatch)
  , ("Replay cache / bounded numeric fields",cacheFields)
  ]
