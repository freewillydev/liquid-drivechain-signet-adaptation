{-# LANGUAGE TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module NodeRules where

import Control.Operation.Validation
import BmmConstants (productionChainName, pegEventDefaultCount, pegEventCountLimit)
import ParentReplay (transition)
import Data.Bits (testBit)
import Data.Int (Int32)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Builder (toLazyByteString, word32BE)

data PegEventRange = PegEventRange Int32 Int32 Int32 | PegEventStart Int32
instance Validation PegEventRange where
  type ValidationResult PegEventRange = Either Int32 Int32
  validate (PegEventStart tip) = Right (fromInteger (max 0 (toInteger tip - toInteger pegEventDefaultCount + 1)))
  validate (PegEventRange start count tip)
    | start < 0 || start > tip = Left 1
    | count < 1 || count > fromIntegral pegEventCountLimit = Left 2
    | otherwise = Right (fromInteger (min (toInteger tip) (toInteger start + toInteger count - 1)))

newtype Unsigned32Fields = Unsigned32Fields [Word64]
instance Validation Unsigned32Fields where
  type ValidationResult Unsigned32Fields = Bool
  validate (Unsigned32Fields fields) = all (<= 4294967295) fields

data JetHeight = JetHeight Bool Word64
instance Validation JetHeight where
  type ValidationResult JetHeight = Bool
  validate (JetHeight present height) = present && height /= 0

data ParentReportFlow = ParentReportFlow Word32 Word32
instance Validation ParentReportFlow where
  type ValidationResult ParentReportFlow = Int32
  validate (ParentReportFlow phase result)
    | phase == 9 = if result == 0 then 10 else 11
    | phase == 12 = if result == 0 then 14 else 13
    | otherwise = transition phase result
        [(1,(5,2)),(2,(3,4)),(3,(-1,-1)),(4,(-1,12)),(5,(8,6)),
         (6,(7,12)),(7,(-1,-1)),(8,(7,9)),(10,(-1,-1)),(11,(-1,12)),
         (13,(14,-11)),(14,(-1,-1))]

-- Preserve the authenticated BMM endpoint cache domain, not legacy proof roots.
data ScriptCacheEncoding = ScriptCacheEncoding Bool B.ByteString
instance Validation ScriptCacheEncoding where
  type ValidationResult ScriptCacheEncoding = Maybe B.ByteString
  validate (ScriptCacheEncoding endpointOnly input)
    | not endpointOnly = Nothing
    | input == B.singleton 0 = Just (domain <> B.singleton 0 <> B.replicate 80 0)
    | B.length input == 81 && B.head input == 1 = Just (domain <> input)
    | otherwise = Nothing
    where
      domain = B.pack
        [0x9f,0xa5,0xb4,0x11,0x85,0xf7,0x39,0x1f,0xfd,0xa6,0x3b,0x6b,0xb1,0x4b,0xa7,0x9b,
         0x13,0x8f,0x46,0x39,0x6b,0xca,0x42,0xb7,0x5e,0xfd,0xe5,0xdc,0x55,0x03,0xfe,0x26,0,1]

newtype ProductionIdentity = ProductionIdentity (Int -> IO Bool)
instance Validation ProductionIdentity where
  type ValidationResult ProductionIdentity = IO Int
  validate (ProductionIdentity readFact) = check facts
    where
      facts = filter (\(step,_) -> step /= 79 && (step < 83 || step > 89)) $ zip [0..] $
        concat (zipWith replicate [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,4,4,3,5,7,9,5,4,7,6,10,6,3,12,6] [1..])
      check [] = pure 0
      check ((step,code):rest) = readFact step >>= \valid -> if valid then check rest else pure code

data PaymentUri = PaymentUri Word32 Word32
instance Validation PaymentUri where
  type ValidationResult PaymentUri = Int32
  validate (PaymentUri flags scheme)
    | flags>7 || scheme>5 = -1
    | scheme==4 = fromIntegral selected
    | scheme==5 = 0
    | scheme==selected || (selected>=2 && scheme>=2) = 1
    | otherwise = 0
    where
      selected | not (testBit flags 0) = 0
               | testBit flags 1 = 1
               | testBit flags 2 = 3
               | otherwise = 2

data AddressAlias = AddressAlias Word32 B.ByteString B.ByteString
instance Validation AddressAlias where
  type ValidationResult AddressAlias = Int32
  validate (AddressAlias flags network prefix)
    | flags > 3 = -1
    | testBit flags 0 || network /= C.pack "elements" = 0
    | prefix == C.pack (if testBit flags 1 then "el" else "ert") = 1
    | otherwise = 0

data NetworkSelection = NetworkSelection Word32 Word32 B.ByteString
instance Validation NetworkSelection where
  type ValidationResult NetworkSelection = Int32
  validate (NetworkSelection mode flags text)
    | mode > 3 || flags > 1 || (mode /= 2 && flags /= 0) = -1
    | mode == 3 = if text `elem` map C.pack [productionChainName,"liquidv1"] then 1 else 0
    | mode == 0 = if text == C.pack productionChainName then 0 else 1
    | mode == 1 = if text == C.pack "usdd" then 2 else 0
    | flags == 1 = 3
    | name == C.pack "simplicity" = 4
    | name == C.pack "dynafed" = 5
    | otherwise = 0
    where name = C.takeWhile (/= ':') text

data ConfigurationField = ConfigurationField Word32 B.ByteString
instance Validation ConfigurationField where
  type ValidationResult ConfigurationField = Either Int B.ByteString
  validate (ConfigurationField mode text)
    | mode > 9 = Left (-1)
    -- Proposal payload is free text followed by manifest32 and source-id20.
    | mode == 9 = if B.length text < 52 || B.length text > 65526 then Left 1
        else Right (B.pack [0,8] <> C.pack "Elements" <> text)
    | mode == 7 = if B.length text==75 && C.pack "__cookie__:" `B.isPrefixOf` text
        then hex (B.drop 11 text) >> Right (B.singleton 1) else Left 1
    | mode == 8 = case C.split ':' text of
        [user,password] | B.length text<=1024 && not (B.null user) && not (B.null password) &&
          user/=C.pack "__cookie__" && B.all (\c -> c>=33 && c<=126) text -> Right (B.singleton 1)
        _ -> Left 1
    | mode == 6 = if B.length text==650 then hex text else Left 1
    | mode == 5 = if B.length text > 131072 then Left 1 else hex text
    | mode == 2 = do
        if B.length text <= 65 || B.index text 64 /= 58 then Left 1 else Right ()
        hash <- hex (B.take 64 text)
        let suffix = B.drop 65 text
            digits = if B.take 1 suffix == B.singleton 43 then B.drop 1 suffix else suffix
        if B.null digits || not (B.all (\c -> c>=48 && c<=57) digits) then Left 1 else Right ()
        let index = B.foldl' (\n c -> min 4294967296 (n*10+fromIntegral c-48)) (0 :: Word64) digits
        if index > 4294967295 then Left 1 else Right ()
        if B.all (==0) hash then Left 2 else
          Right (B.reverse hash <> L.toStrict (toLazyByteString (word32BE (fromIntegral index))))
    | mode == 3 && B.length text > 20000 =
        if even (B.length text) && B.all (either (const False) (const True) . nibble) text then Left 2 else Left 1
    | mode == 3 = do
        bytes <- hex text
        if B.length bytes > 10000 || B.head bytes == 106 then Left 2 else Right bytes
    | B.length text /= 64 = Left 1
    | otherwise = do
        bytes <- hex text
        if mode /= 0 && B.all (==0) bytes then Left 2
        else Right (if mode == 4 then B.reverse bytes else bytes)
    where
      hex bytes
        | B.null bytes || odd (B.length bytes) = Left 1
        | otherwise = B.pack <$> pairs (B.unpack bytes)
      pairs [] = Right []
      pairs (a:b:rest) = do
        high <- nibble a
        low <- nibble b
        ((high*16+low):) <$> pairs rest
      pairs _ = Left 1
      nibble :: Word8 -> Either Int Word8
      nibble c | c>=48 && c<=57 = Right (c-48)
               | c>=65 && c<=70 = Right (c-55)
               | c>=97 && c<=102 = Right (c-87)
               | otherwise = Left 1

data FeeAsset = FeeAsset (Maybe B.ByteString) B.ByteString Bool
instance Validation FeeAsset where
  type ValidationResult FeeAsset = Either Int B.ByteString
  validate (FeeAsset configured pegged canonical)
    | B.length pegged /= 32 = Left (-1)
    | otherwise = case configured of
        Nothing -> Right pegged
        Just text -> do
          requested <- B.reverse <$> validate (ConfigurationField 0 text)
          if canonical && requested /= pegged then Left 2 else Right requested

