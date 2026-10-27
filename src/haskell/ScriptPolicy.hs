{-# LANGUAGE TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ScriptPolicy where

import Control.Operation.Validation
import Data.Bits (testBit, (.&.))
import Data.Int (Int32, Int64)
import Data.Word (Word32, Word64)

data MerkleReplacement = MerkleReplacement Word32 Word32 Word32 Word32
instance Validation MerkleReplacement where
  type ValidationResult MerkleReplacement = Int32
  validate (MerkleReplacement mode index position flags)
    | mode==0 && flags==0 = result (index/=maxBound)
    | mode==1 && flags<=3 = result (flags==3 && index==position)
    | mode==2 && flags<=1 = result (index==maxBound || flags==1)
    | otherwise = -1
    where result accepted=if accepted then 1 else 0

data ParameterGate = ParameterGate Word32 Int64 Int64
instance Validation ParameterGate where
  type ValidationResult ParameterGate = Int32
  validate (ParameterGate mode first second) = case mode of
    0 -> if first >= 0 && second >= first then 1 else 0
    1 | first `elem` [0,1] && second `elem` [0,1] -> if first == 1 && second == 1 then 1 else 0
    2 | second == 0 -> if first >= 0 then 1 else 0
    _ -> -1

data OptionalEnvironment = OptionalEnvironment Word32 Word32 Word32
instance Validation OptionalEnvironment where
  type ValidationResult OptionalEnvironment = Int32
  validate (OptionalEnvironment kind present fields)
    | present>1 = -1
    | otherwise = case kind of
        0 -> exact 1
        1 -> exact 7
        2 -> exact 255
        3 | fields<=7 -> accept (if present==1 then fields .&. 5 == 5 else fields==0)
        4 | fields<=7 -> accept (if present==1 then fields==7 else fields .&. 3 == 0)
        5 | fields<=15 -> accept (if present==1 then fields .&. 13 == 13 else fields==0)
        _ -> -1
    where
      accept valid = if valid then 1 else 0
      exact mask | fields>mask = -1
                 | otherwise = accept (fields==if present==1 then mask else 0)

data TemplateAdmission = TemplateAdmission Word32 Word64
instance Validation TemplateAdmission where
  type ValidationResult TemplateAdmission = Int32
  validate (TemplateAdmission flags size)
    | flags > 31 || (not (testBit flags 4) && size /= 0) = -1
    | testBit flags 1 = 1
    | not (testBit flags 0) = if testBit flags 2 then 1 else 0
    | not (testBit flags 4) = 2
    | size == 32 = 3
    | testBit flags 3 = 1
    | otherwise = 0
