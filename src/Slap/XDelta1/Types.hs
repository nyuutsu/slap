{-# LANGUAGE StrictData #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1Source(..)
  , XDelta1Instruction(..)
  ) where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Measure (Offset(..), FileSize(..))

data XDelta1Patch = XDelta1Patch
  { xdelta1Version      :: String      -- "1.1" or "1.0.4"
  , xdelta1FromName     :: ByteString
  , xdelta1ToName       :: ByteString
  , xdelta1ToMD5        :: ByteString  -- 16 bytes
  , xdelta1TargetLength :: FileSize
  , xdelta1Sources      :: [XDelta1Source]
  , xdelta1Instructions :: [XDelta1Instruction]
  , xdelta1DataSegment  :: ByteString  -- decompressed literal data
  } deriving (Show)

data XDelta1Source = XDelta1Source
  { xdelta1SourceName       :: ByteString
  , xdelta1SourceMD5        :: ByteString  -- 16 bytes
  , xdelta1SourceLength     :: FileSize
  , xdelta1SourceIsData     :: Bool
  , xdelta1SourceSequential :: Bool
  } deriving (Show)

data XDelta1Instruction = XDelta1Instruction
  { xdelta1InstructionIndex  :: Int64     -- array index, stays Int64
  , xdelta1InstructionOffset :: Offset
  , xdelta1InstructionLength :: FileSize
  } deriving (Show)
