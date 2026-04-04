{-# LANGUAGE StrictData #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1Source(..)
  , XDelta1Instruction(..)
  , XDelta1Version(..)
  , fromXDelta1Version
  , XDelta1SourceKind(..)
  , XDelta1OffsetMode(..)
  ) where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Checksum (MD5Hash(..))
import Slap.Measure (Offset(..), FileSize(..))

data XDelta1Version = XDelta1v104 | XDelta1v11
  deriving (Show, Eq)

fromXDelta1Version :: XDelta1Version -> String
fromXDelta1Version XDelta1v104 = "1.0.4"
fromXDelta1Version XDelta1v11  = "1.1"

data XDelta1SourceKind = FileSource | DataSegmentSource
  deriving (Show, Eq)

data XDelta1OffsetMode = AbsoluteOffsets | SequentialOffsets
  deriving (Show, Eq)

data XDelta1Patch = XDelta1Patch
  { xdelta1Version      :: XDelta1Version
  , xdelta1FromName     :: ByteString
  , xdelta1ToName       :: ByteString
  , xdelta1ToMD5        :: MD5Hash
  , xdelta1TargetLength :: FileSize
  , xdelta1Sources      :: [XDelta1Source]
  , xdelta1Instructions :: [XDelta1Instruction]
  , xdelta1DataSegment  :: ByteString  -- decompressed literal data
  } deriving (Show)

data XDelta1Source = XDelta1Source
  { xdelta1SourceName       :: ByteString
  , xdelta1SourceMD5        :: MD5Hash
  , xdelta1SourceLength     :: FileSize
  , xdelta1SourceKind       :: XDelta1SourceKind
  , xdelta1SourceOffsetMode :: XDelta1OffsetMode
  } deriving (Show)

data XDelta1Instruction = XDelta1Instruction
  { xdelta1InstructionIndex  :: Int64     -- array index, stays Int64
  , xdelta1InstructionOffset :: Offset
  , xdelta1InstructionLength :: FileSize
  } deriving (Show)
