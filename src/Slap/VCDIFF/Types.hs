{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.VCDIFF.Types
  ( VCDIFFPatch(..)
  , VCDIFFHeader(..)
  , VCDIFFWindow(..)
  , VCDIFFInstruction(..)
  , VCDIFFAddressMode(..)
  , VCDIFFNearCacheSize(..)
  , VCDIFFSameCacheSize(..)
  , VCDIFFDecodedInstruction(..)
  , VCDIFFVersion(..)
  , toVCDIFFVersion
  , fromVCDIFFVersion
  , VCDIFFWindowSource(..)
  , toVCDIFFWindowSource
  , fromVCDIFFWindowSource
  , VCDIFFSecondaryCompression(..)
  , toVCDIFFSecondaryCompression
  , fromVCDIFFSecondaryCompression
  , CodeEntry(..)
  , defaultCodeTable
  , serializedDefaultTable
  , deserializeCodeTable
  , decodeCustomTable
  , instructionType
  , instructionSize
  , instructionMode
    -- * Named constants
  , vcdiffMagicBytes
  , sameCacheSlots
  ) where

-- Canonical reference: RFC 3284

import Slap.Checksum (Adler32)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..), Length(..), FoundVersion(..))

import Control.Monad (when)
import Data.Array (Array, listArray, (!))
import Data.Bits (testBit, setBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data VCDIFFVersion = VCDIFFStandard | VCDIFFXDelta3
  deriving (Show, Eq)

toVCDIFFVersion :: Word8 -> Either SlapError VCDIFFVersion
toVCDIFFVersion 0    = Right VCDIFFStandard
toVCDIFFVersion 0x53 = Right VCDIFFXDelta3
toVCDIFFVersion byte = Left (BadVersion LabelVCDIFF (FoundVersion byte))

fromVCDIFFVersion :: VCDIFFVersion -> Word8
fromVCDIFFVersion VCDIFFStandard = 0
fromVCDIFFVersion VCDIFFXDelta3  = 0x53

data VCDIFFWindowSource
  = WindowNoSource
  | WindowFromSource
  | WindowFromTarget
  deriving (Show, Eq)

toVCDIFFWindowSource :: Word8 -> VCDIFFWindowSource
toVCDIFFWindowSource indicator
  | testBit indicator 0 = WindowFromSource
  | testBit indicator 1 = WindowFromTarget
  | otherwise            = WindowNoSource

fromVCDIFFWindowSource :: VCDIFFWindowSource -> Word8
fromVCDIFFWindowSource WindowNoSource    = 0
fromVCDIFFWindowSource WindowFromSource  = 1
fromVCDIFFWindowSource WindowFromTarget  = 2

data VCDIFFSecondaryCompression = VCDIFFSecondaryCompression
  { compressAddRunData   :: !Bool
  , compressInstructions :: !Bool
  , compressAddresses    :: !Bool
  } deriving (Show, Eq)

toVCDIFFSecondaryCompression :: Word8 -> VCDIFFSecondaryCompression
toVCDIFFSecondaryCompression indicator = VCDIFFSecondaryCompression
  { compressAddRunData   = testBit indicator 0
  , compressInstructions = testBit indicator 1
  , compressAddresses    = testBit indicator 2
  }

fromVCDIFFSecondaryCompression :: VCDIFFSecondaryCompression -> Word8
fromVCDIFFSecondaryCompression compression =
  applyBit 0 (compressAddRunData compression)
    $ applyBit 1 (compressInstructions compression)
    $ applyBit 2 (compressAddresses compression) 0
  where
    applyBit bit True  byte = setBit byte bit
    applyBit _   False byte = byte

-- | Addressing mode for COPY instructions (RFC 3284 §5). Modes 0
-- and 1 are SELF and HERE; modes 2..near+1 index the near cache;
-- modes near+2..near+same+1 index the same cache.
newtype VCDIFFAddressMode = VCDIFFAddressMode { unVCDIFFAddressMode :: Int }
  deriving (Eq, Ord, Show)

-- | Near-cache size (RFC 3284 §5.3). Default is 4.
newtype VCDIFFNearCacheSize = VCDIFFNearCacheSize { unVCDIFFNearCacheSize :: Int }
  deriving (Eq, Ord, Show)

-- | Same-cache size (RFC 3284 §5.3). The same cache holds
-- @samesize × 256@ slots; default samesize is 3.
newtype VCDIFFSameCacheSize = VCDIFFSameCacheSize { unVCDIFFSameCacheSize :: Int }
  deriving (Eq, Ord, Show)

data VCDIFFInstruction
  = VcdiffNoop
  | VcdiffAdd  { vcdiffAddSize  :: !Length }
  | VcdiffRun  { vcdiffRunSize  :: !Length }
  | VcdiffCopy { vcdiffCopySize :: !Length, vcdiffCopyMode :: !VCDIFFAddressMode }
  deriving (Show)

data VCDIFFHeader = VCDIFFHeader
  { vcdiffVersion      :: VCDIFFVersion
  , vcdiffCompressorId :: Maybe Word8
  , vcdiffHasCodeTable :: Bool
  } deriving (Show)

data VCDIFFWindow = VCDIFFWindow
  { vcdiffWindowSource           :: VCDIFFWindowSource
  , vcdiffSourceLength           :: FileSize
  , vcdiffSourcePosition         :: Offset
  , vcdiffTargetLength           :: FileSize
  , vcdiffSecondaryCompression   :: VCDIFFSecondaryCompression
  , vcdiffAdler32                :: Maybe Adler32
  , vcdiffAddRunData             :: ByteString   -- literal data stream
  , vcdiffInstructions           :: ByteString   -- instruction stream (code + sizes)
  , vcdiffAddresses              :: ByteString   -- address stream
  } deriving (Show)

data VCDIFFPatch = VCDIFFPatch
  { vcdiffHeader    :: VCDIFFHeader
  , vcdiffWindows   :: [VCDIFFWindow]
  , vcdiffCodeTable :: Array Word8 CodeEntry
    -- ^ Either the constant 'defaultCodeTable' (when the patch
    -- had no custom-table flag set) or a custom table parsed via
    -- 'decodeCustomTable'.
  , vcdiffNearSize  :: VCDIFFNearCacheSize
  , vcdiffSameSize  :: VCDIFFSameCacheSize
  } deriving (Show)

-- | Decoded instruction for the explain path — mirrors execute
-- logic but accumulates instructions instead of writing bytes.
-- Three variants: an Add (window offset, payload bytes), a Run
-- (window offset, fill byte, run count), and a Copy (window
-- offset, copy size, optional source offset for the read).
data VCDIFFDecodedInstruction
  = DecodedAdd !Offset !ByteString
  | DecodedRun !Offset !Word8 !Length
  | DecodedCopy !Offset !Length !(Maybe Offset)

-- | Slot count per same-cache entry (RFC 3284 §5.3).
-- Each same-cache entry maps 256 byte values to addresses.
-- | VCDIFF magic bytes (@0xD6 0xC3 0xC4@) per RFC 3284.
vcdiffMagicBytes :: ByteString
vcdiffMagicBytes = "\xd6\xc3\xc4"

sameCacheSlots :: Int
sameCacheSlots = 256

----------------------------------------------------------------------------
-- Default code table (RFC 3284 Section 5.6)
----------------------------------------------------------------------------

-- For size=0 instructions, the actual size follows as a varint in the
-- instruction stream.

data CodeEntry = CodeEntry
  { codeEntryFirst  :: !VCDIFFInstruction
  , codeEntrySecond :: !VCDIFFInstruction
  } deriving (Show)

defaultCodeTable :: Array Word8 CodeEntry
defaultCodeTable = listArray (0, 255) $
  -- 0: RUN 0, Noop
  [CodeEntry (VcdiffRun (Length 0)) VcdiffNoop]
  -- 1-18: ADD size, Noop  (size 0..17)
  ++ [CodeEntry (VcdiffAdd (Length size)) VcdiffNoop | size <- [0..17]]
  -- 19-162: COPY size mode, Noop
  -- 9 modes (0..8), sizes 0..15 for each mode -> 144 entries
  -- For each mode 0..8:
  --   size 0: COPY 0 mode, Noop
  --   sizes 4..18: COPY s mode, Noop
  ++ [CodeEntry (VcdiffCopy (Length size) (VCDIFFAddressMode mode)) VcdiffNoop | mode <- [0..8], size <- 0 : [4..18]]
  -- 163-234: ADD 1..4, COPY 4..6, modes 0..5  -> 72 entries
  ++ [CodeEntry (VcdiffAdd (Length addSize)) (VcdiffCopy (Length copySize) (VCDIFFAddressMode mode)) | mode <- [0..5], addSize <- [1..4], copySize <- [4..6]]
  -- 235-246: ADD 1..4, COPY 4, modes 6..8  -> 12 entries
  ++ [CodeEntry (VcdiffAdd (Length addSize)) (VcdiffCopy (Length 4) (VCDIFFAddressMode mode)) | mode <- [6..8], addSize <- [1..4]]
  -- 247-255: COPY 4, ADD 1, modes 0..8  -> 9 entries
  ++ [CodeEntry (VcdiffCopy (Length 4) (VCDIFFAddressMode mode)) (VcdiffAdd (Length 1)) | mode <- [0..8]]

----------------------------------------------------------------------------
-- Code table serialization (RFC 3284 Section 7)
----------------------------------------------------------------------------

-- Instruction type encoding: Noop=0, Add=1, Run=2, Copy=3
instructionType :: VCDIFFInstruction -> Word8
instructionType VcdiffNoop       = 0
instructionType (VcdiffAdd _)    = 1
instructionType (VcdiffRun _)    = 2
instructionType (VcdiffCopy _ _) = 3

instructionSize :: VCDIFFInstruction -> Word8
instructionSize VcdiffNoop                       = 0
instructionSize (VcdiffAdd  (Length size))       = fromIntegral size
instructionSize (VcdiffRun  (Length size))       = fromIntegral size
instructionSize (VcdiffCopy (Length size) _)     = fromIntegral size

instructionMode :: VCDIFFInstruction -> Word8
instructionMode (VcdiffCopy _ (VCDIFFAddressMode mode)) = fromIntegral mode
instructionMode _                                       = 0

-- | Serialize the default code table to 1536 bytes (6 x 256):
--   types1 ++ types2 ++ sizes1 ++ sizes2 ++ modes1 ++ modes2
serializedDefaultTable :: ByteString
serializedDefaultTable = ByteString.pack $
  map (instructionType . codeEntryFirst . (defaultCodeTable !)) [0..255]
  ++ map (instructionType . codeEntrySecond . (defaultCodeTable !)) [0..255]
  ++ map (instructionSize . codeEntryFirst . (defaultCodeTable !)) [0..255]
  ++ map (instructionSize . codeEntrySecond . (defaultCodeTable !)) [0..255]
  ++ map (instructionMode . codeEntryFirst . (defaultCodeTable !)) [0..255]
  ++ map (instructionMode . codeEntrySecond . (defaultCodeTable !)) [0..255]

deserializeCodeTable :: ByteString -> Either SlapError (Array Word8 CodeEntry)
deserializeCodeTable tableBytes
  | ByteString.length tableBytes /= 1536 = Left $ ParseError LabelVCDIFF ("code table must be 1536 bytes, got " ++ show (ByteString.length tableBytes))
  | otherwise = do
      entries <- mapM makeEntry [0..255]
      pure $ listArray (0, 255) entries
  where
    makeEntry :: Int -> Either SlapError CodeEntry
    makeEntry index = CodeEntry <$> makeInstruction (byteAt index) (byteAt (512+index)) (byteAt (1024+index))
                                <*> makeInstruction (byteAt (256+index)) (byteAt (768+index)) (byteAt (1280+index))
    byteAt = ByteString.index tableBytes
    makeInstruction :: Word8 -> Word8 -> Word8 -> Either SlapError VCDIFFInstruction
    makeInstruction 0 _    _    = Right VcdiffNoop
    makeInstruction 1 size _    = Right (VcdiffAdd  (Length (fromIntegral size)))
    makeInstruction 2 size _    = Right (VcdiffRun  (Length (fromIntegral size)))
    makeInstruction 3 size mode = Right (VcdiffCopy (Length (fromIntegral size))
                                                    (VCDIFFAddressMode (fromIntegral mode)))
    makeInstruction typeCode _ _ = Left (ParseError LabelVCDIFF
                                           ("invalid instruction type in code table: " ++ show typeCode))

-- | Decode a custom code table from the header's code table data.
--   Format: near_size (1 byte), same_size (1 byte), then a VCDIFF delta
--   (using default table) that transforms serializedDefaultTable into the
--   custom table.
--
--   The first argument applies the inner VCDIFF delta to the serialized
--   default table, producing the custom table bytes. This parameter breaks
--   what would otherwise be a circular dependency between Types, Parse,
--   and Apply.
decodeCustomTable :: (ByteString -> Either SlapError ByteString)
                  -> ByteString
                  -> Either SlapError (Array Word8 CodeEntry, VCDIFFNearCacheSize, VCDIFFSameCacheSize)
decodeCustomTable applyInnerDelta input = do
  when (ByteString.length input < 2) $ Left (ParseError LabelVCDIFF "custom code table data too short")
  let nearSize   = VCDIFFNearCacheSize (fromIntegral (ByteString.index input 0))
      sameSize   = VCDIFFSameCacheSize (fromIntegral (ByteString.index input 1))
      deltaBytes = ByteString.drop 2 input
  customSerialized <- applyInnerDelta deltaBytes
  table <- deserializeCodeTable customSerialized
  pure (table, nearSize, sameSize)
