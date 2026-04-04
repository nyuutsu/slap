{-# LANGUAGE StrictData #-}

module Slap.VCDIFF.Types
  ( VCDIFFPatch(..)
  , VCDIFFHeader(..)
  , VCDIFFWindow(..)
  , VCDIFFInstruction(..)
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
  ) where

-- Canonical reference: RFC 3284

import Slap.Checksum (Adler32)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..), Length(..))

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
toVCDIFFVersion byte = Left (BadVersion LabelVCDIFF byte)

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

data VCDIFFInstruction
  = VcdiffNoop
  | VcdiffAdd  { vcdiffAddSize  :: !Int }
  | VcdiffRun  { vcdiffRunSize  :: !Int }
  | VcdiffCopy { vcdiffCopySize :: !Int, vcdiffCopyMode :: !Int }
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
  , vcdiffCodeTable :: Array Word8 CodeEntry  -- default or custom
  , vcdiffNearSize  :: Int                    -- 4 by default
  , vcdiffSameSize  :: Int                    -- 3 by default
  } deriving (Show)

-- | Decoded instruction for the explain path -- mirrors execute logic but
--   accumulates instructions instead of writing bytes.
data VCDIFFDecodedInstruction
  = DecodedAdd
      { decodedAddWindowOffset :: !Offset
      , decodedAddPayload      :: !ByteString
      }
  | DecodedRun
      { decodedRunWindowOffset :: !Offset
      , decodedRunFillByte     :: !Word8
      , decodedRunCount        :: !Length
      }
  | DecodedCopy
      { decodedCopyWindowOffset :: !Offset
      , decodedCopySize         :: !Length
      , decodedCopySourceOffset :: !(Maybe Offset)
      }

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
  [CodeEntry (VcdiffRun 0) VcdiffNoop]
  -- 1-18: ADD size, Noop  (size 0..17)
  ++ [CodeEntry (VcdiffAdd size) VcdiffNoop | size <- [0..17]]
  -- 19-162: COPY size mode, Noop
  -- 9 modes (0..8), sizes 0..15 for each mode -> 144 entries
  -- For each mode 0..8:
  --   size 0: COPY 0 mode, Noop
  --   sizes 4..18: COPY s mode, Noop
  ++ [CodeEntry (VcdiffCopy size mode) VcdiffNoop | mode <- [0..8], size <- 0 : [4..18]]
  -- 163-234: ADD 1..4, COPY 4..6, modes 0..5  -> 72 entries
  ++ [CodeEntry (VcdiffAdd addSize) (VcdiffCopy copySize mode) | mode <- [0..5], addSize <- [1..4], copySize <- [4..6]]
  -- 235-246: ADD 1..4, COPY 4, modes 6..8  -> 12 entries
  ++ [CodeEntry (VcdiffAdd addSize) (VcdiffCopy 4 mode) | mode <- [6..8], addSize <- [1..4]]
  -- 247-255: COPY 4, ADD 1, modes 0..8  -> 9 entries
  ++ [CodeEntry (VcdiffCopy 4 mode) (VcdiffAdd 1) | mode <- [0..8]]

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
instructionSize VcdiffNoop       = 0
instructionSize (VcdiffAdd size)    = fromIntegral size
instructionSize (VcdiffRun size)    = fromIntegral size
instructionSize (VcdiffCopy size _) = fromIntegral size

instructionMode :: VCDIFFInstruction -> Word8
instructionMode (VcdiffCopy _ mode) = fromIntegral mode
instructionMode _                = 0

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
    makeInstruction 0 _ _ = Right VcdiffNoop
    makeInstruction 1 size _ = Right (VcdiffAdd (fromIntegral size))
    makeInstruction 2 size _ = Right (VcdiffRun (fromIntegral size))
    makeInstruction 3 size mode = Right (VcdiffCopy (fromIntegral size) (fromIntegral mode))
    makeInstruction typeCode _ _ = Left (ParseError LabelVCDIFF ("invalid instruction type in code table: " ++ show typeCode))

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
                  -> ByteString -> Either SlapError (Array Word8 CodeEntry, Int, Int)
decodeCustomTable applyInnerDelta input = do
  when (ByteString.length input < 2) $ Left (ParseError LabelVCDIFF "custom code table data too short")
  let nearSize = fromIntegral (ByteString.index input 0) :: Int
      sameSize = fromIntegral (ByteString.index input 1) :: Int
      deltaBytes = ByteString.drop 2 input
  customSerialized <- applyInnerDelta deltaBytes
  table <- deserializeCodeTable customSerialized
  pure (table, nearSize, sameSize)
