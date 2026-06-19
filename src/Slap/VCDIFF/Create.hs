{-# LANGUAGE OverloadedStrings #-}

-- | VCDIFF patch creation — the bedrock floor.
--
-- This emits the smallest wire-valid patch that reconstructs the
-- target: the RFC 3284 parameterless shape degenerated all the way
-- down to one window, no source segment, and a single ADD instruction
-- carrying the whole target. It copies nothing from the source — the
-- source is read only to be ignored — so the patch reconstructs the
-- target whatever it is applied against. That is correct and intended
-- for the floor; source-aware diffing (COPY, the address cache,
-- match-finding) is later work that builds on this plumbing.
--
-- Because it reaches for no flavor-distinguishing feature, the patch
-- this emits parses back as 'Slap.VCDIFF.Types.PatchCoreOnly', not
-- @PatchRFC@. That is right, not a gap: the RFC arc's parameterless
-- default genuinely uses only core features (docs/vcdiff/core/spec.md,
-- "A patch that happens to use only the features described here is
-- valid as either flavor"). The @rfc-vcdiff@ token names the arc the
-- user asked for; these bytes happen to be core-shaped because the
-- floor reaches for nothing RFC-specific.
module Slap.VCDIFF.Create
  ( createRFCVCDIFF
  ) where

import Slap.VCDIFF.Types (vcdiffMagicBytes)
import Slap.Binary (putVcdiffVarint)
import Slap.Status (SlapError, CreateResult(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, word8, toLazyByteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Word (Word8)

-- | Create a VCDIFF patch reconstructing @target@. The source is
-- accepted and ignored — this floor encodes the target outright and
-- copies nothing — so the result is always 'Right'; the 'Either' is
-- shape-symmetry with the other @create*@ entries, whose richer
-- encoders can fail. No metadata, no advisories.
createRFCVCDIFF :: InputFileContents -> OutputFileContents
                -> Either SlapError CreateResult
createRFCVCDIFF _source (OutputFileContents target) =
  Right (CreateResult (PatchFileContents patchBytes) [])
  where
    targetLength = ByteString.length target

    -- The instruction section: one ADD whose size is coded separately.
    -- Default-table index 1 is (ADD, size-coded-separately), so the
    -- opcode byte is followed by the size as a VCDIFF varint. Emitted
    -- uniformly — the inline-size ADD entries (indices 2–18) are a
    -- density optimization for a later layer, and skipping them keeps
    -- this encoder one shape with no table lookup.
    instructionSection = builderBytes
      (word8 addInstructionSizeCodedSeparately <> putVcdiffVarint (fromIntegral targetLength))

    -- The delta encoding: everything the delta-encoding-length field
    -- covers — the target window size, the indicator, the three section
    -- lengths, then the data, instruction, and (empty) address sections.
    deltaEncoding = builderBytes
      (  putVcdiffVarint (fromIntegral targetLength)                          -- target window size
      <> word8 noSectionsCompressed                                          -- Delta_Indicator
      <> putVcdiffVarint (fromIntegral targetLength)                          -- data section length
      <> putVcdiffVarint (fromIntegral (ByteString.length instructionSection)) -- instruction section length
      <> putVcdiffVarint 0                                                    -- address section length
      <> byteString target                                                   -- data section
      <> byteString instructionSection )                                     -- instruction section
                                                                             -- (address section empty)

    patchBytes = builderBytes
      (  byteString vcdiffMagicBytes
      <> word8 version0
      <> word8 noHeaderFeatures
      <> word8 selfContainedWindow                                           -- Win_Indicator: no source segment
      <> putVcdiffVarint (fromIntegral (ByteString.length deltaEncoding))
      <> byteString deltaEncoding )

-- | Default code-table index 1: ADD with its size coded separately in
-- the instruction stream (RFC 3284 §5.6).
addInstructionSizeCodedSeparately :: Word8
addInstructionSizeCodedSeparately = 0x01

-- | Version byte: VCDIFF is at version 0 (RFC 3284 §4.1).
version0 :: Word8
version0 = 0x00

-- | Hdr_Indicator with no bits set: no secondary compressor, no custom
-- code table, no application header.
noHeaderFeatures :: Word8
noHeaderFeatures = 0x00

-- | Win_Indicator with no bits set: no source segment (the window
-- copies from neither the source file nor the produced target), so its
-- two source-segment varints are absent.
selfContainedWindow :: Word8
selfContainedWindow = 0x00

-- | Delta_Indicator with no bits set: none of the three sections is
-- secondary-compressed.
noSectionsCompressed :: Word8
noSectionsCompressed = 0x00

-- | Render a 'Builder' to a strict 'ByteString'.
builderBytes :: Builder -> ByteString
builderBytes = LazyByteString.toStrict . toLazyByteString
