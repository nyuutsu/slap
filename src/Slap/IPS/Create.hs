{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder and high-level diff entry points for the IPS
-- family. This module is the IPS analog of 'Slap.BPS.Create' and
-- 'Slap.UPS.Create' — it owns the byte-laying side of patch
-- creation. The decision side (which records to emit, what shape
-- they should take, how to merge or split runs) lives in
-- 'Slap.IPS.Optimize'.
--
-- The single 'encodeIPSPatch' wire encoder replaces the four
-- near-duplicate top-level encoders of the previous module
-- (@encodeIPS@, @encodeIPS32@, @encodeEBP@, @encodeEBPRaw@). The
-- variant differences — magic bytes, offset width, EOF marker,
-- sentinel offset — are looked up via 'variantSpec' instead of
-- duplicated by hand at four call sites. EBP encoding is a thin
-- wrapper ('encodeEBPPatch') that calls 'encodeIPSPatch' for the
-- standard-IPS body and appends the JSON metadata trailer.
--
-- The public diff-based entry points 'createIPS', 'createIPS32',
-- and 'createEBP' compose the optimizer with the wire encoder.
-- They are the IPS analogues of 'Slap.BPS.Create.createBPS' and
-- 'Slap.UPS.Create.createUPS' — source and target in, patch bytes
-- out — but split three ways for the three on-wire shapes.
module Slap.IPS.Create
  ( -- * Public diff-based entry points
    createIPS
  , createIPS32
  , createEBP
    -- * Lower-level wire encoder (used by 'Slap.Convert')
  , encodeIPSPatch
  , encodeEBPPatch
    -- * Wire-emission helpers
  , encodeIPSRecord
  , encodeOffset
  , encodeTruncationMarker
  , avoidSentinel
  , buildEBPMetadataJSON
    -- * Optimizer pass-through (re-exported for callers and tests)
  , optimalIPSRecords
  ) where

import Slap.Binary (putWord16BE)
import Slap.FileContents
  ( SourceFileContents(..)
  , TargetFileContents
  , PatchFileContents(..)
  , unPatchFileContents
  )
import Slap.Format (padHex)
import Slap.IPS.Optimize (optimalIPSRecords)
import Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , IPSVariantSpec(..)
  , EBPMetadata(..)
  , variantSpec
  )
import Slap.Measure
  ( Offset(..)
  , FileSize(..)
  , Delta(..)
  , Cursor(..)
  , EncodedHunk(..)
  , offsetToInt
  )

import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
  ( Builder
  , byteString
  , toLazyByteString
  , word8
  )
import qualified Data.ByteString.Lazy as LazyByteString
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding

----------------------------------------------------------------------------
-- Public diff-based entry points
----------------------------------------------------------------------------

-- | Create a 'StandardIPS' patch from source and target files.
-- The optimizer chooses the record set; the wire encoder lays the
-- bytes down. The 'IPSPatch' that results from parsing this output,
-- applied to the same source, yields the original target — the
-- BPS/UPS-style canonical create-parse-apply round trip.
--
-- IPS is structurally weaker than BPS or UPS in that it carries no
-- header field for the target size, no checksum, and no metadata.
-- This API doesn't pretend otherwise: it takes only source and
-- target, and the cost-of-correctness is paid at the optimizer
-- and encoder boundaries rather than via a richer config.
createIPS :: SourceFileContents -> TargetFileContents -> PatchFileContents
createIPS source target =
  encodeIPSPatch StandardIPS source
                 (optimalIPSRecords Offset24 source target)
                 Nothing

-- | Create an 'IPS32' patch from source and target files. The
-- IPS32 variant widens the offset field to 32 bits, addressing
-- files up to 4 GiB. There is no community-recognised IPS32
-- truncation marker; the encoder does not emit one and
-- 'Slap.IPS.Parse' refuses any trailing bytes after @"EEOF"@ —
-- see the symmetric strictness pact in @docs/ips/proposal.md@.
createIPS32 :: SourceFileContents -> TargetFileContents -> PatchFileContents
createIPS32 source target =
  encodeIPSPatch IPS32 source
                 (optimalIPSRecords Offset32 source target)
                 Nothing

-- | Create an EBP patch (a 'StandardIPS' patch with a trailing
-- JSON metadata blob) from source and target files plus the EBP
-- metadata to embed. The metadata 'ByteString' is written verbatim;
-- this layer does not validate its structure. Callers that want
-- to construct the JSON from CLI title/author/description fields
-- should call 'buildEBPMetadataJSON' first and wrap the result in
-- an 'EBPMetadata'.
createEBP
  :: SourceFileContents
  -> TargetFileContents
  -> EBPMetadata
  -> PatchFileContents
createEBP source target metadata =
  encodeEBPPatch source
                 (optimalIPSRecords Offset24 source target)
                 metadata

----------------------------------------------------------------------------
-- Parameterized wire encoder
----------------------------------------------------------------------------

-- | Encode a record list as the bytes of an IPS-family patch under
-- the given variant. This is the single wire emitter that replaces
-- the four near-duplicate functions of the previous module; each
-- of those is now either a thin wrapper around this function (the
-- two non-EBP cases) or a thin wrapper around 'encodeEBPPatch' (the
-- two EBP cases).
--
-- The @source@ argument is needed only for 'avoidSentinel', which
-- shifts records sitting at the variant's EOF-collision offset
-- back by one byte and prepends the source byte at the new offset.
-- The encoder does not otherwise touch the source.
--
-- The @optionalTruncation@ argument is honoured only for the
-- 'StandardIPS' variant. For 'IPS32', the truncation marker has
-- no defined wire shape (no community implementation supports
-- it), so the encoder silently drops any truncation passed for
-- IPS32 — emitting one would produce bytes that 'Slap.IPS.Parse'
-- would then reject under the symmetric strictness pact. The
-- 'createIPS32' entry point never passes a non-'Nothing' truncation
-- in the first place; the silent drop is for the 'Slap.Convert'
-- direct path, which threads a 'PatchContents' truncation field
-- without knowing the wire format's appetite for it.
--
-- This function does not validate the records: it assumes each
-- record's offset and length are already within the variant's
-- wire-format range. The optimizer guarantees this by construction;
-- the convert path's 'narrowHunks' pre-pass enforces it for records
-- sourced from other formats.
encodeIPSPatch
  :: IPSVariant
  -> SourceFileContents
  -> [EncodedHunk]
  -> Maybe FileSize
  -> PatchFileContents
encodeIPSPatch variant (SourceFileContents source) records optionalTruncation =
  PatchFileContents
    (LazyByteString.toStrict (toLazyByteString patchBuilder))
  where
    spec        = variantSpec variant
    offsetWidth = ipsVariantOffsetWidth spec

    sentinelAvoidedRecords =
      avoidSentinel (offsetToInt (ipsVariantSentinel spec))
                    source
                    records

    truncationBuilder = case variant of
      StandardIPS ->
        maybe mempty (encodeTruncationMarker offsetWidth) optionalTruncation
      IPS32 -> mempty

    patchBuilder =
      byteString (ipsVariantMagic spec)
      <> foldMap (encodeIPSRecord offsetWidth) sentinelAvoidedRecords
      <> byteString (ipsVariantEOFMarker spec)
      <> truncationBuilder

-- | Encode a record list as an EBP patch (a 'StandardIPS' patch
-- with a trailing JSON metadata blob). EBP has no IPS32 analogue,
-- so the variant is fixed.
--
-- The truncation marker is intentionally not supported here. The
-- IPS_AUDIT brief found no reference implementation that emits
-- truncation-then-JSON inside an EBP patch, and 'Slap.IPS.Parse'
-- only accepts EBP trailers that begin with the JSON opening byte
-- @{@. Emitting a truncation marker before the JSON would produce
-- bytes neither this parser nor any third-party EBP parser would
-- round-trip cleanly.
encodeEBPPatch
  :: SourceFileContents
  -> [EncodedHunk]
  -> EBPMetadata
  -> PatchFileContents
encodeEBPPatch source records (EBPMetadata metadataBytes) =
  let baseStandardIPSBytes =
        unPatchFileContents
          (encodeIPSPatch StandardIPS source records Nothing)
  in PatchFileContents (baseStandardIPSBytes <> metadataBytes)

----------------------------------------------------------------------------
-- Wire-emission helpers
----------------------------------------------------------------------------

-- | Encode a single 'EncodedHunk' as one IPS record. The
-- constructor choice (RLE vs. literal) is made here, by the same
-- heuristic the DP optimizer uses internally: a payload of length
-- ≥ 3 whose every byte is identical is emitted as an RLE record
-- (8 bytes for 'StandardIPS', 9 bytes for 'IPS32', regardless of
-- run length); everything else is emitted as a literal copy
-- record.
--
-- The size threshold of 3 is the smallest run for which RLE ties
-- copy on bytes — for runs of length ≥ 4 RLE is strictly cheaper.
-- We accept the tie at length 3 because emitting RLE there
-- preserves byte-identity with patches generated under the same
-- heuristic by the upstream tool ecosystem (Flips, Lunar IPS).
encodeIPSRecord :: OffsetWidth -> EncodedHunk -> Builder
encodeIPSRecord offsetWidth (EncodedHunk recordOffset recordPayload) =
  encodeOffset offsetWidth (offsetToInt recordOffset)
  <> if shouldEncodeAsRLE recordPayload
       then runLengthEncodedBody
       else literalCopyBody
  where
    payloadLength = ByteString.length recordPayload

    -- RLE record body: zero in the size field acts as the RLE
    -- sentinel, followed by the run length and the fill byte.
    runLengthEncodedBody =
         word8 0x00
      <> word8 0x00
      <> putWord16BE (fromIntegral payloadLength)
      <> word8 (ByteString.index recordPayload 0)

    -- Literal copy record body: the payload length in the size
    -- field followed by the payload bytes verbatim.
    literalCopyBody =
         putWord16BE (fromIntegral payloadLength)
      <> byteString recordPayload

-- | Decide whether a payload should be encoded as an RLE record.
-- True when the payload is at least three bytes long and every
-- byte is identical. See 'encodeIPSRecord' for the cost analysis.
shouldEncodeAsRLE :: ByteString -> Bool
shouldEncodeAsRLE payload =
  ByteString.length payload >= 3
  && ByteString.all (== ByteString.index payload 0) payload

-- | Encode an integer as a big-endian offset field whose width is
-- determined by the variant. 'Offset24' and 'Offset32' are the
-- only two cases — there is no fall-through default branch, so
-- adding a new 'OffsetWidth' constructor in 'Slap.IPS.Types' would
-- force a compile error here, which is exactly what we want.
encodeOffset :: OffsetWidth -> Int -> Builder
encodeOffset Offset24 offsetValue =
     word8 (fromIntegral (offsetValue `shiftR` 16))
  <> word8 (fromIntegral ((offsetValue `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (offsetValue .&. 0xFF))
encodeOffset Offset32 offsetValue =
     word8 (fromIntegral (offsetValue `shiftR` 24))
  <> word8 (fromIntegral ((offsetValue `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((offsetValue `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (offsetValue .&. 0xFF))

-- | Encode a Flips-style truncation marker: a single big-endian
-- offset value, in the same width as the variant's record offsets.
-- Only emitted for 'StandardIPS'; see 'encodeIPSPatch' for the
-- IPS32 rationale.
encodeTruncationMarker :: OffsetWidth -> FileSize -> Builder
encodeTruncationMarker offsetWidth (FileSize truncatedSizeBytes) =
  encodeOffset offsetWidth truncatedSizeBytes

-- | Shift any record sitting at the variant's EOF-collision offset
-- back by one byte, prepending the source byte at the new offset.
-- The Archiveteam wiki recommends exactly this fix for the
-- @0x454F46@ collision; Flips' @libips.cpp@ implements it inline
-- for both standard IPS and a hypothetical IPS32 generalisation.
-- See @docs/ips/spec.md § "The EOF ambiguity"@ for context.
--
-- A no-op when the record is not at the sentinel offset, when the
-- sentinel is the very first byte of the source (no preceding
-- byte to prepend), or when the source is too short to contain
-- the preceding byte. Conversion paths that encode without a
-- source (the contract layer's source-less direct conversion)
-- detect the collision separately and refuse the conversion
-- outright; this function is the encode-time fix-up for the
-- with-source case.
avoidSentinel :: Int -> ByteString -> [EncodedHunk] -> [EncodedHunk]
avoidSentinel sentinelOffsetValue source = map shiftIfAtSentinel
  where
    sentinelOffset = Offset sentinelOffsetValue
    sourceLength   = ByteString.length source

    shiftIfAtSentinel record@(EncodedHunk hunkOffset hunkPayload)
      | hunkOffset == sentinelOffset
      , offsetToInt hunkOffset > 0
      , offsetToInt hunkOffset - 1 < sourceLength =
          let precedingByteIndex = offsetToInt hunkOffset - 1
              precedingByte      =
                ByteString.index source precedingByteIndex
              extendedPayload    =
                ByteString.cons precedingByte hunkPayload
          in EncodedHunk
               { encodedOffset  = displace hunkOffset (Delta (-1))
               , encodedPayload = extendedPayload
               }
      | otherwise = record

-- | Build the EBP-style JSON metadata blob from CLI-supplied
-- title / author / description fields. The four-key shape
-- (@patcher@, @title@, @author@, @description@) matches what
-- EBPatcher and every long-standing community tool emits. slap
-- fixes @patcher@ to @"slap"@ to identify itself as the source.
--
-- The encoding is a hand-rolled minimal JSON object — only the
-- two characters @"@ and @\\@ get escaped, and control bytes
-- below @0x20@ are emitted as @\\u00XX@ escapes. Pulling in
-- @aeson@ for what is effectively four string interpolations
-- would be wildly disproportionate.
buildEBPMetadataJSON :: String -> String -> String -> ByteString
buildEBPMetadataJSON title author description =
  TextEncoding.encodeUtf8 (Text.pack jsonText)
  where
    jsonText =
      "{\"patcher\":\"slap\",\"title\":\""
        ++ escapeJSONString title
        ++ "\",\"author\":\""
        ++ escapeJSONString author
        ++ "\",\"description\":\""
        ++ escapeJSONString description
        ++ "\"}"

    escapeJSONString [] = []
    escapeJSONString ('"'  : rest) = '\\' : '"'  : escapeJSONString rest
    escapeJSONString ('\\' : rest) = '\\' : '\\' : escapeJSONString rest
    escapeJSONString (currentChar : rest)
      | currentChar < ' ' =
          "\\u00"
            ++ padHex 2 (fromEnum currentChar)
            ++ escapeJSONString rest
      | otherwise =
          currentChar : escapeJSONString rest
