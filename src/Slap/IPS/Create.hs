{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for the IPS family. This module owns the
-- byte-laying side of patch creation: given a record list and a
-- variant, it produces the patch bytes. The decision side (which
-- records to emit, what shape they should take, how to merge or
-- split runs) lives in 'Slap.IPS.Optimize'.
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
-- There is no @createIPS@ / @createIPS32@ / @createEBP@ porcelain
-- — neither here nor in "Slap.Create". End-to-end creation for the
-- IPS family is a coordination-layer concern: the
-- 'Slap.Convert.createPatch' pipeline threads a 'PatchContents'
-- through 'Slap.Convert.buildContents' and 'Slap.Convert.encodeDirect',
-- which is where the live creation path runs. The direct family
-- shares that pipeline, so a per-format typed front door would have
-- nothing format-level to wrap; "Slap.Create" reserves its porcelain
-- for the differential family, which has no shared pipeline.
module Slap.IPS.Create
  ( -- * Wire encoder (used by 'Slap.Convert')
    encodeIPSPatch
  , encodeEBPPatch
    -- * Sentinel-collision resolution (used by 'Slap.Convert')
  , resolveSentinelCollisions
    -- * Wire-emission helpers
  , encodeIPSRecord
  , encodeOffset
  , encodeTruncationMarker
  , buildEBPMetadataJSON
    -- * Optimizer pass-through (re-exported for callers and tests)
  , optimalIPSRecords
  ) where

import Slap.Binary (putWord16BE)
import Slap.Status (SlapError(..))
import Slap.FileContents
  ( PatchFileContents(..)
  , InputFileContents(..)
  , unPatchFileContents
  )
import Slap.FormatLabel (FormatLabel(..))
import Slap.IPS.Optimize (optimalIPSRecords)
import Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , IPSVariantSpec(..)
  , EBPMetadata(..)
  , variantSpec
  )
import Slap.Text (encodedTextContent)
import Slap.Measure
  ( FileSize(..)
  , Delta(..)
  , Cursor(..)
  , Hunk(..)
  , SplitHunk
  , splitOffset
  , splitPayload
  , SentinelOffset(..)
  , offsetToInt
  )
import Slap.Narrow
  ( EncodedHunk
  , encodedOffset
  , encodedPayload
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
import Data.Maybe (listToMaybe)
import Data.Word (Word8)
import qualified Data.Aeson as Aeson
import Data.Aeson ((.=))
import qualified Data.Aeson.Encoding as AesonEncoding

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
-- The @optionalTruncation@ argument is honored only for the
-- 'StandardIPS' variant. For 'IPS32', the truncation marker has
-- no defined wire shape (no community implementation supports
-- it), so this encoder drops any truncation passed for IPS32.
-- The contract layer in 'Slap.Convert.canConvert' refuses any
-- conversion whose source patch carries a truncation marker and
-- whose target is 'IPS32' or 'EBP' — so the drop branch is
-- defensive, not operational: it will not fire under well-formed
-- callers. 'Slap.Convert.buildContents' on the create path
-- populates 'contentsTruncation' for IPS32/EBP only so
-- 'rejectTruncation' can surface the shrinkage refusal to the
-- user rather than silently produce a non-truncating patch.
--
-- This function does not validate the records and does not resolve
-- sentinel collisions: it assumes each record's offset and length
-- are already within the variant's wire-format range, and that any
-- record sitting on the variant's trailer sentinel has already been
-- shifted or rejected by 'resolveSentinelCollisions'. The optimizer
-- guarantees the range precondition, and the
-- convert-path pipeline in 'Slap.Convert.encodeDirect' runs
-- @splitHunks@, 'resolveSentinelCollisions', and 'narrowHunks'
-- before calling here.
encodeIPSPatch
  :: IPSVariant
  -> [EncodedHunk]
  -> Maybe FileSize
  -> PatchFileContents
encodeIPSPatch variant records optionalTruncation =
  PatchFileContents
    (LazyByteString.toStrict (toLazyByteString patchBuilder))
  where
    spec        = variantSpec variant
    offsetWidth = ipsVariantOffsetWidth spec

    truncationBuilder = case variant of
      StandardIPS ->
        maybe mempty (encodeTruncationMarker offsetWidth) optionalTruncation
      IPS32 -> mempty

    patchBuilder =
      byteString (ipsVariantMagic spec)
      <> foldMap (encodeIPSRecord offsetWidth) records
      <> byteString (ipsVariantEOFMarker spec)
      <> truncationBuilder

-- | Encode a record list as an EBP patch (a 'StandardIPS' patch
-- with a trailing JSON metadata blob). EBP has no IPS32 analogue,
-- so the variant is fixed.
--
-- The truncation marker is intentionally not supported here. No
-- known EBP reference implementation emits truncation-then-JSON,
-- and 'Slap.IPS.Parse' only accepts EBP trailers that begin with
-- the JSON opening byte @{@. Emitting a truncation marker before
-- the JSON would produce bytes neither this parser nor any
-- third-party EBP parser would round-trip cleanly. The contract
-- layer in 'Slap.Convert.canConvert' refuses conversions that
-- would land truncation here, so the absence of a truncation
-- parameter is enforced upstream rather than silently dropped at
-- this call site.
encodeEBPPatch
  :: [EncodedHunk]
  -> EBPMetadata
  -> PatchFileContents
encodeEBPPatch records metadata =
  let baseStandardIPSBytes =
        unPatchFileContents
          (encodeIPSPatch StandardIPS records Nothing)
      metadataBytes = buildEBPMetadataJSON metadata
  in PatchFileContents (baseStandardIPSBytes <> metadataBytes)

----------------------------------------------------------------------------
-- Wire-emission helpers
----------------------------------------------------------------------------

-- | Encode a single 'EncodedHunk' as one IPS record.
-- The constructor choice (RLE vs. literal) is made here, by the same heuristic the DP optimizer uses internally:
-- a payload of length ≥ 4 whose every byte is identical is emitted as an RLE record
-- (8 bytes for 'StandardIPS', 9 bytes for 'IPS32', regardless of run length);
-- everything else is emitted as a literal copy record.
--
-- At length 3 an RLE record ties a copy record on bytes, so copy wins;
-- only for runs of length ≥ 4 is RLE strictly cheaper.
-- We emit RLE only when it strictly saves bytes, so the length-3 tie resolves to copy,
-- in step with the DP's break-even (@rleBreakEvenRunLength@ in 'Slap.IPS.Optimize').
encodeIPSRecord :: OffsetWidth -> EncodedHunk -> Builder
encodeIPSRecord offsetWidth ehunk =
  encodeOffset offsetWidth (offsetToInt recordOffset)
  <> if shouldEncodeAsRLE recordPayload
       then runLengthEncodedBody
       else literalCopyBody
  where
    recordOffset  = encodedOffset ehunk
    recordPayload = encodedPayload ehunk
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
-- See 'encodeIPSRecord' for the cost analysis.
shouldEncodeAsRLE :: ByteString -> Bool
shouldEncodeAsRLE payload =
  ByteString.length payload >= 4
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

-- | Encode a post-EOF truncation marker: a single big-endian
-- offset value, in the same width as the variant's record offsets.
-- Only emitted for 'StandardIPS'; see 'encodeIPSPatch' for the
-- IPS32 rationale. Assumes the size fits the width — the create
-- path guarantees it via
-- 'Slap.IPS.Types.ipsRejectIncompatibleSizeChange', and a parsed
-- marker fits, having been read from this same
-- field.
encodeTruncationMarker :: OffsetWidth -> FileSize -> Builder
encodeTruncationMarker offsetWidth (FileSize truncatedSizeBytes) =
  encodeOffset offsetWidth truncatedSizeBytes

-- | Resolve every record that sits on the variant's trailer
-- sentinel. Two outcomes per record:
--
-- * "Fixable": the record's offset equals the sentinel and the output
--   byte at @sentinel - 1@ is known. The record is rewritten to begin
--   one byte earlier with that byte prepended to its payload — the
--   same shift-and-prepend trick the Archiveteam wiki recommends for
--   IPS's @0x454F46@ collision and that Flips' @libips.cpp@ implements
--   inline.
--
-- * "Unfixable": the record's offset equals the sentinel but the
--   output byte at @sentinel - 1@ cannot be determined — the sentinel
--   sits at offset @0@ so there is no preceding position, or the
--   position is unchanged (no record covers it) and there is no
--   source byte to read it from (source-less direct conversion, or a
--   source shorter than @sentinel@). The whole call returns
--   'Left' 'SentinelCollisionUnfixable' with the format label and
--   the colliding offset, and the conversion aborts rather than
--   emitting bytes a parser could not faithfully round-trip.
--
-- The prepended byte is the byte the output is meant to hold at
-- @sentinel - 1@, /not/ the source byte there. The two agree only
-- when that position is unchanged; when a record boundary falls on
-- the sentinel mid-diff — a @0xFFFF@ split boundary, or a partition
-- the optimizer chose — the byte at @sentinel - 1@ is the tail of the
-- preceding record's payload, a changed target byte. Since IPS
-- applies in wire order and the shifted record is written last, its
-- prepended byte lands over that tail; reading the /source/ byte
-- there would overwrite the correct target byte with the wrong one,
-- and no IPS checksum would catch it. So the byte is read from
-- whatever record covers @sentinel - 1@ (the last one, in wire
-- order), and only from the source when no record does.
--
-- Records whose offset is not the sentinel pass through unchanged —
-- the explicit "not a collision" branch, not a silent catch-all.
--
-- Both 'Slap.Convert.createPatch' (with real source bytes) and
-- 'Slap.Convert.convertDirect' (with an empty 'InputFileContents')
-- call through this function. The caller decides whether to invoke
-- sentinel resolution at all based on whether the format has a
-- sentinel (IPS, IPS32, EBP do; nothing else does).
--
-- The function operates on already-split records ('SplitHunk') and
-- unwraps them to raw 'Hunk's on output. The byte-prepend on a fixable
-- collision can push a record's payload one byte past the original
-- 'splitHunks' cap, so the proof is dropped: the convert pipeline
-- runs 'splitHunks' a second time after this function returns,
-- restoring the typed bound and catching the case where a
-- @0xFFFF@-byte payload at the sentinel offset would otherwise overflow
-- IPS's 16-bit length field on the wire.
resolveSentinelCollisions
  :: FormatLabel
  -> SentinelOffset
  -> InputFileContents
  -> [SplitHunk]
  -> Either SlapError [Hunk]
resolveSentinelCollisions label sentinel (InputFileContents source) records =
  traverse resolveOne records
  where
    SentinelOffset sentinelOffset = sentinel
    sentinelPosition              = offsetToInt sentinelOffset
    precedingPosition             = sentinelPosition - 1
    sourceLength                  = ByteString.length source

    -- The byte the output is meant to hold at @sentinel - 1@: the one
    -- the shifted record must prepend. Computed once and shared, and
    -- forced only when a record actually collides. Whatever record
    -- covers the position writes it (the last, in wire order); failing
    -- that the position is unchanged and the source supplies it; and
    -- if neither can, the collision is unfixable.
    outputByteBeforeSentinel :: Maybe Word8
    outputByteBeforeSentinel
      | precedingPosition < 0 = Nothing
      | otherwise = case lastRecordByteAt precedingPosition of
          Just covered -> Just covered
          Nothing
            | precedingPosition < sourceLength ->
                Just (ByteString.index source precedingPosition)
            | otherwise -> Nothing

    -- The byte the last record (in wire order) covering @position@
    -- writes there, if any record covers it.
    lastRecordByteAt :: Int -> Maybe Word8
    lastRecordByteAt position = listToMaybe
      [ ByteString.index payload (position - recordStart)
      | record <- reverse records
      , let recordStart = offsetToInt (splitOffset record)
            payload     = splitPayload record
      , recordStart <= position
      , position < recordStart + ByteString.length payload
      ]

    resolveOne record
      | offsetToInt recordOffset /= sentinelPosition =
          Right (Hunk recordOffset recordPayload)
      | Just prependByte <- outputByteBeforeSentinel =
          Right (Hunk (displace recordOffset (Delta (-1)))
                      (ByteString.cons prependByte recordPayload))
      | otherwise =
          Left (SentinelCollisionUnfixable label sentinel)
      where
        recordOffset  = splitOffset record
        recordPayload = splitPayload record

-- | Build the EBP-style JSON metadata blob from a structured
-- 'EBPMetadata'. The four-key shape (@patcher@, @title@, @author@,
-- @description@) matches what EBPatcher and every long-standing
-- community tool emits. Each field is emitted only when 'Just';
-- absent ('Nothing') fields simply do not appear in the JSON
-- output.
--
-- EBP metadata is JSON, so the emitter goes through @aeson@: the
-- field values arrive as 'EncodedText' (each tagged with whichever
-- encoding it came in under — CLI-locale or JSON-extracted UTF-8),
-- and the 'Text' content lands in the JSON string slots verbatim.
-- @aeson@'s 'Aeson.pairs' builds an 'Encoding' in declared order, so
-- the four-key sequence reaches the wire as
-- @{patcher,title,author,description}@ when all four are present.
buildEBPMetadataJSON :: EBPMetadata -> ByteString
buildEBPMetadataJSON metadata =
  LazyByteString.toStrict (AesonEncoding.encodingToLazyByteString jsonEncoding)
  where
    jsonEncoding = Aeson.pairs
      (  optionalField "patcher"     (ebpMetadataPatcher     metadata)
      <> optionalField "title"       (ebpMetadataTitle       metadata)
      <> optionalField "author"      (ebpMetadataAuthor      metadata)
      <> optionalField "description" (ebpMetadataDescription metadata)
      )
    optionalField _       Nothing      = mempty
    optionalField keyName (Just value) = keyName .= encodedTextContent value
