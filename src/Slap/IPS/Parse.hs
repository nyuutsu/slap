-- IPS-family wire-format parser. See @docs/ips/spec.md@ for the
-- format and @docs/ips/proposal.md@ for slap's resolved design
-- decisions on truncation, EBP, and the variant ceiling check.
module Slap.IPS.Parse
  ( parseIPS
  ) where

import Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , IPSVariantSpec(..)
  , IPSRecord(..)
  , IPSPatch(..)
  , EBPMetadata(..)
  , EBPPatch(..)
  , IPSParseResult(..)
  , ipsRecordOffset
  , recordPayloadLength
  , variantSpec
  , ipsVariantMaxRecordEnd
  , ipsMagicLength
  , ipsRecordHeaderLength
  , ipsRleCountFieldLength
  , ipsRleFillByteLength
  , offsetWidthByteCount
  )
import Slap.Binary (getWord24BE)
import Slap.Error (SlapError(..), SlapWarning(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get
  ( Get
  , runGet
  , getByte
  , getBytes
  , skip
  , word16BE
  , word24BE
  , word32BE
  , lookAhead
  , remaining
  )
import Slap.Measure
  ( Offset(..)
  , Length(..)
  , FileSize(..)
  , ActionIndex(..)
  , Cursor(..)
  , byteLength
  , firstAction
  , nextAction
  , RequiredLength(..)
  , ActualLength(..)
  , ActualMagic(..)
  , ActualOffset(..)
  , MaxOffset(..)
  , TrailerMarker(..)
  )

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word8)

----------------------------------------------------------------------------
-- parseIPS — top-level dispatch
----------------------------------------------------------------------------

-- | Parse a patch from any IPS-family wire format.
--
-- The success payload is an 'IPSParseResult' — a three-way sum that
-- names the shapes the parser actually produces. 'IPSParseCleanIPS'
-- and 'IPSParseCleanEBP' cover the two EOF-terminated dispositions;
-- 'IPSParseTruncated' covers the case where the input ran out before
-- a matching EOF marker was found, and is accompanied in the
-- 'Parsed' warnings channel by a 'NoEOFMarker' warning. The error
-- channel is reserved for inputs that violate the wire format in
-- ways no shape covers — bad magic, variant-ceiling overrun,
-- zero-count RLE, unrecognised trailing bytes after a valid
-- @"EOF"@\/@"EEOF"@ marker, and so on.
--
-- The variant ('StandardIPS' vs 'IPS32') is decided once, by reading
-- the first 'ipsMagicLength' bytes against each variant's
-- 'ipsVariantMagic'. Everything downstream — offset width, EOF
-- marker bytes, ceiling — is a function of that single decision,
-- looked up via 'variantSpec'.
parseIPS :: PatchFileContents -> Either SlapError (Parsed IPSParseResult)
parseIPS (PatchFileContents inputBytes)
  | ByteString.length inputBytes < unLength ipsMagicLength =
      Left (InputTooShort LabelIPS
              (RequiredLength ipsMagicLength)
              (ActualLength (Length (ByteString.length inputBytes))))
  | leadingMagicBytes == ipsVariantMagic (variantSpec StandardIPS) =
      runVariantParser StandardIPS
  | leadingMagicBytes == ipsVariantMagic (variantSpec IPS32) =
      runVariantParser IPS32
  | otherwise =
      Left (BadMagic LabelIPS (ActualMagic leadingMagicBytes))
  where
    leadingMagicBytes =
      ByteString.take (unLength ipsMagicLength) inputBytes

    runVariantParser variant =
      let bodyAfterMagic =
            ByteString.drop (unLength ipsMagicLength) inputBytes
      in case runGet (parseIPSBody variant) bodyAfterMagic of
           Left getErrorMessage ->
             Left (ParseError LabelIPS getErrorMessage)
           Right bodyShape ->
             finaliseBodyShape variant bodyShape

----------------------------------------------------------------------------
-- Body-level shape — clean EOF vs truncated
----------------------------------------------------------------------------

-- | What the record-stream walk produced. 'IPSBodyClean' records
-- were followed by a matching EOF marker for the active variant;
-- 'IPSBodyTruncated' records were all the parser could decode
-- before running out of input. Both shapes carry the list of
-- walker-time warnings accumulated during the record walk, in
-- wire order — today only 'ZeroCountRLERecord' is emitted here,
-- but the channel generalises cleanly to future per-record
-- observations that the parser wants to surface without failing.
-- This shape is strictly private: 'parseIPS' lifts it into the
-- public 'IPSParseResult' after the shared validation pass.
data IPSBodyShape
  = IPSBodyClean     ![IPSRecord] !ByteString ![SlapWarning]
  | IPSBodyTruncated ![IPSRecord] ![SlapWarning]

-- | Apply the post-walk validation to the records and lift the
-- body shape into the public 'IPSParseResult'. Validation runs
-- uniformly on both body shapes: a truncated body whose partial
-- records violate the variant ceiling is still a structural parse
-- failure, not a warning.
--
-- The returned 'Parsed' value concatenates structural warnings in
-- a fixed order so downstream callers and tests can rely on it:
--
--   1. Walker-time warnings (zero-count RLE), in wire order.
--   2. Pair-wise overlap warnings from 'detectOverlappingRecords'.
--   3. The first unsorted-record warning from 'detectFirstUnsorted'.
--   4. For 'IPSBodyClean' 'IPS32' bodies only, a trailing-bytes
--      warning emitted by 'assembleCleanResult'.
--
-- 'IPSBodyTruncated' additionally carries the long-standing
-- 'NoEOFMarker' warning at the head of the list; the rest of the
-- ordering is the same.
finaliseBodyShape :: IPSVariant
                  -> IPSBodyShape
                  -> Either SlapError (Parsed IPSParseResult)
finaliseBodyShape variant bodyShape = case bodyShape of
  IPSBodyClean recordList trailingBytes walkerWarnings -> do
    () <- validateRecordList variant recordList
    let recordVector    = Vector.fromList recordList
        variantLabel    = labelForIPSVariant variant
        overlapWarnings = detectOverlappingRecords variantLabel recordVector
        unsortedWarnings = detectFirstUnsortedRecord variantLabel recordVector
    (resultPayload, trailerWarnings) <-
      assembleCleanResult variant recordVector trailingBytes
    pure (Parsed resultPayload
                 (walkerWarnings
                  ++ overlapWarnings
                  ++ unsortedWarnings
                  ++ trailerWarnings))
  IPSBodyTruncated recordList walkerWarnings -> do
    () <- validateRecordList variant recordList
    let recordVector    = Vector.fromList recordList
        variantLabel    = labelForIPSVariant variant
        overlapWarnings = detectOverlappingRecords variantLabel recordVector
        unsortedWarnings = detectFirstUnsortedRecord variantLabel recordVector
    pure (Parsed (IPSParseTruncated variant recordVector)
                 (NoEOFMarker LabelIPS
                  : walkerWarnings
                  ++ overlapWarnings
                  ++ unsortedWarnings))

-- | Label used when surfacing a structural warning keyed to an IPS
-- variant. The two 'IPSVariant' cases map to the two format labels
-- the CLI and renderers already use: 'StandardIPS' surfaces as
-- @IPS@, 'IPS32' surfaces as @IPS32@. EBP patches are not a
-- separate case because their body is structurally a 'StandardIPS'
-- record stream; the EBP wrapper is decided by the post-@"EOF"@
-- trailer bytes, after the record walk has already labelled its
-- warnings.
labelForIPSVariant :: IPSVariant -> FormatLabel
labelForIPSVariant StandardIPS = LabelIPS
labelForIPSVariant IPS32       = LabelIPS32

----------------------------------------------------------------------------
-- parseIPSBody — Get-monad inner record loop
----------------------------------------------------------------------------

-- | Walk the post-magic record stream record by record, peeking at
-- every iteration for the variant's EOF marker.
--
-- Three things can happen on each iteration:
--
--   * The bytes at the cursor are the variant's EOF marker. We
--     consume the marker, capture the rest of the input as the
--     post-trailer slice, and return 'IPSBodyClean'. The trailer
--     disambiguation (plain / truncated / EBP / reject) happens
--     outside this loop in 'assembleCleanResult'.
--
--   * The bytes at the cursor are not the EOF marker and we have
--     enough remaining input to read another complete record. We
--     decode the record and recurse.
--
--   * The remaining input is too short to hold either an EOF
--     marker or a complete next record. We return 'IPSBodyTruncated'
--     with the records decoded so far; 'parseIPS' will surface this
--     as an 'IPSParseTruncated' with a 'NoEOFMarker' warning.
--
-- The peek is genuinely non-destructive: 'lookAhead' from
-- 'Slap.Get' runs the sub-parser and rewinds the cursor regardless
-- of result, so the subsequent record-decode path consumes the same
-- bytes the peek inspected.
--
-- Why peek at all: the IPS "EOF" sentinel is a famous footgun.
-- The bytes @0x45 0x4F 0x46@ are simultaneously the ASCII "EOF"
-- trailer and a perfectly valid 24-bit big-endian offset value
-- (4,542,278). A parser that consumes the next three bytes
-- unconditionally cannot tell whether it just read the next
-- record's offset field or the stream-closing trailer. IPS32 has
-- the same problem at @0x45454F46@ / @"EEOF"@. Peek-then-branch is
-- the only honest disambiguation.
--
-- Wire order is preserved exactly: records appear in the returned
-- list in the order they were laid out on the wire. Parse does not
-- sort, dedupe, detect overlap, or otherwise normalise — overlap,
-- sort-order, and duplicate-offset handling are Apply's problem,
-- not Parse's.
--
-- The 'remaining'-first guards on each step mean we never start a
-- record we cannot finish: the truncation boundary always falls
-- between whole records, so 'IPSBodyTruncated' carries complete
-- decoded records and nothing half-read. A half-consumed header
-- followed by a short payload reports as truncated before the
-- first byte of that record is touched.
parseIPSBody :: IPSVariant -> Get IPSBodyShape
parseIPSBody variant = bodyLoop [] [] firstAction
  where
    spec               = variantSpec variant
    eofMarkerBytes     = ipsVariantEOFMarker spec
    eofMarkerLength    = byteLength eofMarkerBytes
    offsetWidth        = ipsVariantOffsetWidth spec
    recordHeaderLength = ipsRecordHeaderLength offsetWidth
    rleTailLength      = ipsRleCountFieldLength <> ipsRleFillByteLength
    variantLabel       = labelForIPSVariant variant

    readRecordOffset :: Get Offset
    readRecordOffset = case offsetWidth of
      Offset24 -> Offset . fromIntegral <$> word24BE
      Offset32 -> Offset . fromIntegral <$> word32BE

    truncatedFrom :: [IPSRecord] -> [SlapWarning] -> Get IPSBodyShape
    truncatedFrom accumulatedReversed warningsReversed =
      pure (IPSBodyTruncated (reverse accumulatedReversed)
                             (reverse warningsReversed))

    -- | @accumulatedReversed@ and @warningsReversed@ are the
    -- walker's two reversed accumulators; @currentIndex@ is the
    -- 'ActionIndex' that the next successfully-decoded record
    -- will be tagged with in wire order. The index advances
    -- exactly once per accepted record — a truncated tail leaves
    -- it unchanged, since no record was committed.
    bodyLoop :: [IPSRecord] -> [SlapWarning] -> ActionIndex -> Get IPSBodyShape
    bodyLoop accumulatedReversed warningsReversed currentIndex = do
      bytesLeft <- remaining
      if unLength bytesLeft < unLength eofMarkerLength
        then truncatedFrom accumulatedReversed warningsReversed
        else do
          peekedBytes <- lookAhead (getBytes eofMarkerLength)
          if peekedBytes == eofMarkerBytes
            then do
              skip eofMarkerLength
              trailerLength <- remaining
              trailingBytes <- getBytes trailerLength
              pure (IPSBodyClean (reverse accumulatedReversed)
                                 trailingBytes
                                 (reverse warningsReversed))
            else
              if unLength bytesLeft < unLength recordHeaderLength
                then truncatedFrom accumulatedReversed warningsReversed
                else decodeOneRecordOrTruncate accumulatedReversed
                                               warningsReversed
                                               currentIndex

    decodeOneRecordOrTruncate :: [IPSRecord]
                              -> [SlapWarning]
                              -> ActionIndex
                              -> Get IPSBodyShape
    decodeOneRecordOrTruncate accumulatedReversed warningsReversed currentIndex = do
      recordOffset       <- readRecordOffset
      rawSizeField       <- word16BE
      let declaredPayload = Length (fromIntegral rawSizeField)
      if unLength declaredPayload == 0
        then decodeRLEBody  accumulatedReversed warningsReversed currentIndex recordOffset
        else decodeCopyBody accumulatedReversed warningsReversed currentIndex recordOffset declaredPayload

    -- | Decode an RLE record. A zero-count run is accepted verbatim
    -- (stored as an 'IPSRecordRLE' with @ipsRleCount = Length 0@) and
    -- flagged with a 'ZeroCountRLERecord' warning keyed to the
    -- record's wire-order 'ActionIndex'. The ceiling check in
    -- 'validateRecordList' still runs against the final record list;
    -- a zero-count RLE whose offset is in range is a no-op, which is
    -- exactly what Apply will execute.
    decodeRLEBody :: [IPSRecord] -> [SlapWarning] -> ActionIndex -> Offset -> Get IPSBodyShape
    decodeRLEBody accumulatedReversed warningsReversed currentIndex recordOffset = do
      tailSpace <- remaining
      if unLength tailSpace < unLength rleTailLength
        then truncatedFrom accumulatedReversed warningsReversed
        else do
          rawRunLength <- word16BE
          fillByte     <- getByte
          let runLength   = Length (fromIntegral rawRunLength)
              newRecord   = IPSRecordRLE
                              { ipsRleOffset = recordOffset
                              , ipsRleCount  = runLength
                              , ipsRleFill   = fillByte
                              }
              newWarnings = if unLength runLength == 0
                              then ZeroCountRLERecord variantLabel currentIndex
                                     : warningsReversed
                              else warningsReversed
          bodyLoop (newRecord : accumulatedReversed)
                   newWarnings
                   (nextAction currentIndex)

    decodeCopyBody :: [IPSRecord] -> [SlapWarning] -> ActionIndex -> Offset -> Length -> Get IPSBodyShape
    decodeCopyBody accumulatedReversed warningsReversed currentIndex recordOffset declaredPayload = do
      payloadSpace <- remaining
      if unLength payloadSpace < unLength declaredPayload
        then truncatedFrom accumulatedReversed warningsReversed
        else do
          payloadBytes <- getBytes declaredPayload
          bodyLoop (IPSRecordCopy
                     { ipsCopyOffset  = recordOffset
                     , ipsCopyPayload = payloadBytes
                     } : accumulatedReversed)
                   warningsReversed
                   (nextAction currentIndex)

----------------------------------------------------------------------------
-- Pure validation pass — variant ceiling and RLE-zero rejection
----------------------------------------------------------------------------

-- | Walk the parsed record list, rejecting any record that would
-- overflow the variant's spec ceiling. The check fires per-record
-- and fails with a structured 'SlapError' carrying the offending
-- record's 'ActionIndex' so the user knows which record they need
-- to look at.
--
-- The ceiling check uses 'ipsVariantMaxRecordEnd' from
-- 'Slap.IPS.Types' directly, so the @maxAddressableOffset +
-- maxRecordPayload@ formula has exactly one home in the codebase.
-- The naive bound @offset ≤ maxAddressableOffset@ would falsely
-- reject conformant patches like fe6 whose final record sits at
-- offset @0xFFFFFF@ and writes a payload that ends at @0x1000000@:
-- the offset by itself is at the limit but the record's end
-- position has another @ipsMaxRecordPayload@ bytes of legal range
-- still ahead of it. The sum-of-two-limits ceiling makes that case
-- legal exactly because the offset and payload caps are
-- independent — any single record can saturate both at once.
--
-- Validation runs on both 'IPSBodyClean' and 'IPSBodyTruncated'
-- record lists: a truncated body whose partial records already
-- violate a structural rule is still a structural parse failure.
-- Only the EOF-marker absence is softened to a warning; wire-level
-- corruption inside the surviving records is not.
--
-- The walk uses a manual recursive helper rather than @do@-notation
-- in 'Either' so the action index is forced (via the bang pattern)
-- on every iteration. Without that, a 27-MB stadium2-scale patch
-- would build a multi-megabyte chain of @nextAction@ thunks that
-- would only get forced if validation eventually failed — and the
-- forcing would risk a stack overflow at exactly the moment the
-- user is trying to read an error message.
validateRecordList :: IPSVariant -> [IPSRecord] -> Either SlapError ()
validateRecordList variant = walkAt firstAction
  where
    maxRecordEnd = ipsVariantMaxRecordEnd variant

    walkAt :: ActionIndex -> [IPSRecord] -> Either SlapError ()
    walkAt _              []                       = Right ()
    walkAt !currentIndex (currentRecord : rest)   =
      case checkCeiling currentIndex currentRecord of
        Left ceilingFailure -> Left ceilingFailure
        Right ()            -> walkAt (nextAction currentIndex) rest

    checkCeiling :: ActionIndex -> IPSRecord -> Either SlapError ()
    checkCeiling currentIndex currentRecord =
      let recordEndOffset =
            advance (ipsRecordOffset currentRecord)
                    (recordPayloadLength currentRecord)
      in if unOffset recordEndOffset > unOffset maxRecordEnd
           then Left (RecordExceedsAddressableRange LabelIPS
                        currentIndex
                        (ActualOffset recordEndOffset)
                        (MaxOffset maxRecordEnd))
           else Right ()

----------------------------------------------------------------------------
-- Post-validation structural warnings — overlap and unsorted records
----------------------------------------------------------------------------

-- | Emit one 'OverlappingRecords' warning for every pair of records
-- whose write regions intersect. The comparison runs over the
-- wire-order finalized record vector, so the 'ActionIndex' values
-- name wire positions verbatim.
--
-- The algorithm is the naive @O(n^2)@ pairwise scan: for each
-- later-in-wire-order record, check every earlier record for
-- interval overlap. The pair order is @(earlier, later)@, matching
-- the semantics of the 'OverlappingRecords' warning: the later
-- record's writes clobber the earlier's. Overlap permissiveness is
-- by design in the IPS family (see @docs/ips/questions.md@); the
-- warning exists to flag the unusual structural property, not to
-- reject it.
--
-- @O(n^2)@ is accepted because IPS patches are small by construction
-- — the wire-level record count is capped well below the scale
-- where asymptotic concerns would bite, and any patch that did
-- somehow contain millions of records with mutual overlap is a
-- structural pathology the warning should be verbose about.
detectOverlappingRecords :: FormatLabel
                         -> Vector.Vector IPSRecord
                         -> [SlapWarning]
detectOverlappingRecords label recordVector =
  [ OverlappingRecords label (ActionIndex earlierIndex) (ActionIndex laterIndex)
  | laterIndex    <- [0 .. recordCount - 1]
  , earlierIndex  <- [0 .. laterIndex - 1]
  , writeRegionsOverlap (recordVector Vector.! earlierIndex)
                        (recordVector Vector.! laterIndex)
  ]
  where
    recordCount = Vector.length recordVector

    writeRegionsOverlap :: IPSRecord -> IPSRecord -> Bool
    writeRegionsOverlap leftRecord rightRecord =
      let leftStart  = unOffset (ipsRecordOffset leftRecord)
          leftEnd    = leftStart  + unLength (recordPayloadLength leftRecord)
          rightStart = unOffset (ipsRecordOffset rightRecord)
          rightEnd   = rightStart + unLength (recordPayloadLength rightRecord)
      in leftStart < rightEnd && rightStart < leftEnd

-- | Emit a single 'UnsortedRecords' warning naming the first
-- wire-order record whose offset is lower than the record that
-- preceded it. The IPS family applies records strictly in wire
-- order, so an unsorted record stream is well-defined behaviour;
-- it's just unusual enough in well-formed patches to be worth
-- flagging. Only the first such pair is reported — emitting one
-- warning per out-of-order record would drown every subsequent
-- structural warning in a fully reverse-sorted pathological patch.
detectFirstUnsortedRecord :: FormatLabel
                          -> Vector.Vector IPSRecord
                          -> [SlapWarning]
detectFirstUnsortedRecord label recordVector = scanFrom 1
  where
    recordCount = Vector.length recordVector

    scanFrom :: Int -> [SlapWarning]
    scanFrom candidateIndex
      | candidateIndex >= recordCount = []
      | laterOffset < earlierOffset   =
          [UnsortedRecords label (ActionIndex candidateIndex)]
      | otherwise                     = scanFrom (candidateIndex + 1)
      where
        earlierOffset = ipsRecordOffset (recordVector Vector.! (candidateIndex - 1))
        laterOffset   = ipsRecordOffset (recordVector Vector.! candidateIndex)

----------------------------------------------------------------------------
-- Trailer disambiguation
----------------------------------------------------------------------------

-- | The 0x7B byte (@'{'@). The leading byte of any well-formed EBP
-- JSON metadata blob, and the only thing the parser inspects to
-- decide the EBP-vs-garbage question. EBP shape recognition is
-- shape-only: the JSON is captured as opaque bytes and never
-- validated against the EBPatcher schema, the discriminator field,
-- or anything else below 'Slap.IPS.Describe'. Validating against a
-- specific patcher's conventions would couple Parse to one
-- implementation's metadata format and reject perfectly-valid
-- variants from other tools.
ebpJSONOpeningByte :: Word8
ebpJSONOpeningByte = 0x7B

-- | The exact byte length of a Flips-style truncation marker that
-- may follow a 'StandardIPS' @"EOF"@ trailer. The marker carries a
-- big-endian truncation offset whose width matches the variant's
-- own offset field — three bytes for 'StandardIPS'. Local to Parse
-- because the constant has no use elsewhere in the codebase, and
-- expressed as a function of 'variantSpec' so the 3 / Offset24
-- mapping has exactly one home.
ipsTruncationMarkerLength :: Length
ipsTruncationMarkerLength =
  offsetWidthByteCount (ipsVariantOffsetWidth (variantSpec StandardIPS))

-- | Build the final 'IPSParseResult' from the validated record
-- vector and the captured post-trailer bytes, along with any
-- trailer-disambiguation warnings the assembly emitted. Only
-- invoked for the 'IPSBodyClean' body shape — the truncated shape
-- has no trailer bytes to disambiguate, and is mapped directly to
-- 'IPSParseTruncated' by 'finaliseBodyShape'.
--
-- 'StandardIPS' post-@"EOF"@ has four accepted shapes (Q2
-- resolution from @docs/ips/proposal.md@):
--
--   1. empty trailer → 'IPSParseCleanIPS' with no truncation. The
--      canonical case from the original SNESTool spec.
--
--   2. exactly 'ipsTruncationMarkerLength' bytes → 'IPSParseCleanIPS'
--      with a Flips-style truncation marker. Decoded as a 24-bit
--      big-endian unsigned value and stored as
--      'ipsTruncatedTargetSize'.
--
--   3. trailer beginning with 'ebpJSONOpeningByte' (@'{'@) →
--      'IPSParseCleanEBP'. The trailing bytes are captured verbatim
--      as 'EBPMetadata' and the underlying 'IPSPatch' is wrapped in
--      an 'EBPPatch'.
--
--   4. anything else (1- or 2-byte trailer, 4+-byte non-JSON
--      trailer, etc.) → 'SlapError'. The strict thing to do with
--      garbage trailers is reject them, not guess their intent.
--
-- 'IPS32' post-@"EEOF"@ has two accepted shapes: an empty trailer,
-- and any non-empty trailer, which is dropped with an
-- 'IPS32TrailingBytes' warning. The lenient handling reflects the
-- variants' ecosystem histories — 'StandardIPS' has three
-- well-attested post-trailer shapes through Flips, EBP, and the
-- original spec, so a non-matching trailer there is most usefully
-- read as garbage; 'IPS32' has no defined post-trailer shape at
-- all, so there is no pattern to diverge from, and silently
-- keeping the records the user successfully parsed is kinder than
-- a hard rejection over trailing bytes nobody has semantics for.
assembleCleanResult :: IPSVariant
                    -> Vector.Vector IPSRecord
                    -> ByteString
                    -> Either SlapError (IPSParseResult, [SlapWarning])
assembleCleanResult StandardIPS recordVector trailingBytes
  | ByteString.null trailingBytes =
      Right (IPSParseCleanIPS IPSPatch
               { ipsVariant             = StandardIPS
               , ipsRecords             = recordVector
               , ipsTruncatedTargetSize = Nothing
               }
            , [])
  | ByteString.length trailingBytes == unLength ipsTruncationMarkerLength =
      let truncatedTargetSize =
            FileSize (fromIntegral (getWord24BE 0 trailingBytes))
      in Right (IPSParseCleanIPS IPSPatch
                  { ipsVariant             = StandardIPS
                  , ipsRecords             = recordVector
                  , ipsTruncatedTargetSize = Just truncatedTargetSize
                  }
               , [])
  | ByteString.head trailingBytes == ebpJSONOpeningByte =
      let basePatch = IPSPatch
            { ipsVariant             = StandardIPS
            , ipsRecords             = recordVector
            , ipsTruncatedTargetSize = Nothing
            }
      in Right (IPSParseCleanEBP EBPPatch
                  { ebpBasePatch = basePatch
                  , ebpMetadata  = EBPMetadata trailingBytes
                  }
               , [])
  | otherwise =
      Left (UnrecognizedTrailer LabelIPS
              (TrailerMarker (ipsVariantEOFMarker (variantSpec StandardIPS)))
              (ActualLength (Length (ByteString.length trailingBytes))))
assembleCleanResult IPS32 recordVector trailingBytes =
  let trailerLength  = ByteString.length trailingBytes
      ips32Patch     = IPSParseCleanIPS IPSPatch
                         { ipsVariant             = IPS32
                         , ipsRecords             = recordVector
                         , ipsTruncatedTargetSize = Nothing
                         }
      trailingWarnings
        | trailerLength == 0 = []
        | otherwise          =
            [IPS32TrailingBytes LabelIPS32 (Length trailerLength)]
  in Right (ips32Patch, trailingWarnings)
