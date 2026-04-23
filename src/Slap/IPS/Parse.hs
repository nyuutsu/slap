-- IPS-family wire-format parser. See @docs/ips/spec.md@ for the
-- format and @docs/ips/proposal.md@ for slap's resolved design
-- decisions on truncation, EBP, and the variant ceiling check.
module Slap.IPS.Parse
  ( parseIPS
  , parseRecords
  ) where

import Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , IPSVariantSpec(..)
  , IPSRecord(..)
  , IPSPatch(..)
  , EBPMetadata(..)
  , EBPPatch(..)
  , ipsRecordOffset
  , recordPayloadLength
  , variantSpec
  , ipsVariantMaxRecordEnd
  , ipsMagicLength
  , offsetWidthByteCount
  )
import Slap.Binary (getWord24BE)
import Slap.Error (SlapError(..), FieldName(..), Parsed(..))
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
  , ActionIndex
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
-- Outer 'Either' is the error channel; inner 'Either' distinguishes
-- plain IPS from EBP based on what followed the trailer. Both
-- success shapes are equally valid: the parser sees a common record
-- body and only branches on the post-trailer bytes that decide
-- whether the patch was authored as plain IPS or EBP-wrapped.
--
-- The variant ('StandardIPS' vs 'IPS32') is decided once, by reading
-- the first 'ipsMagicLength' bytes against each variant's
-- 'ipsVariantMagic'. Everything downstream — offset width, EOF
-- marker bytes, ceiling — is a function of that single decision,
-- looked up via 'variantSpec'.
parseIPS :: PatchFileContents -> Either SlapError (Parsed (Either IPSPatch EBPPatch))
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
      in case runGet (parseRecordsAndCaptureTrailer variant) bodyAfterMagic of
           Left getErrorMessage ->
             Left (ParseError LabelIPS getErrorMessage)
           Right (recordList, trailingBytes) ->
             case validateRecordList variant recordList of
               Left validationFailure -> Left validationFailure
               Right ()               ->
                 fmap (\resultPayload -> Parsed resultPayload [])
                      (buildResultPatch variant
                                        (Vector.fromList recordList)
                                        trailingBytes)

----------------------------------------------------------------------------
-- parseRecords — Get-monad inner record loop
----------------------------------------------------------------------------

-- | Walk the post-magic record stream record by record, peeking at
-- every iteration for the variant's EOF marker. On a marker match,
-- consume the marker and return the accumulated records (in wire
-- order). On no match, decode one record and recurse.
--
-- The peek is genuinely non-destructive: 'lookAhead' from
-- 'Slap.Get' runs the sub-parser and rewinds the cursor regardless
-- of result, so the subsequent record-decode path consumes the same
-- bytes the peek inspected. The combinator exists for exactly this
-- pattern; doing the same with bare 'getPosition' / 'setPosition'
-- would reinvent it inline and is forbidden by the prep commit's
-- design.
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
parseRecords :: IPSVariant -> Get [IPSRecord]
parseRecords variant = recordLoop []
  where
    spec               = variantSpec variant
    eofMarkerBytes     = ipsVariantEOFMarker spec
    eofMarkerLength    = byteLength eofMarkerBytes
    offsetWidth        = ipsVariantOffsetWidth spec

    -- | Decode one record's offset field. The width is variant-
    -- dependent — 24-bit for 'StandardIPS', 32-bit for 'IPS32' —
    -- and 'Slap.IPS.Types.offsetWidthByteCount' is the only place
    -- in the codebase that knows the 3/4 mapping. We pattern-match
    -- on the 'OffsetWidth' value, not on the byte count, so the raw
    -- integers never appear in this loop.
    readRecordOffset :: Get Offset
    readRecordOffset = case offsetWidth of
      Offset24 -> Offset . fromIntegral <$> word24BE
      Offset32 -> Offset . fromIntegral <$> word32BE

    -- | Read the 2-byte big-endian size field and dispatch on its
    -- value. A non-zero size is the literal payload length that
    -- follows; zero is the sentinel marking the record as RLE,
    -- with the 2-byte run length and 1-byte fill that follow it.
    decodeOneRecord :: Offset -> Get IPSRecord
    decodeOneRecord recordOffset = do
      rawSizeField <- word16BE
      let sizeFieldValue = fromIntegral rawSizeField :: Int
      if sizeFieldValue == 0
        then do
          rawRunLength <- word16BE
          fillByte     <- getByte
          pure IPSRecordRLE
            { ipsRleOffset = recordOffset
            , ipsRleCount  = Length (fromIntegral rawRunLength)
            , ipsRleFill   = fillByte
            }
        else do
          payloadBytes <- getBytes (Length sizeFieldValue)
          pure IPSRecordCopy
            { ipsCopyOffset  = recordOffset
            , ipsCopyPayload = payloadBytes
            }

    recordLoop :: [IPSRecord] -> Get [IPSRecord]
    recordLoop accumulatedReversed = do
      peekedBytes <- lookAhead (getBytes eofMarkerLength)
      if peekedBytes == eofMarkerBytes
        then do
          skip eofMarkerLength
          pure (reverse accumulatedReversed)
        else do
          recordOffset  <- readRecordOffset
          decodedRecord <- decodeOneRecord recordOffset
          recordLoop (decodedRecord : accumulatedReversed)

-- | Run 'parseRecords' for the given variant, then consume whatever
-- bytes remain after the EOF marker as the post-trailer slice. The
-- returned trailer is the raw bytes the trailer-disambiguation pass
-- will inspect to decide between plain IPS / truncation marker /
-- EBP metadata / SlapError. Captured as a 'ByteString' rather than
-- left in the 'Get' monad's residual buffer because the
-- disambiguation lives outside 'Get' (it produces structured
-- 'SlapError' values that 'Get' has no way to surface).
parseRecordsAndCaptureTrailer :: IPSVariant -> Get ([IPSRecord], ByteString)
parseRecordsAndCaptureTrailer variant = do
  recordList      <- parseRecords variant
  remainingLength <- remaining
  trailingBytes   <- getBytes remainingLength
  pure (recordList, trailingBytes)

----------------------------------------------------------------------------
-- Pure validation pass — variant ceiling and RLE-zero rejection
----------------------------------------------------------------------------

-- | Walk the parsed record list, rejecting any record that would
-- overflow the variant's spec ceiling and any RLE record whose run
-- length is zero. Both checks fire per-record; both fail with a
-- structured 'SlapError' carrying the offending record's
-- 'ActionIndex' so the user knows which record they need to look
-- at.
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
-- The RLE-zero check rejects @IPSRecordRLE { ipsRleCount = Length
-- 0 }@. The spec is silent on RLE records with run length zero;
-- slap's strict discipline rejects them rather than silently
-- treating them as no-ops, on the principle that a malformed-field
-- record is a parse error, not a runtime curiosity for 'Apply' to
-- inherit.
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
        Right () -> case checkRLERunLength currentIndex currentRecord of
          Left rleFailure -> Left rleFailure
          Right ()        -> walkAt (nextAction currentIndex) rest

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

    checkRLERunLength :: ActionIndex -> IPSRecord -> Either SlapError ()
    checkRLERunLength currentIndex IPSRecordRLE { ipsRleCount = Length 0 } =
      Left (MalformedRecordField LabelIPS currentIndex FieldRLERunLength)
    checkRLERunLength _ _ = Right ()

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

-- | Build the final 'IPSPatch' or 'EBPPatch' from the validated
-- record vector and the captured post-trailer bytes.
--
-- 'StandardIPS' post-@"EOF"@ has four accepted shapes (Q2
-- resolution from @docs/ips/proposal.md@):
--
--   1. empty trailer → plain 'IPSPatch' with no truncation. The
--      canonical case from the original SNESTool spec.
--
--   2. exactly 'ipsTruncationMarkerLength' bytes → plain 'IPSPatch'
--      with a Flips-style truncation marker. Decoded as a 24-bit
--      big-endian unsigned value and stored as
--      'ipsTruncatedTargetSize'.
--
--   3. trailer beginning with 'ebpJSONOpeningByte' (@'{'@) →
--      EBP-wrapped IPS. The trailing bytes are captured verbatim as
--      'EBPMetadata' and the underlying 'IPSPatch' is wrapped in an
--      'EBPPatch'.
--
--   4. anything else (1- or 2-byte trailer, 4+-byte non-JSON
--      trailer, etc.) → 'SlapError'. The strict thing to do with
--      garbage trailers is reject them, not guess their intent.
--
-- 'IPS32' post-@"EEOF"@ accepts only the empty trailer (Q1
-- resolution). Any trailing bytes at all are 'SlapError'. The
-- harder no after @"EEOF"@ versus @"EOF"@ reflects the variants'
-- ecosystem histories: 'StandardIPS' has accumulated three
-- well-attested post-trailer shapes through Flips, EBP, and the
-- original spec; 'IPS32' has none. There is no shape to recognise
-- for 'IPS32' trailing bytes, so the strict thing is total
-- rejection.
buildResultPatch :: IPSVariant
                 -> Vector.Vector IPSRecord
                 -> ByteString
                 -> Either SlapError (Either IPSPatch EBPPatch)
buildResultPatch StandardIPS recordVector trailingBytes
  | ByteString.null trailingBytes =
      Right (Left IPSPatch
        { ipsVariant             = StandardIPS
        , ipsRecords             = recordVector
        , ipsTruncatedTargetSize = Nothing
        })
  | ByteString.length trailingBytes == unLength ipsTruncationMarkerLength =
      let truncatedTargetSize =
            FileSize (fromIntegral (getWord24BE 0 trailingBytes))
      in Right (Left IPSPatch
           { ipsVariant             = StandardIPS
           , ipsRecords             = recordVector
           , ipsTruncatedTargetSize = Just truncatedTargetSize
           })
  | ByteString.head trailingBytes == ebpJSONOpeningByte =
      let basePatch = IPSPatch
            { ipsVariant             = StandardIPS
            , ipsRecords             = recordVector
            , ipsTruncatedTargetSize = Nothing
            }
      in Right (Right EBPPatch
           { ebpBasePatch = basePatch
           , ebpMetadata  = EBPMetadata trailingBytes
           })
  | otherwise =
      Left (UnrecognizedTrailer LabelIPS
              (TrailerMarker (ipsVariantEOFMarker (variantSpec StandardIPS)))
              (ActualLength (Length (ByteString.length trailingBytes))))
buildResultPatch IPS32 recordVector trailingBytes
  | ByteString.null trailingBytes =
      Right (Left IPSPatch
        { ipsVariant             = IPS32
        , ipsRecords             = recordVector
        , ipsTruncatedTargetSize = Nothing
        })
  | otherwise =
      Left (UnrecognizedTrailer LabelIPS
              (TrailerMarker (ipsVariantEOFMarker (variantSpec IPS32)))
              (ActualLength (Length (ByteString.length trailingBytes))))
