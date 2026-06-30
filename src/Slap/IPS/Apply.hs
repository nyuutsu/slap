module Slap.IPS.Apply
  ( applyIPS
  ) where

import Slap.IPS.Types (IPSPatch(..), IPSRecord(..), IPSVariant(..),
                       ipsRecordOffset, recordPayloadLength,
                       MarkerDisposition(..), decideMarkerDisposition,
                       effectiveTargetSize)
import Slap.Binary (copyRegion, fillNewBuffer)
import Slap.Status (SlapError(..), ApplyError(..), SlapAdvisory(..),
                   Outcome(..), ClippedRecordCount(..), MarkerOvershootBytes(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(unActionIndex),
                     RequestedLength(..), RemainingLength(..),
                     DeclaredTargetSize(..), NaturalTargetSize(..),
                     Cursor(..), fitsWithin, offsetToFileSize, remainingFromOffset,
                     subtractLength, minLength, byteLength, byteFileSize,
                     firstAction, nextAction, streamEndIndex, plusOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (StateT, modify, runStateT)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Record placement classifier
----------------------------------------------------------------------------

-- | Where an IPS record's write span sits relative to the effective output size, classified by 'handleHonored' (under 'MarkerHonored').
data RecordPlacement
  = RecordFits
    -- ^ The record's write span ends at or before the effective
    -- size. The handler writes the full payload.
  | RecordPartiallyOvershoots !Length
    -- ^ The record starts in bounds but its write span extends past
    -- the effective size. The carried 'Length' is the in-bounds
    -- prefix the handler still writes; the remaining payload bytes
    -- are accounted as overshoot.
  | RecordEntirelyPastBoundary
    -- ^ The record's start position sits at or past the effective
    -- size. The handler writes nothing; the full payload length is
    -- accounted as overshoot.
  deriving (Show, Eq)

-- | Classify an IPS record's write span against the effective output size.
classifyRecordPlacement :: Offset -> Length -> FileSize -> RecordPlacement
classifyRecordPlacement writePosition writeLength effectiveSize
  | fitsWithin writePosition writeLength effectiveSize = RecordFits
  | offsetToFileSize writePosition >= effectiveSize    = RecordEntirelyPastBoundary
  | otherwise =
      RecordPartiallyOvershoots (remainingFromOffset writePosition effectiveSize)

----------------------------------------------------------------------------
-- applyIPS
----------------------------------------------------------------------------

-- | A 'Left' means the parsed patch is semantically malformed, not that its bytes were corrupted.
-- CRC and file-size verification is the caller's responsibility, done before calling; this function does not do it.
--
-- IPS has no output-length field, so the target size is derived.
-- The natural size is @max sourceSize maxRecordEnd@; the marker disposition (see 'MarkerDisposition') then turns natural into effective.
--
-- The buffer is allocated to the effective size, seeded by 'initialFill', and the record walk overlays each named write on that baseline.
-- Any byte no record names keeps its seeded value: the source byte at that offset, or zero past the source end.
--
-- Under 'MarkerHonored', 'handleHonored' clips and counts records that cross the effective size;
-- the other three dispositions go through 'handleStrict', a strict bounds check.
--
-- A defensive total guard returns 'NegativeTargetSize' on an effective size that cannot actually be negative:
-- 'NaturalTargetSize' is non-negative, and 'DeclaredTargetSize' comes from a non-negative wire value.
--
-- Apply does not re-check records against the variant's spec ceiling ('Slap.IPS.Types.ipsVariantMaxRecordEnd');
-- 'Slap.IPS.Parse' owns that check and rejects an over-ceiling record before the patch can reach here.
--
-- Error and warning labels come from the patch's 'ipsVariant', not the container it arrived in:
-- an EBP-wrapped patch surfaces as 'LabelIPS' once the wrapper is peeled.
applyIPS :: InputFileContents -> IPSPatch -> Either SlapError (Outcome OutputFileContents)
applyIPS (InputFileContents source) patch
  | unFileSize effectiveSize < 0 =
      Left (NegativeTargetSize patchLabel effectiveSize)
  | otherwise = unsafePerformIO $ do
      (result, (errorOutcome, clipOutcome)) <-
        fillNewBuffer effectiveSize $ \outputPointer ->
          runStateT (runApply outputPointer) Nothing
      pure $ case errorOutcome of
        Just applyErr -> Left (ApplyFailed patchLabel applyErr)
        Nothing       -> Right (Outcome
          (OutputFileContents result)
          (dispositionWarnings ++ clipWarnings clipOutcome))
  where
    patchLabel    = case ipsVariant patch of
                      StandardIPS -> LabelIPS
                      IPS32       -> LabelIPS32
    records       = ipsRecords patch
    sourceSize    = byteFileSize source
    maxRecordEnd  = Vector.foldl' extendMaxWith (FileSize 0) records
    naturalSize   = NaturalTargetSize (max sourceSize maxRecordEnd)
    declaredSize  = fmap DeclaredTargetSize (ipsTruncatedTargetSize patch)
    disposition   = decideMarkerDisposition declaredSize naturalSize
    effectiveSize = effectiveTargetSize disposition

    -- | Extend the running 'maxRecordEnd' upper bound to cover one more record's write region.
    -- A record that writes nothing leaves the bound unchanged:
    -- the zero-count RLE is the parse-accepted no-op (docs/ips/questions.md), and a no-op cannot grow the output.
    extendMaxWith :: FileSize -> IPSRecord -> FileSize
    extendMaxWith currentMax record
      | recordPayloadLength record == Length 0 = currentMax
      | otherwise =
          max currentMax (offsetToFileSize
                            (advance (ipsRecordOffset record)
                                     (recordPayloadLength record)))

    -- | Apply-time warnings derived from the disposition alone.
    dispositionWarnings :: [SlapAdvisory]
    dispositionWarnings = case disposition of
      MarkerAbsent  _natural          -> []
      MarkerHonored declared natural -> [IPSTruncationMarkerHonored patchLabel declared natural]
      MarkerNoOp     _declared        -> []
      MarkerIgnored  declared natural -> [IPSTruncationMarkerIgnored  patchLabel declared natural]

    -- | Apply-time warning derived from clip state.
    clipWarnings :: Maybe ClipAccumulator -> [SlapAdvisory]
    clipWarnings Nothing = []
    clipWarnings (Just clip) =
      [IPSRecordsClippedByMarker patchLabel
        (clipCount clip) (clipFirstIndex clip) (clipOvershoot clip)]

    recordStreamEnd = streamEndIndex records

    runApply outputPointer =
      let
        recordClip :: ActionIndex -> Length -> IPSApply ()
        recordClip recordIndex overshootLength =
          modify (<> Just (ClipAccumulator (ClippedRecordCount 1) recordIndex (MarkerOvershootBytes overshootLength)))

        -- | Seed every byte of the output buffer before any record runs.
        -- The leading @min sourceSize effectiveSize@ bytes are a direct copy of the source ByteString;
        -- the trailing @effectiveSize - sourceSize@ bytes (if any) are zero-filled.
        -- After this call returns, every byte in the buffer holds a well-defined value, and subsequent record writes overlay that value at their declared offsets.
        initialFill :: IO ()
        initialFill = do
          let targetLength      = Length (unFileSize effectiveSize)
              availableInSource = remainingFromOffset (Offset 0) sourceSize
              sourceCopyLength  = minLength targetLength availableInSource
              zeroFillLength    = subtractLength targetLength sourceCopyLength
              zeroFillStart     = advance (Offset 0) sourceCopyLength
          copyRegion outputPointer (Offset 0) source (Offset 0) sourceCopyLength
          when (unLength zeroFillLength > 0) $
            fillBytes (plusOffset outputPointer zeroFillStart)
                      (0 :: Word8)
                      (unLength zeroFillLength)

        -- | Execute a single record's write against the output
        -- buffer. Called only after the per-disposition handler has
        -- proven the write fits — this helper itself performs no
        -- bounds check and trusts its caller.
        writeRecord :: IPSRecord -> IO ()
        writeRecord IPSRecordCopy { ipsCopyOffset  = writePosition
                                  , ipsCopyPayload = payload } =
          copyRegion outputPointer writePosition
                     payload (Offset 0) (byteLength payload)
        writeRecord IPSRecordRLE { ipsRleOffset = writePosition
                                 , ipsRleCount  = runLength
                                 , ipsRleFill   = fillByte } =
          fillBytes (plusOffset outputPointer writePosition)
                    fillByte
                    (unLength runLength)

        -- | Write only the leading @prefixLength@ bytes of a
        -- record's payload. Used by 'handleHonored' for records
        -- that straddle the effective boundary.
        writeRecordPrefix :: IPSRecord -> Length -> IO ()
        writeRecordPrefix IPSRecordCopy { ipsCopyOffset  = writePosition
                                        , ipsCopyPayload = payload } prefixLength =
          copyRegion outputPointer writePosition
                     payload (Offset 0) prefixLength
        writeRecordPrefix IPSRecordRLE { ipsRleOffset = writePosition
                                       , ipsRleFill   = fillByte } prefixLength =
          fillBytes (plusOffset outputPointer writePosition)
                    fillByte
                    (unLength prefixLength)

        -- | The clip accumulator lives in the surrounding 'IPSApply' state, so each step needs only the current index.
        -- End-of-stream returns no error;
        -- a failed bounds guard returns the error, leaving whatever clip state had been built up so far in place.
        -- The buffer is already fully populated by 'initialFill' before the walk begins.
        --
        -- A record that writes nothing is the parse-accepted no-op (docs/ips/questions.md).
        -- It takes no part in the walk — no write, no bounds geometry, no clip accounting — just as it took no part in the natural-size fold above.
        -- Its offset may legally sit past the effective size, so the handlers never compute geometry for it.
        applyRecordStream :: ActionIndex -> IPSApply (Maybe ApplyError)
        applyRecordStream !recordIndex
          | recordIndex >= recordStreamEnd          = pure Nothing
          | recordPayloadLength record == Length 0  = applyRecordStream (nextAction recordIndex)
          | otherwise                               = selectedRecordHandler recordIndex record
          where
            record = Vector.unsafeIndex records (unActionIndex recordIndex)

        -- | The per-record handler, chosen once for the whole walk.
        -- The disposition is loop-invariant, so the four-arm dispatch runs when 'selectedRecordHandler' is first forced, not on every record.
        -- The match is explicit rather than a catch-all, so a future fifth disposition fires '-Wincomplete-patterns' here and the author must decide which class it belongs to.
        selectedRecordHandler :: ActionIndex -> IPSRecord -> IPSApply (Maybe ApplyError)
        selectedRecordHandler = case disposition of
          MarkerHonored _declared _natural  -> handleHonored
          MarkerAbsent   _natural           -> handleStrict
          MarkerNoOp     _declared          -> handleStrict
          MarkerIgnored  _declared _natural -> handleStrict

        -- | Record handler for 'MarkerHonored'. Dispatches on
        -- 'classifyRecordPlacement' and either writes the record (in
        -- full or as an in-bounds prefix) or counts it as overshoot.
        -- The per-arm bookkeeping is the only thing this handler
        -- adds on top of the classifier's geometry.
        handleHonored :: ActionIndex -> IPSRecord -> IPSApply (Maybe ApplyError)
        handleHonored recordIndex record = do
          let writePosition = ipsRecordOffset record
              writeLength   = recordPayloadLength record
          case classifyRecordPlacement writePosition writeLength effectiveSize of
            RecordFits -> do
              liftIO (writeRecord record)
              applyRecordStream (nextAction recordIndex)
            RecordEntirelyPastBoundary -> do
              recordClip recordIndex writeLength
              applyRecordStream (nextAction recordIndex)
            RecordPartiallyOvershoots prefixLength -> do
              let overshootLength = subtractLength writeLength prefixLength
              liftIO (writeRecordPrefix record prefixLength)
              recordClip recordIndex overshootLength
              applyRecordStream (nextAction recordIndex)

        -- | Record handler for the three non-Honored dispositions.
        -- Strict bounds check; 'ApplyWritesPastTarget' on overrun.
        -- Structurally unreachable for these dispositions
        -- (effective >= maxRecordEnd), kept as a
        -- defensive total guard.
        handleStrict :: ActionIndex -> IPSRecord -> IPSApply (Maybe ApplyError)
        handleStrict recordIndex record =
          let writePosition  = ipsRecordOffset record
              writeLength    = recordPayloadLength record
              remainingSpace = remainingFromOffset writePosition effectiveSize
          in if not (fitsWithin writePosition writeLength effectiveSize)
               then pure (Just (ApplyWritesPastTarget recordIndex
                                  (RequestedLength writeLength)
                                  (RemainingLength remainingSpace)))
               else do
                 liftIO (writeRecord record)
                 applyRecordStream (nextAction recordIndex)

      in do
        liftIO initialFill
        applyRecordStream firstAction

----------------------------------------------------------------------------
-- ClipAccumulator
----------------------------------------------------------------------------

-- | Aggregated clip statistics across the record walk. Only
-- populated when at least one record was clipped under
-- 'MarkerHonored'; the apply's clip outcome is 'Nothing' when no
-- clips happened.
data ClipAccumulator = ClipAccumulator
  { clipCount      :: !ClippedRecordCount
  , clipFirstIndex :: !ActionIndex
  , clipOvershoot  :: !MarkerOvershootBytes
  }

instance Semigroup ClipAccumulator where
  earlier <> later = ClipAccumulator
    { clipCount      = ClippedRecordCount
                         (unClippedRecordCount (clipCount earlier) + unClippedRecordCount (clipCount later))
    , clipFirstIndex = clipFirstIndex earlier
    , clipOvershoot  = clipOvershoot earlier <> clipOvershoot later
    }

-- | The state monad threaded through the record walk. The state
-- slot carries the running clip accumulator (initially 'Nothing'),
-- while the underlying 'IO' layer hosts the buffer writes. Strict
-- 'StateT' is used because the accumulator updates on every
-- clipped record and lazy thunk build-up would buy nothing.
type IPSApply = StateT (Maybe ClipAccumulator) IO
