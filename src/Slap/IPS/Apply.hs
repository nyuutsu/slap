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

-- | Where an IPS record's write span sits relative to the effective
-- output size. Used by 'handleHonored' (under 'MarkerHonored') to
-- decide between writing the record in full, writing only an
-- in-bounds prefix, or accounting the entire payload as overshoot
-- without writing.
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

-- | Classify an IPS record's write span against the effective output
-- size. Pure function of three typed arguments: the record's write
-- position, its payload length, and the effective output size.
classifyRecordPlacement :: Offset -> Length -> FileSize -> RecordPlacement
classifyRecordPlacement writePosition writeLength effectiveSize
  | fitsWithin writePosition writeLength effectiveSize = RecordFits
  | offsetToFileSize writePosition >= effectiveSize    = RecordEntirelyPastBoundary
  | otherwise =
      RecordPartiallyOvershoots (remainingFromOffset writePosition effectiveSize)

----------------------------------------------------------------------------
-- applyIPS
----------------------------------------------------------------------------

-- | Apply a parsed IPS-family patch to a source ByteString. Returns
-- the resulting target bytes plus any apply-time warnings, wrapped
-- in 'Outcome'; or a structured error if the patch is semantically
-- malformed. The caller is responsible for CRC and file-size
-- verification before calling; a 'Left' return here means the
-- parsed patch is semantically malformed, not that the patch bytes
-- were corrupted.
--
-- The target size is DERIVED, not parsed: IPS carries no header
-- field for the final output length. Derivation runs in two steps.
-- First, the natural size is computed as @max sourceSize maxRecordEnd@.
-- Second, the marker disposition (see 'MarkerDisposition') decides
-- the effective size by comparing the natural size to any
-- truncation marker the patch carries:
--
--   * 'MarkerAbsent': effective = natural.
--   * 'MarkerHonored' (declared < natural): effective = declared.
--     Records whose write regions extend past the effective size
--     are clipped and counted into 'IPSRecordsClippedByMarker'.
--   * 'MarkerNoOp' (declared == natural): effective = declared.
--     Silent.
--   * 'MarkerIgnored' (declared > natural): effective = natural.
--     The marker would grow the output; slap ignores it for sizing
--     and emits 'IPSTruncationMarkerIgnored'.
--
-- The buffer is allocated to the effective size and seeded by
-- 'initialFill': the leading @min sourceSize effectiveSize@ bytes
-- copy from source, the trailing zero-fills if effective exceeds
-- source. The record walk overlays named writes on the seeded
-- baseline. IPS records are additive overlays, so any byte not
-- named by a record equals either the source byte at that offset
-- or zero past source end.
--
-- For 'MarkerHonored', per-record writes are bounded by the
-- effective size and clip-and-count when records cross. For the
-- other three dispositions, per-record writes are guarded by a
-- strict bounds check that raises 'ApplyWritesPastTarget' on
-- overrun. The strict guard is structurally unreachable for those
-- dispositions (effective >= maxRecordEnd by construction) but
-- stays as a defensive total guard.
--
-- A defensive guard returns 'NegativeTargetSize' if the effective
-- size is somehow negative. Unreachable by construction —
-- 'NaturalTargetSize' is non-negative and 'DeclaredTargetSize' is
-- parsed from a non-negative wire value — but kept for parity with
-- BPS and UPS.
--
-- Apply does NOT re-validate each record against the variant's
-- spec ceiling ('Slap.IPS.Types.ipsVariantMaxRecordEnd'). That
-- axis is owned by 'Slap.IPS.Parse', which rejects any record
-- whose end exceeds the ceiling before an 'IPSPatch' can reach
-- this function.
--
-- The 'FormatLabel' attached to any returned error or warning is
-- derived from the patch's 'ipsVariant' ('LabelIPS' for
-- 'StandardIPS', 'LabelIPS32' for 'IPS32'), not the parse-level
-- label of whatever container the patch arrived in. An EBP-wrapped
-- patch, whose body is a 'StandardIPS' record stream, surfaces
-- apply errors and warnings as 'LabelIPS' rather than 'LabelEBP'
-- — the EBP wrapper has been peeled away by the time this function
-- runs.
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

    -- | Extend the running 'maxRecordEnd' upper bound to cover one
    -- more record's write region. Used as the fold step over the
    -- record vector.
    extendMaxWith :: FileSize -> IPSRecord -> FileSize
    extendMaxWith currentMax record =
      max currentMax (offsetToFileSize
                        (advance (ipsRecordOffset record)
                                 (recordPayloadLength record)))

    -- | Apply-time warnings derived from the disposition alone.
    -- 'MarkerAbsent' and 'MarkerNoOp' are silent; the other two
    -- emit one warning each.
    dispositionWarnings :: [SlapAdvisory]
    dispositionWarnings = case disposition of
      MarkerAbsent  _natural          -> []
      MarkerHonored declared natural -> [IPSTruncationMarkerHonored patchLabel declared natural]
      MarkerNoOp     _declared        -> []
      MarkerIgnored  declared natural -> [IPSTruncationMarkerIgnored  patchLabel declared natural]

    -- | Apply-time warning derived from clip state. Empty list when
    -- no clipping happened (the common case under all four
    -- dispositions); a single 'IPSRecordsClippedByMarker' when
    -- records were clipped under 'MarkerHonored'.
    clipWarnings :: Maybe ClipAccumulator -> [SlapAdvisory]
    clipWarnings Nothing = []
    clipWarnings (Just clip) =
      [IPSRecordsClippedByMarker patchLabel
        (clipCount clip) (clipFirstIndex clip) (clipOvershoot clip)]

    recordStreamEnd = streamEndIndex records

    runApply outputPointer =
      let
        -- | Record a clip event into the accumulator. The first
        -- clip starts the accumulator with count=1 and notes the
        -- record's index; subsequent clips increment count and add
        -- to total overshoot, preserving the first index. The
        -- accumulator lives in the 'IPSApply' state; this action
        -- updates it in place, leaving the walker free of explicit
        -- clip-state plumbing.
        recordClip :: ActionIndex -> Length -> IPSApply ()
        recordClip recordIndex overshootLen = modify $ \current -> Just $ case current of
          Nothing -> ClipAccumulator
            { clipCount      = ClippedRecordCount 1
            , clipFirstIndex = recordIndex
            , clipOvershoot  = MarkerOvershootBytes overshootLen
            }
          Just existing -> existing
            { clipCount     = ClippedRecordCount
                                (unClippedRecordCount (clipCount existing) + 1)
            , clipOvershoot = clipOvershoot existing <> MarkerOvershootBytes overshootLen
            }

        -- | Seed every byte of the output buffer before any record
        -- runs. The leading @min sourceSize effectiveSize@ bytes are
        -- a direct copy of the source ByteString; the trailing
        -- @effectiveSize - sourceSize@ bytes (if any) are
        -- zero-filled. After this call returns, every byte in the
        -- buffer holds a well-defined value and subsequent record
        -- writes overlay that value at their declared offsets.
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

        -- | Tail-recursive walk over the record vector. The clip
        -- accumulator lives in the surrounding 'IPSApply' state, so
        -- each step needs only the current index. End-of-stream
        -- returns no error; a failed bounds guard returns the
        -- error and leaves whatever clip state had been built up
        -- so far in place. The buffer is already fully populated
        -- by 'initialFill' before the walk begins.
        applyRecordStream :: ActionIndex -> IPSApply (Maybe ApplyError)
        applyRecordStream !recordIndex
          | recordIndex >= recordStreamEnd = pure Nothing
          | otherwise =
              selectedRecordHandler recordIndex
                (Vector.unsafeIndex records (unActionIndex recordIndex))

        -- | The per-record handler, chosen once for the whole walk.
        -- The disposition is loop-invariant, so the four-arm dispatch
        -- runs when 'selectedRecordHandler' is first forced rather
        -- than on every record. 'MarkerHonored' routes to
        -- 'handleHonored' (clip-and-count); the other three route to
        -- 'handleStrict' (defensive bounds check). The match is
        -- explicit rather than a catch-all so a future fifth
        -- disposition fires '-Wincomplete-patterns' here and the
        -- author has to decide which class it belongs to.
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
        -- (effective >= maxRecordEnd by construction), kept as a
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

-- | The state monad threaded through the record walk. The state
-- slot carries the running clip accumulator (initially 'Nothing'),
-- while the underlying 'IO' layer hosts the buffer writes. Strict
-- 'StateT' is used because the accumulator updates on every
-- clipped record and lazy thunk build-up would buy nothing.
type IPSApply = StateT (Maybe ClipAccumulator) IO
