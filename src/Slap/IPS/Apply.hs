module Slap.IPS.Apply
  ( applyIPS
  ) where

import Slap.IPS.Types (IPSPatch(..), IPSRecord(..), IPSVariant(..),
                       ipsRecordOffset, recordPayloadLength,
                       MarkerDisposition(..), decideMarkerDisposition,
                       effectiveTargetSize)
import Slap.Binary (copyRegion)
import Slap.Error (SlapError(..), ApplyError(..), SlapWarning(..),
                   Outcome(..), ClippedRecordCount(..), MarkerOvershootBytes(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(unActionIndex),
                     RequestedLength(..), RemainingLength(..),
                     DeclaredTargetSize(..), NaturalTargetSize(..),
                     Cursor(..), fitsWithin, remainingFromOffset,
                     subtractLength, minLength, byteLength, byteFileSize,
                     firstAction, nextAction, streamEndIndex, plusOffset)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import Control.Monad (when)
import Data.ByteString.Internal (create)
import Data.IORef (newIORef, readIORef, writeIORef, modifyIORef')
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import System.IO.Unsafe (unsafePerformIO)

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
applyIPS :: SourceFileContents -> IPSPatch -> Either SlapError (Outcome TargetFileContents)
applyIPS (SourceFileContents source) patch
  | unFileSize effectiveSize < 0 =
      Left (NegativeTargetSize patchLabel effectiveSize)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      clipRef  <- newIORef Nothing
      result <- create (unFileSize effectiveSize) $ \outputPointer ->
        runApply outputPointer errorRef clipRef
      errorState <- readIORef errorRef
      clipState  <- readIORef clipRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed patchLabel applyErr)
        Nothing       -> Right (Outcome
          (TargetFileContents result)
          (dispositionWarnings ++ clipWarnings clipState))
  where
    patchLabel    = case ipsVariant patch of
                      StandardIPS -> LabelIPS
                      IPS32       -> LabelIPS32
    records       = ipsRecords patch
    sourceSize    = byteFileSize source
    maxRecordEnd  = Vector.foldl' stepMaxEnd (FileSize 0) records
    naturalSize   = NaturalTargetSize
                      (FileSize (max (unFileSize sourceSize)
                                     (unFileSize maxRecordEnd)))
    declaredSize  = fmap DeclaredTargetSize (ipsTruncatedTargetSize patch)
    disposition   = decideMarkerDisposition declaredSize naturalSize
    effectiveSize = effectiveTargetSize disposition

    -- | Strict fold step that grows the running 'maxRecordEnd'
    -- upper bound to cover the given record.
    stepMaxEnd :: FileSize -> IPSRecord -> FileSize
    stepMaxEnd currentMax record =
      let thisRecordEnd = unOffset (ipsRecordOffset record)
                          + unLength (recordPayloadLength record)
      in FileSize (max (unFileSize currentMax) thisRecordEnd)

    -- | Apply-time warnings derived from the disposition alone.
    -- 'MarkerAbsent' and 'MarkerNoOp' are silent; the other two
    -- emit one warning each.
    dispositionWarnings :: [SlapWarning]
    dispositionWarnings = case disposition of
      MarkerAbsent  _natural          -> []
      MarkerHonored declared natural -> [IPSTruncationMarkerHonored patchLabel declared natural]
      MarkerNoOp     _declared        -> []
      MarkerIgnored  declared natural -> [IPSTruncationMarkerIgnored  patchLabel declared natural]

    -- | Apply-time warning derived from clip state. Empty list when
    -- no clipping happened (the common case under all four
    -- dispositions); a single 'IPSRecordsClippedByMarker' when
    -- records were clipped under 'MarkerHonored'.
    clipWarnings :: Maybe ClipAccumulator -> [SlapWarning]
    clipWarnings Nothing = []
    clipWarnings (Just clip) =
      [IPSRecordsClippedByMarker patchLabel
        (clipCount clip) (clipFirstIndex clip) (clipOvershoot clip)]

    recordStreamEnd = streamEndIndex records

    runApply outputPointer errorRef clipRef =
      let
        abort :: ApplyError -> IO ()
        abort applyErr = writeIORef errorRef (Just applyErr)

        -- | Record a clip event into the accumulator. The first
        -- clip starts the accumulator with count=1 and notes the
        -- record's index; subsequent clips increment count and add
        -- to total overshoot, preserving the first index.
        recordClip :: ActionIndex -> Length -> IO ()
        recordClip recordIndex overshootLen =
          modifyIORef' clipRef $ \current -> Just $ case current of
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

        -- | Tail-recursive walk over the record vector. Each step
        -- indexes the next record, hands it to 'handleRecord', and
        -- either aborts (on a failed bounds guard) or recurses (on
        -- a successful write). End-of-stream is a bare 'pure ()' —
        -- the buffer is already fully populated by 'initialFill'
        -- before the walk begins.
        applyRecordStream :: ActionIndex -> IO ()
        applyRecordStream !recordIndex
          | recordIndex >= recordStreamEnd = pure ()
          | otherwise =
              handleRecord recordIndex
                (Vector.unsafeIndex records (unActionIndex recordIndex))

        -- | Per-record dispatch. Routes 'MarkerHonored' through
        -- 'handleHonored' (clip-and-count) and the other three
        -- dispositions through 'handleStrict' (defensive bounds
        -- check). Explicit four-arm match: a future fifth
        -- disposition fires '-Wincomplete-patterns' here and the
        -- author has to decide which class it belongs to.
        handleRecord :: ActionIndex -> IPSRecord -> IO ()
        handleRecord recordIndex record = case disposition of
          MarkerHonored _declared _natural -> handleHonored recordIndex record
          MarkerAbsent   _natural           -> handleStrict   recordIndex record
          MarkerNoOp     _declared          -> handleStrict   recordIndex record
          MarkerIgnored  _declared _natural -> handleStrict   recordIndex record

        -- | Record handler for 'MarkerHonored'. Three behaviors
        -- per record: entirely-within-effective writes verbatim;
        -- entirely-past-effective skips and counts the full
        -- payload as overshoot; straddling-effective writes the
        -- fitting prefix and counts the trailing length as
        -- overshoot.
        handleHonored :: ActionIndex -> IPSRecord -> IO ()
        handleHonored recordIndex record =
          let writePosition = ipsRecordOffset record
              writeLength   = recordPayloadLength record
              writeStart    = unOffset writePosition
              effectiveEnd  = unFileSize effectiveSize
          in if writeStart + unLength writeLength <= effectiveEnd
               then do
                 writeRecord record
                 applyRecordStream (nextAction recordIndex)
               else if writeStart >= effectiveEnd
                 then do
                   recordClip recordIndex writeLength
                   applyRecordStream (nextAction recordIndex)
                 else
                   let prefixLength = remainingFromOffset writePosition effectiveSize
                       overshootLen = subtractLength writeLength prefixLength
                   in do
                     writeRecordPrefix record prefixLength
                     recordClip recordIndex overshootLen
                     applyRecordStream (nextAction recordIndex)

        -- | Record handler for the three non-Honored dispositions.
        -- Strict bounds check; 'ApplyWritesPastTarget' on overrun.
        -- Structurally unreachable for these dispositions
        -- (effective >= maxRecordEnd by construction), kept as a
        -- defensive total guard.
        handleStrict :: ActionIndex -> IPSRecord -> IO ()
        handleStrict recordIndex record =
          let writePosition  = ipsRecordOffset record
              writeLength    = recordPayloadLength record
              remainingSpace = remainingFromOffset writePosition effectiveSize
          in if not (fitsWithin writePosition writeLength effectiveSize)
               then abort (ApplyWritesPastTarget recordIndex
                            (RequestedLength writeLength)
                            (RemainingLength remainingSpace))
               else do
                 writeRecord record
                 applyRecordStream (nextAction recordIndex)

      in do
        initialFill
        applyRecordStream firstAction

----------------------------------------------------------------------------
-- ClipAccumulator
----------------------------------------------------------------------------

-- | Aggregated clip statistics across the record walk. Only
-- populated when at least one record was clipped under
-- 'MarkerHonored'; 'Nothing' in the surrounding 'IORef' means no
-- clips happened.
data ClipAccumulator = ClipAccumulator
  { clipCount      :: !ClippedRecordCount
  , clipFirstIndex :: !ActionIndex
  , clipOvershoot  :: !MarkerOvershootBytes
  }
