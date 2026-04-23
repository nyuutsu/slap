module Slap.IPS.Apply
  ( applyIPS
  ) where

import Slap.IPS.Types (IPSPatch(..), IPSRecord(..), IPSVariant(..),
                       ipsRecordOffset, recordPayloadLength)
import Slap.Binary (copyRegion)
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(..),
                     RequestedLength(..), RemainingLength(..),
                     Cursor(..), fitsWithin, remainingFromOffset,
                     subtractLength, minLength, byteLength,
                     firstAction, nextAction, plusOffset)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import Control.Monad (when)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- applyIPS
----------------------------------------------------------------------------

-- | Apply a parsed IPS-family patch to a source ByteString. Returns
-- 'Left' with a structured error if the patch's derived target size
-- is non-sensical (unreachable by construction but defensively
-- guarded for parity with BPS/UPS) or if a record's write region
-- would overrun the derived target (the way a Flips-style
-- truncation marker declaring a target smaller than the record
-- spread surfaces — per-record, at the offending 'ActionIndex',
-- as 'ApplyWritesPastTarget'). This coverage is uniform across
-- every declared target size, zero included: the zero-target
-- short-circuit below fires only for the no-op case of an empty
-- record vector alongside a zero declared target, not as a
-- catch-all that would swallow records when the declared size
-- happens to be zero. The caller is responsible for CRC
-- and file-size verification before calling; a 'Left' return here
-- means the parsed patch is semantically malformed, not that the
-- patch bytes were corrupted.
--
-- Target size is DERIVED, not parsed. IPS carries no header field
-- for the final output length. The derivation uses the max of the
-- source size and the largest record end across the record vector,
-- or the Flips-style truncation marker's declared value if the
-- patch carries one. The short rationale: IPS records are
-- additive overlays on top of a source passthrough, so any byte
-- not named by a record equals either the source byte at that
-- offset or zero (past source end). 'initialFill' seeds the
-- buffer with the source-plus-zero-tail baseline; the record
-- walk then overlays the named writes.
--
-- Apply does NOT re-validate each record against the variant's spec
-- ceiling ('Slap.IPS.Types.ipsVariantMaxRecordEnd'). That axis is
-- owned by 'Slap.IPS.Parse', which rejects any record whose end
-- exceeds the ceiling before an 'IPSPatch' can reach this function.
--
-- The 'FormatLabel' attached to any returned error is derived from
-- the patch's 'ipsVariant' ('LabelIPS' for 'StandardIPS',
-- 'LabelIPS32' for 'IPS32'), not the parse-level label of whatever
-- container the patch arrived in. An EBP-wrapped patch, whose body
-- is a 'StandardIPS' record stream, therefore surfaces apply errors
-- as 'LabelIPS' rather than 'LabelEBP' — the failure is structurally
-- an IPS apply failure, and the EBP wrapper has already been peeled
-- away by the time this function runs.
applyIPS :: SourceFileContents -> IPSPatch -> Either SlapError TargetFileContents
applyIPS (SourceFileContents source) patch
  | unFileSize targetSize < 0 =
      Left (NegativeTargetSize patchLabel targetSize)
  | unFileSize targetSize == 0 && Vector.null records =
      Right (TargetFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize targetSize) $ \outputPointer ->
        runApply outputPointer errorRef
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed patchLabel applyErr)
        Nothing       -> Right (TargetFileContents result)
  where
    patchLabel      = case ipsVariant patch of
                        StandardIPS -> LabelIPS
                        IPS32       -> LabelIPS32
    records         = ipsRecords patch
    sourceSize      = FileSize (ByteString.length source)
    maxRecordEnd    = Vector.foldl' stepMaxEnd (FileSize 0) records
    targetSize      =
      case ipsTruncatedTargetSize patch of
        Just declared -> declared
        Nothing       ->
          FileSize (max (unFileSize sourceSize) (unFileSize maxRecordEnd))
    recordStreamEnd = ActionIndex (Vector.length records)

    -- | Strict fold step that grows the running 'maxRecordEnd'
    -- upper bound to cover the given record. Lives in the 'where'
    -- clause because it closes over nothing — pulling it out to
    -- top level would not buy anything.
    stepMaxEnd :: FileSize -> IPSRecord -> FileSize
    stepMaxEnd currentMax record =
      let thisRecordEnd = unOffset (ipsRecordOffset record)
                          + unLength (recordPayloadLength record)
      in FileSize (max (unFileSize currentMax) thisRecordEnd)

    runApply outputPointer errorRef =
      let
        abort :: ApplyError -> IO ()
        abort applyErr = writeIORef errorRef (Just applyErr)

        -- | Seed every byte of the output buffer before any record
        -- runs. The leading @min sourceSize targetSize@ bytes are a
        -- direct copy of the source ByteString; the trailing
        -- @targetSize - sourceSize@ bytes (if any) are zero-filled.
        -- After this call returns, every byte in the buffer holds a
        -- well-defined value and subsequent record writes overlay
        -- that value at their declared offsets.
        initialFill :: IO ()
        initialFill = do
          let targetLength      = Length (unFileSize targetSize)
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
        -- buffer. Called only after 'handleRecord' has proven the
        -- write fits within 'targetSize' — this helper itself
        -- performs no bounds check and trusts its caller.
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

        -- | Tail-recursive walk over the record vector. Each step
        -- indexes the next record, hands it to 'handleRecord', and
        -- either aborts (on a failed bounds guard) or recurses (on
        -- a successful write). End-of-stream is a bare 'pure ()' —
        -- the buffer is already fully populated by 'initialFill'
        -- before the walk begins, so there is no end-of-stream
        -- underfill check analogous to BPS's
        -- 'ApplyTargetUnderfilled'.
        applyRecordStream :: ActionIndex -> IO ()
        applyRecordStream !recordIndex
          | recordIndex >= recordStreamEnd = pure ()
          | otherwise =
              handleRecord recordIndex
                (Vector.unsafeIndex records (unActionIndex recordIndex))

        -- | Bounds-guard a single record, then dispatch. The guard
        -- runs BEFORE the write: per the strict-apply invariant, no
        -- byte is written until its destination has been proven to
        -- lie within 'targetSize'. On failure, 'abort' writes the
        -- error into the IORef and the recursion terminates — the
        -- walker does not continue past an aborted record. On
        -- success, the write runs and 'applyRecordStream' recurses
        -- to the next index.
        handleRecord :: ActionIndex -> IPSRecord -> IO ()
        handleRecord recordIndex record =
          let writePosition  = ipsRecordOffset record
              writeLength    = recordPayloadLength record
              remainingSpace = remainingFromOffset writePosition targetSize
          in if not (fitsWithin writePosition writeLength targetSize)
               then abort (ApplyWritesPastTarget recordIndex
                            (RequestedLength writeLength)
                            (RemainingLength remainingSpace))
               else do
                 writeRecord record
                 applyRecordStream (nextAction recordIndex)

      in do
        initialFill
        applyRecordStream firstAction
