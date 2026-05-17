module Slap.BSDiff.Apply
  ( applyBSDiff
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (createAndTrim')
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..))
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), Cursor(..),
                     ActionIndex, RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..), WritePosition(..),
                     fitsWithin, remainingFromOffset, byteFileSize,
                     firstAction, nextAction)
import Data.Word (Word8)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Apply-time cursors
----------------------------------------------------------------------------

-- | Read cursor into the diff byte stream. Advances by @addLength@
-- per instruction.
newtype DiffStreamReadOffset = DiffStreamReadOffset
  { unDiffStreamReadOffset :: Offset
  } deriving (Eq, Ord, Show)

-- | Read cursor into the extra byte stream. Advances by @copyLength@
-- per instruction.
newtype ExtraStreamReadOffset = ExtraStreamReadOffset
  { unExtraStreamReadOffset :: Offset
  } deriving (Eq, Ord, Show)

-- | Read cursor into the source ROM. Carried as 'SignedOffset'
-- because BSDiff's Seek delta can take the cursor negative or past
-- the end of the source. The bsdiff matching-window extension rule
-- (see 'sourceByteOrZero') treats source positions outside
-- @[0, sourceLength)@ as contributing zero to the byte-wise sum,
-- which is required for correctness — valid patches use this to
-- encode bytes in a match-section whose corresponding source
-- position falls outside the source.
newtype OriginalReadPosition = OriginalReadPosition
  { unOriginalReadPosition :: SignedOffset
  } deriving (Eq, Ord, Show)

-- | Write cursor into the output target buffer. Advances by
-- @addLength <> copyLength@ per instruction.
newtype OutputWritePosition = OutputWritePosition
  { unOutputWritePosition :: Offset
  } deriving (Eq, Ord, Show)

instance Cursor DiffStreamReadOffset where
  advance  (DiffStreamReadOffset position) stride = DiffStreamReadOffset (advance  position stride)
  displace (DiffStreamReadOffset position) delta  = DiffStreamReadOffset (displace position delta)

instance Cursor ExtraStreamReadOffset where
  advance  (ExtraStreamReadOffset position) stride = ExtraStreamReadOffset (advance  position stride)
  displace (ExtraStreamReadOffset position) delta  = ExtraStreamReadOffset (displace position delta)

instance Cursor OriginalReadPosition where
  advance  (OriginalReadPosition position) stride = OriginalReadPosition (advance  position stride)
  displace (OriginalReadPosition position) delta  = OriginalReadPosition (displace position delta)

instance Cursor OutputWritePosition where
  advance  (OutputWritePosition position) stride = OutputWritePosition (advance  position stride)
  displace (OutputWritePosition position) delta  = OutputWritePosition (displace position delta)

-- | The four cursors threaded through 'applyLoop': one per stream
-- (diff, extra, source, output). Lifted into a record so the
-- recursive call updates fields by name; a future edit cannot
-- transpose two same-typed cursors at the recursive call site
-- without the type checker noticing.
data BSDiffCursors = BSDiffCursors
  { diffStreamRead  :: !DiffStreamReadOffset
  , extraStreamRead :: !ExtraStreamReadOffset
  , originalRead    :: !OriginalReadPosition
  , outputWrite     :: !OutputWritePosition
  } deriving (Show)

-- | Cursor record at the start of an apply: every stream reads from
-- its own offset zero, and the output buffer's write head sits at
-- offset zero.
initialCursors :: BSDiffCursors
initialCursors = BSDiffCursors
  { diffStreamRead  = DiffStreamReadOffset (Offset 0)
  , extraStreamRead = ExtraStreamReadOffset (Offset 0)
  , originalRead    = OriginalReadPosition (SignedOffset 0)
  , outputWrite     = OutputWritePosition (Offset 0)
  }

----------------------------------------------------------------------------
-- applyBSDiff
----------------------------------------------------------------------------

-- | Apply a parsed BSDiff patch to a source ByteString. Each
-- instruction in the patch's control stream describes one
-- (ADD, COPY) pair plus a signed seek over the source; the apply
-- walks the stream and runs the per-instruction preconditions at
-- the instruction boundary, returning 'Left' with a structured
-- 'ApplyError' if any precondition fails. The source cursor is
-- intentionally unbounded — see 'sourceByteOrZero' for the
-- matching-window extension rule that makes this safe.
applyBSDiff :: BSDiffPatch -> InputFileContents -> Either SlapError OutputFileContents
applyBSDiff patch _
  | unFileSize (bsdiffTargetSize patch) == 0 = Right (OutputFileContents ByteString.empty)
  | unFileSize (bsdiffTargetSize patch) < 0  = Left (NegativeTargetSize LabelBSDiff (bsdiffTargetSize patch))
applyBSDiff patch (InputFileContents source) = unsafePerformIO $ do
    (result, outcome) <- createAndTrim' outputSize $ \targetPointer -> do
      maybeErr <- runApply targetPointer
      pure (0, outputSize, maybeErr)
    pure $ case outcome of
      Just applyErr -> Left (ApplyFailed LabelBSDiff applyErr)
      Nothing       -> Right (OutputFileContents result)
  where
    outputSize     = unFileSize targetFileSize
    targetFileSize = bsdiffTargetSize patch
    diffBytes      = bsdiffDiffData patch
    extraBytes     = bsdiffExtraData patch
    diffSize       = byteFileSize diffBytes
    extraSize      = byteFileSize extraBytes

    runApply targetPointer =
      let
        applyLoop :: BSDiffCursors -> [BSDiffInstruction] -> ActionIndex -> IO (Maybe ApplyError)
        applyLoop !cursors [] _actionIndex
          | remainingFromOffset (unOutputWritePosition (outputWrite cursors)) targetFileSize == Length 0 =
              pure Nothing
          | otherwise =
              pure (Just (ApplyTargetUnderfilled
                            (WritePosition (unOutputWritePosition (outputWrite cursors)))
                            (ExpectedSize targetFileSize)))
        applyLoop !cursors (instruction:rest) !actionIndex = do
          let outputPosition   = unOutputWritePosition (outputWrite cursors)
              diffReadOffset   = unDiffStreamReadOffset (diffStreamRead cursors)
              extraReadOffset  = unExtraStreamReadOffset (extraStreamRead cursors)
              originalPosition = unOriginalReadPosition (originalRead cursors)
              addLength        = controlAdd instruction
              copyLength       = controlCopy instruction
              seekDelta        = controlSeek instruction
              outputAfterAdd   = advance outputPosition addLength
              remainingForAdd  = remainingFromOffset outputPosition targetFileSize
              remainingForCopy = remainingFromOffset outputAfterAdd targetFileSize
          -- ADD region's preconditions: target-write and diff-read.
          -- The source byte read is NOT bounded here: the bsdiff
          -- matching-window extension rule (see 'sourceByteOrZero')
          -- defines the algorithm for source positions outside
          -- [0, sourceLength).
          if not (fitsWithin outputPosition addLength targetFileSize)
            then pure (Just (ApplyWritesPastTarget actionIndex
                              (RequestedLength addLength)
                              (RemainingLength remainingForAdd)))
            else if not (fitsWithin diffReadOffset addLength diffSize)
            then pure (Just (ApplyDiffReadOutOfBounds actionIndex
                              (advance diffReadOffset addLength) diffSize))
            else do
              -- Add: target[outputPosition+i] = source[originalPosition+i] + diff[diffOffset+i]
              let totalBytes = unLength addLength
                  sourceBase = unSignedOffset originalPosition
                  diffBase   = unOffset diffReadOffset
                  writeBase  = targetPointer `plusPtr` unOffset outputPosition
                  addLoop !byteOffset
                    | byteOffset >= totalBytes = pure ()
                    | otherwise = do
                        let sourceByte = sourceByteOrZero source (sourceBase + byteOffset)
                            diffByte   = ByteString.index diffBytes (diffBase + byteOffset)
                        pokeByteOff writeBase byteOffset (sourceByte + diffByte :: Word8)
                        addLoop (byteOffset + 1)
              addLoop 0
              -- COPY region's preconditions: target-write and extra-read.
              if not (fitsWithin outputAfterAdd copyLength targetFileSize)
                then pure (Just (ApplyWritesPastTarget actionIndex
                                  (RequestedLength copyLength)
                                  (RemainingLength remainingForCopy)))
                else if not (fitsWithin extraReadOffset copyLength extraSize)
                then pure (Just (ApplyExtraReadOutOfBounds actionIndex
                                  (advance extraReadOffset copyLength) extraSize))
                else do
                  copyRegion targetPointer outputAfterAdd extraBytes extraReadOffset copyLength
                  applyLoop
                    cursors
                      { diffStreamRead  = advance (diffStreamRead cursors) addLength
                      , extraStreamRead = advance (extraStreamRead cursors) copyLength
                      , originalRead    = displace (advance (originalRead cursors) addLength) seekDelta
                      , outputWrite     = advance (outputWrite cursors) (addLength <> copyLength)
                      }
                    rest
                    (nextAction actionIndex)
      in applyLoop initialCursors (bsdiffInstructions patch) firstAction

-- | Read a byte at @index@ from the source ByteString, returning 0
-- for out-of-bounds indices (negative or past the end).
--
-- This implements the bsdiff matching-window extension rule: a
-- single ADD instruction encodes a match-window of @addLength@
-- bytes where the diff stream stores @new[i] − old[oldpos+i]@.
-- The compressor exploits this encoding to extend matches past
-- either end of the source by storing the full target byte
-- verbatim in the diff stream — those bytes get "added to zero"
-- at apply time and reproduce exactly.
--
-- This rule applies to the source byte specifically. The diff
-- stream is bounds-checked per-instruction and produces an
-- 'ApplyDiffReadOutOfBounds' error on overflow; only the source
-- side carries the extension-zero semantics.
sourceByteOrZero :: ByteString -> Int -> Word8
sourceByteOrZero bytes index
  | index >= 0 && index < ByteString.length bytes =
      ByteString.index bytes index
  | otherwise = 0
