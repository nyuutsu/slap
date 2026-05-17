module Slap.BSDiff.Apply
  ( applyBSDiff
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..))
import Slap.Status (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), Cursor(..), remainingFromOffset,
                     minLength)
import Data.Word (Word8)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (pokeByteOff)

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
-- because BSDiff's Seek delta can take it negative; the apply path
-- accepts the negative case via 'safeByteAt' \'s zero-fill rather
-- than raising an error.
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

applyBSDiff :: BSDiffPatch -> InputFileContents -> Either SlapError OutputFileContents
applyBSDiff patch _
  | unFileSize (bsdiffTargetSize patch) == 0 = Right (OutputFileContents ByteString.empty)
  | unFileSize (bsdiffTargetSize patch) < 0  = Left (NegativeTargetSize LabelBSDiff (bsdiffTargetSize patch))
applyBSDiff patch (InputFileContents source) = Right $ OutputFileContents $ unsafeCreate outputSize $ \targetPointer ->
    let
      applyLoop :: BSDiffCursors -> [BSDiffInstruction] -> IO ()
      applyLoop _cursors [] = pure ()
      applyLoop !cursors (instruction:rest) = do
        let outputPosition   = unOutputWritePosition (outputWrite cursors)
            diffReadOffset   = unDiffStreamReadOffset (diffStreamRead cursors)
            extraReadOffset  = unExtraStreamReadOffset (extraStreamRead cursors)
            originalPosition = unOriginalReadPosition (originalRead cursors)
            addLength        = min (controlAdd instruction)
                                   (remainingFromOffset outputPosition targetFileSize)
            copyLength       = min (controlCopy instruction)
                                   (remainingFromOffset (advance outputPosition addLength) targetFileSize)
            seekDelta        = controlSeek instruction
        -- Add: target[outputPosition+i] = source[originalPosition+i] + diff[diffOffset+i]
        let totalBytes = unLength addLength
            sourceBase = unSignedOffset originalPosition
            diffBase   = unOffset diffReadOffset
            writeBase  = targetPointer `plusPtr` unOffset outputPosition
            addLoop !byteOffset
              | byteOffset >= totalBytes = pure ()
              | otherwise = do
                  let sourceByte = safeByteAt source    (sourceBase + byteOffset)
                      diffByte   = safeByteAt diffBytes (diffBase + byteOffset)
                  pokeByteOff writeBase byteOffset (sourceByte + diffByte :: Word8)
                  addLoop (byteOffset + 1)
        addLoop 0
        -- Copy: target[outputPosition+addLength..] = extra[extraOffset..]
        let safeCopyLength = if unOffset extraReadOffset >= 0 && unOffset extraReadOffset < extraLength
                        then minLength copyLength (remainingFromOffset extraReadOffset (FileSize extraLength))
                        else Length 0
        copyRegion targetPointer (advance outputPosition addLength) extraBytes extraReadOffset safeCopyLength
        applyLoop
          cursors
            { diffStreamRead  = advance (diffStreamRead cursors) addLength
            , extraStreamRead = advance (extraStreamRead cursors) copyLength
            , originalRead    = displace (advance (originalRead cursors) addLength) seekDelta
            , outputWrite     = advance (outputWrite cursors) (addLength <> copyLength)
            }
          rest
    in applyLoop initialCursors (bsdiffInstructions patch)
  where
    outputSize     = unFileSize (bsdiffTargetSize patch)
    targetFileSize = bsdiffTargetSize patch
    diffBytes      = bsdiffDiffData patch
    extraBytes     = bsdiffExtraData patch
    extraLength    = ByteString.length extraBytes

    -- | Read a byte at @index@ from @bytes@, returning 0 for out-of-bounds
    -- reads. Used by BSDiff's Add step, where 0 is the neutral element for
    -- the byte-wise addition of the source and diff byte streams.
    safeByteAt :: ByteString -> Int -> Word8
    safeByteAt bytes index
      | index >= 0 && index < ByteString.length bytes =
          ByteString.index bytes index
      | otherwise = 0
