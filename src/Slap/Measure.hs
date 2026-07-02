{-# LANGUAGE StrictData #-}

module Slap.Measure
  ( -- * Newtypes
    Offset(..)
  , Length(..)
  , FileSize(..)
  , Delta(..)
  , Position(..)
  , SignedOffset(..)
  , ActionIndex(unActionIndex)
  , ReadOffset(..)
  , WritePosition(..)
  , RequestedLength(..)
  , RemainingLength(..)
  , ActualSize(..)
  , ExpectedSize(..)
  , MaxAddressableSize(..)
  , SourceFileSize(..)
  , TargetFileSize(..)
  , DeclaredTargetSize(..)
  , NaturalTargetSize(..)
    -- * Parse/create-error role newtypes
  , RequiredLength(..)
  , ActualLength(..)
  , EncodedLength(..)
  , MaxLength(..)
  , OriginalLength(..)
  , TruncatedLength(..)
  , SubstitutionCount(..)
  , ActualOffset(..)
  , MaxOffset(..)
  , SentinelOffset(..)
  , ExpectedMagic(..)
  , ActualMagic(..)
  , TrailerMarker(..)
  , ParsedSizeValue(..)
  , FoundVersion(..)
  , RawFlagByte(..)
  , EncodingMethodByte(..)
    -- * Records
  , Hunk(..)
  , SplitHunk
  , splitOffset
  , splitPayload
  , SplitUndoHunk
  , splitUndoOffset
  , splitUndoPayload
  , splitUndoOriginal
  , OffsetRange(..)
  , rangeEndExclusive
  , rangeLastByte
    -- * Conversions
  , offsetToInt
  , fileSizeToInt
  , lengthToFileSize
  , lengthToOffset
  , offsetToFileSize
  , offsetFromParsed
    -- * Seeking
  , seekTo
    -- * Cursor typeclass
  , Cursor(..)
    -- * Cursor helpers
  , remainingFromOffset
  , remainingFromPosition
  , firstAction
  , nextAction
  , streamEndIndex
  , actionAtPosition
  , subtractLength
  , minLength
  , plusOffset
  , SignedOffsetSign(..)
  , examineSignedOffset
    -- * Arithmetic
  , distance
  , fitsWithin
  , boundedWriteEnd
  , byteLength
  , byteFileSize
  , hunkEnd
    -- * Splitting
  , splitHunk
  , splitHunks
  , splitHunksUnbounded
  , splitUndoHunks
  , splitUndoHunkFromParsed
    -- * IPS sentinel values
  , ipsSentinel
  , ips32Sentinel
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO (Handle, SeekMode(AbsoluteSeek), hSeek)

----------------------------------------------------------------------------
-- Newtypes
----------------------------------------------------------------------------

-- | A byte position in a zero-indexed buffer. Slap's apply paths
-- operate on output buffers, source/target ByteStrings, and region
-- payloads — all zero-indexed — and parsed wire
-- offsets name positions within those buffers. There is no place in
-- slap where 'Offset' means a position in a non-zero-indexed buffer;
-- 'SignedOffset' exists separately to carry the may-be-negative
-- temporary state across BPS's displace-then-examine pattern.
newtype Offset = Offset { unOffset :: Int } deriving (Eq, Ord, Show)
newtype Length   = Length   { unLength   :: Int } deriving (Eq, Ord, Show)
newtype FileSize = FileSize { unFileSize :: Int } deriving (Eq, Ord, Show)
newtype Delta    = Delta    { unDelta    :: Int } deriving (Eq, Ord, Show)
newtype Position = Position { unPosition :: Int } deriving (Eq, Ord, Show)

-- | A cursor position carrying the result of signed arithmetic.
-- BPS apply's @SourceCopy@ and @TargetCopy@ actions advance their
-- relative cursors by a signed delta, and the post-displace value
-- can be negative. Per the BPS spec a negative cursor means the
-- patch is invalid; the negative case is detected at the read site
-- via 'examineSignedOffset' and produces 'ApplyCursorUnderflow'.
-- Outside the displace-then-examine pattern, code should use
-- 'Offset' instead.
newtype SignedOffset = SignedOffset { unSignedOffset :: Int }
  deriving (Eq, Ord, Show)

newtype ActionIndex = ActionIndex { unActionIndex :: Int }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- Apply-time role newtypes
----------------------------------------------------------------------------

-- | The offset at which a read is performed. Used as the working
-- type in apply paths where a bare 'Offset' would be ambiguous
-- with another offset-valued field, and carried into error
-- contexts at the failure site.
newtype ReadOffset = ReadOffset { unReadOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The current write position in a buffer being populated. Used
-- as the working type in apply paths where a bare 'Offset' would
-- be ambiguous with another offset-valued field, and carried into
-- error contexts at the failure site.
newtype WritePosition = WritePosition { unWritePosition :: Offset }
  deriving (Eq, Ord, Show)

-- | A length an action requested to copy or write. Used in error
-- contexts where a bare 'Length' would be ambiguous with another
-- length-valued field.
newtype RequestedLength = RequestedLength { unRequestedLength :: Length }
  deriving (Eq, Ord, Show)

-- | The length of space remaining in a buffer being populated.
-- Used in error contexts where a bare 'Length' would be ambiguous
-- with another length-valued field.
newtype RemainingLength = RemainingLength { unRemainingLength :: Length }
  deriving (Eq, Ord, Show)

-- | The actual size achieved by a partial or completed operation.
-- Used in error contexts where a bare 'FileSize' would be
-- ambiguous with another size-valued field.
newtype ActualSize = ActualSize { unActualSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | The expected or declared size of something. Used in error
-- contexts where a bare 'FileSize' would be ambiguous with another
-- size-valued field.
newtype ExpectedSize = ExpectedSize { unExpectedSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | The maximum size slap can address on the host platform, given that offsets and lengths flow through 'Int':
-- the host's 'maxBound' :: 'Int'.
-- Carried by 'FileExceedsAddressableRange' when a create-path size guard rejects an oversized input.
newtype MaxAddressableSize = MaxAddressableSize { unMaxAddressableSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | The byte size of a differ's source (input) file.
-- Paired with 'TargetFileSize' where a refusal carries both and bare 'FileSize's would transpose silently.
newtype SourceFileSize = SourceFileSize { unSourceFileSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | The byte size of a differ's target (output) file; see 'SourceFileSize'.
newtype TargetFileSize = TargetFileSize { unTargetFileSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | A target file size declared explicitly by something in the
-- patch — a header field, a trailer marker, or similar. Distinct
-- from 'NaturalTargetSize' because some formats compare the two at
-- apply time to decide whether the declaration is honored (IPS does,
-- via its optional post-EOF truncation marker).
-- Bare 'FileSize' arguments at the comparison would let a
-- transposition silently invert the policy decision.
newtype DeclaredTargetSize = DeclaredTargetSize
  { unDeclaredTargetSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | A target file size derived from operation inputs alone: the
-- source size and the maximum write end across the patch's records,
-- actions, or hunks. Equal to @max sourceSize maxRecordEnd@ for IPS.
-- Distinct from
-- 'DeclaredTargetSize' for the same reason 'DeclaredTargetSize'
-- exists.
newtype NaturalTargetSize = NaturalTargetSize
  { unNaturalTargetSize :: FileSize }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- Parse/create-error role newtypes
----------------------------------------------------------------------------

-- | The minimum length a parser requires before it can proceed.
newtype RequiredLength = RequiredLength { unRequiredLength :: Length }
  deriving (Eq, Ord, Show)

-- | The actual length available when a parser found it insufficient.
newtype ActualLength = ActualLength { unActualLength :: Length }
  deriving (Eq, Ord, Show)

-- | The encoded byte length of a field that exceeded its format's
-- maximum.
newtype EncodedLength = EncodedLength { unEncodedLength :: Length }
  deriving (Eq, Ord, Show)

-- | The maximum byte length a format allows for a given field.
newtype MaxLength = MaxLength { unMaxLength :: Length }
  deriving (Eq, Ord, Show)

-- | The original byte length of a field before truncation.
newtype OriginalLength = OriginalLength { unOriginalLength :: Length }
  deriving (Eq, Ord, Show)

-- | The byte length of a field after truncation to fit its format.
newtype TruncatedLength = TruncatedLength { unTruncatedLength :: Length }
  deriving (Eq, Ord, Show)

-- | How many codepoints were replaced by a substitution character
-- during a lenient text decode or encode. Each event corresponds to
-- one input character that the target encoding (encode) or the
-- declared source encoding (decode) couldn't represent; the count is
-- the running tally a format-level advisory surfaces to the user.
newtype SubstitutionCount = SubstitutionCount { unSubstitutionCount :: Int }
  deriving (Eq, Ord, Show)

-- | An offset that a hunk or record actually carried, used in
-- encode-error contexts where a bare 'Offset' would be ambiguous.
newtype ActualOffset = ActualOffset { unActualOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The maximum offset a format allows, used in encode-error
-- contexts where a bare 'Offset' would be ambiguous.
newtype MaxOffset = MaxOffset { unMaxOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The offset at which a format's trailer sentinel sits: the
-- big-endian encoding of this offset collides with the format's
-- stream-closing marker on the wire, so a record emitted at this
-- offset would be indistinguishable from the trailer. IPS's
-- @0x454F46@ ("EOF") and IPS32's @0x45454F46@ ("EEOF") are the
-- motivating examples. Carried distinct from plain 'Offset' so that
-- sentinel-collision code can never accidentally be passed a record
-- offset, and vice versa.
newtype SentinelOffset = SentinelOffset { unSentinelOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The magic bytes a parser expected to find.
newtype ExpectedMagic = ExpectedMagic { unExpectedMagic :: ByteString }
  deriving (Eq, Show)

-- | The magic bytes a parser actually found.
newtype ActualMagic = ActualMagic { unActualMagic :: ByteString }
  deriving (Eq, Show)

-- | The trailer-marker bytes a parser was looking for when it
-- encountered unrecognized post-trailer content. The IPS family's
-- @"EOF"@ and @"EEOF"@ markers are the motivating example: when
-- 'Slap.IPS.Parse' rejects bytes that follow one of these markers,
-- the marker bytes are carried in the resulting error so the
-- renderer can name the marker the parser was anchored to without
-- knowing about IPS variants. The bytes are stored verbatim;
-- whether they print as ASCII or hex is the renderer's problem.
newtype TrailerMarker = TrailerMarker { unTrailerMarker :: ByteString }
  deriving (Eq, Show)

-- | A size field whose decoded value was negative (an Int that
-- should have been non-negative).
newtype ParsedSizeValue = ParsedSizeValue { unParsedSizeValue :: Int }
  deriving (Eq, Ord, Show)

-- | A version byte the parser did not recognize.
newtype FoundVersion = FoundVersion { unFoundVersion :: Word8 }
  deriving (Eq, Ord, Show)

-- | A flag byte the parser did not recognize.
newtype RawFlagByte = RawFlagByte { unRawFlagByte :: Word8 }
  deriving (Eq, Ord, Show)

-- | An encoding-method byte the parser did not recognize.
newtype EncodingMethodByte = EncodingMethodByte { unEncodingMethodByte :: Word8 }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- Records
----------------------------------------------------------------------------

-- | A raw edit span — a target 'Offset' and the payload bytes to write there — as produced by 'Slap.Binary.diffHunks' before any per-record size check.
-- 'splitHunk' / 'splitHunks' refine it into a 'SplitHunk' whose payload respects a format's per-record cap; only that refined form reaches an encoder.
data Hunk = Hunk
  { hunkOffset  :: !Offset
  , hunkPayload :: !ByteString
  } deriving (Eq, Show)

-- | A 'Hunk' whose payload has been validated against a format's
-- per-record payload bound, or had that validation explicitly waived
-- for a format whose wire encoding has no per-record cap (see
-- 'splitHunksUnbounded'). The constructor is intentionally not
-- exported: every 'SplitHunk' that exists in slap came from one of
-- the @split*@ functions in this module. Encoders that would
-- otherwise risk a silent @fromIntegral length :: Word8/Word32@
-- truncation receive their input through the typed pipeline
-- @[Hunk] -> [SplitHunk] -> [EncodedHunk]@; the only way to obtain
-- an 'EncodedHunk' is for both passes to have completed
-- successfully.
data SplitHunk = SplitHunk
  { splitOffset  :: !Offset
  , splitPayload :: !ByteString
  } deriving (Eq, Show)

-- | A PPF3-style undo record whose payload has been validated against
-- the format's per-record payload bound. Constructor private; values
-- come from one of two named producers in this module:
--
-- * 'splitUndoHunks'       — create-time, splits a 'Hunk' list against
--                            the payload bound and computes per-piece
--                            original-bytes from the source ROM.
-- * 'splitUndoHunkFromParsed' — parse-time, lifts an already-validated
--                               wire-format record (the parser's
--                               1-byte length field guarantees the
--                               bound).
--
-- Every encoder that emits a PPF3 undo record consumes 'EncodedUndoHunk'
-- (in 'Slap.Narrow'), which can only be produced by narrowing a
-- 'SplitUndoHunk'. The pipeline is type-enforced; the only way to
-- emit a record is through both passes.
data SplitUndoHunk = SplitUndoHunk
  { splitUndoOffset   :: !Offset
  , splitUndoPayload  :: !ByteString
  , splitUndoOriginal :: !ByteString
  } deriving (Eq, Show)

-- | A contiguous span of bytes in a target file: a starting 'Offset'
-- and a 'Length'. Used by the display layer to surface where a patch
-- operates ("the patch touches bytes 0x000100 through 0x00FFFF") and
-- by the explain summary as the range over which records cluster.
--
-- Held as start-plus-length rather than start-plus-end so the span's
-- length is a typed 'Length' (cannot be transposed with an offset)
-- and so an empty range is impossible to construct accidentally — an
-- absent range is 'Nothing', not an empty @start == end@. The
-- end offset is recovered via 'rangeEndExclusive' when needed.
data OffsetRange = OffsetRange
  { rangeStart  :: !Offset
  , rangeLength :: !Length
  } deriving (Eq, Show)

-- | The exclusive end of an 'OffsetRange': @start + length@. Suitable
-- for half-open intervals (read-bound checks, end-pointer arithmetic).
rangeEndExclusive :: OffsetRange -> Offset
rangeEndExclusive range = advance (rangeStart range) (rangeLength range)

-- | The last byte 'Offset' inside an 'OffsetRange', i.e.
-- @rangeEndExclusive - 1@. Suitable for inclusive display
-- ("0x000100 – 0x00FFFF"). Undefined for an empty range; every
-- call site builds the range from a non-empty record stream.
rangeLastByte :: OffsetRange -> Offset
rangeLastByte range = Offset (unOffset (rangeEndExclusive range) - 1)

----------------------------------------------------------------------------
-- Instances
----------------------------------------------------------------------------

instance Semigroup Length where
  Length left <> Length right = Length (left + right)

instance Monoid Length where
  mempty = Length 0

----------------------------------------------------------------------------
-- Conversions
----------------------------------------------------------------------------

offsetToInt :: Offset -> Int
offsetToInt = unOffset

fileSizeToInt :: FileSize -> Int
fileSizeToInt = unFileSize

lengthToFileSize :: Length -> FileSize
lengthToFileSize (Length lengthValue) = FileSize lengthValue

lengthToOffset :: Length -> Offset
lengthToOffset (Length lengthValue) = Offset lengthValue

-- | An 'Offset' as a 'FileSize': the byte count of a buffer whose
-- last written byte sits one position before this 'Offset', when the
-- buffer is indexed from 'Offset' @0@. Useful at end-of-apply
-- diagnostics where the cursor's position from the start equals the
-- number of bytes written. The conversion is meaningful only for
-- buffers indexed from zero with no gaps.
offsetToFileSize :: Offset -> FileSize
offsetToFileSize (Offset position) = FileSize position

-- | Widen an integer just decoded by a parser into an 'Offset'.
-- The named home for the parse-boundary 'fromIntegral': a format parser reads a raw 'Data.Word.Word32' (or 'Data.Int.Int64', or a varint) and wraps it here rather than inlining @Offset . fromIntegral@ at each call site.
-- Sibling to 'splitUndoHunkFromParsed'; both are where a parsed wire value crosses into a typed position.
--
-- Pure widening, no validation.
-- A negative value is preserved as-is: PPF1/PPF2/PPF3/PPF4 carry signed offsets on the wire, and an out-of-range one is the apply layer's to reject (via 'Slap.Status.ApplyNegativeRecordOffset'), not the parser's to pre-empt.
-- The 'Integral' constraint lets one builder serve every wire width; the widening to host 'Int' is the same conversion the inline form performed.
offsetFromParsed :: Integral a => a -> Offset
offsetFromParsed = Offset . fromIntegral

----------------------------------------------------------------------------
-- Seeking
----------------------------------------------------------------------------

seekTo :: Handle -> Offset -> IO ()
seekTo handle targetOffset =
  hSeek handle AbsoluteSeek (fromIntegral (unOffset targetOffset))

----------------------------------------------------------------------------
-- Cursor typeclass
----------------------------------------------------------------------------

-- | Buffer cursors that support position arithmetic. 'Offset' is
-- the everyday case (forward-walking; non-negative by convention).
-- 'SignedOffset' carries the potentially-negative result of BPS
-- apply's relative-delta arithmetic from the displace site to the
-- validity check at the read site. Per the BPS spec, a negative
-- cursor means the patch is invalid; slap detects this at apply
-- time via 'examineSignedOffset', per the wire-vs-semantic-
-- invalidity doctrine in @questions.md@. Currently only BPS apply
-- uses the 'SignedOffset' instance.
class Cursor cursor where
  advance  :: cursor -> Length -> cursor
  displace :: cursor -> Delta  -> cursor

instance Cursor Offset where
  advance  (Offset position) (Length stride) =
    Offset (position + stride)
  displace (Offset position) (Delta displacement) =
    Offset (position + displacement)

instance Cursor SignedOffset where
  advance  (SignedOffset position) (Length stride) =
    SignedOffset (position + stride)
  displace (SignedOffset position) (Delta displacement) =
    SignedOffset (position + displacement)

instance Cursor ReadOffset where
  advance  (ReadOffset position) stride = ReadOffset (advance  position stride)
  displace (ReadOffset position) delta  = ReadOffset (displace position delta)

instance Cursor WritePosition where
  advance  (WritePosition position) stride = WritePosition (advance  position stride)
  displace (WritePosition position) delta  = WritePosition (displace position delta)

----------------------------------------------------------------------------
-- Cursor helpers
----------------------------------------------------------------------------

-- | The number of bytes remaining in a file from a given offset, as a
-- non-negative 'Length'. The helper assumes @position '<=' totalSize@;
-- violating that precondition is a programming error and raises
-- 'error' rather than returning a clamped zero. Callers whose
-- algorithm genuinely needs the past-end case to read as zero must
-- detect it explicitly upstream and not invoke this helper.
remainingFromOffset :: Offset -> FileSize -> Length
remainingFromOffset (Offset position) (FileSize totalSize)
  | position <= totalSize = Length (totalSize - position)
  | otherwise =
      error ("remainingFromOffset: position " ++ show position
              ++ " past size " ++ show totalSize)

-- | The number of bytes remaining in a 'ByteString' from a given parse
-- 'Position'. The 'Position'-aware analogue of 'remainingFromOffset',
-- with the same honest contract: assumes @cursorPosition '<=' length@
-- and raises 'error' otherwise. Used by 'Slap.ByteParser.remaining',
-- whose primitives maintain @Position '<=' length@ as an invariant.
remainingFromPosition :: Position -> ByteString -> Length
remainingFromPosition (Position cursorPosition) input
  | cursorPosition <= inputLength = Length (inputLength - cursorPosition)
  | otherwise =
      error ("remainingFromPosition: position " ++ show cursorPosition
              ++ " past input length " ++ show inputLength)
  where
    inputLength = ByteString.length input

-- | The first index in any action stream.
firstAction :: ActionIndex
firstAction = ActionIndex 0

-- | Step to the next action in a stream.
nextAction :: ActionIndex -> ActionIndex
nextAction (ActionIndex index) = ActionIndex (index + 1)

-- | The 'ActionIndex' one past the end of an action stream — the
-- termination bound for a recursive applier walking an indexed
-- container. The 'Foldable' constraint forces callers to hand in
-- the actual stream rather than a pre-computed count, foreclosing
-- the @ActionIndex (length xs)@ shape that fabricates an index
-- from a count where threading was the right verb.
streamEndIndex :: Foldable t => t a -> ActionIndex
streamEndIndex stream = ActionIndex (length stream)

-- | An 'ActionIndex' identified by its position in a stream the
-- caller is iterating over by hand — parse-time scanners with
-- 'Int' loop counters, OOB detectors driven by 'Vector.ifoldl''.
-- The newtype boundary makes "this 'Int' is a step number, not a
-- byte offset or a length" explicit at the call site. Prefer
-- threading via 'firstAction' / 'nextAction' when the surrounding
-- code can express the walk that way; reach for this builder only
-- when the index genuinely arrives from an external loop.
actionAtPosition :: Int -> ActionIndex
actionAtPosition = ActionIndex

-- | Subtract two 'Length' values. Assumes @minuend '>=' subtrahend@
-- and raises 'error' on underflow rather than clamping to zero —
-- caller is responsible for establishing the ordering upstream (the
-- typical pattern is bounding 'subtrahend' via 'minLength' against
-- 'minuend' first).
subtractLength :: Length -> Length -> Length
subtractLength (Length minuend) (Length subtrahend)
  | minuend >= subtrahend = Length (minuend - subtrahend)
  | otherwise =
      error ("subtractLength: underflow (" ++ show minuend
              ++ " - " ++ show subtrahend ++ ")")

-- | The smaller of two 'Length' values. Used in apply workers when
-- splitting a region into in-bounds and zero-fill phases: the
-- in-bounds length is the minimum of the requested length and the
-- bytes remaining in source.
minLength :: Length -> Length -> Length
minLength (Length left) (Length right) = Length (min left right)

-- | The result of examining a 'SignedOffset' for non-negativity,
-- produced by 'examineSignedOffset'. 'NonNegativeCursor' carries an
-- 'Offset' the apply path can use for reads; 'NegativeCursor' carries
-- the original signed value so the negative case can flow into error
-- context (e.g. as the
-- 'SignedOffset' field of 'ApplyCursorUnderflow').
data SignedOffsetSign
  = NegativeCursor SignedOffset
  | NonNegativeCursor Offset
  deriving (Show, Eq)

-- | Examine a 'SignedOffset' and return either the original
-- negative value (carried for error reporting) or a non-negative
-- 'Offset' suitable for use as a read position.
examineSignedOffset :: SignedOffset -> SignedOffsetSign
examineSignedOffset signedCursor@(SignedOffset position)
  | position < 0 = NegativeCursor signedCursor
  | otherwise    = NonNegativeCursor (Offset position)

-- | Advance a raw byte pointer by a typed 'Offset'. Used at the
-- FFI boundary in apply workers, where the typed cursor needs to
-- be turned into a destination address for 'fillBytes', 'pokeByteOff',
-- or similar primitives.
plusOffset :: Ptr Word8 -> Offset -> Ptr Word8
plusOffset pointer (Offset position) = pointer `plusPtr` position

----------------------------------------------------------------------------
-- Arithmetic
----------------------------------------------------------------------------

-- | The 'Length' from the start 'Offset' to the end 'Offset':
-- @end - start@. Assumes @startOffset '<=' endOffset@ and raises
-- 'error' otherwise — call sites that span a forward walk
-- ('findRegionEnd', record-stream order, sorted seed positions) have
-- this ordering. The argument order mirrors the
-- typical reading "the distance /from/ start /to/ end."
distance :: Offset -> Offset -> Length
distance (Offset startOffset) (Offset endOffset)
  | startOffset <= endOffset = Length (endOffset - startOffset)
  | otherwise =
      error ("distance: end " ++ show endOffset
              ++ " before start " ++ show startOffset)

-- | Does a region of @regionLength@ bytes starting at @regionStart@
-- lie entirely within a space of @totalSize@ bytes? The bounds check
-- every apply and parse walk leans on before a read or a write.
--
-- Total over the whole 'Int' range. slap carries
-- offsets and sizes as a signed 'Int', and several formats decode wire
-- fields wide enough — a 63-bit PPF3 offset, a byuu or VCDIFF varint, a
-- bsdiff sign-magnitude length — to seat a near-'maxBound' value here.
-- A plain @regionStart + regionLength <= totalSize@ would then overflow
-- the carrier and wrap to a negative sum that falsely reports "fits",
-- which is the gap an out-of-bounds access slips through. So the test
-- never adds: each clause is a comparison, and the
-- @totalSize - regionStart@ subtraction is reached only once
-- @0 <= regionStart <= totalSize@ holds, so it cannot underflow either.
-- A negative @regionStart@ or @regionLength@ — a malformed wire value
-- that was never a real position or length — answers "does not fit"
-- rather than being summed into a wrong verdict.
fitsWithin :: Offset -> Length -> FileSize -> Bool
fitsWithin (Offset regionStart) (Length regionLength) (FileSize totalSize) =
     regionStart  >= 0
  && regionLength >= 0
  && regionStart  <= totalSize
  && regionLength <= totalSize - regionStart

-- | The exclusive end of a write of @regionLength@ bytes at
-- @regionStart@ — @regionStart + regionLength@ — or 'Nothing' when that
-- sum overflows the signed 'Int' a position is carried in.
--
-- This is the apply-side companion to 'fitsWithin': the same ceiling
-- ('maxBound' :: 'Int'), met not by a bounds check but by /computing/ an
-- extent that crosses it. A format whose wire offset is as wide as the
-- carrier — PPF3's signed 64-bit field — can name a write whose end no
-- 'Int' can hold; the fold that sizes the output buffer must answer "I
-- cannot address that" rather than wrap into a too-small buffer. A
-- non-negative @regionLength@ added to a non-negative @regionStart@ can
-- only land lower than @regionStart@ by wrapping, so @end < regionStart@
-- detects the overflow exactly. A negative @regionStart@ cannot wrap a
-- non-negative length upward and so is not reported here — it is the
-- apply walk's to reject as the malformed position it is.
boundedWriteEnd :: Offset -> Length -> Maybe Offset
boundedWriteEnd (Offset regionStart) (Length regionLength)
  | end < regionStart = Nothing
  | otherwise         = Just (Offset end)
  where
    end = regionStart + regionLength

byteLength :: ByteString -> Length
byteLength bytes = Length (ByteString.length bytes)

-- | Measure a 'ByteString' as a 'FileSize'.  Parallels 'byteLength',
-- which measures a 'ByteString' as a 'Length' (the size of a part,
-- never of a whole).  Use this for a buffer that is the whole space a
-- cursor addresses: a complete source/target/patch file, or a slice —
-- a decompressed window section, say — that is a region one layer up
-- but the entire space to the walk inside it.  Part-versus-whole is
-- positional, not intrinsic to the bytes: 'FileSize' names whichever
-- side of a bounds check ('fitsWithin', 'remainingFromOffset') plays
-- the total extent.
byteFileSize :: ByteString -> FileSize
byteFileSize bytes = FileSize (ByteString.length bytes)

hunkEnd :: Hunk -> Offset
hunkEnd hunk = advance (hunkOffset hunk) (byteLength (hunkPayload hunk))

----------------------------------------------------------------------------
-- Splitting
----------------------------------------------------------------------------

-- | Split a 'Hunk' into 'SplitHunk's whose payloads are each at most
-- @maxLength@ bytes. Offset advances by chunk length between
-- emissions. Empty payloads pass through as a single empty
-- 'SplitHunk'; callers that want to drop empties must filter at their
-- own level. A 'SplitHunk' is the type-level proof that the
-- payload-bound check happened — every direct-format encoder consumes
-- 'EncodedHunk', which can only be produced by narrowing a 'SplitHunk'
-- in 'Slap.Narrow'.
splitHunk :: Length -> Hunk -> [SplitHunk]
splitHunk maxLength (Hunk startOffset payload)
  | byteLength payload <= maxLength = [SplitHunk startOffset payload]
  | otherwise =
      let (chunk, remaining) = ByteString.splitAt (unLength maxLength) payload
          nextOffset         = advance startOffset maxLength
      in SplitHunk startOffset chunk : splitHunk maxLength (Hunk nextOffset remaining)

-- | Split a list of hunks so every emitted 'SplitHunk' carries a
-- payload of at most @maxLength@ bytes.
splitHunks :: Length -> [Hunk] -> [SplitHunk]
splitHunks maxLength = concatMap (splitHunk maxLength)

-- | Lift a list of 'Hunk's to 'SplitHunk's without payload-bound
-- validation. Only legitimate for formats whose wire encoding
-- imposes no per-record payload cap — currently NINJA1 (variable-
-- width length-of-length, structurally unbounded). Documented
-- opt-out parallel to 'Slap.Narrow.narrowHunksUnbounded'.
splitHunksUnbounded :: [Hunk] -> [SplitHunk]
splitHunksUnbounded = map (\h -> SplitHunk (hunkOffset h) (hunkPayload h))

-- | Split a list of 'Hunk's against the format's per-record payload
-- bound and pair each split piece with the corresponding bytes from
-- @source@ (the original-bytes field every PPF3 undo record carries).
-- Empty payloads produce no output. When a piece extends past the
-- source's end, the missing tail bytes are zero-padded.
splitUndoHunks :: Length -> ByteString -> [Hunk] -> [SplitUndoHunk]
splitUndoHunks maxLength source = concatMap pieces
  where
    sourceLength = ByteString.length source
    pieces h
      | ByteString.null (hunkPayload h) = []
      | otherwise = map perPiece (splitHunk maxLength h)
    perPiece piece =
      SplitUndoHunk
        (splitOffset piece)
        (splitPayload piece)
        (originalAt (unOffset (splitOffset piece))
                    (ByteString.length (splitPayload piece)))
    originalAt position chunkLength
      | position >= sourceLength = ByteString.replicate chunkLength 0
      | position + chunkLength > sourceLength =
          ByteString.take (sourceLength - position) (ByteString.drop position source)
          <> ByteString.replicate (chunkLength - (sourceLength - position)) 0
      | otherwise =
          ByteString.take chunkLength (ByteString.drop position source)

-- | Lift a parsed wire-format undo record to a 'SplitUndoHunk', trusting the parser's payload-bound guarantee.
-- PPF3's wire format prefixes the undo payload with a single byte naming its length, so any 'SplitUndoHunk' constructed here is ≤ 255 bytes by the parser's contract.
-- A named lift rather than a bare constructor keeps every parse-built 'SplitUndoHunk' coming from this one site.
splitUndoHunkFromParsed :: Offset -> ByteString -> ByteString -> SplitUndoHunk
splitUndoHunkFromParsed = SplitUndoHunk

----------------------------------------------------------------------------
-- IPS sentinel values
----------------------------------------------------------------------------

-- | IPS EOF marker value (ASCII "EOF").
ipsSentinel :: Word32
ipsSentinel = 0x454F46

-- | IPS32 EEOF marker value (ASCII "EEOF").
ips32Sentinel :: Word32
ips32Sentinel = 0x45454F46
