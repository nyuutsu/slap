-- | The VCDIFF code table: the 256-entry structure that maps each byte
-- of a window's instruction stream to one or two delta instructions.
--
-- This is the one concept the two VCDIFF flavors — RFC 3284 and
-- xdelta3 — share verbatim, and the only slap format with anything
-- like it, so it earns its own module. Core uses the fixed default
-- table ('defaultCodeTable'); a patch may also carry a custom table on
-- the wire, decoded against the 1536-byte serialized image
-- ('serializeCodeTable' / 'deserializeCodeTable'). Building both
-- directions now lets the round-trip be the proof that the table is
-- right; the custom-table envelope that wraps the image is RFC-arc work
-- that lands later and builds on this representation.
--
-- The module depends on nothing from the rest of the VCDIFF family —
-- it defines its own instruction vocabulary — so it can be laid before
-- that family exists.
--
-- Spec: @docs\/vcdiff\/core\/spec.md@, "Instructions" and "The default
-- code table"; the serialized layout is @docs\/vcdiff\/rfc-vcdiff\/spec.md@.
module Slap.VCDIFF.CodeTable
  ( -- * The instruction-template vocabulary
    InstructionTemplate(..)
  , InstructionSize(..)
  , FixedInstructionSize(..)
  , CopyAddressMode(..)
    -- * The table
  , CodeTableEntry(..)
  , CodeTable
  , codeTableEntries
  , defaultCodeTable
    -- * The serialized 1536-byte image
  , serializeCodeTable
  , deserializeCodeTable
  , serializedCodeTableLength
  , codeTableEntryCount
  ) where

import Slap.Measure (Length(..), ActualLength(..), byteLength)
import Slap.Status (SlapError(..), VCDIFFCodeTableMalformation(..), VCDIFFCodeTableField(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Vector (Vector)
import qualified Data.Vector as Vector
import Data.Word (Word8)

----------------------------------------------------------------------------
-- The instruction-template vocabulary
----------------------------------------------------------------------------

-- | One instruction as the code table /templates/ it: a type, a
-- possibly-deferred size, and — for COPY alone — an address-mode
-- selector. This is not yet a concrete delta instruction; the size may
-- still be coded separately and the address mode still has to be
-- decoded against the address cache. Decode instantiates a template
-- into a 'Slap.VCDIFF.Types.VCDIFFInstruction'. The type is the
-- constructor, never a numeric code; the wire codes (NOOP=0, ADD=1,
-- RUN=2, COPY=3) are facts of serialization, mapped only at the
-- 'serializeCodeTable' / 'deserializeCodeTable' boundary.
--
-- Folding type, size, and mode into one sum makes the spec's implicit
-- rules unrepresentable-when-violated rather than merely documented: a
-- 'Noop' carries no size and no mode (it is the empty half of a
-- single-instruction entry), 'Add' and 'Run' carry a size but no mode,
-- and only 'Copy' carries an address mode. The spec's "a zero mode
-- applies to non-COPY instructions" is then not a convention to
-- remember but a state that cannot be built.
data InstructionTemplate
  = Noop
  | Add  !InstructionSize
  | Run  !InstructionSize
  | Copy !InstructionSize !CopyAddressMode
  deriving (Eq, Ord, Show)

-- | An instruction's size, as the code table holds it. The spec lets a
-- table entry either fix the size inline or defer it: a zero size byte
-- means "the real size is read separately as a varint from the
-- instruction stream." Modeling that as a sum keeps the zero from
-- being a magic value a reader has to know about — 'SizeCodedSeparately'
-- says what the zero means at every site that matches on it.
data InstructionSize
  = SizeCodedSeparately
  | SizeIs !FixedInstructionSize
  deriving (Eq, Ord, Show)

-- | A size fixed inline in the code table: 1–255 on the wire (a zero
-- byte is 'SizeCodedSeparately', not a fixed size of zero). The size
-- arrays are one byte per entry, so the inline ceiling is a 'Word8'.
newtype FixedInstructionSize = FixedInstructionSize { unFixedInstructionSize :: Word8 }
  deriving (Eq, Ord, Show)

-- | A COPY instruction's address mode: the selector the address cache
-- reads to decode the COPY's address (SELF, HERE, a near slot, or a
-- same slot). The legal upper bound depends on the cache
-- configuration — the near-cache and same-cache sizes, plus one, so
-- 0–8 for the default caches — which this layer does not know: the
-- mode array is one byte per entry, and the window decoder, which
-- holds the cache sizes, enforces the bound. Here it is carried
-- verbatim.
newtype CopyAddressMode = CopyAddressMode { unCopyAddressMode :: Word8 }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- The table
----------------------------------------------------------------------------

-- | One code-table entry: the one or two instruction templates a
-- single instruction-stream byte expands to. A 'Noop' in
-- 'secondTemplate' marks the entry as encoding a single instruction.
data CodeTableEntry = CodeTableEntry
  { firstTemplate  :: !InstructionTemplate
  , secondTemplate :: !InstructionTemplate
  }
  deriving (Eq, Ord, Show)

-- | A complete VCDIFF code table: exactly 'codeTableEntryCount'
-- entries, indexed by the instruction-stream byte. The constructor is
-- intentionally not exported: every 'CodeTable' that exists came from
-- 'defaultCodeTable' or 'deserializeCodeTable', both provably
-- 256-wide, so the window decoder's @'Vector.!' codeByte@ lookup is
-- total by construction — the same proof-by-provenance discipline as
-- 'Slap.Measure.SplitHunk'.
newtype CodeTable = CodeTable { codeTableEntries :: Vector CodeTableEntry }
  deriving (Eq, Show)

-- | The fixed default code table (RFC 3284 §5.6,
-- @docs\/vcdiff\/core\/spec.md@). Not stored in a patch; in force
-- whenever a patch supplies no custom table. Every entry is derived
-- from the spec's index ranges below, not transcribed from memory:
--
--   * index 0      — RUN, size coded separately
--   * 1–18         — ADD, size coded separately then sizes 1–17
--   * 19–162       — COPY, for each mode 0–8: size coded separately then sizes 4–18
--   * 163–234      — ADD(1–4) + COPY(4–6), modes 0–5
--   * 235–246      — ADD(1–4) + COPY(4), modes 6–8
--   * 247–255      — COPY(4) + ADD(1), modes 0–8
--
-- In the combined rows the ADD size is the outer loop and the COPY
-- size the inner, so 163 is ADD(1)+COPY(4), 164 ADD(1)+COPY(5), 165
-- ADD(1)+COPY(6), 166 ADD(2)+COPY(4), and so on.
defaultCodeTable :: CodeTable
defaultCodeTable = CodeTable (Vector.fromList (concat
  [ runEntry
  , addEntries
  , copyEntries
  , addCopyEntriesModes0to5
  , addCopyEntriesModes6to8
  , copyAddEntries
  ]))
  where
    -- index 0
    runEntry =
      [ single (Run SizeCodedSeparately) ]

    -- indices 1–18
    addEntries =
      single (Add SizeCodedSeparately)
        : [ single (Add (sized size)) | size <- [1 .. 17] ]

    -- indices 19–162
    copyEntries =
      [ entry
      | mode  <- [0 .. 8]
      , entry <- single (Copy SizeCodedSeparately (CopyAddressMode mode))
                   : [ single (Copy (sized size) (CopyAddressMode mode)) | size <- [4 .. 18] ]
      ]

    -- indices 163–234
    addCopyEntriesModes0to5 =
      [ paired (Add (sized addSize)) (Copy (sized copySize) (CopyAddressMode mode))
      | mode     <- [0 .. 5]
      , addSize  <- [1 .. 4]
      , copySize <- [4 .. 6]
      ]

    -- indices 235–246
    addCopyEntriesModes6to8 =
      [ paired (Add (sized addSize)) (Copy (sized 4) (CopyAddressMode mode))
      | mode    <- [6 .. 8]
      , addSize <- [1 .. 4]
      ]

    -- indices 247–255
    copyAddEntries =
      [ paired (Copy (sized 4) (CopyAddressMode mode)) (Add (sized 1))
      | mode <- [0 .. 8]
      ]

    single :: InstructionTemplate -> CodeTableEntry
    single template = CodeTableEntry template Noop

    paired :: InstructionTemplate -> InstructionTemplate -> CodeTableEntry
    paired = CodeTableEntry

    sized :: Word8 -> InstructionSize
    sized = SizeIs . FixedInstructionSize

----------------------------------------------------------------------------
-- The serialized 1536-byte image
----------------------------------------------------------------------------

-- | The number of entries in any VCDIFF code table.
codeTableEntryCount :: Int
codeTableEntryCount = 256

-- | The byte length of a serialized code table: six
-- 'codeTableEntryCount'-byte arrays (the first instruction's types,
-- the second's types, then likewise for sizes and modes). 1536 with
-- the default count.
serializedCodeTableLength :: Length
serializedCodeTableLength = Length (6 * codeTableEntryCount)

-- | Serialize a code table to its 1536-byte image: six byte arrays,
-- one byte per entry — the first instruction's types, the second's
-- types, then likewise for sizes and modes. This is the image a
-- custom-table inner delta applies against; 'deserializeCodeTable' is
-- its inverse.
serializeCodeTable :: CodeTable -> ByteString
serializeCodeTable (CodeTable entries) = ByteString.pack
  (  map (wireType . firstTemplate)  rows
  ++ map (wireType . secondTemplate) rows
  ++ map (wireSize . firstTemplate)  rows
  ++ map (wireSize . secondTemplate) rows
  ++ map (wireMode . firstTemplate)  rows
  ++ map (wireMode . secondTemplate) rows )
  where rows = Vector.toList entries

-- | Read a 1536-byte image back into a code table — the reader a custom
-- code table needs. Rejects an image of the wrong width, a type byte
-- that names no instruction, or a nonzero size or mode byte on a
-- template type that carries no such field, through the existing
-- VCDIFF code-table error vocabulary. Every check decidable from the
-- image alone happens here; a COPY's mode byte is carried verbatim
-- ('CopyAddressMode'), because its legal range is cache-dependent and
-- belongs to the window decoder, not here.
deserializeCodeTable :: ByteString -> Either SlapError CodeTable
deserializeCodeTable image
  | byteLength image /= serializedCodeTableLength =
      Left (MalformedVCDIFFCodeTable
              (VCDIFFCodeTableWrongLength (ActualLength (byteLength image))))
  | otherwise =
      CodeTable . Vector.fromList <$> traverse decodeEntryAt [0 .. codeTableEntryCount - 1]
  where
    (firstTypes,  afterFirstTypes)  = ByteString.splitAt codeTableEntryCount image
    (secondTypes, afterSecondTypes) = ByteString.splitAt codeTableEntryCount afterFirstTypes
    (firstSizes,  afterFirstSizes)  = ByteString.splitAt codeTableEntryCount afterSecondTypes
    (secondSizes, afterSecondSizes) = ByteString.splitAt codeTableEntryCount afterFirstSizes
    (firstModes,  secondModes)      = ByteString.splitAt codeTableEntryCount afterSecondSizes

    decodeEntryAt index =
      CodeTableEntry
        <$> decodeInstructionTemplate (ByteString.index firstTypes index)
                                      (ByteString.index firstSizes index)
                                      (ByteString.index firstModes index)
        <*> decodeInstructionTemplate (ByteString.index secondTypes index)
                                      (ByteString.index secondSizes index)
                                      (ByteString.index secondModes index)

-- The wire codes for the four instruction types. Together with the
-- zero an absent size or mode serializes as, these four constants are
-- the entire numeric vocabulary of the code table; all of it lives at
-- the serialization boundary and nowhere else.
noopWireCode, addWireCode, runWireCode, copyWireCode :: Word8
noopWireCode = 0
addWireCode  = 1
runWireCode  = 2
copyWireCode = 3

wireType :: InstructionTemplate -> Word8
wireType Noop       = noopWireCode
wireType (Add _)    = addWireCode
wireType (Run _)    = runWireCode
wireType (Copy _ _) = copyWireCode

wireSize :: InstructionTemplate -> Word8
wireSize Noop          = 0
wireSize (Add size)    = sizeWireByte size
wireSize (Run size)    = sizeWireByte size
wireSize (Copy size _) = sizeWireByte size

wireMode :: InstructionTemplate -> Word8
wireMode Noop                          = 0
wireMode (Add _)                       = 0
wireMode (Run _)                       = 0
wireMode (Copy _ (CopyAddressMode mode)) = mode

sizeWireByte :: InstructionSize -> Word8
sizeWireByte SizeCodedSeparately                       = 0
sizeWireByte (SizeIs (FixedInstructionSize fixedSize)) = fixedSize

-- | Reconstruct one instruction template from its three wire bytes.
-- A type byte outside the four codes is malformed; a size of zero
-- means 'SizeCodedSeparately'; and a size or mode byte must be zero
-- for a type that carries no such field — the don't-care positions
-- have exactly one well-formed value, so a nonzero one is refused as
-- evidence of damage rather than read past
-- (docs/vcdiff/rfc-vcdiff/questions.md, "invalid decoded-table
-- entries").
decodeInstructionTemplate :: Word8 -> Word8 -> Word8 -> Either SlapError InstructionTemplate
decodeInstructionTemplate typeByte sizeByte modeByte
  | typeByte == noopWireCode = do
      requireUnusedFieldZero CodeTableSizeField sizeByte
      requireUnusedFieldZero CodeTableModeField modeByte
      Right Noop
  | typeByte == addWireCode = do
      requireUnusedFieldZero CodeTableModeField modeByte
      Right (Add (decodeSize sizeByte))
  | typeByte == runWireCode = do
      requireUnusedFieldZero CodeTableModeField modeByte
      Right (Run (decodeSize sizeByte))
  | typeByte == copyWireCode = Right (Copy (decodeSize sizeByte) (CopyAddressMode modeByte))
  | otherwise =
      Left (MalformedVCDIFFCodeTable (VCDIFFCodeTableInvalidInstructionType typeByte))

-- | Refuse a nonzero byte in a field its template type does not carry.
requireUnusedFieldZero :: VCDIFFCodeTableField -> Word8 -> Either SlapError ()
requireUnusedFieldZero _ 0 = Right ()
requireUnusedFieldZero field byte =
  Left (MalformedVCDIFFCodeTable (VCDIFFCodeTableUnusedFieldSet field byte))

decodeSize :: Word8 -> InstructionSize
decodeSize 0        = SizeCodedSeparately
decodeSize sizeByte = SizeIs (FixedInstructionSize sizeByte)
