-- | The VCDIFF code table: the 256-entry structure mapping each byte of a window's instruction stream to one or two delta instructions.
--
-- The one concept the two flavors (RFC 3284 and xdelta3) share verbatim, and the only slap format with anything like it, so it earns its own module.
-- Core uses the fixed default table ('defaultCodeTable'); a patch may also carry a custom table on the wire, decoded against the 1536-byte serialized image ('serializeCodeTable' \/ 'deserializeCodeTable').
--
-- The module depends on nothing else in the VCDIFF family: it defines its own instruction vocabulary.
--
-- Spec: @docs\/vcdiff\/core\/spec.md@, "Instructions" and "The default code table"; the serialized layout is @docs\/vcdiff\/rfc-vcdiff\/spec.md@.
module Slap.VCDIFF.CodeTable
  ( -- * The instruction-template vocabulary
    InstructionTemplate(..)
  , InstructionSize(..)
  , FixedInstructionSize(..)
  , CopyAddressMode(..)
    -- * The table
  , CodeTableEntry(..)
  , Opcode(..)
  , CodeTable
  , codeTableEntries
  , codeTableEntry
  , codeTableAssocs
  , defaultCodeTable
  , codeTableWithEntriesReplaced
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

-- | One instruction as the code table /templates/ it: a type, a possibly-deferred size, and (for COPY alone) an address-mode selector.
-- Not yet a concrete delta instruction: the size may still be coded separately and the address mode still has to be decoded against the address cache. Decode instantiates a template into a 'Slap.VCDIFF.Types.VCDIFFInstruction'.
-- The type is the constructor, never a numeric code; the wire codes (NOOP=0, ADD=1, RUN=2, COPY=3) are facts of serialization, mapped only at the 'serializeCodeTable' \/ 'deserializeCodeTable' boundary.
--
-- Folding type, size, and mode into one sum makes the spec's implicit rules unrepresentable when violated rather than merely documented: 'Noop' carries no size and no mode (the empty half of a single-instruction entry), 'Add' and 'Run' a size but no mode, only 'Copy' an address mode.
-- The spec's "a zero mode applies to non-COPY instructions" is then not a convention to remember but a state that cannot be built.
data InstructionTemplate
  = Noop
  | Add  !InstructionSize
  | Run  !InstructionSize
  | Copy !InstructionSize !CopyAddressMode
  deriving (Eq, Ord, Show)

-- | An instruction's size, as the code table holds it: fixed inline, or deferred, a zero size byte meaning "the real size is read separately as a varint from the instruction stream."
-- Modeling that as a sum keeps the zero from being a magic value a reader has to know: 'SizeCodedSeparately' says what it means at every site that matches on it.
data InstructionSize
  = SizeCodedSeparately
  | SizeIs !FixedInstructionSize
  deriving (Eq, Ord, Show)

-- | A size fixed inline in the code table: 1–255 on the wire (a zero byte is 'SizeCodedSeparately', not a fixed size of zero).
-- The size arrays are one byte per entry, so the inline ceiling is a 'Word8'.
newtype FixedInstructionSize = FixedInstructionSize { unFixedInstructionSize :: Word8 }
  deriving (Eq, Ord, Show)

-- | A COPY instruction's address mode: the selector the address cache reads to decode the COPY's address (SELF, HERE, a near slot, or a same slot).
-- Its legal upper bound is cache-dependent (the near and same sizes plus one, so 0–8 for the default caches) and this layer does not know it: the window decoder, which holds the cache sizes, enforces the bound, and here the mode is carried verbatim.
newtype CopyAddressMode = CopyAddressMode { unCopyAddressMode :: Word8 }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- The table
----------------------------------------------------------------------------

-- | One code-table entry: the one or two instruction templates a single instruction-stream byte expands to. A 'Noop' in 'secondTemplate' marks a single-instruction entry.
data CodeTableEntry = CodeTableEntry
  { firstTemplate  :: !InstructionTemplate
  , secondTemplate :: !InstructionTemplate
  }
  deriving (Eq, Ord, Show)

-- | A complete VCDIFF code table: exactly 'codeTableEntryCount' entries, indexed by the instruction-stream byte.
-- The constructor is not exported, so every 'CodeTable' came from 'defaultCodeTable', 'deserializeCodeTable', or 'codeTableWithEntriesReplaced', all provably 256-wide, making 'codeTableEntry' total: the same proof-by-provenance discipline as 'Slap.Measure.SplitHunk'.
newtype CodeTable = CodeTable { codeTableEntries :: Vector CodeTableEntry }
  deriving (Eq, Show)

-- | An opcode: one byte of a window's instruction stream, indexing the code table to the one or two templates it expands to.
-- The wrapper names the role in every signature it crosses and keeps it distinct from the other bytes encode and decode pass (a fill byte, a same-slot operand).
-- Its range is the whole 'Word8', exactly the 'codeTableEntryCount' entries a table holds, which is what makes 'codeTableEntry' total.
newtype Opcode = Opcode { unOpcode :: Word8 }
  deriving (Eq, Ord, Show)

-- | The entry an opcode selects. Total by provenance: an 'Opcode' wraps a 'Word8' so the index lands in @[0, 'codeTableEntryCount')@, and every 'CodeTable' is that wide.
-- The window decoder's per-instruction lookup, with the raw 'Vector.!' kept here, not at the call site.
codeTableEntry :: CodeTable -> Opcode -> CodeTableEntry
codeTableEntry (CodeTable entries) (Opcode opcode) = entries Vector.! fromIntegral opcode

-- | Every entry paired with the opcode that selects it, in opcode order: the inverse of 'codeTableEntry'.
-- The encoder reads its opcode set off this rather than zipping indices onto the raw entry vector by hand.
codeTableAssocs :: CodeTable -> [(Opcode, CodeTableEntry)]
codeTableAssocs (CodeTable entries) =
  [ (Opcode (fromIntegral index), entry)
  | (index, entry) <- zip [0 :: Int ..] (Vector.toList entries) ]

-- | The fixed default code table (RFC 3284 §5.6, @docs\/vcdiff\/core\/spec.md@). Not stored in a patch; in force whenever a patch supplies no custom table.
-- Every entry is derived from the spec's index ranges below, not transcribed from memory:
--
--   * index 0   : RUN, size coded separately
--   * 1–18      : ADD, size coded separately then sizes 1–17
--   * 19–162    : COPY, for each mode 0–8, size coded separately then sizes 4–18
--   * 163–234   : ADD(1–4) + COPY(4–6), modes 0–5
--   * 235–246   : ADD(1–4) + COPY(4), modes 6–8
--   * 247–255   : COPY(4) + ADD(1), modes 0–8
--
-- In the combined rows the ADD size is the outer loop and the COPY size the inner, so 163 is ADD(1)+COPY(4), 164 ADD(1)+COPY(5), 165 ADD(1)+COPY(6), 166 ADD(2)+COPY(4), and so on.
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

-- | Derive a code table from another by replacing the entries at the listed opcodes, leaving every other entry untouched.
-- The base supplies the entry count and the result keeps it ('Vector.//' preserves length, and every 'Opcode' wraps a 'Word8'), so a table built this way is as total under 'codeTableEntry' as 'defaultCodeTable' and 'deserializeCodeTable'.
-- The third and last way a 'CodeTable' comes to exist: the encoder mints a handful of combined entries into donor opcodes the patch never uses, keeping the rest of the default table intact (@docs\/vcdiff\/rfc-vcdiff\/spec.md@, "Custom code tables").
codeTableWithEntriesReplaced :: CodeTable -> [(Opcode, CodeTableEntry)] -> CodeTable
codeTableWithEntriesReplaced (CodeTable entries) replacements =
  CodeTable (entries Vector.// [ (fromIntegral (unOpcode opcode), entry) | (opcode, entry) <- replacements ])

----------------------------------------------------------------------------
-- The serialized 1536-byte image
----------------------------------------------------------------------------

-- | The number of entries in any VCDIFF code table.
codeTableEntryCount :: Int
codeTableEntryCount = 256

-- | The byte length of a serialized code table: six 'codeTableEntryCount'-byte arrays (the two instructions' types, then sizes, then modes). 1536 with the default count.
serializedCodeTableLength :: Length
serializedCodeTableLength = Length (6 * codeTableEntryCount)

-- | Serialize a code table to its 1536-byte image: six byte arrays, one byte per entry, the two instructions' types, then sizes, then modes.
-- The image a custom-table inner delta applies against; 'deserializeCodeTable' is its inverse.
serializeCodeTable :: CodeTable -> ByteString
serializeCodeTable (CodeTable entries) = ByteString.pack
  (  map (wireType . firstTemplate)  rows
  ++ map (wireType . secondTemplate) rows
  ++ map (wireSize . firstTemplate)  rows
  ++ map (wireSize . secondTemplate) rows
  ++ map (wireMode . firstTemplate)  rows
  ++ map (wireMode . secondTemplate) rows )
  where rows = Vector.toList entries

-- | Read a 1536-byte image back into a code table, the reader a custom code table needs.
-- Rejects a wrong-width image, a type byte that names no instruction, or a nonzero size or mode byte on a template type that carries no such field, through the existing VCDIFF code-table error vocabulary.
-- Every check decidable from the image alone happens here; a COPY's mode byte is carried verbatim ('CopyAddressMode'), its legal range being cache-dependent and the window decoder's, not here.
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

-- The wire codes for the four instruction types. With the zero an absent size or mode serializes as, these four constants are the code table's entire numeric vocabulary, all of it at the serialization boundary and nowhere else.
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
-- A type byte outside the four codes is malformed; a size of zero means 'SizeCodedSeparately'; a size or mode byte must be zero for a type that carries no such field.
-- The don't-care positions have exactly one well-formed value, so a nonzero one is refused as evidence of damage rather than read past (docs/vcdiff/rfc-vcdiff/questions.md, "invalid decoded-table entries").
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
