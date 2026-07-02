-- | The VCDIFF address cache: the codec vocabulary both directions share for the compact encoding of COPY addresses (RFC 3284 §5, @docs\/vcdiff\/core\/spec.md@ "Address cache").
--
-- A decoder maintains two small caches, a round-robin /near/ cache and a modulo-slotted /same/ cache, resetting them per window and updating both after every COPY.
-- A later COPY can then name its address as a short distance off a recent one (NEAR) or as a single byte when a slot already holds it (SAME), instead of the full offset (SELF) or a distance back from the write head (HERE). The encoder chooses among those modes; the decoder reads whichever was chosen.
--
-- The cache's home, because the encoder and decoder do not run the same /kind/ of cache but /one/ cache, which must hold byte-identical state at every step: the moment they diverge, a NEAR or SAME address decodes to the wrong place and the patch is silently wrong.
-- So 'recordAddress', the post-COPY update, has exactly one definition, run by 'decodeCopyAddress' on the way in and 'selectCopyAddressMode' on the way out, the two side by side here as inverses, the way 'Slap.VCDIFF.CodeTable' keeps its serializer beside its deserializer.
--
-- The vocabulary is format-defined and pure (no 'Slap.ByteParser', no 'Slap.Status'), so it sits below 'Slap.VCDIFF.Parse' (which imports it and re-exports the testing surface) and 'Slap.VCDIFF.Create' (which imports the selection), neither reaching into the other.
module Slap.VCDIFF.AddressCache
  ( -- * Configuration and caches
    AddressCacheConfig(..)
  , NearSlotCount(..)
  , SameBlockCount(..)
  , defaultAddressCacheConfig
  , NearSlotIndex(..)
  , SameBlockIndex(..)
  , SameSlotByte(..)
  , AddressCache(..)
  , slotsPerSameBlock
  , sameSlotCount
  , readNearSlot
  , readSameSlot
  , advanceNearWriteSlot
  , nearSlotIndices
  , freshAddressCache
  , recordAddress
    -- * Address-mode layout
  , selfMode
  , hereMode
  , firstNearMode
  , firstSameMode
  , modeCeiling
    -- * Mode classification
  , AddressModeFamily(..)
  , classifyAddressMode
  , modeFamilyToByte
    -- * Decode (mode + operand -> address)
  , decodeCopyAddress
  , CopyAddressReading(..)
  , AddressDecodeFailure(..)
    -- * Encode (address -> cheapest mode + operand)
  , selectCopyAddressMode
  , SelectedCopyAddress(..)
  , CopyAddressOperand(..)
  ) where

import Slap.Measure
  ( Offset(..), Length(..), Delta(..)
  , Cursor(..), fitsWithin, offsetToInt, byteFileSize )
import Slap.Binary (getVcdiffVarint, VarintResult(..), minimalVcdiffVarintLength)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Int (Int64)
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.List (minimumBy)
import Data.Ord (comparing)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Configuration and caches
----------------------------------------------------------------------------

-- | @s_near@: the number of near slots a cache holds. A role newtype over 'Int' so it cannot be transposed with 'SameBlockCount': the two share a base type and are built side by side from two adjacent wire bytes ('Slap.VCDIFF.Parse' peels a custom table's @s_near@\/@s_same@ pair), so a bare-'Int' pair would admit a silent swap decoding every COPY address through the wrong cache.
newtype NearSlotCount = NearSlotCount { unNearSlotCount :: Int }
  deriving (Eq, Show)

-- | @s_same@: the number of 256-slot same blocks a cache holds. The peer of 'NearSlotCount'; see its note for why both are newtypes, not 'Int's.
newtype SameBlockCount = SameBlockCount { unSameBlockCount :: Int }
  deriving (Eq, Show)

-- | How many slots each cache holds: @s_near@ near slots and @s_same@ 256-slot same blocks.
-- The default code table fixes these ('defaultAddressCacheConfig'); a custom code table declares its own.
-- The cache carries its configuration so the sizes drive the round-robin wrap, the slot bounds, and the same-block arithmetic at runtime, rather than being baked into the types.
data AddressCacheConfig = AddressCacheConfig
  { nearSlotCount  :: !NearSlotCount
  , sameBlockCount :: !SameBlockCount
  }
  deriving (Eq, Show)

-- | The default code table's cache configuration: four near slots and three same blocks, the core's nine address modes (0–8). The one place @4@ and @3@ are named.
defaultAddressCacheConfig :: AddressCacheConfig
defaultAddressCacheConfig = AddressCacheConfig
  { nearSlotCount  = NearSlotCount 4
  , sameBlockCount = SameBlockCount 3
  }

-- | A near-cache slot index, in @[0, s_near)@. Constructed only within bounds, by 'classifyAddressMode' from a mode in the near band and by 'advanceNearWriteSlot' whose modulus keeps it in range, so a slot the cache lacks is unrepresentable, the guarantee total over any @s_near@ and living where the index is made.
newtype NearSlotIndex = NearSlotIndex Int
  deriving (Eq, Show)

-- | A same-cache block index, in @[0, s_same)@.
-- Constructed only within bounds by 'classifyAddressMode' from a mode in the same band, with the same guarantee as 'NearSlotIndex'.
newtype SameBlockIndex = SameBlockIndex Int
  deriving (Eq, Show)

-- | A same-cache within-block slot byte: the one-byte SAME operand indexing within a 'SameBlockIndex'. A 'Word8' because a same block holds 256 slots.
newtype SameSlotByte = SameSlotByte Word8
  deriving (Eq, Show)

-- | The two address caches a VCDIFF decoder maintains in lockstep with the encoder, the configuration that sizes them, and the next near slot to overwrite. Both reset to empty at the start of every window and update after every COPY.
--
-- The two caches are one idea twice: each an 'IntMap' keyed by slot, read with a zero default (an untouched slot decodes address 0, so the empty 'IntMap' /is/ the semantics) and written one slot at a time.
-- The cache threads linearly through the decode, each value consumed once to produce the next; a per-COPY 'IntMap' path-copy is the cheap update an array clone would not be.
data AddressCache = AddressCache
  { cacheConfig       :: !AddressCacheConfig
  , nearAddresses     :: !(IntMap Offset)
    -- ^ The near cache, keyed by slot index in @[0, s_near)@.
  , sameAddresses     :: !(IntMap Offset)
    -- ^ The same cache, keyed by @address mod (256 * s_same)@.
  , nextNearWriteSlot :: !NearSlotIndex
    -- ^ The next near slot to overwrite, advanced round-robin.
  }
  deriving (Eq, Show)

-- | The slots in one same block, fixed by the format: a same-mode COPY's one-byte operand indexes within the block, so a block spans 256 slots regardless of configuration.
slotsPerSameBlock :: Int
slotsPerSameBlock = 256

sameSlotCount :: AddressCacheConfig -> Int
sameSlotCount config = unSameBlockCount (sameBlockCount config) * slotsPerSameBlock

-- | The address held in one near slot.
readNearSlot :: NearSlotIndex -> IntMap Offset -> Offset
readNearSlot (NearSlotIndex slot) = IntMap.findWithDefault (Offset 0) slot

-- | The next near write slot, round-robin. The modulus is safe: 'nearSlotCount' is positive and the result lands in @[0, s_near)@.
advanceNearWriteSlot :: AddressCacheConfig -> NearSlotIndex -> NearSlotIndex
advanceNearWriteSlot config (NearSlotIndex slot) =
  NearSlotIndex ((slot + 1) `mod` unNearSlotCount (nearSlotCount config))

-- | The near slots a configuration defines, in order: @[0, s_near)@ as typed indices.
-- The one place the count becomes a sequence, so the encoder's near-slot search iterates these rather than a bare 'Int' range.
nearSlotIndices :: AddressCacheConfig -> [NearSlotIndex]
nearSlotIndices config =
  [ NearSlotIndex slot | slot <- [0 .. unNearSlotCount (nearSlotCount config) - 1] ]

-- | The address held in one same slot: the block index and the one-byte operand select within the block's 256-slot span.
readSameSlot :: SameBlockIndex -> SameSlotByte -> IntMap Offset -> Offset
readSameSlot (SameBlockIndex block) (SameSlotByte slotByte) =
  IntMap.findWithDefault (Offset 0) (block * slotsPerSameBlock + fromIntegral slotByte)

-- | A zeroed cache for the given configuration, as at the start of each window.
freshAddressCache :: AddressCacheConfig -> AddressCache
freshAddressCache config = AddressCache
  { cacheConfig       = config
  , nearAddresses     = IntMap.empty
  , sameAddresses     = IntMap.empty
  , nextNearWriteSlot = NearSlotIndex 0
  }

-- | Write a freshly-handled address into both caches: the near cache at the current write slot (then advancing round-robin) and the same cache at @address mod (256 * s_same)@.
recordAddress :: AddressCache -> Offset -> AddressCache
recordAddress cache address = cache
  { nearAddresses     = IntMap.insert writeSlot address (nearAddresses cache)
  , nextNearWriteSlot = advanceNearWriteSlot config (nextNearWriteSlot cache)
  , sameAddresses     = IntMap.insert (offsetToInt address `mod` sameSlotCount config) address (sameAddresses cache)
  }
  where
    config                  = cacheConfig cache
    NearSlotIndex writeSlot = nextNearWriteSlot cache

----------------------------------------------------------------------------
-- The address-mode layout
----------------------------------------------------------------------------

-- | SELF (0) and HERE (1): the two fixed modes before the near band.
-- SELF reads the address as a varint; HERE reads it as a distance back from the write head.
selfMode, hereMode :: Int
selfMode = 0
hereMode = 1

-- | The first address mode that names a near slot. SELF (0) and HERE (1) precede the near band, so it always begins at mode 2, whatever the cache sizes.
-- A near mode names the slot at its distance past this base, and a near slot's mode byte is this base plus its index: the one mapping 'classifyAddressMode' reads and 'selectCopyAddressMode' writes.
firstNearMode :: Int
firstNearMode = 2

-- | The first address mode that names a same block: the near band fills @s_near@ modes up from 'firstNearMode', so the same band begins just past it.
-- Decode ('classifyAddressMode') and encode ('selectCopyAddressMode') must place this boundary identically, or a same-mode address decodes through the wrong band, so it has one definition here, derived from @s_near@ (RFC 3284 §5.3).
firstSameMode :: AddressCacheConfig -> Int
firstSameMode config = firstNearMode + unNearSlotCount (nearSlotCount config)

-- | One past the last address mode the cache defines: the same band fills @s_same@ modes up from 'firstSameMode'.
-- A mode at or above this names no band: 'classifyAddressMode' returns 'Nothing', and the custom-table check rejects a COPY template that reaches it.
modeCeiling :: AddressCacheConfig -> Int
modeCeiling config = firstSameMode config + unSameBlockCount (sameBlockCount config)

----------------------------------------------------------------------------
-- Mode classification
----------------------------------------------------------------------------

-- | What a COPY address mode byte asks for, classified before any bytes are read: one of the two varint modes, a near-slot read, or a same-block read.
-- The wire's mode arithmetic (RFC 3284 §5.3's @2 + s_near + s_same@ bands) is collapsed into the classifier; everything after dispatches on named cases.
data AddressModeFamily
  = SelfAddress
    -- ^ Mode 0 (SELF): the address is a varint, read directly.
  | HereAddress
    -- ^ Mode 1 (HERE): the address is @here@ minus a varint.
  | NearAddress !NearSlotIndex
    -- ^ Near modes: a varint added to the slot's cached address.
  | SameAddress !SameBlockIndex
    -- ^ Same modes: a single byte indexing the block's 256 slots.

-- | Name a mode byte's family against a cache configuration: SELF, then HERE, then 'nearSlotCount' near slots, then 'sameBlockCount' same blocks (RFC 3284 §5.3's @2 + s_near + s_same@ bands).
-- 'Nothing' is a mode past the last band, the 'UnknownAddressMode' decline at the caller.
classifyAddressMode :: AddressCacheConfig -> Word8 -> Maybe AddressModeFamily
classifyAddressMode config mode
  | modeNumber == selfMode            = Just SelfAddress
  | modeNumber == hereMode            = Just HereAddress
  | modeNumber < firstSameMode config = Just (NearAddress (NearSlotIndex (modeNumber - firstNearMode)))
  | modeNumber < modeCeiling config   = Just (SameAddress (SameBlockIndex (modeNumber - firstSameMode config)))
  | otherwise                         = Nothing
  where
    modeNumber = fromIntegral mode

-- | The mode byte that names a family: the inverse of 'classifyAddressMode'.
modeFamilyToByte :: AddressCacheConfig -> AddressModeFamily -> Word8
modeFamilyToByte config family = case family of
  SelfAddress                        -> fromIntegral selfMode
  HereAddress                        -> fromIntegral hereMode
  NearAddress (NearSlotIndex slot)   -> fromIntegral (firstNearMode + slot)
  SameAddress (SameBlockIndex block) -> fromIntegral (firstSameMode config + block)

----------------------------------------------------------------------------
-- Decode (mode + operand -> address)
----------------------------------------------------------------------------

-- | Why 'decodeCopyAddress' could not produce an address. Mapped to a 'Slap.Status.VCDIFFMalformation' by the caller, which holds the instruction index these lack.
data AddressDecodeFailure
  = AddressSectionExhausted
  | UnknownAddressMode !Word8
  deriving (Eq, Show)

-- | The product of one COPY-address decode: the absolute address into the superstring, plus the post-state the decode leaves behind, the cache with the address recorded and the address-section cursor advanced past the consumed bytes.
data CopyAddressReading = CopyAddressReading
  { copyAddressDecoded     :: !Offset
    -- ^ The absolute superstring address the COPY names.
  , copyAddressCacheAfter  :: !AddressCache
  , copyAddressCursorAfter :: !Offset
    -- ^ The address-section position just past the bytes this decode consumed.
  }
  deriving (Eq, Show)

-- | Decode one COPY address from the address section, given the cache, the current @here@ position in the superstring, and the address mode (families classified by 'classifyAddressMode').
-- The upstream half of a two-stage pipeline: the absolute @U@ offset decoded here is what 'Slap.VCDIFF.Apply.resolveCopyAddress' later resolves into a physical read.
decodeCopyAddress
  :: AddressCache -> Offset -> Word8 -> ByteString -> Offset
  -> Either AddressDecodeFailure CopyAddressReading
decodeCopyAddress cache here mode addrSection cursor =
  case classifyAddressMode (cacheConfig cache) mode of
    Nothing -> Left (UnknownAddressMode mode)
    Just SelfAddress -> fromVarint Offset
    Just HereAddress -> fromVarint (\value -> displace here (Delta (negate value)))
    Just (NearAddress nearSlot) ->
      fromVarint (\value -> advance (readNearSlot nearSlot (nearAddresses cache)) (Length value))
    Just (SameAddress sameBlock) -> fromSameByte sameBlock
  where
    fromVarint computeAddress =
      case getVcdiffVarint (offsetToInt cursor) addrSection of
        Left _ -> Left AddressSectionExhausted
        Right (VarintResult value consumed) ->
          Right (readingOf (computeAddress (fromIntegral value))
                           (advance cursor (Length consumed)))

    fromSameByte sameBlock
      | fitsWithin cursor (Length 1) (byteFileSize addrSection) =
          let slotByte = SameSlotByte (ByteString.index addrSection (offsetToInt cursor))
          in Right (readingOf (readSameSlot sameBlock slotByte (sameAddresses cache))
                              (advance cursor (Length 1)))
      | otherwise = Left AddressSectionExhausted

    readingOf address cursorAfter = CopyAddressReading
      { copyAddressDecoded     = address
      , copyAddressCacheAfter  = recordAddress cache address
      , copyAddressCursorAfter = cursorAfter
      }

----------------------------------------------------------------------------
-- Encode (address -> cheapest mode + operand)
----------------------------------------------------------------------------

-- | A COPY's address-section operand, as the chosen mode reads it back: a varint for SELF \/ HERE \/ NEAR, a single byte for SAME.
data CopyAddressOperand
  = AddressVarint !Int64
    -- ^ The varint a SELF, HERE, or NEAR mode reads: the address, the distance back from @here@, or the distance forward from a near slot.
  | AddressSameByte !SameSlotByte
    -- ^ The single byte a SAME mode reads to index its block.
  deriving (Eq, Show)

-- | The encoder's choice for one COPY: the mode byte to emit (matching a 'Slap.VCDIFF.CodeTable.CopyAddressMode' the active table can name), the operand that mode reads back to the address, and the cache after recording the address.
data SelectedCopyAddress = SelectedCopyAddress
  { selectedAddressMode       :: !Word8
  , selectedAddressOperand    :: !CopyAddressOperand
  , selectedAddressCacheAfter :: !AddressCache
  }
  deriving (Eq, Show)

-- | One candidate encoding of an address: a mode, its operand, and the address-section byte count it would cost. Internal to the selection.
data AddressCandidate = AddressCandidate
  { candidateMode    :: !Word8
  , candidateOperand :: !CopyAddressOperand
  , candidateCost    :: !Int
  }

-- | Choose the cheapest encoding of a COPY's absolute superstring address against the current cache and the write head @here@, then record the address so the encoder's cache tracks the decoder's.
-- The inverse of 'decodeCopyAddress', reusing the same slot arithmetic so "is this address in its slot" is the very computation 'recordAddress' placed it by: agreement by reuse, not parallel re-derivation.
--
-- Cheapest is by emitted address-section bytes, with SELF (the address verbatim, always available) as the baseline a cache mode must beat outright.
-- SAME is a single byte, so it wins whenever the address already sits in its same-slot and SELF would spend more than one. NEAR is the smallest forward delta off a near slot, HERE the distance back from @here@; each is taken only when strictly shorter than SELF.
-- A mode that merely ties SELF (an untouched near slot whose zero default equals the address, a same-slot holding an address SELF encodes just as short) leaves the plain offset in place, so a cache mode appears exactly where it shrinks the section and SELF is the default everywhere else.
selectCopyAddressMode :: AddressCache -> Offset -> Offset -> SelectedCopyAddress
selectCopyAddressMode cache here address = recordInto chosen
  where
    config     = cacheConfig cache
    addressInt = offsetToInt address
    hereInt    = offsetToInt here

    -- The cheapest candidate, SELF first so it takes every tie: 'minimumBy' keeps the first least, so among equal-cost modes the earlier-listed wins.
    chosen :: AddressCandidate
    chosen = minimumBy (comparing candidateCost) (selfCandidate : cacheCandidates)

    -- The cache-mode candidates, in the order a tie favours them.
    cacheCandidates :: [AddressCandidate]
    cacheCandidates = maybe [] pure sameCandidate ++ nearCandidate ++ [hereCandidate]

    -- SAME: available exactly when the address's same-slot already holds it (an untouched slot holds zero, legitimately matching address zero). The operand is the byte indexing within the block.
    sameCandidate :: Maybe AddressCandidate
    sameCandidate
      | readSameSlot (SameBlockIndex block) slotByte (sameAddresses cache) == address =
          Just (AddressCandidate (modeFamilyToByte config (SameAddress (SameBlockIndex block))) (AddressSameByte slotByte) 1)
      | otherwise = Nothing
      where
        globalSlot = addressInt `mod` sameSlotCount config
        block      = globalSlot `div` slotsPerSameBlock
        -- The remainder is in @[0, 256)@, the exact 'Word8' range.
        slotByte   = SameSlotByte (fromIntegral (globalSlot `mod` slotsPerSameBlock))

    -- NEAR: the slot with the smallest forward delta among those whose cached address does not exceed this one.
    nearCandidate :: [AddressCandidate]
    nearCandidate = case forwardNearSlots of
      []    -> []
      slots -> let (slot, delta) = minimumBy (comparing snd) slots
               in [varintCandidate (modeFamilyToByte config (NearAddress slot)) delta]

    forwardNearSlots :: [(NearSlotIndex, Int)]   -- (slot, forward delta)
    forwardNearSlots =
      [ (slot, addressInt - slotAddrInt)
      | slot <- nearSlotIndices config
      , let slotAddrInt = offsetToInt (readNearSlot slot (nearAddresses cache))
      , slotAddrInt <= addressInt
      ]

    hereCandidate = varintCandidate (modeFamilyToByte config HereAddress) (hereInt - addressInt)
    selfCandidate = varintCandidate (modeFamilyToByte config SelfAddress) addressInt

    varintCandidate :: Word8 -> Int -> AddressCandidate
    varintCandidate mode value =
      AddressCandidate mode (AddressVarint (fromIntegral value))
        (minimalVcdiffVarintLength (fromIntegral value))

    recordInto candidate = SelectedCopyAddress
      { selectedAddressMode       = candidateMode candidate
      , selectedAddressOperand    = candidateOperand candidate
      , selectedAddressCacheAfter = recordAddress cache address
      }
