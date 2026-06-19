-- | The VCDIFF address cache: the codec vocabulary both directions
-- share for the compact encoding of COPY addresses (RFC 3284 §5,
-- @docs\/vcdiff\/core\/spec.md@ "Address cache").
--
-- A decoder maintains two small caches — a round-robin /near/ cache and
-- a modulo-slotted /same/ cache — resetting them per window and updating
-- both after every COPY, so a later COPY can name its address as a short
-- distance off a recent one (NEAR), or as a single byte when a slot
-- already holds it (SAME), instead of the full offset (SELF) or a
-- distance back from the write head (HERE). The encoder chooses among
-- those same modes; the decoder reads whichever was chosen.
--
-- This module is the cache's home because the encoder and decoder do not
-- merely run the /same kind/ of cache — they run /one/ cache, and it
-- must hold byte-identical state at every step, forever: the moment the
-- two diverge, a NEAR or SAME address decodes to the wrong place and the
-- patch is silently wrong. So 'recordAddress' — the post-COPY update —
-- has exactly one definition, run by 'decodeCopyAddress' on the way in
-- and by 'selectCopyAddressMode' on the way out; divergence is not
-- tested-against but unrepresentable. The two operations sit side by
-- side here, inverses the way 'Slap.VCDIFF.CodeTable' keeps
-- 'Slap.VCDIFF.CodeTable.serializeCodeTable' beside its deserializer.
--
-- The vocabulary is format-defined and pure — no 'Slap.ByteParser', no
-- 'Slap.Status' — so it sits below 'Slap.VCDIFF.Parse' (which imports it
-- and re-exports the testing surface) and 'Slap.VCDIFF.Create' (which
-- imports the selection), neither reaching into the other.
module Slap.VCDIFF.AddressCache
  ( -- * Configuration and caches
    AddressCacheConfig(..)
  , defaultAddressCacheConfig
  , NearSlotIndex(..)
  , SameBlockIndex(..)
  , AddressCache(..)
  , slotsPerSameBlock
  , sameSlotCount
  , readNearSlot
  , readSameSlot
  , advanceNearWriteSlot
  , freshAddressCache
  , recordAddress
    -- * Mode classification
  , AddressModeFamily(..)
  , classifyAddressMode
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

-- | How many slots each cache holds: @s_near@ near slots and @s_same@
-- 256-slot same blocks (docs/vcdiff/core/spec.md "Address cache"). The
-- default code table fixes these ('defaultAddressCacheConfig'); a custom
-- code table declares its own. The cache carries its configuration so the
-- sizes drive the round-robin wrap, the slot bounds, and the same-block
-- arithmetic at runtime, rather than being baked into the types.
data AddressCacheConfig = AddressCacheConfig
  { nearSlotCount  :: !Int   -- ^ @s_near@: the number of near slots.
  , sameBlockCount :: !Int   -- ^ @s_same@: the number of 256-slot same blocks.
  }
  deriving (Eq, Show)

-- | The default code table's cache configuration: four near slots and
-- three same blocks, the nine address modes (0–8) of the core. The one
-- place @4@ and @3@ are named.
defaultAddressCacheConfig :: AddressCacheConfig
defaultAddressCacheConfig = AddressCacheConfig
  { nearSlotCount  = 4
  , sameBlockCount = 3
  }

-- | A near-cache slot index, in @[0, s_near)@. Constructed only within
-- bounds — by 'classifyAddressMode' from a mode in the near band, and by
-- 'advanceNearWriteSlot' whose modulus keeps it in range — so a slot the
-- cache lacks is unrepresentable: the four-arm sum's old guarantee, now
-- total over any @s_near@ and living where the index is made.
newtype NearSlotIndex = NearSlotIndex Int
  deriving (Eq, Show)

-- | A same-cache block index, in @[0, s_same)@. Constructed only within
-- bounds by 'classifyAddressMode' from a mode in the same band, with the
-- same guarantee as 'NearSlotIndex'.
newtype SameBlockIndex = SameBlockIndex Int
  deriving (Eq, Show)

-- | The two address caches a VCDIFF decoder maintains in lockstep with
-- the encoder (docs/vcdiff/core/spec.md "Address cache"), the
-- configuration that sizes them, and the next near slot to overwrite.
-- Both caches reset to empty at the start of every window and update
-- after every COPY.
--
-- The two caches are one idea twice: each an 'IntMap' keyed by slot,
-- read with a zero default — a slot never written reads as zero, since
-- xd3 zero-initializes both and a read of an untouched slot legitimately
-- decodes address 0, so the empty map /is/ the semantics, not a wall of
-- stored zeroes — and written one slot at a time. The cache is threaded
-- linearly through the decode, each value consumed once to produce the
-- next, so a per-COPY 'IntMap' path-copy is the cheap update an array
-- clone would not be.
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

-- | The slots in one same block, fixed by the format: a same-mode COPY's
-- one-byte operand indexes within the block, so a block spans 256 slots
-- regardless of configuration.
slotsPerSameBlock :: Int
slotsPerSameBlock = 256

-- | The same cache's total slot count for a configuration: 'sameBlockCount'
-- blocks of 'slotsPerSameBlock'.
sameSlotCount :: AddressCacheConfig -> Int
sameSlotCount config = sameBlockCount config * slotsPerSameBlock

-- | The address held in one near slot; an untouched slot holds zero.
readNearSlot :: NearSlotIndex -> IntMap Offset -> Offset
readNearSlot (NearSlotIndex slot) = IntMap.findWithDefault (Offset 0) slot

-- | The next near write slot, round-robin. The modulus is the safe one:
-- 'nearSlotCount' is positive and the result lands in @[0, s_near)@.
advanceNearWriteSlot :: AddressCacheConfig -> NearSlotIndex -> NearSlotIndex
advanceNearWriteSlot config (NearSlotIndex slot) =
  NearSlotIndex ((slot + 1) `mod` nearSlotCount config)

-- | The address held in one same slot; the block index and the one-byte
-- operand select the slot within the block's 256-slot span, and an
-- untouched slot holds zero.
readSameSlot :: SameBlockIndex -> Int -> IntMap Offset -> Offset
readSameSlot (SameBlockIndex block) slotByte =
  IntMap.findWithDefault (Offset 0) (block * slotsPerSameBlock + slotByte)

-- | A zeroed cache for the given configuration, as at the start of each
-- window.
freshAddressCache :: AddressCacheConfig -> AddressCache
freshAddressCache config = AddressCache
  { cacheConfig       = config
  , nearAddresses     = IntMap.empty
  , sameAddresses     = IntMap.empty
  , nextNearWriteSlot = NearSlotIndex 0
  }

-- | Write a freshly-handled address into both caches: the near cache at
-- the current write slot (then advancing round-robin) and the same cache
-- at @address mod (256 * s_same)@. The one definition both directions
-- run — the decoder after reading an address, the encoder after choosing
-- one — so their caches are a single state, not two kept in step.
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
-- Mode classification
----------------------------------------------------------------------------

-- | What a COPY address mode byte asks for, classified before any
-- bytes are read: one of the two varint modes, a read of a near
-- slot, or a read of a same block. The wire's mode arithmetic
-- (RFC 3284 §5.3's @2 + s_near + s_same@ bands) is collapsed into
-- the classifier; everything after it dispatches on named cases.
data AddressModeFamily
  = SelfAddress
    -- ^ Mode 0 (SELF): the address is a varint, read directly.
  | HereAddress
    -- ^ Mode 1 (HERE): the address is @here@ minus a varint.
  | NearAddress !NearSlotIndex
    -- ^ Near modes: a varint added to the slot's cached address.
  | SameAddress !SameBlockIndex
    -- ^ Same modes: a single byte indexing the block's 256 slots.

-- | Name a mode byte's family against a cache configuration: SELF, then
-- HERE, then 'nearSlotCount' near slots, then 'sameBlockCount' same
-- blocks (RFC 3284 §5.3's @2 + s_near + s_same@ bands). 'Nothing' is a
-- mode past the last band — the 'UnknownAddressMode' decline at the
-- caller. The near and same indices are made here, each inside its own
-- band, so neither can name a slot the cache lacks.
classifyAddressMode :: AddressCacheConfig -> Word8 -> Maybe AddressModeFamily
classifyAddressMode config mode
  | modeNumber == 0          = Just SelfAddress
  | modeNumber == 1          = Just HereAddress
  | modeNumber < nearBandEnd = Just (NearAddress (NearSlotIndex (modeNumber - 2)))
  | modeNumber < sameBandEnd = Just (SameAddress (SameBlockIndex (modeNumber - nearBandEnd)))
  | otherwise                = Nothing
  where
    modeNumber  = fromIntegral mode
    nearBandEnd = 2 + nearSlotCount config
    sameBandEnd = nearBandEnd + sameBlockCount config

----------------------------------------------------------------------------
-- Decode (mode + operand -> address)
----------------------------------------------------------------------------

-- | Why 'decodeCopyAddress' could not produce an address. Mapped to a
-- 'Slap.Status.VCDIFFMalformation' by the caller, which holds the
-- instruction index these are free of.
data AddressDecodeFailure
  = AddressSectionExhausted
  | UnknownAddressMode !Word8
  deriving (Eq, Show)

-- | The product of one COPY-address decode: the absolute address into
-- the superstring, plus the post-state the decode leaves behind — the
-- cache with the address recorded, and the address-section cursor
-- advanced past the consumed bytes. Named so callers read the three
-- by name rather than by tuple position, in the manner of
-- 'Slap.Binary.VarintResult'.
data CopyAddressReading = CopyAddressReading
  { copyAddressDecoded     :: !Offset
    -- ^ The absolute superstring address the COPY names.
  , copyAddressCacheAfter  :: !AddressCache
  , copyAddressCursorAfter :: !Offset
    -- ^ The address-section position just past the bytes this decode
    -- consumed.
  }
  deriving (Eq, Show)

-- | Decode one COPY address from the address section, given the cache,
-- the current @here@ position in the superstring, and the address
-- mode. The mode families are classified by 'classifyAddressMode'
-- (docs/vcdiff/core/spec.md "Address cache").
--
-- Both caches are updated after the address is decoded, regardless of
-- the mode it came through — the round-robin near write and the
-- modulo-slotted same write that keep decoder and encoder in step.
--
-- The upstream half of a two-stage pipeline: the absolute @U@ offset
-- decoded here is what 'Slap.VCDIFF.Apply.resolveCopyAddress' later
-- resolves into a physical read against the source file or the output
-- buffer.
decodeCopyAddress
  :: AddressCache -> Offset -> Word8 -> ByteString -> Offset
  -> Either AddressDecodeFailure CopyAddressReading
decodeCopyAddress cache here mode addrSection cursor =
  case classifyAddressMode (cacheConfig cache) mode of
    Nothing -> Left (UnknownAddressMode mode)
    -- The raw varint means a different thing per mode; each gives it the
    -- right shape. SELF: it is the address. HERE: a distance back from
    -- @here@. NEAR: a distance forward from the slot's cached address.
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
          let slotByte = fromIntegral (ByteString.index addrSection (offsetToInt cursor))
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

-- | A COPY's address-section operand, as the chosen mode reads it back:
-- a varint for SELF \/ HERE \/ NEAR, a single byte for SAME.
data CopyAddressOperand
  = AddressVarint !Int64
    -- ^ The varint a SELF, HERE, or NEAR mode reads: the address, the
    -- distance back from @here@, or the distance forward from a near slot.
  | AddressSameByte !Word8
    -- ^ The single byte a SAME mode reads to index its block.
  deriving (Eq, Show)

-- | The encoder's choice for one COPY: the mode byte to emit (matching a
-- 'Slap.VCDIFF.CodeTable.CopyAddressMode' the active table can name), the
-- operand that mode reads back to the address, and the cache after
-- recording the address — the same post-state 'decodeCopyAddress'
-- produces, so the encoder and decoder caches stay one state. Named for
-- 'CopyAddressReading', its decode mirror.
data SelectedCopyAddress = SelectedCopyAddress
  { selectedAddressMode       :: !Word8
  , selectedAddressOperand    :: !CopyAddressOperand
  , selectedAddressCacheAfter :: !AddressCache
  }
  deriving (Eq, Show)

-- | One candidate encoding of an address: a mode, its operand, and the
-- address-section byte count it would cost. Internal to the selection.
data AddressCandidate = AddressCandidate
  { candidateMode    :: !Word8
  , candidateOperand :: !CopyAddressOperand
  , candidateCost    :: !Int
  }

-- | Choose the cheapest encoding of a COPY's absolute superstring
-- address against the current cache and the write head @here@, then
-- record the address so the encoder's cache tracks the decoder's. The
-- inverse of 'decodeCopyAddress', reusing the same slot arithmetic so
-- "is this address in its slot" is the very computation 'recordAddress'
-- placed it by — agreement by construction, not by parallel
-- re-derivation.
--
-- Cheapest is by emitted address-section bytes, with SELF — the address
-- verbatim, always available — as the baseline a cache mode must beat
-- outright. SAME is a single byte, so it wins whenever the address
-- already sits in its same-slot and SELF would spend more than one byte.
-- NEAR is the smallest forward delta off a near slot, HERE the distance
-- back from @here@; each is taken only when strictly shorter than SELF.
-- A mode that merely ties SELF — an untouched near slot whose zero
-- default equals the address, a same-slot holding an address SELF
-- encodes just as short — leaves the plain offset in place, so a cache
-- mode appears exactly where it shrinks the section and SELF is the
-- default everywhere else. An equal-cost tie goes to the earlier mode
-- tried — SELF first, then same, near, here — so SELF holds every tie.
selectCopyAddressMode :: AddressCache -> Offset -> Offset -> SelectedCopyAddress
selectCopyAddressMode cache here address = recordInto chosen
  where
    config     = cacheConfig cache
    addressInt = offsetToInt address
    hereInt    = offsetToInt here

    -- The cheapest candidate, SELF first so it takes every tie: a cache
    -- mode is chosen only where strictly shorter, and among equal-cost
    -- modes the earlier listed wins ('minimumBy' keeps the first least).
    chosen :: AddressCandidate
    chosen = minimumBy (comparing candidateCost) (selfCandidate : cacheCandidates)

    -- The cache-mode candidates, in the order a tie favours them.
    cacheCandidates :: [AddressCandidate]
    cacheCandidates = maybe [] pure sameCandidate ++ nearCandidate ++ [hereCandidate]

    -- SAME: available exactly when the address's same-slot already holds
    -- it (an untouched slot holds zero, which legitimately matches
    -- address zero). The operand is the byte indexing within the block.
    sameCandidate :: Maybe AddressCandidate
    sameCandidate
      | readSameSlot (SameBlockIndex block) slotByte (sameAddresses cache) == address =
          Just (AddressCandidate (sameModeByte block) (AddressSameByte (fromIntegral slotByte)) 1)
      | otherwise = Nothing
      where
        globalSlot = addressInt `mod` sameSlotCount config
        block      = globalSlot `div` slotsPerSameBlock
        slotByte   = globalSlot `mod` slotsPerSameBlock

    -- NEAR: the slot with the smallest forward delta among those whose
    -- cached address does not exceed this one.
    nearCandidate :: [AddressCandidate]
    nearCandidate = case forwardNearSlots of
      []    -> []
      slots -> let (slotIndex, delta) = minimumBy (comparing snd) slots
               in [varintCandidate (nearModeByte slotIndex) delta]

    forwardNearSlots :: [(Int, Int)]   -- (slot index, forward delta)
    forwardNearSlots =
      [ (slotIndex, addressInt - slotAddrInt)
      | slotIndex <- [0 .. nearSlotCount config - 1]
      , let slotAddrInt = offsetToInt (readNearSlot (NearSlotIndex slotIndex) (nearAddresses cache))
      , slotAddrInt <= addressInt
      ]

    hereCandidate = varintCandidate 1 (hereInt - addressInt)
    selfCandidate = varintCandidate 0 addressInt

    varintCandidate :: Word8 -> Int -> AddressCandidate
    varintCandidate mode value =
      AddressCandidate mode (AddressVarint (fromIntegral value))
        (minimalVcdiffVarintLength (fromIntegral value))

    nearModeByte slotIndex = fromIntegral (2 + slotIndex)
    sameModeByte block     = fromIntegral (2 + nearSlotCount config + block)

    recordInto candidate = SelectedCopyAddress
      { selectedAddressMode       = candidateMode candidate
      , selectedAddressOperand    = candidateOperand candidate
      , selectedAddressCacheAfter = recordAddress cache address
      }
