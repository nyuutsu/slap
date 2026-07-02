-- | The DP optimizer for IPS records.
-- The encoder in 'Slap.IPS.Create' is a mechanical wire-translation pass;
-- the choices about /which/ regions of the target to emit, /what shape/ each record should take, and /where/ to merge or split runs all happen here.
--
-- The single exported function takes the variant's offset width (because the cost-model constants are width-dependent), the source bytes, and the target bytes,
-- and returns the partitioned record list as 'Hunk' values in offset order.
-- The encoder narrows each to an 'Slap.Narrow.EncodedHunk' before emission, applying the variant's wire-format offset bound,
-- and then turns each narrowed hunk into the cheapest record at emission time using the same heuristic the DP itself used
-- (length-≥4 all-same payloads → RLE record, everything else → copy record),
-- so the encoder's choices and the DP's choices stay in lockstep.
--
-- The split between this module and 'Slap.IPS.Create' exists for three reasons:
--
--   * The wire encoder is total and mechanical and is unit-testable against hand-crafted record lists.
--     Coupling it to the optimizer would force every encoder test to also exercise the optimizer's cost model.
--
--   * The optimizer is a heavy piece of code with cost analyses, ST-based DP, and byte-run scanning.
--     It is exactly the kind of piece that might one day be replaced by a Rust port;
--     that replacement should not have to touch wire emission to do so.
--
--   * The convert path produces records from /another format's/ parser output, with no source bytes to diff against.
--     That path needs the encoder but not the optimizer;
--     separating the two lets it import only what it actually uses.
module Slap.IPS.Optimize
  ( optimalIPSRecords
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.IPS.Types
  ( OffsetWidth
  , ipsCopyRecordOverhead
  , ipsRleRecordOverhead
  , ipsMaxRecordPayload
  )
import Slap.Measure
  ( Offset(..)
  , Length(..)
  , Hunk(..)
  , subtractLength
  , Cursor(advance)
  , byteLength
  , distance
  )

import Control.Monad.ST (ST, runST)
import Data.Array (Array, listArray, (!))
import Data.Array.MArray (newArray, readArray, writeArray)
import Data.Array.ST (STUArray)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (sort)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Records
----------------------------------------------------------------------------

-- | A maximal same-byte run inside a single diff region, naming the
-- slice of the region where the run lives. The DP partition step
-- consumes a list of these as the seed positions at which it is
-- allowed to consider an RLE record candidate.
--
-- @byteRunStart@ is /region-relative/, not an absolute file offset —
-- the DP only re-introduces the absolute offset when it builds the
-- final 'Hunk' values during backtracking. The start+length shape
-- mirrors 'Slap.Measure.OffsetRange'; use 'byteRunEndExclusive' for
-- the half-open end at the call sites that need it.
data ByteRun = ByteRun
  { byteRunStart  :: !Offset
  , byteRunLength :: !Length
  } deriving (Eq, Show)

-- | The exclusive end of a 'ByteRun': @byteRunStart + byteRunLength@.
-- Used by run-membership checks (a position lies in a run iff it is
-- in @[byteRunStart, byteRunEndExclusive)@).
byteRunEndExclusive :: ByteRun -> Offset
byteRunEndExclusive run = advance (byteRunStart run) (byteRunLength run)

----------------------------------------------------------------------------
-- Public entry point
----------------------------------------------------------------------------

-- | Compute the optimal IPS record set for a (source, target) pair
-- under the given offset width. The result has these properties:
--
--   * Records are returned in target-offset order.
--   * Each record's offset is an absolute target byte index, not a
--     position relative to any diff region.
--   * Each record's payload length is at most 'ipsMaxRecordPayload';
--     the partition step's seed-position list is preprocessed by
--     'ensureMaxGap' so no DP transition can name a longer slice.
--   * The total wire cost (per the cost model in the DP body) is at
--     most that of any other partition into copy and RLE records
--     bounded by the same per-record payload cap.
--
-- The 'OffsetWidth' parameter determines the cost-model constants (different overhead for 'Offset24' and 'Offset32').
optimalIPSRecords
  :: OffsetWidth
  -> InputFileContents
  -> OutputFileContents
  -> [Hunk]
optimalIPSRecords
    offsetWidth
    inputContents
    outputContents@(OutputFileContents target) =
  concatMap (partitionDiffRegion offsetWidth target) gapMergedDiffRegions
  where
    rawDiffRegions       = scanDiffRegions inputContents outputContents
    gapMergedDiffRegions = mergeNarrowGaps offsetWidth target rawDiffRegions

----------------------------------------------------------------------------
-- Step 1: scan source and target for the raw diff regions
----------------------------------------------------------------------------

-- | Scan source and target in lockstep for contiguous regions where
-- their bytes differ, plus a final extension region for any tail
-- of @target@ that has no matching source bytes. Each region is
-- returned as a 'Hunk' carrying the absolute target offset
-- and the /target/ bytes for that region — the IPS record format
-- writes literal target bytes, never source bytes.
--
-- The pass is intentionally naive: no merging, no RLE detection,
-- no per-record bounds checks. Its job is just to partition the
-- target into "regions where source agrees" and "regions where it
-- disagrees" so the cost-aware passes downstream have something to
-- chew on.
scanDiffRegions :: InputFileContents -> OutputFileContents -> [Hunk]
scanDiffRegions (InputFileContents source) (OutputFileContents target) =
  scanFromPosition (Offset 0) ++ tailExtension
  where
    sourceLength = ByteString.length source
    targetLength = ByteString.length target
    overlapEnd   = Offset (min sourceLength targetLength)

    -- Bytes of @target@ past the end of @source@ are by definition
    -- different from anything in source (there's nothing in source
    -- to compare against), so they're a single trailing region of
    -- their own. Empty when @target@ is no longer than @source@.
    tailExtension
      | targetLength > sourceLength =
          [ Hunk
              { hunkOffset  = Offset sourceLength
              , hunkPayload = ByteString.drop sourceLength target
              }
          ]
      | otherwise = []

    scanFromPosition :: Offset -> [Hunk]
    scanFromPosition !position
      | position >= overlapEnd = []
      | ByteString.index source (unOffset position)
          == ByteString.index target (unOffset position) =
          scanFromPosition (advance position (Length 1))
      | otherwise =
          let regionEnd     = findRegionEnd (advance position (Length 1))
              regionLength  = distance position regionEnd
              regionPayload =
                ByteString.take (unLength regionLength)
                                (ByteString.drop (unOffset position) target)
              region = Hunk
                { hunkOffset  = position
                , hunkPayload = regionPayload
                }
          in region : scanFromPosition regionEnd

    -- | Walk forward while bytes still differ; return the first
    -- position at which they re-converge (or @overlapEnd@ if
    -- they never do within the shared range).
    findRegionEnd :: Offset -> Offset
    findRegionEnd !position
      | position >= overlapEnd = overlapEnd
      | ByteString.index source (unOffset position)
          /= ByteString.index target (unOffset position) =
          findRegionEnd (advance position (Length 1))
      | otherwise = position

----------------------------------------------------------------------------
-- Step 2: merge gaps narrower than the cost-of-separating threshold
----------------------------------------------------------------------------

-- | Bridge adjacent diff regions across an unchanged-byte gap narrow enough
-- that one merged record costs strictly fewer wire bytes than two separate copy records.
--
-- The cost-model derivation, in full:
--
-- @
--     separate cost: 2 * ipsCopyRecordOverhead + |A| + |B|
--     merged   cost: 1 * ipsCopyRecordOverhead + |A| + G + |B|
--                      (G = unchanged bytes between A and B)
--
--     merge − separate = G − ipsCopyRecordOverhead
-- @
--
-- Merging is strictly cheaper exactly when @G < ipsCopyRecordOverhead@,
-- i.e. when @G ≤ ipsCopyRecordOverhead − 1@.
-- The looser threshold @G ≤ ipsCopyRecordOverhead@ would also merge in the tie case @G = ipsCopyRecordOverhead@,
-- where merging neither saves nor costs any bytes — strictly equivalent on cost.
-- So we decline that merge: a merge is only worth making when it strictly saves wire bytes.
--
-- The merged region this pass produces can be longer than 'ipsMaxRecordPayload';
-- that's fine, because the subsequent 'partitionDiffRegion' step preprocesses its seed positions through 'ensureMaxGap'
-- so the eventual records still respect the 16-bit size cap.
mergeNarrowGaps :: OffsetWidth -> ByteString -> [Hunk] -> [Hunk]
mergeNarrowGaps offsetWidth target = mergeStep
  where
    breakEvenGap = mergeBreakEvenGapLength offsetWidth

    mergeStep [] = []
    mergeStep [singleRegion] = [singleRegion]
    mergeStep (firstRegion : secondRegion : remainingRegions) =
      let firstStart  = hunkOffset firstRegion
          firstEnd    = advance firstStart (byteLength (hunkPayload firstRegion))
          secondStart = hunkOffset secondRegion
          gap         = distance firstEnd secondStart
      in if gap <= breakEvenGap
           then
             let mergedEnd =
                   advance secondStart
                           (byteLength (hunkPayload secondRegion))
                 mergedLength = distance firstStart mergedEnd
                 mergedPayload =
                   ByteString.take (unLength mergedLength)
                                   (ByteString.drop (unOffset firstStart) target)
                 mergedRegion = Hunk
                   { hunkOffset  = firstStart
                   , hunkPayload = mergedPayload
                   }
             in mergeStep (mergedRegion : remainingRegions)
           else
             firstRegion
             : mergeStep (secondRegion : remainingRegions)

-- | The largest unchanged-byte gap @G@ for which merging two
-- adjacent diff regions across @G@ is strictly cheaper than
-- emitting them as two separate copy records. See 'mergeNarrowGaps'
-- for the cost analysis. Equal to @ipsCopyRecordOverhead − 1@: one
-- byte short of a single copy record's fixed overhead.
mergeBreakEvenGapLength :: OffsetWidth -> Length
mergeBreakEvenGapLength offsetWidth =
  subtractLength (ipsCopyRecordOverhead offsetWidth) (Length 1)

----------------------------------------------------------------------------
-- Step 3: optimal copy/RLE partition within a diff region
----------------------------------------------------------------------------

-- | Partition a single diff region into the optimal sequence of
-- copy and/or RLE records under the cost model from
-- 'Slap.IPS.Types'. The DP state is an array indexed by /partition
-- position/ (an index into the seed-position list); the value at
-- index @i@ is the minimum total wire cost to encode bytes
-- @[0, position i)@ of the region. Backtracking through the
-- predecessor array yields the chosen record list in offset order.
--
-- The seed-position list comes from three sources:
--
--   1. The endpoints of the diff region (positions @0@ and @N@).
--   2. The endpoints of every maximal byte-run of length ≥ 4, so
--      the DP can consider RLE-record boundaries.
--   3. Synthetic positions inserted by 'ensureMaxGap' to bound any
--      single record at 'ipsMaxRecordPayload' bytes.
--
-- The list is sorted, deduplicated, and gap-bounded before the DP
-- runs. The DP only considers transitions between seed positions,
-- so every chosen record boundary coincides with a run endpoint or
-- the size cap.
partitionDiffRegion :: OffsetWidth -> ByteString -> Hunk -> [Hunk]
partitionDiffRegion offsetWidth _target region
  | ByteString.null regionPayload = []
  | otherwise = runST runPartitionDP
  where
    regionPayload = hunkPayload region
    regionStart   = hunkOffset region
    regionLength  = byteLength regionPayload

    copyRecordOverheadBytes = unLength (ipsCopyRecordOverhead offsetWidth)
    rleRecordOverheadBytes  = unLength (ipsRleRecordOverhead  offsetWidth)
    rleBreakEvenLength      = rleBreakEvenRunLength offsetWidth

    -- Step 3a: every maximal same-byte run inside the region.
    runs :: [ByteRun]
    runs = findByteRuns regionPayload

    -- Step 3b: the seed positions the DP is allowed to choose
    -- between. Endpoints of the region itself, plus the endpoints
    -- of every byte-run (so each run's start and end can be the
    -- boundary of an RLE candidate), then ensureMaxGap fills in any
    -- gap longer than the per-record payload cap.
    rawSeedPositions :: [Offset]
    rawSeedPositions =
      sortAndDeduplicate
        ( Offset 0
        : advance (Offset 0) regionLength
        : concatMap (\run -> [byteRunStart run, byteRunEndExclusive run]) runs
        )

    seedPositions :: [Offset]
    seedPositions = ensureMaxGap ipsMaxRecordPayload rawSeedPositions

    seedPositionCount :: Int
    seedPositionCount = length seedPositions

    seedPositionArray :: Array Int Offset
    seedPositionArray =
      listArray (0, seedPositionCount - 1) seedPositions

    -- For each seed position, the index of its RLE-eligible
    -- predecessor (the previous seed position that lies in the
    -- same maximal run as this one), or 'noPredecessor' when no run spans the
    -- gap. The DP uses these indices to gate RLE-cost candidates:
    -- an RLE record can only span a contiguous subrange of a
    -- single maximal run, so any RLE transition must be between
    -- two seed positions both inside the same run.
    rleEligiblePredecessorArray :: Array Int Int
    rleEligiblePredecessorArray =
      listArray (0, seedPositionCount - 1)
                (computeRLEEligiblePredecessors seedPositions runs)

    -- An infeasible upper bound used to seed the DP cost array. Any
    -- legal partition is strictly cheaper than this, so the
    -- @candidateCost < bestCost@ comparison never matches the seed
    -- by accident. The @+1@ keeps the seed strictly above the worst
    -- feasible cost rather than just at it.
    impossiblyExpensiveCost :: Int
    impossiblyExpensiveCost =
      unLength regionLength * (copyRecordOverheadBytes + 5) + 1

    runPartitionDP :: forall s. ST s [Hunk]
    runPartitionDP = do
      costArray <-
        newArray (0, seedPositionCount - 1) impossiblyExpensiveCost
        :: ST s (STUArray s Int Int)
      predecessorArray <-
        newArray (0, seedPositionCount - 1) noPredecessor
        :: ST s (STUArray s Int Int)
      writeArray costArray 0 0

      -- Forward DP pass: for each destination from 1 upward, find
      -- the cheapest predecessor (copy candidate or RLE candidate)
      -- and record the winning cost and predecessor in the two DP
      -- arrays.
      let scanDestinations !destinationIndex
            | destinationIndex >= seedPositionCount = pure ()
            | otherwise = do
                let destinationPosition = seedPositionArray ! destinationIndex

                    -- Copy candidate scan: walk all earlier seed positions
                    -- whose distance to the destination is within the
                    -- per-record payload cap, and pick the one whose
                    -- (predecessor cost + copy-record cost) is smallest.
                    -- Returns @(bestCost, bestPredecessorIndex)@.
                    scanCopyCandidates !bestCost !bestPredecessor !predecessorIndex
                      | not (hasPredecessor predecessorIndex) = pure (bestCost, bestPredecessor)
                      | recordPayloadLength > ipsMaxRecordPayload =
                          pure (bestCost, bestPredecessor)
                      | otherwise = do
                          predecessorCost <- readArray costArray predecessorIndex
                          let candidateCost =
                                predecessorCost
                                + copyRecordOverheadBytes
                                + unLength recordPayloadLength
                          if candidateCost < bestCost
                            then scanCopyCandidates candidateCost
                                                    predecessorIndex
                                                    (predecessorIndex - 1)
                            else scanCopyCandidates bestCost
                                                    bestPredecessor
                                                    (predecessorIndex - 1)
                      where
                        recordPayloadLength =
                          distance (seedPositionArray ! predecessorIndex) destinationPosition

                (copyCandidateCost, copyCandidatePredecessor) <-
                  scanCopyCandidates impossiblyExpensiveCost noPredecessor (destinationIndex - 1)

                -- RLE candidate: only available when the destination's preceding seed position is inside the same maximal run as the destination,
                -- AND the resulting run length exceeds the break-even 'rleBreakEvenRunLength' — 3 for both variants, so RLE first wins at length 4.
                let rleEligiblePredecessor =
                      rleEligiblePredecessorArray ! destinationIndex
                    rleCandidateRunLength
                      | hasPredecessor rleEligiblePredecessor =
                          distance (seedPositionArray ! rleEligiblePredecessor)
                                   destinationPosition
                      | otherwise = mempty

                (winningCost, winningPredecessor) <-
                  if hasPredecessor rleEligiblePredecessor
                       && rleCandidateRunLength > rleBreakEvenLength
                    then do
                      rlePredecessorCost <-
                        readArray costArray rleEligiblePredecessor
                      let rleCandidateCost =
                            rlePredecessorCost + rleRecordOverheadBytes
                      if rleCandidateCost < copyCandidateCost
                        then pure (rleCandidateCost, rleEligiblePredecessor)
                        else pure (copyCandidateCost, copyCandidatePredecessor)
                    else pure (copyCandidateCost, copyCandidatePredecessor)

                writeArray costArray        destinationIndex winningCost
                writeArray predecessorArray destinationIndex winningPredecessor
                scanDestinations (destinationIndex + 1)
      scanDestinations 1

      -- Backtrack from the final position, building the record list
      -- in offset order. Each step reads the chosen predecessor of
      -- the current position, slices the corresponding bytes out
      -- of the region payload, wraps them in a 'Hunk' with
      -- the absolute file offset, and continues at the predecessor.
      let backtrackFrom !destinationIndex !accumulatedRecords
            | destinationIndex <= 0 = pure accumulatedRecords
            | otherwise = do
                predecessorIndex <- readArray predecessorArray destinationIndex
                let predecessorPosition = seedPositionArray ! predecessorIndex
                    destinationPosition = seedPositionArray ! destinationIndex
                    sliceLength         = distance predecessorPosition destinationPosition
                    slicePayload =
                      ByteString.take (unLength sliceLength)
                                      (ByteString.drop (unOffset predecessorPosition) regionPayload)
                    -- Region-relative Offset to absolute file Offset.
                    absoluteOffset = advance regionStart
                                             (distance (Offset 0) predecessorPosition)
                    chosenRecord = Hunk
                      { hunkOffset  = absoluteOffset
                      , hunkPayload = slicePayload
                      }
                backtrackFrom predecessorIndex (chosenRecord : accumulatedRecords)
      backtrackFrom (seedPositionCount - 1) []

-- | The smallest run length at which an RLE record is strictly
-- cheaper than the equivalent copy record, expressed as a function
-- of the per-record overhead constants from 'Slap.IPS.Types'.
--
-- Cost analysis:
--
-- @
--     copy cost (length N): ipsCopyRecordOverhead + N
--     rle  cost (length N): ipsRleRecordOverhead   (independent of N)
-- @
--
-- For RLE to win we need
--
-- @
--     ipsRleRecordOverhead < ipsCopyRecordOverhead + N
--     N > ipsRleRecordOverhead − ipsCopyRecordOverhead
-- @
--
-- This evaluates to @3@ for both 'Offset24' and 'Offset32' (the
-- difference is the RLE-only count field plus the fill byte =
-- 2 + 1 bytes), but we compute it from the constants so any future
-- change to the overhead formulas propagates here automatically.
-- The DP's break-even comparison uses the strict @>@ comparator,
-- so a run of exactly @rleBreakEvenRunLength@ bytes stays as a copy
-- record (RLE would tie on cost).
rleBreakEvenRunLength :: OffsetWidth -> Length
rleBreakEvenRunLength offsetWidth =
  subtractLength (ipsRleRecordOverhead  offsetWidth)
                 (ipsCopyRecordOverhead offsetWidth)

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Find every maximal same-byte run of length ≥ 4 inside a
-- ByteString, returning the runs in left-to-right order.
findByteRuns :: ByteString -> [ByteRun]
findByteRuns input
  | ByteString.null input = []
  | otherwise = scanRuns 0 (ByteString.index input 0) 1
  where
    inputLength = ByteString.length input

    scanRuns :: Int -> Word8 -> Int -> [ByteRun]
    scanRuns !runStartPosition !runByte !position
      | position >= inputLength =
          let runLength = distance (Offset runStartPosition) (Offset inputLength)
          in [ ByteRun (Offset runStartPosition) runLength
             | runLength >= Length 4
             ]
      | ByteString.index input position == runByte =
          scanRuns runStartPosition runByte (position + 1)
      | otherwise =
          let runLength = distance (Offset runStartPosition) (Offset position)
          in [ ByteRun (Offset runStartPosition) runLength
             | runLength >= Length 4
             ]
          ++ scanRuns position
                      (ByteString.index input position)
                      (position + 1)

-- | Insert synthetic positions into a sorted seed list so that no
-- two adjacent positions are more than @maxGapBytes@ apart. Used by
-- the partition step to enforce the per-record payload cap: any DP
-- transition between two seed positions corresponds to a record
-- whose payload length equals the gap, and that gap must be at
-- most 'ipsMaxRecordPayload' bytes long.
ensureMaxGap :: Length -> [Offset] -> [Offset]
ensureMaxGap _ []          = []
ensureMaxGap _ [singleton] = [singleton]
ensureMaxGap maxGap (firstPosition : secondPosition : remainingPositions)
  | distance firstPosition secondPosition <= maxGap =
      firstPosition
      : ensureMaxGap maxGap (secondPosition : remainingPositions)
  | otherwise =
      firstPosition
      : ensureMaxGap maxGap
          (advance firstPosition maxGap : secondPosition : remainingPositions)

-- | Seed-position list preparation for the DP.
-- Library functions @nub@ and @group@ are O(n²) and O(n log n) respectively but allocate;
-- this fused sort + linear sweep matches their result and stays in one shape.
sortAndDeduplicate :: Ord a => [a] -> [a]
sortAndDeduplicate = removeConsecutiveDuplicates . sort
  where
    removeConsecutiveDuplicates []         = []
    removeConsecutiveDuplicates [singleton] = [singleton]
    removeConsecutiveDuplicates (firstValue : secondValue : remainingValues)
      | firstValue == secondValue =
          removeConsecutiveDuplicates (secondValue : remainingValues)
      | otherwise =
          firstValue
          : removeConsecutiveDuplicates (secondValue : remainingValues)

noPredecessor :: Int
noPredecessor = -1

hasPredecessor :: Int -> Bool
hasPredecessor candidateIndex = candidateIndex >= 0

-- | For each seed position, the previous seed position in the same maximal byte-run, or 'noPredecessor' when no run spans the gap.
-- Parallel to the seed list: the @i@-th entry is the predecessor of the @i@-th seed.
computeRLEEligiblePredecessors :: [Offset] -> [ByteRun] -> [Int]
computeRLEEligiblePredecessors seedPositions runs =
  noPredecessor : zipWith
         eligibilityForPair
         [1 ..]
         (zip seedPositions (drop 1 seedPositions))
  where
    eligibilityForPair :: Int -> (Offset, Offset) -> Int
    eligibilityForPair currentIndex (previousPosition, currentPosition)
      | positionsLieInSameRun previousPosition currentPosition =
          currentIndex - 1
      | otherwise = noPredecessor

    positionsLieInSameRun :: Offset -> Offset -> Bool
    positionsLieInSameRun previousPosition currentPosition =
      any (\run ->
             byteRunStart run <= previousPosition
             && currentPosition <= byteRunEndExclusive run)
          runs
