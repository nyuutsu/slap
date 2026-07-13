{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | ROM-image canonicalization for the NINJA formats.
--
-- A NINJA patch's records are built against a canonical form of the ROM —
-- headerless, deinterleaved, native byte order — named by the patch's ROM type.
-- The procedures follow convroms.txt and the ninja2.php reference.
-- Where that reference refuses an unfamiliar image, slap takes it as-is and warns instead: a wrong guess fails the patch's own source checksum,
-- and an absent checksum is the creator's omission, not slap's reason to be stricter than the format.
-- slap's specific calls are recorded in docs/ninja1/rom-normalization.md and docs/ninja2/rom-normalization.md.
module Slap.Normalize
  ( -- * The apply-side instruction
    SourceNormalization(..)
  , RestoreDiscipline(..)
  , NormalizationConfirmation(..)
    -- * Normalizing
  , NormalizedSource(..)
  , normalizeApplySource
  , normalizeCreatePair
  , CanonicalizedImage(..)
  , canonicalizeRomImage
    -- * Restoring
  , RestoreStep(..)
  , StrippedHeader(..)
  , OriginalUNIFImage(..)
  , restoreStrippedContent
    -- * Convert retag rule
  , sharesNormalizationLayout
    -- * N64 byte-order probe
  , isV64Image
    -- * Exercised directly by the property suite
  , deinterleaveByChart
  , snesGD3Chart20Mbit
  , snesGD3Chart24Mbit
  , snesGD3Chart48Mbit
  , evenOddInterleaveChart
  , rebuildUNIFContainer
  , UNIFRebuildMismatch(..)
  ) where

import Data.Array (Array, accumArray, bounds, listArray, (!))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (isDigit)
import Data.List (mapAccumL)

import Slap.Binary (getWord16LE, getWord32LE,
                    swapAdjacentBytePairs, deinterleaveSMDBlock)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Length(..), FileSize(..), byteLength, byteFileSize, lengthToInt,
                     ActualSize(..), ExpectedSize(..))
import Slap.PlatformType (PlatformType(..))
import Slap.Status (SlapAdvisory(..), NormalizationStep(..),
                    SNESInterleaveLayout(..), NormalizedImageRole(..),
                    NormalizationSkipReason(..), RestoredContent(..))

----------------------------------------------------------------------------
-- The apply-side instruction
----------------------------------------------------------------------------

-- | The apply-side normalization instruction, decided at parse time.
-- Data, not a closure, so it stays inspectable the way 'Slap.SomePatch.Verification' does.
data SourceNormalization = SourceNormalization
  { normalizationFormat       :: FormatLabel
  , normalizationPlatform     :: PlatformType
  , normalizationDiscipline   :: RestoreDiscipline
  , normalizationConfirmation :: NormalizationConfirmation
  } deriving (Show)

-- | Whether content the procedure set aside returns to the output.
-- NINJA2 restores it; NINJA1 is forward-only — its reference readers return the clean bytes and never re-emit a header.
data RestoreDiscipline = RestoreStrippedContent | ForwardOnly
  deriving (Eq, Show)

-- | Whether the patch carries a source checksum that can vouch for the normalized bytes.
-- A procedure is a guess about the input's shape; a present checksum confirms or refutes it on its own,
-- while 'NoSourceChecksumToConfirm' makes the apply warn that nothing can.
data NormalizationConfirmation = ConfirmableBySourceChecksum | NoSourceChecksumToConfirm
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- Normalizing
----------------------------------------------------------------------------

data NormalizedSource = NormalizedSource
  { normalizedSourceBytes      :: InputFileContents
  , normalizedSourceRestore    :: RestoreStep
  , normalizedSourceAdvisories :: [SlapAdvisory]
  } deriving (Show)

-- | Normalize the apply-side input per the patch's instruction.
-- 'Nothing' — a format with no ROM types, or a ROM type with no procedure — passes it through untouched.
normalizeApplySource :: Maybe SourceNormalization -> InputFileContents -> NormalizedSource
normalizeApplySource Nothing source = NormalizedSource source NothingToRestore []
normalizeApplySource (Just normalization) (InputFileContents sourceBytes) =
  NormalizedSource
    { normalizedSourceBytes      = InputFileContents (canonicalImageBytes canonical)
    , normalizedSourceRestore    = case normalizationDiscipline normalization of
        RestoreStrippedContent -> canonicalImageRestore canonical
        ForwardOnly            -> NothingToRestore
    , normalizedSourceAdvisories = canonicalImageAdvisories canonical ++ confirmationAdvisories
    }
  where
    canonical = canonicalizeRomImage (normalizationFormat normalization)
                                     NormalizedApplyInput
                                     (normalizationPlatform normalization)
                                     sourceBytes
    confirmationAdvisories = case normalizationConfirmation normalization of
      ConfirmableBySourceChecksum -> []
      NoSourceChecksumToConfirm   ->
        [RomTypeNormalizationUnconfirmable (normalizationFormat normalization)
                                           (normalizationPlatform normalization)]

-- | Normalize both files of a create (or @--with@ convert) before they are diffed and hashed,
-- so the patch's records and checksums describe the canonical forms.
-- Create keeps nothing to restore — the patch stores clean against clean, and the apply is what puts stripped content back.
normalizeCreatePair
  :: FormatLabel -> PlatformType
  -> InputFileContents -> OutputFileContents
  -> (InputFileContents, OutputFileContents, [SlapAdvisory])
normalizeCreatePair label platform (InputFileContents original) (OutputFileContents modified) =
  ( InputFileContents  (canonicalImageBytes originalCanonical)
  , OutputFileContents (canonicalImageBytes modifiedCanonical)
  , canonicalImageAdvisories originalCanonical ++ canonicalImageAdvisories modifiedCanonical
  )
  where
    originalCanonical = canonicalizeRomImage label NormalizedCreateOriginal platform original
    modifiedCanonical = canonicalizeRomImage label NormalizedCreateModified platform modified

data CanonicalizedImage = CanonicalizedImage
  { canonicalImageBytes      :: ByteString
  , canonicalImageRestore    :: RestoreStep
  , canonicalImageAdvisories :: [SlapAdvisory]
  } deriving (Show)

canonicalizeRomImage :: FormatLabel -> NormalizedImageRole -> PlatformType -> ByteString -> CanonicalizedImage
canonicalizeRomImage label role platform image = CanonicalizedImage
  { canonicalImageBytes      = procedureBytes outcome
  , canonicalImageRestore    = procedureRestore outcome
  , canonicalImageAdvisories = map advisoryOfEvent (procedureEvents outcome)
  }
  where
    outcome = procedureForPlatform platform image
    advisoryOfEvent (PerformedStep step)    = RomImageNormalized label role platform step
    advisoryOfEvent ShapeUnrecognized       = RomImageShapeUnrecognized label role platform
    advisoryOfEvent (SkippedBecause reason) = RomImageNormalizationSkipped label role platform reason

----------------------------------------------------------------------------
-- Restoring
----------------------------------------------------------------------------

-- | Content a normalization set aside for the output.
-- It returns after target verification, not before: the reference computes its stored target MD5 over the clean form.
data RestoreStep
  = NothingToRestore
  | RestoreHeaderPrefix StrippedHeader
  | RestoreIntoUNIFContainer OriginalUNIFImage
  deriving (Show)

newtype StrippedHeader = StrippedHeader { unStrippedHeader :: ByteString }
  deriving (Show)

newtype OriginalUNIFImage = OriginalUNIFImage { unOriginalUNIFImage :: ByteString }
  deriving (Show)

-- | The UNIF arm can decline — a patch that resized the merged data leaves the chunk table nothing it can hold — and says so with an advisory.
restoreStrippedContent :: FormatLabel -> RestoreStep -> OutputFileContents -> (OutputFileContents, [SlapAdvisory])
restoreStrippedContent _ NothingToRestore output = (output, [])
restoreStrippedContent label (RestoreHeaderPrefix (StrippedHeader header)) (OutputFileContents body) =
  ( OutputFileContents (header <> body)
  , [RomImageContentRestored label (RestoredHeaderPrefix (byteLength header))]
  )
restoreStrippedContent label (RestoreIntoUNIFContainer (OriginalUNIFImage container)) (OutputFileContents patchedData) =
  case rebuildUNIFContainer container patchedData of
    Right rebuilt ->
      (OutputFileContents rebuilt, [RomImageContentRestored label RestoredUNIFContainer])
    Left (UNIFRebuildMismatch containerTotal patchedLength) ->
      (OutputFileContents patchedData, [UNIFContainerNotRebuilt label containerTotal patchedLength])

----------------------------------------------------------------------------
-- Convert retag rule
----------------------------------------------------------------------------

-- | Whether two platforms normalize identically,
-- so a patch tagged as one may be retagged as the other without changing what appliers do to its input.
-- SMS and Game Gear are the one such pair: NINJA2 stores them in a single combined slot, and @--rom-type@ on convert exists to pick a side of it.
sharesNormalizationLayout :: PlatformType -> PlatformType -> Bool
sharesNormalizationLayout PlatformSMS      PlatformGameGear = True
sharesNormalizationLayout PlatformGameGear PlatformSMS      = True
sharesNormalizationLayout carried requested = carried == requested

----------------------------------------------------------------------------
-- The procedures
----------------------------------------------------------------------------

-- | A procedure's raw outcome, before 'canonicalizeRomImage' turns events into advisories.
data ProcedureOutcome = ProcedureOutcome
  { procedureBytes   :: ByteString
  , procedureRestore :: RestoreStep
  , procedureEvents  :: [ProcedureEvent]
  }

-- | What a procedure reports: a transform it performed, an image it couldn't place, or a transform it had to skip.
data ProcedureEvent
  = PerformedStep NormalizationStep
  | ShapeUnrecognized
  | SkippedBecause NormalizationSkipReason

-- | The image already is the canonical form: nothing to do, and nothing to say.
imageTakenAsIs :: ByteString -> ProcedureOutcome
imageTakenAsIs image = ProcedureOutcome image NothingToRestore []

procedureForPlatform :: PlatformType -> ByteString -> ProcedureOutcome
procedureForPlatform PlatformNES      = normalizeNESImage
procedureForPlatform PlatformSNES     = normalizeSNESImage
procedureForPlatform PlatformN64      = normalizeN64Image
procedureForPlatform PlatformGB       = normalizeGameBoyImage
procedureForPlatform PlatformSMS      = normalizeSegaImage smsSEGASignatureOffset
procedureForPlatform PlatformGameGear = normalizeSegaImage smsSEGASignatureOffset
procedureForPlatform PlatformGenesis  = normalizeSegaImage genesisSEGASignatureOffset
procedureForPlatform PlatformPCEngine = normalizePCEngineImage
procedureForPlatform PlatformLynx     = normalizeLynxImage
procedureForPlatform _                = imageTakenAsIs

stripHeaderKeeping :: NormalizationStep -> Length -> ByteString -> ProcedureOutcome
stripHeaderKeeping step width image
  | ByteString.length image < headerWidth =
      ProcedureOutcome image NothingToRestore [SkippedBecause ImageShorterThanItsHeader]
  | otherwise =
      let (header, body) = ByteString.splitAt headerWidth image
      in ProcedureOutcome body (RestoreHeaderPrefix (StrippedHeader header)) [PerformedStep step]
  where
    headerWidth = lengthToInt width

-- | Remove a header of the given width and let it go — the reference never restores these (copier and SmartCard-style headers).
stripHeaderDropping :: NormalizationStep -> Length -> ByteString -> ProcedureOutcome
stripHeaderDropping step width image
  | ByteString.length image < headerWidth =
      ProcedureOutcome image NothingToRestore [SkippedBecause ImageShorterThanItsHeader]
  | otherwise =
      ProcedureOutcome (ByteString.drop headerWidth image) NothingToRestore [PerformedStep step]
  where
    headerWidth = lengthToInt width

-- | The @0xAA 0xBB@ marker at offset 8 that FFE-style copier headers carry; NES (FFE) and the Sega SMD header share it.
copierMarkerPresentAtOffset8 :: ByteString -> Bool
copierMarkerPresentAtOffset8 image =
  ByteString.take 2 (ByteString.drop 0x8 image) == ByteString.pack [0xAA, 0xBB]

----------------------------------------------------------------------------
-- NES: iNES, FFE, UNIF
----------------------------------------------------------------------------

-- | NES images come in three shapes: iNES (16-byte header), FFE (512-byte header, @0xAA 0xBB@ at offset 8),
-- and UNIF (a chunk container the PRG and CHR data are merged out of).
-- All three restore on apply — the headers re-prepend, UNIF data reinserts into the original container.
normalizeNESImage :: ByteString -> ProcedureOutcome
normalizeNESImage image
  | ByteString.take 3 image == "NES"        = stripHeaderKeeping StrippedINESHeader (Length 0x10) image
  | copierMarkerPresentAtOffset8 image      = stripHeaderKeeping StrippedFFEHeader (Length 0x200) image
  | ByteString.take 4 image == "UNIF"       = mergeUNIFImage image
  | otherwise = ProcedureOutcome image NothingToRestore [ShapeUnrecognized]

-- | Merge a UNIF container's PRG and CHR chunks into one image, keeping the whole container for the restore.
mergeUNIFImage :: ByteString -> ProcedureOutcome
mergeUNIFImage image = case walkUNIFChunks image of
  UNIFWalkTruncated ->
    ProcedureOutcome image NothingToRestore [SkippedBecause UNIFChunkTableTruncated]
  UNIFWalkComplete chunks ->
    ProcedureOutcome
      (ByteString.concat [unifChunkPayload chunk | chunk <- chunks, unifChunkClass chunk == PRGOrCHRChunk])
      (RestoreIntoUNIFContainer (OriginalUNIFImage image))
      [PerformedStep MergedUNIFChunks]

-- | One chunk of a UNIF container, framing preserved verbatim so a rebuild can re-emit it.
data UNIFChunkView = UNIFChunkView
  { unifChunkFraming :: ByteString  -- ^ The 8 framing bytes: 4-byte id, 4-byte little-endian length.
  , unifChunkPayload :: ByteString
  , unifChunkClass   :: UNIFChunkClass
  }

data UNIFChunkClass = PRGOrCHRChunk | OtherChunk
  deriving (Eq)

data UNIFWalkOutcome
  = UNIFWalkComplete [UNIFChunkView]
  | UNIFWalkTruncated

-- | Walk a UNIF container's chunk table, starting at offset 0x20 past the 32-byte file header.
-- (convroms.txt says 0x40; the reference seeks to 0x20, and the implementation byte wins, as it does for NINJA1's subformat identifier.)
-- Framing or payload running past the end of the file ends the walk as 'UNIFWalkTruncated' — merge and rebuild cannot honor a partial chunk.
walkUNIFChunks :: ByteString -> UNIFWalkOutcome
walkUNIFChunks image = walkFrom unifChunkTableOffset []
  where
    imageLength = ByteString.length image
    walkFrom position collected
      | position == imageLength = UNIFWalkComplete (reverse collected)
      | position + 8 > imageLength = UNIFWalkTruncated
      | otherwise =
          let framing       = ByteString.take 8 (ByteString.drop position image)
              chunkId       = ByteString.take 4 framing
              payloadLength = fromIntegral (getWord32LE (position + 4) image)
              payloadStart  = position + 8
          in if payloadStart + payloadLength > imageLength
               then UNIFWalkTruncated
               else walkFrom (payloadStart + payloadLength)
                             (UNIFChunkView
                                { unifChunkFraming = framing
                                , unifChunkPayload = ByteString.take payloadLength (ByteString.drop payloadStart image)
                                , unifChunkClass   = if isPRGOrCHRChunkId chunkId then PRGOrCHRChunk else OtherChunk
                                } : collected)

unifChunkTableOffset :: Int
unifChunkTableOffset = 0x20

-- | @PRG0@..@PRGF@ and @CHR0@..@CHRF@, uppercase hex digit — the reference spells out all sixteen of each.
isPRGOrCHRChunkId :: ByteString -> Bool
isPRGOrCHRChunkId chunkId =
  (ByteString.take 3 chunkId == "PRG" || ByteString.take 3 chunkId == "CHR")
  && ByteString.length chunkId == 4
  && isUppercaseHexDigit (ByteString8.index chunkId 3)
  where
    isUppercaseHexDigit character = isDigit character || (character >= 'A' && character <= 'F')

-- | The rebuild's refusal: the container's PRG and CHR chunks hold one byte count and the patched data another,
-- so reinsertion has no defined shape.
data UNIFRebuildMismatch = UNIFRebuildMismatch ExpectedSize ActualSize
  deriving (Show)

-- | Reinsert patched data into the original UNIF container: each PRG and CHR payload takes the next slice, every other chunk re-emits verbatim.
-- Only an exact byte-count match rebuilds — the chunk lengths are wire facts this walk must not invent.
rebuildUNIFContainer :: ByteString -> ByteString -> Either UNIFRebuildMismatch ByteString
rebuildUNIFContainer container patchedData = case walkUNIFChunks container of
  -- The container walked whole at merge time, so a truncated re-walk cannot happen here;
  -- the zero-total mismatch is its typed answer anyway.
  UNIFWalkTruncated -> Left (mismatchAgainst 0)
  UNIFWalkComplete chunks
    | containerTotal /= ByteString.length patchedData -> Left (mismatchAgainst (fromIntegral containerTotal))
    | otherwise ->
        let fillChunk remainingData chunk = case unifChunkClass chunk of
              OtherChunk    -> (remainingData, unifChunkFraming chunk <> unifChunkPayload chunk)
              PRGOrCHRChunk ->
                let (replacement, dataAfter) = ByteString.splitAt (ByteString.length (unifChunkPayload chunk)) remainingData
                in (dataAfter, unifChunkFraming chunk <> replacement)
            (_, rebuiltChunks) = mapAccumL fillChunk patchedData chunks
        in Right (ByteString.concat (ByteString.take unifChunkTableOffset container : rebuiltChunks))
    where
      containerTotal = sum [ByteString.length (unifChunkPayload chunk) | chunk <- chunks, unifChunkClass chunk == PRGOrCHRChunk]
  where
    mismatchAgainst containerTotal = UNIFRebuildMismatch
      (ExpectedSize (FileSize containerTotal))
      (ActualSize (byteFileSize patchedData))

----------------------------------------------------------------------------
-- SNES: copier headers, NSRT, HiROM deinterleaving
----------------------------------------------------------------------------

-- | The SNES procedure, per the reference's @sfam_read@.
-- Two decisions run in sequence and stay independent.
-- First the header: a 512-byte header comes off whenever the image is not whole 32 KiB banks;
-- its NSRT flavor (probed at 0x1E8, inside the header about to come off) is kept for the restore, a plain copier header dropped.
-- Then the body, by the internal-header checksum at 0x7FDC: LoROM passes through;
-- an interleaved HiROM deinterleaves, by Game Doctor chart at the three exact chart sizes or by even/odd halves otherwise;
-- and a body that answers only at 0xFFDC is an already-deinterleaved HiROM.
-- The Super UFO carve-out is honored — a @SUPERUFO@ signature at offset 8 routes even chart-sized images through the even/odd scheme.
normalizeSNESImage :: ByteString -> ProcedureOutcome
normalizeSNESImage image
  | not headerStripNeeded           = withBodyClassified image NothingToRestore []
  | ByteString.length image < 0x200 =
      ProcedureOutcome image NothingToRestore [SkippedBecause ImageShorterThanItsHeader]
  | nsrtSignaturePresent            =
      withBodyClassified strippedBody (RestoreHeaderPrefix (StrippedHeader header)) [PerformedStep StrippedNSRTHeader]
  | otherwise                       =
      withBodyClassified strippedBody NothingToRestore [PerformedStep StrippedSNESCopierHeader]
  where
    headerStripNeeded    = ByteString.length image `mod` snesBankWidth /= 0
    nsrtSignaturePresent = ByteString.take 4 (ByteString.drop 0x1E8 image) == "NSRT"
    superUFOSignaturePresent = ByteString.take 8 (ByteString.drop 0x8 image) == "SUPERUFO"
    (header, strippedBody) = ByteString.splitAt 0x200 image

    withBodyClassified body restore headerEvents =
      let (canonicalBytes, bodyEvents) = classifyBody body
      in ProcedureOutcome canonicalBytes restore (headerEvents <> bodyEvents)

    classifyBody body = case snesInternalHeaderProbe 0x7FDC body of
      Just (checksumPairValid, romstateOdd)
        | checksumPairValid && not romstateOdd -> (body, [])  -- LoROM: already canonical.
        | checksumPairValid                    -> deinterleaveHiROM body
      _ -> case snesInternalHeaderProbe 0xFFDC body of
        -- A valid pair at 0xFFDC with an odd romstate is a deinterleaved HiROM;
        -- a failing pair with an odd romstate is the reference's "possibly a beta cart".
        -- Both pass through as-is, the second quietly.
        Just (_, True) -> (body, [])
        _              -> (body, [ShapeUnrecognized])

    deinterleaveHiROM body
      | superUFOSignaturePresent = evenOddHalves body
      | otherwise = case ByteString.length body of
          0x280000 -> deinterleavedBy GD3Chart20MbitLayout snesGD3Chart20Mbit
          0x300000 -> deinterleavedBy GD3Chart24MbitLayout snesGD3Chart24Mbit
          0x600000 -> deinterleavedBy GD3Chart48MbitLayout snesGD3Chart48Mbit
          _        -> evenOddHalves body
      where
        deinterleavedBy layout chart =
          (deinterleaveByChart chart body, [PerformedStep (DeinterleavedSNESHiROM layout)])

    evenOddHalves body
      | bodyLength `mod` snesBankWidth /= 0 || odd bankCount =
          (body, [SkippedBecause SNESInterleavedBlocksNotWhole])
      | otherwise =
          ( deinterleaveByChart (evenOddInterleaveChart bankCount) body
          , [PerformedStep (DeinterleavedSNESHiROM EvenOddHalvesLayout)] )
      where
        bodyLength = ByteString.length body
        bankCount  = bodyLength `div` snesBankWidth

-- | Probe an SNES internal header at the given base: the inverse checksum at @base@,
-- the checksum at @base + 2@ (both little-endian), and the ROM-state byte at @base - 7@.
-- Answers whether the pair sums to @0xFFFF@ and whether the state's low nibble is odd (odd marks HiROM);
-- 'Nothing' when the image is too small to hold the header.
snesInternalHeaderProbe :: Int -> ByteString -> Maybe (Bool, Bool)
snesInternalHeaderProbe checksumBase body
  | ByteString.length body < checksumBase + 4 = Nothing
  | otherwise =
      let inversePair  = fromIntegral (getWord16LE checksumBase body) :: Int
          checksumPair = fromIntegral (getWord16LE (checksumBase + 2) body) :: Int
          romstate     = fromIntegral (ByteString.index body (checksumBase - 7)) `mod` 0x10 :: Int
      in Just (inversePair + checksumPair == 0xFFFF, odd romstate)

-- | One SNES bank: 32 KiB.
snesBankWidth :: Int
snesBankWidth = 0x8000

-- | Reorder an image's 32 KiB banks by a chart.
-- @chart[j] = i@ sends input bank @j@ to output position @i@, so the walk runs over output positions through the inverted chart.
-- The image must be exactly the chart's bank count; callers hold that.
deinterleaveByChart :: Array Int Int -> ByteString -> ByteString
deinterleaveByChart chart image =
  ByteString.concat [bankAt (inverted ! outputPosition) | outputPosition <- [low .. high]]
  where
    (low, high) = bounds chart
    inverted    = accumArray (\_ sourceBank -> sourceBank) 0 (low, high)
                    [(chart ! sourceBank, sourceBank) | sourceBank <- [low .. high]]
    bankAt position = ByteString.take snesBankWidth (ByteString.drop (position * snesBankWidth) image)

-- | The Game Doctor SF deinterleave charts (20, 24, 48 Mbit), verbatim from convroms.txt.
snesGD3Chart20Mbit :: Array Int Int
snesGD3Chart20Mbit = listArray (0, 79)
  [  1,   3,   5,   7,   9,  11,  13,  15,  17,  19,  21,  23,  25,  27,  29
  , 31,  33,  35,  37,  39,  41,  43,  45,  47,  49,  51,  53,  55,  57,  59
  , 61,  63,  65,  67,  69,  71,  73,  75,  77,  79,  64,  66,  68,  70,  72
  , 74,  76,  78,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54
  , 56,  58,  60,  62,   0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20
  , 22,  24,  26,  28,  30
  ]

snesGD3Chart24Mbit :: Array Int Int
snesGD3Chart24Mbit = listArray (0, 95)
  [  1,   3,   5,   7,   9,  11,  13,  15,  17,  19,  21,  23,  25,  27,  29
  , 31,  33,  35,  37,  39,  41,  43,  45,  47,  49,  51,  53,  55,  57,  59
  , 61,  63,  65,  67,  69,  71,  73,  75,  77,  79,  81,  83,  85,  87,  89
  , 91,  93,  95,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86
  , 88,  90,  92,  94,   0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20
  , 22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50
  , 52,  54,  56,  58,  60,  62
  ]

snesGD3Chart48Mbit :: Array Int Int
snesGD3Chart48Mbit = listArray (0, 191)
  [ 129, 131, 133, 135, 137, 139, 141, 143, 145, 147, 149, 151, 153, 155, 157
  , 159, 161, 163, 165, 167, 169, 171, 173, 175, 177, 179, 181, 183, 185, 187
  , 189, 191, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152
  , 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182
  , 184, 186, 188, 190,   1,   3,   5,   7,   9,  11,  13,  15,  17,  19,  21
  ,  23,  25,  27,  29,  31,  33,  35,  37,  39,  41,  43,  45,  47,  49,  51
  ,  53,  55,  57,  59,  61,  63,  65,  67,  69,  71,  73,  75,  77,  79,  81
  ,  83,  85,  87,  89,  91,  93,  95,  97,  99, 101, 103, 105, 107, 109, 111
  , 113, 115, 117, 119, 121, 123, 125, 127,   0,   2,   4,   6,   8,  10,  12
  ,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42
  ,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62,  64,  66,  68,  70,  72
  ,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94,  96,  98, 100, 102
  , 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126
  ]

-- | The deinterleave an interleaved HiROM uses when no Game Doctor chart applies: the copier stored the odd banks first,
-- then the even (@01234567@ becomes @13570246@).
-- Computed rather than tabulated, since the scheme is defined at every even bank count.
evenOddInterleaveChart :: Int -> Array Int Int
evenOddInterleaveChart bankCount =
  listArray (0, bankCount - 1)
    [ if bank < halfCount then 2 * bank + 1 else 2 * (bank - halfCount)
    | bank <- [0 .. bankCount - 1] ]
  where
    halfCount = bankCount `div` 2

----------------------------------------------------------------------------
-- N64: byte order
----------------------------------------------------------------------------

-- | N64 images declare their byte order in the leading magic: native @0x80371240@ passes through,
-- byteswapped @0x37804012@ (the V64 order) has every adjacent byte pair swapped, and any other lead is unrecognized.
normalizeN64Image :: ByteString -> ProcedureOutcome
normalizeN64Image image
  | leadingMagic == n64NativeOrderMagic = imageTakenAsIs image
  | leadingMagic == n64ByteswappedMagic =
      if even (ByteString.length image)
        then ProcedureOutcome (swapAdjacentBytePairs image) NothingToRestore [PerformedStep ByteswappedN64Image]
        else ProcedureOutcome image NothingToRestore [SkippedBecause N64ImageOddLength]
  | otherwise = ProcedureOutcome image NothingToRestore [ShapeUnrecognized]
  where
    leadingMagic = ByteString.take 4 image

n64NativeOrderMagic :: ByteString
n64NativeOrderMagic = ByteString.pack [0x80, 0x37, 0x12, 0x40]

n64ByteswappedMagic :: ByteString
n64ByteswappedMagic = ByteString.pack [0x37, 0x80, 0x40, 0x12]

-- | Whether the image leads with the V64 (byteswapped) magic — the one N64 byte order APS-N64's gate must tell apart.
isV64Image :: ByteString -> Bool
isV64Image image = ByteString.take 4 image == n64ByteswappedMagic

----------------------------------------------------------------------------
-- Game Boy and PC-Engine: size-probed headers
----------------------------------------------------------------------------

-- | A Game Boy image whose size is not whole 16 KiB banks carries a 512-byte SmartCard header to remove;
-- a bank-aligned image is already canonical.
-- The reference also probes the logo bytes at 0x104 and refuses on a mismatch, but that probe gates no transform, so slap does not run it.
normalizeGameBoyImage :: ByteString -> ProcedureOutcome
normalizeGameBoyImage image
  | ByteString.length image `mod` 0x4000 == 0 = imageTakenAsIs image
  | otherwise = stripHeaderDropping StrippedSmartCardHeader (Length 0x200) image

-- | A PC-Engine image whose size is not whole 4 KiB units carries a 512-byte Magic Super Griffin header to remove.
normalizePCEngineImage :: ByteString -> ProcedureOutcome
normalizePCEngineImage image
  | ByteString.length image `mod` 0x1000 == 0 = imageTakenAsIs image
  | otherwise = stripHeaderDropping StrippedMagicSuperGriffinHeader (Length 0x200) image

----------------------------------------------------------------------------
-- Sega: SMS/Game Gear and Genesis
----------------------------------------------------------------------------

-- | The offset of the SEGA signature that marks an already-canonical (BIN-format) image: 0x7FF4 for Master System and Game Gear,
-- 0x100 for Genesis.
-- The two procedures differ in nothing else.
smsSEGASignatureOffset, genesisSEGASignatureOffset :: Int
smsSEGASignatureOffset     = 0x7FF4
genesisSEGASignatureOffset = 0x100

-- | The shared Sega procedure.
-- A SEGA signature at the platform's offset means BIN format, already canonical;
-- the @0xAA 0xBB@ marker at offset 8 means SMD format — a 512-byte header comes off and each 16 KiB block deinterleaves.
-- With neither present the image is taken as-is with a warning, where the reference refuses.
normalizeSegaImage :: Int -> ByteString -> ProcedureOutcome
normalizeSegaImage segaSignatureOffset image
  | ByteString.take 4 (ByteString.drop segaSignatureOffset image) == "SEGA" = imageTakenAsIs image
  | copierMarkerPresentAtOffset8 image =
      let body = ByteString.drop 0x200 image
          bodyLength = ByteString.length body
          blockAt position = ByteString.take smdBlockWidth (ByteString.drop (position * smdBlockWidth) body)
      in if ByteString.length image < 0x200
           then ProcedureOutcome image NothingToRestore [SkippedBecause ImageShorterThanItsHeader]
           else if bodyLength `mod` smdBlockWidth /= 0
             then ProcedureOutcome image NothingToRestore [SkippedBecause SMDBlocksNotWhole]
             else ProcedureOutcome
                    (ByteString.concat [deinterleaveSMDBlock (blockAt position) | position <- [0 .. bodyLength `div` smdBlockWidth - 1]])
                    NothingToRestore
                    [PerformedStep DeinterleavedSMDImage]
  | otherwise = ProcedureOutcome image NothingToRestore [ShapeUnrecognized]

-- | One SMD block: 16 KiB.
smdBlockWidth :: Int
smdBlockWidth = 0x4000

----------------------------------------------------------------------------
-- Lynx
----------------------------------------------------------------------------

-- | A @LYNX@ signature marks a 64-byte header to remove and restore — it carries the screen-rotation flag vertically-played games need back.
-- An unsignatured image is already canonical.
normalizeLynxImage :: ByteString -> ProcedureOutcome
normalizeLynxImage image
  | ByteString.take 4 image == "LYNX" = stripHeaderKeeping StrippedLynxHeader (Length 0x40) image
  | otherwise                         = imageTakenAsIs image
