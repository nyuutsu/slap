{-# LANGUAGE OverloadedStrings #-}

-- | Reading a parsed patch's declared expectations against actual bytes.
--
-- The passes are pure and hand back every mismatch they found, so the caller chooses which ones reach the user.
-- The preprocessing a patch's checksums assume ('applySourcePreHash') lives here too, below any frontend,
-- so everything that verifies hashes the same bytes the same way.
module Slap.Verify
  ( -- * The user's posture
    VerificationPolicy(..)
    -- * What a patch declares
  , Verification(..)
  , noVerification
  , SourcePreHash(..)
  , applySourcePreHash
  , BlockCheck(..)
  , ValidationBlock(..)
  , WindowCheck(..)
  , ByteCheck(..)
  , AdvisoryExpectedBytes(..)
  , FileSizeCheck(..)
  , ExpectedN64ByteOrder(..)
    -- * Weighing a file against it
  , verifySource
  , verifyTarget
  ) where

import Slap.Binary (crc16, md5, sha1, viewBytesInRange, zeroExtendedBlock)
import Slap.Checksum (CRC32, CRC16, Adler32, MD5Hash, SHA1Hash,
                      ExpectedCRC32(..), ActualCRC32(..))
import Slap.FFI (crc32, adler32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset, Length(..), FileSize,
                     ExpectedSize(..), ActualSize(..), byteFileSize)
import Slap.Normalize (isV64Image)
import Slap.Status (SlapError(..), SlapAdvisory(..), Outcome(..),
                    VerificationSide(..), HashAlgorithm(..),
                    ExpectedAdler32(..), ActualAdler32(..), ByteCheckLabel(..))
import qualified Slap.NINJA1.Create as NINJA1

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Maybe (catMaybes, maybeToList)
import Data.Text (Text)

----------------------------------------------------------------------------
-- The user's posture
----------------------------------------------------------------------------

-- | The user's runtime posture toward verification mismatches.
-- 'EnforceVerification' (default) fails with a readable error on a hash mismatch;
-- 'SkipVerification' (set by @--no-verify@) downgrades the mismatch to a warning and applies anyway.
-- Formats without source checksums are unaffected either way.
--
-- The enforcement axis of slap's @--no-verify@ family, set on apply, undo, and convert (the @--with INPUT@ check).
-- The embed-side counterpart and the full family map live on 'Slap.Convert.VerificationInclusion'.
data VerificationPolicy
  = EnforceVerification
  | SkipVerification
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- What a patch declares
----------------------------------------------------------------------------

-- | Verification data extracted from a parsed patch.
-- All fields are optional; formats populate whichever they carry.
data Verification = Verification
  { verifySourceCRC32  :: Maybe CRC32
  , verifySourceMD5    :: Maybe MD5Hash
  , verifySourceSHA1   :: Maybe SHA1Hash
  , verifyTargetCRC32  :: Maybe CRC32
  , verifyTargetMD5    :: Maybe MD5Hash
  , verifySourceBlocks  :: [BlockCheck]
  , verifyTargetBlocks  :: [BlockCheck]
  , verifyPPFBlock      :: Maybe ValidationBlock
    -- | File-size check, present when the format declares an expected source size.
    -- The 'FileSizeCheck' carries its own advisory-or-required severity.
  , verifyFileSize :: Maybe FileSizeCheck
  , verifyWindowAdler32 :: [WindowCheck]
  , verifySourceBytes   :: [ByteCheck]
  , verifySourcePreHash :: SourcePreHash
    -- | Set for an APS-N64 Type-1 source; gates its byte-order on apply, 'Nothing' otherwise.
  , verifyN64ByteOrder :: Maybe ExpectedN64ByteOrder
  }

noVerification :: Verification
noVerification = Verification
  { verifySourceCRC32 = Nothing, verifySourceMD5 = Nothing, verifySourceSHA1 = Nothing
  , verifyTargetCRC32 = Nothing, verifyTargetMD5 = Nothing
  , verifySourceBlocks = [], verifyTargetBlocks = []
  , verifyPPFBlock = Nothing, verifyFileSize = Nothing
  , verifyWindowAdler32 = [], verifySourceBytes = []
  , verifySourcePreHash = HashWholeSource
  , verifyN64ByteOrder = Nothing
  }

-- | How the source bytes are transformed before the source hashes are computed —
-- data, not a bare function, so 'Verification' stays inspectable.
-- 'HashNINJA1Sample' is NINJA1's large-file sampling rule ('Slap.NINJA1.Create.ninja1HashInput');
-- 'HashWholeSource' is the default for every other format.
data SourcePreHash = HashWholeSource | HashNINJA1Sample
  deriving (Eq, Show)

applySourcePreHash :: SourcePreHash -> ByteString -> ByteString
applySourcePreHash HashWholeSource  = id
applySourcePreHash HashNINJA1Sample = NINJA1.ninja1HashInput

-- | The N64 image byte-order an APS-N64 Type-1 patch was built against.
-- Its record offsets assume one order, so applying to a source in the other would corrupt it;
-- the format distinguishes only V64 (the byteswapped "Doctor" image) from everything else.
data ExpectedN64ByteOrder = SourceMustBeV64 | SourceMustNotBeV64
  deriving (Show, Eq)

-- | Per-block CRC16 check (APS-GBA): the CRC16 covers the zero-extended block, not the clipped tail.
data BlockCheck = BlockCheck !Offset !Length !CRC16
  deriving (Show)

-- | Validation block comparison (PPF2 and PPF3). The bytes are carried as a raw 'ByteString' at this cross-cutting layer;
-- each format wraps them in its own role newtype during parse and emit.
data ValidationBlock = ValidationBlock !Offset !ByteString
  deriving (Show)

-- | Per-window Adler32 check (VCDIFF).
data WindowCheck = WindowCheck
  { windowCheckTargetBase    :: !Offset
  , windowCheckOutputLength  :: !Length
  , windowCheckStoredAdler32 :: !Adler32
  }
  deriving (Show)

-- | Advisory byte-range comparison (APS-N64 cart ID, country, CRC).
-- The trailing 'Text' field is the check's label.
data ByteCheck = ByteCheck !Offset !AdvisoryExpectedBytes !Text
  deriving (Show)

-- | The bytes an advisory 'ByteCheck' expects to find at its offset in the source file.
-- Advisory, not required: a mismatch emits a warning and the apply proceeds.
newtype AdvisoryExpectedBytes = AdvisoryExpectedBytes
  { unAdvisoryExpectedBytes :: ByteString }
  deriving (Show, Eq)

-- | A declared file-size expectation paired with how a mismatch is treated.
-- File size is the one verification check whose severity varies by format,
-- so the severity rides on the value here rather than on which field carries it.
data FileSizeCheck
  = AdvisorySize !FileSize
    -- ^ The format has a stronger integrity gate (e.g. a CRC32), so a size mismatch only warns; the stronger check catches real corruption.
  | RequiredSize !FileSize
    -- ^ The format treats the declared size as a hard precondition of apply, so a mismatch fails unless @--no-verify@ is set.
    -- DPS's size is its only integrity gate; xdelta1's reference applier refuses a wrong-length from file even with MD5s present.
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- Weighing a file against it
----------------------------------------------------------------------------

-- Each pass sorts what it finds into two classes: advisory-class mismatches, which warn regardless of @--no-verify@,
-- and fatal-class mismatches, whose fate 'VerificationPolicy' decides.
-- File size lands in either class ('FileSizeCheck' says which), and sorts ahead of the hash checks,
-- so a size mismatch surfaces before a hash one.

-- | Weigh apply's input against everything the patch declared about its source.
verifySource :: VerificationPolicy -> Verification -> InputFileContents -> Outcome (Either SlapError ())
verifySource verificationPolicy verification (InputFileContents sourceBytes) =
  judgeMismatches verificationPolicy (advisoryClass ++ advisorySize) (fatalSize ++ fatalClass)
  where
    preprocessed = applySourcePreHash (verifySourcePreHash verification) sourceBytes
    advisoryClass = catMaybes
      (  map (blockCRC16Mismatch SourceSide sourceBytes) (verifySourceBlocks verification)
      ++ map (ppfBlockMismatch sourceBytes) (maybeToList (verifyPPFBlock verification))
      ++ map (sourceBytesMismatch sourceBytes) (verifySourceBytes verification)
      )
    (advisorySize, fatalSize) = fileSizeMismatch (verifyFileSize verification) (byteFileSize sourceBytes)
    fatalClass = catMaybes
      (  [ crcMismatch SourceSide expected (crc32 preprocessed)      | expected <- maybeToList (verifySourceCRC32 verification) ]
      ++ [ hashMismatch SourceSide MD5 expected (md5 preprocessed)   | expected <- maybeToList (verifySourceMD5 verification) ]
      ++ [ hashMismatch SourceSide SHA1 expected (sha1 preprocessed) | expected <- maybeToList (verifySourceSHA1 verification) ]
      ++ [ byteOrderMismatch sourceBytes expected                    | expected <- maybeToList (verifyN64ByteOrder verification) ]
      )

-- | Weigh apply's output against everything the patch declared about its target.
verifyTarget :: VerificationPolicy -> Verification -> OutputFileContents -> Outcome (Either SlapError ())
verifyTarget verificationPolicy verification (OutputFileContents targetBytes) =
  judgeMismatches verificationPolicy advisoryClass fatalClass
  where
    advisoryClass = catMaybes (map (blockCRC16Mismatch TargetSide targetBytes) (verifyTargetBlocks verification))
    fatalClass = catMaybes
      (  [ crcMismatch TargetSide expected (crc32 targetBytes)    | expected <- maybeToList (verifyTargetCRC32 verification) ]
      ++ [ hashMismatch TargetSide MD5 expected (md5 targetBytes) | expected <- maybeToList (verifyTargetMD5 verification) ]
      ++ [ adlerMismatch windowOffset expected (adler32 (viewBytesInRange windowOffset windowLength targetBytes))
         | WindowCheck windowOffset windowLength expected <- verifyWindowAdler32 verification ]
      )

-- | Fold the user's policy over what a pass found.
-- 'EnforceVerification' turns the first fatal-class mismatch into the run-stopping error; 'SkipVerification' warns instead.
-- Advisory-class findings ride the 'Outcome' either way, the 'Left' included.
judgeMismatches :: VerificationPolicy -> [SlapAdvisory] -> [SlapAdvisory] -> Outcome (Either SlapError ())
judgeMismatches SkipVerification    advisoryClass fatalClass = Outcome (Right ()) (advisoryClass ++ fatalClass)
judgeMismatches EnforceVerification advisoryClass fatalClass = case fatalClass of
  []                -> Outcome (Right ()) advisoryClass
  firstMismatch : _ -> Outcome (Left (VerificationFatal firstMismatch)) advisoryClass

----------------------------------------------------------------------------
-- The per-check judgments
----------------------------------------------------------------------------

blockCRC16Mismatch :: VerificationSide -> ByteString -> BlockCheck -> Maybe SlapAdvisory
blockCRC16Mismatch side subjectBytes (BlockCheck blockOffset blockLength expected)
  | crc16 (zeroExtendedBlock blockOffset blockLength subjectBytes) == expected = Nothing
  | otherwise = Just (VerificationBlockCRC16Mismatch side blockOffset)

ppfBlockMismatch :: ByteString -> ValidationBlock -> Maybe SlapAdvisory
ppfBlockMismatch sourceBytes (ValidationBlock blockOffset expectedData)
  | viewBytesInRange blockOffset (Length (ByteString.length expectedData)) sourceBytes == expectedData = Nothing
  | otherwise = Just (VerificationPPFBlockMismatch blockOffset)

sourceBytesMismatch :: ByteString -> ByteCheck -> Maybe SlapAdvisory
sourceBytesMismatch sourceBytes (ByteCheck checkOffset (AdvisoryExpectedBytes expectedData) checkLabel)
  | viewBytesInRange checkOffset (Length (ByteString.length expectedData)) sourceBytes == expectedData = Nothing
  | otherwise = Just (VerificationSourceBytesMismatch (ByteCheckLabel checkLabel) checkOffset)

-- | Judge a declared file size, sorting the possible mismatch onto the side its severity names:
-- @(advisory-class, fatal-class)@, at most one populated.
fileSizeMismatch :: Maybe FileSizeCheck -> FileSize -> ([SlapAdvisory], [SlapAdvisory])
fileSizeMismatch declaredSize actualSize = case declaredSize of
  Nothing -> ([], [])
  Just (AdvisorySize expected)
    | expected == actualSize -> ([], [])
    | otherwise -> ([VerificationFileSizeAdvisory (ExpectedSize expected) (ActualSize actualSize)], [])
  Just (RequiredSize expected)
    | expected == actualSize -> ([], [])
    | otherwise -> ([], [VerificationFileSizeMismatch SourceSide (ExpectedSize expected) (ActualSize actualSize)])

crcMismatch :: VerificationSide -> CRC32 -> CRC32 -> Maybe SlapAdvisory
crcMismatch side expected actual
  | expected == actual = Nothing
  | otherwise          = Just (VerificationCRCMismatch side (ExpectedCRC32 expected) (ActualCRC32 actual))

hashMismatch :: Eq hash => VerificationSide -> HashAlgorithm -> hash -> hash -> Maybe SlapAdvisory
hashMismatch side algorithm expected actual
  | expected == actual = Nothing
  | otherwise          = Just (VerificationHashMismatch side algorithm)

adlerMismatch :: Offset -> Adler32 -> Adler32 -> Maybe SlapAdvisory
adlerMismatch windowOffset expected actual
  | expected == actual = Nothing
  | otherwise          = Just (VerificationAdler32Mismatch windowOffset (ExpectedAdler32 expected) (ActualAdler32 actual))

byteOrderMismatch :: ByteString -> ExpectedN64ByteOrder -> Maybe SlapAdvisory
byteOrderMismatch sourceBytes expected
  | mismatched = Just APSN64ImageFormatMismatch
  | otherwise  = Nothing
  where
    mismatched = case expected of
      SourceMustBeV64    -> not (isV64Image sourceBytes)
      SourceMustNotBeV64 -> isV64Image sourceBytes
