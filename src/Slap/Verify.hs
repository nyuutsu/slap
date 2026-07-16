{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DerivingVia #-}

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
  , Weighing
  , weighSource
  , weighTarget
  , flipSpokenSides
  , judgeWeighing
    -- * The mismatches and their enforcement lanes
  , VerificationMismatch(..)
  , MismatchClass(..)
  , mismatchClass
    -- * The verdict, before any policy
  , VerificationVerdict(..)
  , DeclaredCheckKind(..)
  , verdictOnWeighing
  , verdictOnSource
  , verdictOnTarget
  ) where

import Slap.Binary (crc16, md5, sha1, viewBytesInRange, zeroExtendedBlock)
import Slap.Checksum (CRC32, CRC16, Adler32, MD5Hash, SHA1Hash,
                      ExpectedCRC32(..), ActualCRC32(..))
import Slap.FFI (crc32, adler32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset, Length(..), FileSize,
                     ExpectedSize(..), ActualSize(..), byteFileSize, byteLength)
import Slap.Normalize (isV64Image)
import Slap.Status (SlapError(..), SlapAdvisory(..), VerificationMismatch(..), Outcome(..),
                    VerificationSide(..), HashAlgorithm(..), DeclaredCheckKind(..),
                    ExpectedAdler32(..), ActualAdler32(..), ByteCheckLabel(..))
import qualified Slap.NINJA1.Create as NINJA1

import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString (ByteString)
import Data.List (nub)
import Data.List.NonEmpty (NonEmpty(..))
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

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
  deriving (Show, Eq, Generic)
  deriving (FromJSON) via Generically VerificationPolicy

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

-- | A patch's declared checks, each weighed against a file's actual bytes.
-- 'judgeWeighing' and 'verdictOnWeighing' both read one weighing, so they cannot disagree about what was compared.
newtype Weighing = Weighing [WeighedCheck]

instance Semigroup Weighing where
  Weighing leftChecks <> Weighing rightChecks = Weighing (leftChecks <> rightChecks)

instance Monoid Weighing where
  mempty = Weighing []

-- | One declared check, weighed against the actual bytes.
data WeighedCheck = WeighedCheck !DeclaredCheckKind !CheckFinding

data CheckFinding = CheckHeld | CheckMismatched !VerificationMismatch

-- | Which enforcement lane a mismatch lands in; 'judgeWeighing' folds the user's policy over the fatal class only.
data MismatchClass = AdvisoryClass | FatalClass
  deriving (Eq)

-- | Every mismatch's lane, read off its constructor. File size is the one check whose severity varies by format,
-- and its two severities are already two constructors, so the table stays total.
mismatchClass :: VerificationMismatch -> MismatchClass
mismatchClass mismatch = case mismatch of
  VerificationCRCMismatch {}         -> FatalClass
  VerificationHashMismatch {}        -> FatalClass
  VerificationAdler32Mismatch {}     -> FatalClass
  VerificationFileSizeMismatch {}    -> FatalClass
  APSN64ImageFormatMismatch          -> FatalClass
  VerificationFileSizeAdvisory {}    -> AdvisoryClass
  VerificationBlockCRC16Mismatch {}  -> AdvisoryClass
  VerificationPPFBlockMismatch {}    -> AdvisoryClass
  VerificationSourceBytesMismatch {} -> AdvisoryClass

-- | Weigh apply's input against everything the patch declared about its source.
-- The size check sorts ahead of the whole-file hashes: a wrong-size file mismatches both, and the size is the better first fact.
-- Row order does double duty: it picks which fatal mismatch 'judgeWeighing' refuses with,
-- and it orders the kinds 'verdictOnWeighing' hands the report's prose.
weighSource :: Verification -> InputFileContents -> Weighing
weighSource verification (InputFileContents sourceBytes) = mconcat
  [ weighAll DeclaredBlockCRC16      (blockCRC16Mismatch SourceSide sourceBytes)                 (verifySourceBlocks verification)
  , weighAll DeclaredValidationBlock (ppfBlockMismatch sourceBytes)                              (verifyPPFBlock verification)
  , weighAll DeclaredByteComparison  (sourceBytesMismatch sourceBytes)                           (verifySourceBytes verification)
  , weighAll DeclaredFileSize        (fileSizeMismatch (byteFileSize sourceBytes))               (verifyFileSize verification)
  , weighAll DeclaredCRC32           (crcMismatch SourceSide (ActualCRC32 (crc32 preprocessed))) (verifySourceCRC32 verification)
  , weighAll DeclaredMD5             (hashMismatch SourceSide MD5 (md5 preprocessed))            (verifySourceMD5 verification)
  , weighAll DeclaredSHA1            (hashMismatch SourceSide SHA1 (sha1 preprocessed))          (verifySourceSHA1 verification)
  , weighAll DeclaredByteOrder       (byteOrderMismatch sourceBytes)                             (verifyN64ByteOrder verification)
  ]
  where
    preprocessed = applySourcePreHash (verifySourcePreHash verification) sourceBytes

-- | Weigh apply's output against everything the patch declared about its target.
weighTarget :: Verification -> OutputFileContents -> Weighing
weighTarget verification (OutputFileContents targetBytes) = mconcat
  [ weighAll DeclaredBlockCRC16    (blockCRC16Mismatch TargetSide targetBytes)                (verifyTargetBlocks verification)
  , weighAll DeclaredCRC32         (crcMismatch TargetSide (ActualCRC32 (crc32 targetBytes))) (verifyTargetCRC32 verification)
  , weighAll DeclaredMD5           (hashMismatch TargetSide MD5 (md5 targetBytes))            (verifyTargetMD5 verification)
  , weighAll DeclaredWindowAdler32 windowAdlerMismatch                                        (verifyWindowAdler32 verification)
  ]
  where
    windowAdlerMismatch (WindowCheck windowOffset windowLength expected) =
      adlerMismatch windowOffset (ActualAdler32 (adler32 (viewBytesInRange windowOffset windowLength targetBytes))) expected

-- | One weighing row: judge every declared check of one kind.
-- 'Foldable' spans the two shapes a declaration arrives in — a list of checks, or one optional check.
weighAll :: Foldable declared => DeclaredCheckKind -> (check -> Maybe VerificationMismatch) -> declared check -> Weighing
weighAll checkKind judge = foldMap (\declaredCheck -> Weighing [weigh checkKind (judge declaredCheck)])

weigh :: DeclaredCheckKind -> Maybe VerificationMismatch -> WeighedCheck
weigh checkKind = WeighedCheck checkKind . maybe CheckHeld CheckMismatched

-- | Speak a weighing's side labels reversed. Undo reads the patch backwards —
-- the target declaration describes the file handed in, the source declaration the file written back —
-- so the labels its findings speak flip to keep naming the run's own input and output.
flipSpokenSides :: Weighing -> Weighing
flipSpokenSides (Weighing weighedChecks) = Weighing (map flipWeighedCheck weighedChecks)
  where
    flipWeighedCheck (WeighedCheck checkKind checkFinding) =
      WeighedCheck checkKind (flipCheckFinding checkFinding)
    flipCheckFinding CheckHeld = CheckHeld
    flipCheckFinding (CheckMismatched mismatch) = CheckMismatched (flipMismatchSide mismatch)

-- | The sided mismatches speak the opposite side; the unsided ones have nothing to flip.
-- Total over 'VerificationMismatch', so a new sided check cannot slip past undo unflipped.
flipMismatchSide :: VerificationMismatch -> VerificationMismatch
flipMismatchSide mismatch = case mismatch of
  VerificationCRCMismatch side expected actual      -> VerificationCRCMismatch (opposite side) expected actual
  VerificationHashMismatch side algorithm           -> VerificationHashMismatch (opposite side) algorithm
  VerificationFileSizeMismatch side expected actual -> VerificationFileSizeMismatch (opposite side) expected actual
  VerificationBlockCRC16Mismatch side blockOffset   -> VerificationBlockCRC16Mismatch (opposite side) blockOffset
  VerificationAdler32Mismatch {}                    -> mismatch
  VerificationPPFBlockMismatch {}                   -> mismatch
  VerificationFileSizeAdvisory {}                   -> mismatch
  VerificationSourceBytesMismatch {}                -> mismatch
  APSN64ImageFormatMismatch                         -> mismatch
  where
    opposite SourceSide = TargetSide
    opposite TargetSide = SourceSide

-- | Fold the user's policy over a weighing.
-- 'EnforceVerification' turns the first fatal-class mismatch into the run-stopping error; 'SkipVerification' warns instead.
-- Advisory-class findings ride the 'Outcome' either way, the 'Left' included.
judgeWeighing :: VerificationPolicy -> Weighing -> Outcome (Either SlapError ())
judgeWeighing verificationPolicy (Weighing weighedChecks) = case verificationPolicy of
  SkipVerification    -> Outcome (Right ()) (spoken (advisoryMismatches ++ fatalMismatches))
  EnforceVerification -> case fatalMismatches of
    []                -> Outcome (Right ()) (spoken advisoryMismatches)
    firstMismatch : _ -> Outcome (Left (VerificationFatal firstMismatch)) (spoken advisoryMismatches)
  where
    spoken             = map DeclaredCheckMismatched
    advisoryMismatches = mismatchesInClass AdvisoryClass weighedChecks
    fatalMismatches    = mismatchesInClass FatalClass weighedChecks

mismatchesInClass :: MismatchClass -> [WeighedCheck] -> [VerificationMismatch]
mismatchesInClass wantedClass weighedChecks =
  [ mismatch | WeighedCheck _ (CheckMismatched mismatch) <- weighedChecks, mismatchClass mismatch == wantedClass ]

----------------------------------------------------------------------------
-- The verdict, before any policy
----------------------------------------------------------------------------

-- | Does this file agree with what the patch declares about it?
-- Keeps apart the two facts 'judgeWeighing' conflates into @'Right' ()@: "every declared check held" and "there was nothing to check".
data VerificationVerdict
  = VerdictMatches !(NonEmpty DeclaredCheckKind)
    -- ^ At least one check is declared, and every one of them held — the kinds say what that claim rests on.
  | VerdictDiffers !(NonEmpty VerificationMismatch)
    -- ^ At least one declared check did not hold. Every disagreement is carried, advisory-class included —
    -- a wider net than 'EnforceVerification', which refuses only over fatal-class mismatches.
  | VerdictUncheckable
    -- ^ The patch declares nothing about this file, so slap cannot say whether it is the right one.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically VerificationVerdict

-- | The verdict on apply's input: weigh and take the verdict in one step.
verdictOnSource :: Verification -> InputFileContents -> VerificationVerdict
verdictOnSource verification = verdictOnWeighing . weighSource verification

-- | The verdict on apply's output; the target-side mirror of 'verdictOnSource'.
verdictOnTarget :: Verification -> OutputFileContents -> VerificationVerdict
verdictOnTarget verification = verdictOnWeighing . weighTarget verification

verdictOnWeighing :: Weighing -> VerificationVerdict
verdictOnWeighing (Weighing weighedChecks)
  | mismatch : mismatches   <- disagreements = VerdictDiffers (mismatch :| mismatches)
  | checkKind : checkKinds  <- declaredKinds = VerdictMatches (checkKind :| checkKinds)
  | otherwise                                = VerdictUncheckable
  where
    disagreements = [ mismatch | WeighedCheck _ (CheckMismatched mismatch) <- weighedChecks ]
    declaredKinds = nub [ checkKind | WeighedCheck checkKind _ <- weighedChecks ]

----------------------------------------------------------------------------
-- The per-check judgments
----------------------------------------------------------------------------

blockCRC16Mismatch :: VerificationSide -> ByteString -> BlockCheck -> Maybe VerificationMismatch
blockCRC16Mismatch side subjectBytes (BlockCheck blockOffset blockLength expected)
  | crc16 (zeroExtendedBlock blockOffset blockLength subjectBytes) == expected = Nothing
  | otherwise = Just (VerificationBlockCRC16Mismatch side blockOffset)

ppfBlockMismatch :: ByteString -> ValidationBlock -> Maybe VerificationMismatch
ppfBlockMismatch sourceBytes (ValidationBlock blockOffset expectedData)
  | viewBytesInRange blockOffset (byteLength expectedData) sourceBytes == expectedData = Nothing
  | otherwise = Just (VerificationPPFBlockMismatch blockOffset)

sourceBytesMismatch :: ByteString -> ByteCheck -> Maybe VerificationMismatch
sourceBytesMismatch sourceBytes (ByteCheck checkOffset (AdvisoryExpectedBytes expectedData) checkLabel)
  | viewBytesInRange checkOffset (byteLength expectedData) sourceBytes == expectedData = Nothing
  | otherwise = Just (VerificationSourceBytesMismatch (ByteCheckLabel checkLabel) checkOffset)

fileSizeMismatch :: FileSize -> FileSizeCheck -> Maybe VerificationMismatch
fileSizeMismatch actualSize sizeCheck = case sizeCheck of
  AdvisorySize expected -> disagreement expected (VerificationFileSizeAdvisory (ExpectedSize expected) (ActualSize actualSize))
  RequiredSize expected -> disagreement expected (VerificationFileSizeMismatch SourceSide (ExpectedSize expected) (ActualSize actualSize))
  where
    disagreement expected mismatch
      | expected == actualSize = Nothing
      | otherwise              = Just mismatch

crcMismatch :: VerificationSide -> ActualCRC32 -> CRC32 -> Maybe VerificationMismatch
crcMismatch side (ActualCRC32 actual) expected
  | expected == actual = Nothing
  | otherwise          = Just (VerificationCRCMismatch side (ExpectedCRC32 expected) (ActualCRC32 actual))

hashMismatch :: Eq hash => VerificationSide -> HashAlgorithm -> hash -> hash -> Maybe VerificationMismatch
hashMismatch side algorithm actual expected
  | expected == actual = Nothing
  | otherwise          = Just (VerificationHashMismatch side algorithm)

adlerMismatch :: Offset -> ActualAdler32 -> Adler32 -> Maybe VerificationMismatch
adlerMismatch windowOffset (ActualAdler32 actual) expected
  | expected == actual = Nothing
  | otherwise          = Just (VerificationAdler32Mismatch windowOffset (ExpectedAdler32 expected) (ActualAdler32 actual))

byteOrderMismatch :: ByteString -> ExpectedN64ByteOrder -> Maybe VerificationMismatch
byteOrderMismatch sourceBytes expected
  | mismatched = Just APSN64ImageFormatMismatch
  | otherwise  = Nothing
  where
    mismatched = case expected of
      SourceMustBeV64    -> not (isV64Image sourceBytes)
      SourceMustNotBeV64 -> isV64Image sourceBytes
