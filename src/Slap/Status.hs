{-# LANGUAGE OverloadedStrings #-}

-- | The public face of the status area: the whole vocabulary re-exported,
-- plus the emit pipeline — the only IO — that carries a rendered status item to stderr.
module Slap.Status
  ( -- Severity
    Severity(..)
  , severityLabel
  , slapAdvisorySeverity
    -- Emit pipeline
  , emitToStderr
  , emitAdvisory
  , emitAdvisories
  , bailError
  , orBail
    -- Status values
  , SlapError(..)
  , SourceRequiredCause(..)
  , ExtractionSubject(..)
  , SlapAdvisory(..)
  , ApplyError(..)
  , CursorKind(..)
  , UnencodeabilityReason(..)
  , DecompressionFailure(..)
  , BSDiffSection(..)
  , DecompressionCause(..)
  , XDelta1DiffCause(..)
  , BSDiffDifferCause(..)
  , GDIFFDiffCause(..)
  , XDelta1GzipStreamInputs(..)
  , CompressionAlgorithm(..)
  , decompressionAlgorithm
  , compressionAlgorithmName
  , bsDiffSectionName
  , renderDecompressionFailure
  , DroppedValue(..)
  , CreateResult(..)
  , Parsed(..)
  , Outcome(..)
  , noAdvisories
  , OverlapCount(..)
  , ClippedRecordCount(..)
  , OOBBlockCount(..)
  , UndoRecordCount(..)
  , ControlSectionSize(..)
  , DiffSectionSize(..)
  , TargetSectionSize(..)
  , MarkerOvershootBytes(..)
  , OOBOvershootBytes(..)
  , ApplyDirection(..)
  , directionVerb
  , VerificationSide(..)
  , HashAlgorithm(..)
  , ExpectedAdler32(..)
  , ActualAdler32(..)
  , ByteCheckLabel(..)
  , verificationSideLabel
  , hashAlgorithmLabel
    -- Restructured payload sums / newtypes
  , EmptyUnit(..)
  , emptyUnitLabel
  , XDelta1KnownUnsupportedVersion(..)
  , XDelta1ShapeViolation(..)
  , XDelta1SourceListShape(..)
  , XDelta1SourcelessShape(..)
  , XDelta1SourceFlag(..)
  , VCDIFFShapeViolation(..)
  , VCDIFFCodeTableMalformation(..)
  , VCDIFFCodeTableField(..)
  , VCDIFFCodeTableTemplateKind(..)
  , VCDIFFRFCFeature(..)
  , VCDIFFXDelta3Feature(..)
  , VCDIFFMalformation(..)
  , VCDIFFIndicatorKind(..)
  , ReservedBitsSet(..)
  , VCDIFFSection(..)
  , VCDIFFOnDemandSection(..)
  , BSDiffHeaderMalformation(..)
  , APSN64HeaderMalformation(..)
  , NINJA1Malformation(..)
  , NINJA1SubformatConversion(..)
  , NormalizationStep(..)
  , SNESInterleaveLayout(..)
  , NormalizedImageRole(..)
  , NormalizationSkipReason(..)
  , RestoredContent(..)
  , BPSMetadataDivergence(..)
  , LineText(..)
  , OffsetTokenText(..)
  , ChecksumTokenText(..)
  , ByteParserError(..)
  , ByteParserOperation(..)
  , DroppedDescriptionText(..)
    -- Rendering
  , renderSlapError
  , renderApplyError
  , renderByteParserError
  , renderCursorKind
  , renderSlapAdvisory
  ) where

import Slap.Status.Advisory
import Slap.Status.ApplyError
import Slap.Status.ByteParserError
import Slap.Status.Decompression
import Slap.Status.Error
import Slap.Status.Render.Advisory (renderSlapAdvisory)
import Slap.Status.Render.Error (renderSlapError)
import Slap.Status.Severity
import Slap.Status.VCDIFF
import Slap.Status.Vocabulary
import Slap.Status.XDelta1

import Data.Foldable (traverse_)
import Data.Text (Text)
import qualified Data.Text.IO as TextIO
import System.Exit (exitFailure)
import System.IO (stderr)

-- | The single stderr writer: every error, warning, or note slap emits routes through here.
emitToStderr :: Severity -> Text -> IO ()
emitToStderr severity body =
  TextIO.hPutStrLn stderr ("slap: " <> severityLabel severity <> ": " <> body)

emitAdvisory :: SlapAdvisory -> IO ()
emitAdvisory advisory = emitToStderr severity body
  where severity = slapAdvisorySeverity advisory
        body     = renderSlapAdvisory advisory

emitAdvisories :: [SlapAdvisory] -> IO ()
emitAdvisories = traverse_ emitAdvisory

bailError :: SlapError -> IO a
bailError slapError = emitToStderr SeverityError (renderSlapError slapError) >> exitFailure

orBail :: Either SlapError a -> IO a
orBail = either bailError pure
