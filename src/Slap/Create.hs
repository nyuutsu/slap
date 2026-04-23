-- | Coordination-layer porcelain for patch creation. This module
-- is the single home for "the thing that makes a patch": one
-- named entry point per format slap can emit, each written as a
-- thin wrapper over the underlying format-level encoder (for
-- differential formats) or over 'createFromMemory' (for direct
-- formats whose creation path threads a 'PatchContents' through
-- the shared pipeline owned by "Slap.Convert").
--
-- Slap.Create and "Slap.Convert" sit together in the coordination
-- layer. Slap.Convert owns the conversion porcelain — the
-- 'PatchContents' pipeline, the 'FormatSpecification' contract
-- checker, and the 'convertDirect' engine. Slap.Create owns the
-- creation porcelain — the per-format front doors that know which
-- format they're targeting statically. Callers that arrive with a
-- 'CreateFormat' tag (notably the CLI in @app/Main.hs@) use
-- 'createFromMemory', which Slap.Create re-exports from Slap.Convert;
-- callers whose target format is fixed at compile time use the
-- per-format porcelain here.
--
-- The diff-format porcelain is genuinely thin: each function
-- either re-exports or forwards directly to the format's
-- @Slap.Foo.Create.createFoo@. Those entry points already accept
-- source and target file contents plus whatever structured extras
-- the format needs, so there is nothing to coordinate beyond the
-- argument list.
--
-- The direct-format porcelain is thinner still in intent but thicker
-- in mechanics: direct-format creation routes through
-- 'createFromMemory', which owns the shared 'buildContents' ->
-- 'encodeDirect' pipeline that builds a universal 'PatchContents'
-- from source and target bytes and then encodes it into the target
-- format. The per-format direct wrappers therefore assemble a
-- 'RequestedPatchMetadata' (and, for 'createNINJA1', a seed 'PatchContents' to
-- carry the compression flag through the @--with@ inheritance slot)
-- and call 'createFromMemory'. This asymmetry isn't an apology —
-- it's a statement of what the types express: the direct family
-- shares a pipeline, the differential family doesn't, and the
-- porcelain reflects the underlying shape rather than hiding it
-- behind per-format facades.
--
-- The "extras" on the direct-format porcelain are design-fresh:
-- 'BPSMetadata', 'PPFDescription', and 'PCHTXTDescription' are
-- newtype wrappers introduced so a call site can say what a raw
-- 'ByteString' or 'String' is for; 'PPFOptions' and 'NINJA1Options'
-- are records that group the extras a caller must decide on, so
-- multi-parameter call sites never pass two bare 'Bool's or two
-- similarly-typed values in a row.
module Slap.Create
  ( -- * Differential-format porcelain
    createBPS
  , createUPS
  , createDPS
  , createNINJA2
  , createAPSGBA
  , createGDIFF
    -- * Direct-format porcelain
  , createIPS
  , createIPS32
  , createEBP
  , createPPF3
  , createNINJA1
  , createPMSR
  , createPCHTXT
  , createAPSN64
    -- * Porcelain aggregate records
  , PPFOptions(..)
  , NINJA1Options(..)
    -- * Dynamic entry point (re-export)
  , createFromMemory
  ) where

import qualified Slap.BPS.Create as BPS
import Slap.BPS.Types (BPSMetadata(..))
import Slap.UPS.Create (createUPS)
import qualified Slap.DPS.Create as DPS
import Slap.DPS.Types (DPSMetadata, DPSStability)
import qualified Slap.NINJA2.Create as NINJA2
import Slap.NINJA2.Types (NINJA2Metadata)
import Slap.APSGBA.Create (createAPSGBA)
import Slap.GDIFF.Create (createGDIFF)
import Slap.IPS.Types (EBPMetadataFields(..))
import Slap.PPF.Types
  ( PPFDescription(..)
  , PPFImageType
  , PPFUndoInclusion(..)
  , PPFValidationInclusion(..)
  )
import Slap.PCHTXT.Types (PCHTXTDescription(..))
import Slap.NINJA1.Types (NINJA1Compression(..))
import Slap.APSN64.Types (APSN64Description(..))
import Slap.PlatformType (PlatformType)

import Slap.Convert
  ( CreateFormat(..)
  , RequestedPatchMetadata(..)
  , UndoInclusion(..)
  , ValidationInclusion(..)
  , DirectCreate(..)
  , PatchContents(..)
  , createFromMemory
  , noMetadataRequested
  , emptyContents
  )
import Slap.Error (SlapError, CreateResult)
import Slap.FileContents (SourceFileContents, TargetFileContents)

----------------------------------------------------------------------------
-- Porcelain aggregate records
--
-- These records live here rather than in the format Types modules
-- because they group format extras specifically for the porcelain
-- call site — they are aggregate-of-options records, not wire-level
-- vocabulary. The underlying two-constructor sums (PPFUndoInclusion,
-- PPFValidationInclusion, NINJA1Compression) live in their format
-- Types modules where they belong.
----------------------------------------------------------------------------

-- | Options the 'createPPF3' porcelain needs besides source, target,
-- description, and image type. Grouping the two flags in a record
-- avoids a call site that reads as two positional 'Bool's.
data PPFOptions = PPFOptions
  { ppfOptionsUndo       :: PPFUndoInclusion
  , ppfOptionsValidation :: PPFValidationInclusion
  } deriving (Show, Eq)

-- | Options the 'createNINJA1' porcelain needs besides source and
-- target. Holds the platform type (the cross-format lingua franca
-- from "Slap.PlatformType", not the format-specific 'NINJA1RomType')
-- and the compression choice.
data NINJA1Options = NINJA1Options
  { ninja1OptionsPlatform    :: PlatformType
  , ninja1OptionsCompression :: NINJA1Compression
  } deriving (Show, Eq)

----------------------------------------------------------------------------
-- Differential-format porcelain
----------------------------------------------------------------------------

-- | Create a BPS patch. The metadata blob is an opaque bytestring
-- wrapped in 'BPSMetadata' so the porcelain surface names what the
-- bytes are for; the wire-level encoder in "Slap.BPS.Create" still
-- takes raw bytes and the unwrap happens at this boundary.
createBPS
  :: SourceFileContents
  -> TargetFileContents
  -> BPSMetadata
  -> Either SlapError CreateResult
createBPS source target (BPSMetadata metadataBytes) =
  BPS.createBPS source target metadataBytes

-- | Create a DPS patch. 'DPSMetadata' carries the three header
-- fields (name, author, version) as structured 'String's;
-- 'DPSStability' names the stable-vs-unstable flag byte.
createDPS
  :: SourceFileContents
  -> TargetFileContents
  -> DPSMetadata
  -> DPSStability
  -> Either SlapError CreateResult
createDPS = DPS.createDPS

-- | Create a NINJA2 patch. 'NINJA2Metadata' is the large record
-- covering the fixed-header fields and the platform type.
createNINJA2
  :: SourceFileContents
  -> TargetFileContents
  -> NINJA2Metadata
  -> Either SlapError CreateResult
createNINJA2 = NINJA2.createNINJA2

----------------------------------------------------------------------------
-- Direct-format porcelain
--
-- Every function in this section is a thin wrapper over
-- 'createFromMemory': 'CreateDirect' tag, a 'RequestedPatchMetadata' carrying
-- the format's extras (if any), and an optional seed 'PatchContents'
-- used only by 'createNINJA1' to thread the compression flag through
-- 'buildContents''s inheritance slot. The uniformity is deliberate
-- — direct-format creation is a 'PatchContents' pipeline owned by
-- "Slap.Convert", and the per-format wrappers only decide how their
-- extras map onto that pipeline's existing inputs.
----------------------------------------------------------------------------

-- | Create a standard IPS patch (@"PATCH"@ magic, 24-bit offsets).
createIPS
  :: SourceFileContents
  -> TargetFileContents
  -> Either SlapError CreateResult
createIPS source target =
  createFromMemory (CreateDirect CreateIPS) source target noMetadataRequested Nothing

-- | Create an IPS32 patch (@"IPS32"@ magic, 32-bit offsets).
createIPS32
  :: SourceFileContents
  -> TargetFileContents
  -> Either SlapError CreateResult
createIPS32 source target =
  createFromMemory (CreateDirect CreateIPS32) source target noMetadataRequested Nothing

-- | Create an EBP patch. 'EBPMetadataFields' carries the title,
-- author, and description that 'buildEBPMetadataJSON' will emit as
-- the trailing JSON blob; the porcelain threads the three fields
-- through the corresponding 'RequestedPatchMetadata' slots so the
-- shared description-resolution logic in 'Slap.Convert.encodeDirect'
-- picks them up alongside the standard-IPS body.
createEBP
  :: SourceFileContents
  -> TargetFileContents
  -> EBPMetadataFields
  -> Either SlapError CreateResult
createEBP source target fields =
  createFromMemory
    (CreateDirect CreateEBP)
    source
    target
    noMetadataRequested
      { requestedTitle       = Just (ebpMetadataTitle       fields)
      , requestedAuthor      = Just (ebpMetadataAuthor      fields)
      , requestedDescription = Just (ebpMetadataDescription fields)
      }
    Nothing

-- | Create a PPF3 patch. 'PPFDescription' is the 50-byte header
-- description, 'PPFOptions' names the undo and validation-block
-- choices, and 'PPFImageType' selects the validation offset
-- (@0x9320@ for 'BIN', @0x80A0@ for 'GI').
createPPF3
  :: SourceFileContents
  -> TargetFileContents
  -> PPFDescription
  -> PPFOptions
  -> PPFImageType
  -> Either SlapError CreateResult
createPPF3 source target (PPFDescription descriptionString) options imageType =
  createFromMemory
    (CreateDirect CreatePPF3)
    source
    target
    noMetadataRequested
      { requestedDescription         = Just descriptionString
      , requestedUndoInclusion       = Just (ppfToUndoInclusion       (ppfOptionsUndo options))
      , requestedValidationInclusion = Just (ppfToValidationInclusion (ppfOptionsValidation options))
      , requestedImageType           = Just imageType
      }
    Nothing
  where
    ppfToUndoInclusion PPFIncludeUndo = IncludeUndoData
    ppfToUndoInclusion PPFOmitUndo    = OmitUndoData
    ppfToValidationInclusion PPFIncludeValidation = IncludeValidationBlock
    ppfToValidationInclusion PPFOmitValidation    = OmitValidationBlock

-- | Create a NINJA1 (@.rup@ binary) patch. 'NINJA1Options' names the
-- platform (routed through 'PlatformType' so the lossy shared-to-NINJA1
-- translation and its warnings run inside 'encodeDirect') and the
-- compression choice. The compression choice is threaded through a
-- seed 'PatchContents' — 'buildContents' reads 'contentsNINJA1Compressed'
-- from the optional source-patch slot, and that's the one place the
-- pipeline will look for it.
createNINJA1
  :: SourceFileContents
  -> TargetFileContents
  -> NINJA1Options
  -> Either SlapError CreateResult
createNINJA1 source target options =
  createFromMemory
    (CreateDirect CreateNINJA1)
    source
    target
    noMetadataRequested { requestedRomType = Just (ninja1OptionsPlatform options) }
    (Just (emptyContents [])
      { contentsNINJA1Compressed = Just (compressionFlag (ninja1OptionsCompression options)) })
  where
    compressionFlag NINJA1Compressed   = True
    compressionFlag NINJA1Uncompressed = False

-- | Create a PMSR patch. No format-specific extras beyond source and
-- target.
createPMSR
  :: SourceFileContents
  -> TargetFileContents
  -> Either SlapError CreateResult
createPMSR source target =
  createFromMemory (CreateDirect CreatePMSR) source target noMetadataRequested Nothing

-- | Create a PCHTXT patch. The optional 'PCHTXTDescription' becomes
-- either an @\@nsobid-...@ build-ID header (when it's a 32+-character
-- hex digest) or a @// ...@ comment line.
createPCHTXT
  :: SourceFileContents
  -> TargetFileContents
  -> Maybe PCHTXTDescription
  -> Either SlapError CreateResult
createPCHTXT source target maybeDescription =
  createFromMemory
    (CreateDirect CreatePCHTXT)
    source
    target
    noMetadataRequested { requestedDescription = fmap unPCHTXTDescription maybeDescription }
    Nothing

-- | Create an APS-N64 patch. 'APSN64Description' is the 50-byte
-- header description, locale-encoded and truncated on overflow.
createAPSN64
  :: SourceFileContents
  -> TargetFileContents
  -> APSN64Description
  -> Either SlapError CreateResult
createAPSN64 source target (APSN64Description descriptionString) =
  createFromMemory
    (CreateDirect CreateAPSN64)
    source
    target
    noMetadataRequested { requestedDescription = Just descriptionString }
    Nothing
