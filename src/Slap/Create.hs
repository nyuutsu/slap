-- | Coordination-layer creation porcelain. Slap.Create owns the
-- per-format typed front doors for the differential family —
-- formats whose creation paths don't share a pipeline and whose
-- typed inputs (BPS metadata blob, DPS metadata triple plus
-- stability flag, NINJA2 metadata record) want a named home where
-- call sites can express them structurally. The format-level
-- encoders in @Slap.<Format>.Create.create<Format>@ do the wire
-- emission; this module's wrappers add the typed surface.
--
-- 'createPatch' is re-exported here as the dynamic entry point for callers who don't want to pick a submodule;
-- direct-format creation has no front door of its own, going through the 'PatchContents' pipeline in "Slap.Convert" instead.
--
-- See the Haddock on 'Slap.Convert.RequestedPatchMetadata' in
-- "Slap.Convert" for which 'Maybe' fields each direct format
-- consumes from the bag.
module Slap.Create
  ( -- * Differential-format porcelain
    createBPS
  , createUPS
  , createDPS
  , createNINJA2
  , createAPSGBA
  , createGDIFF
  , createXDelta1
  , createRFCVCDIFF
  , createXDelta3
    -- * Dynamic entry point (re-export)
  , createPatch
  ) where

import qualified Slap.BPS.Create as BPS
import Slap.BPS.Types (BPSMetadata(..))
import Slap.UPS.Create (createUPS)
import qualified Slap.DPS.Create as DPS
import Slap.DPS.Types (DPSCreateMetadata, DPSStability)
import qualified Slap.NINJA2.Create as NINJA2
import Slap.NINJA2.Types (NINJA2CreateMetadata)
import Slap.APSGBA.Create (createAPSGBA)
import Slap.GDIFF.Create (createGDIFF)
import Slap.VCDIFF.Create (createRFCVCDIFF, createXDelta3)
import qualified Slap.XDelta1.Create as XDelta1

import Slap.Convert (createPatch)
import Slap.Status (SlapError, CreateResult)
import Slap.FileContents (InputFileContents, OutputFileContents)
import Slap.MetadataInclusion (VerificationInclusion(..), CompressionInclusion(..))
import Slap.XDelta1.Types (ResolvedXDelta1FileNames)

----------------------------------------------------------------------------
-- Differential-format porcelain
----------------------------------------------------------------------------

-- | Create a BPS patch.
-- The metadata blob is an opaque bytestring wrapped in 'BPSMetadata' so the porcelain surface names what the bytes are for.
createBPS
  :: InputFileContents
  -> OutputFileContents
  -> BPSMetadata
  -> Either SlapError CreateResult
createBPS source target (BPSMetadata metadataBytes) =
  BPS.createBPS source target metadataBytes

-- | Create a DPS patch.
createDPS
  :: InputFileContents
  -> OutputFileContents
  -> DPSCreateMetadata
  -> DPSStability
  -> Either SlapError CreateResult
createDPS = DPS.createDPS

-- | Create a NINJA2 patch.
createNINJA2
  :: InputFileContents
  -> OutputFileContents
  -> NINJA2CreateMetadata
  -> Either SlapError CreateResult
createNINJA2 = NINJA2.createNINJA2

-- | Create an xdelta1 patch. The 'VerificationInclusion' choice
-- (set by @slap create --omit-verification@) gates @FLAG_NO_VERIFY@ and the
-- per-source MD5 fields; the 'CompressionInclusion' choice (set
-- by @slap create --no-compress@) gates @FLAG_PATCH_COMPRESSED@
-- and whether the data and control segments are gzip-deflated
-- before placement. Both shapes round-trip through
-- 'Slap.XDelta1.Parse.parseXDelta1'.
--
-- The 'ResolvedXDelta1FileNames' carries the from-name and to-name header fields,
-- resolved and cap-checked by the porcelain via 'Slap.XDelta1.Types.resolveXDelta1FileNames' / 'Slap.XDelta1.Types.requireXDelta1FileNames'.
createXDelta1
  :: VerificationInclusion
  -> CompressionInclusion
  -> ResolvedXDelta1FileNames
  -> InputFileContents
  -> OutputFileContents
  -> Either SlapError CreateResult
createXDelta1 = XDelta1.createXDelta1
