-- | The "should the output patch carry this optional channel?"
-- choices the porcelain threads through 'Slap.Convert.RequestedPatchMetadata'.
-- Lives in its own module so format-level encoders ("Slap.XDelta1.Create"
-- and friends) can consume the type without depending on the
-- format-aware "Slap.Convert" they themselves are wired into.
module Slap.MetadataInclusion
  ( UndoInclusion(..)
  , VerificationInclusion(..)
  , CompressionInclusion(..)
  ) where

-- | Whether the output patch should carry undo data, when the format supports it.
--
-- PPF3 is the primary consumer: its patch format has an optional trailing undo
-- section that lets an applied patch be reversed without access to the original
-- source. Other direct formats may gain undo support; this type stays agnostic.
data UndoInclusion
  = IncludeUndoData
  | OmitUndoData
  deriving (Show, Eq)

-- | Whether the output patch should carry source-integrity-checking
-- data, when the format supports embedding such data.
--
-- The embed-side member of slap's verification family, set by @--omit-verification@ on 'slap create' (and convert).
-- Family siblings:
--
-- * 'Slap.Verify.VerificationPolicy' — the apply-side member, set by @--no-verify@:
--   what 'slap apply' does at runtime when verification data is present and mismatches the input.
-- * 'Slap.XDelta1.Types.XDelta1VerificationPosture' — the parse-side member:
--   what a parsed xdelta1 patch declares about its own verification data,
--   surfaced to the user as the 'Slap.Status.VerificationOptedOutByCreator' warning when the creator opted out.
--
-- Format-specific wire mechanisms vary — PPF3 samples a 1024-byte block from a format-specific offset in the source ROM;
-- xdelta1 hashes the entire source and target with MD5.
-- Both answer the same user-facing question: "does the source the user is applying against match the one the patch was created from?"
-- @--omit-verification@ chooses whether to embed that data; slap routes it to whichever wire mechanism the chosen format supports.
data VerificationInclusion
  = IncludeVerification
  | OmitVerification
  deriving (Show, Eq)

-- | Whether the output patch's payload should be compressed, when the
-- format has a compressed form. Set by @--no-compress@ on 'slap create'
-- (and convert).
--
-- Format-specific wire mechanisms vary — xdelta1 gzip-deflates its data
-- and control segments inside the patch envelope
-- ('Slap.XDelta1.Types.XDelta1PatchCompression' is the wire-level fact
-- this choice gates); xdelta3 runs its window sections through the
-- declared secondary compressor, LZMA on slap's emission
-- ('Slap.VCDIFF.Create'). Both answer the same user-facing question:
-- "should the patch spend CPU to be smaller on disk?"
data CompressionInclusion
  = IncludeCompression
  | OmitCompression
  deriving (Show, Eq)
