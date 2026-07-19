{-# LANGUAGE DerivingVia #-}

-- | The serialized crossing: a 'Slap.Web' answer rendered to one JSON buffer for the reactor's exports.
-- Structure crosses as derived JSON, each error and advisory beside the sentence slap would speak for it,
-- so the page never composes prose from envelope tags. Large payloads (roms, patches) cross as raw buffers, never in here —
-- an act's answer splits into its spoken half and the bytes 'encodeEnvelopeAndTail' hands back beside it.
module Slap.Web.Envelope
  ( Envelope(..)
  , SpokenError(..)
  , SpokenAdvisory(..)
  , envelopeOf
  , encodeEnvelope
  , SpokenPatchIdentity(..)
  , speakPatchIdentity
  , SpokenVerdict(..)
  , SpokenGap(..)
  , speakVerdict
  , SpokenPatchedRom(..)
  , SpokenRevertedRom(..)
  , SpokenCreatedPatch(..)
  , speakPatchedRom
  , speakRevertedRom
  , speakCreatedPatch
  , encodeEnvelopeAndTail
  ) where

import Data.Aeson (ToJSON)
import qualified Data.Aeson as Aeson
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Set (Set)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

import Slap.Convert (CreateFormat)
import Slap.Dialect (Dialect)
import Slap.Display.Info (InputSideVerdict, OutputSideVerdict)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel, formatLabelName)
import Slap.Status (Outcome(..), Severity, SlapAdvisory, SlapError,
                    renderSlapAdvisory, renderSlapError, slapAdvisorySeverity)
import Slap.Web (CreatedPatch(..), Gap(..), PatchIdentity(..), PatchedRom(..), Resolution,
                 RevertedRom(..), UndoAnswer, Verdict(..), VerdictStanding)

-- | A refusal beside the sentence slap speaks for it.
data SpokenError = SpokenError
  { spokenError         :: !SlapError
  , spokenErrorSentence :: !Text
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenError

-- | An advisory beside its severity lane and its sentence.
data SpokenAdvisory = SpokenAdvisory
  { spokenAdvisory         :: !SlapAdvisory
  , spokenAdvisorySeverity :: !Severity
  , spokenAdvisorySentence :: !Text
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenAdvisory

-- | An 'Outcome', spoken for the crossing.
data Envelope answer = Envelope
  { envelopeAnswer     :: Either SpokenError answer
  , envelopeAdvisories :: [SpokenAdvisory]
  }
  deriving (Eq, Show, Generic)

deriving via Generically (Envelope answer) instance ToJSON answer => ToJSON (Envelope answer)

speakError :: SlapError -> SpokenError
speakError refusal = SpokenError
  { spokenError         = refusal
  , spokenErrorSentence = renderSlapError refusal
  }

envelopeOf :: Outcome (Either SlapError answer) -> Envelope answer
envelopeOf (Outcome answer advisories) = Envelope
  { envelopeAnswer     = first speakError answer
  , envelopeAdvisories = map speakAdvisory advisories
  }
  where
    speakAdvisory advisory = SpokenAdvisory
      { spokenAdvisory         = advisory
      , spokenAdvisorySeverity = slapAdvisorySeverity advisory
      , spokenAdvisorySentence = renderSlapAdvisory advisory
      }

encodeEnvelope :: ToJSON answer => Outcome (Either SlapError answer) -> ByteString
encodeEnvelope = LazyByteString.toStrict . Aeson.encode . envelopeOf

-- | 'Slap.SomePatch.PatchIdentity', spoken for the crossing with the format's display name beside its label:
-- the name table ('formatLabelName') is engine knowledge, not a page's to re-type.
data SpokenPatchIdentity = SpokenPatchIdentity
  { spokenIdentityFormat     :: FormatLabel
  , spokenIdentityFormatName :: Text
  , spokenIdentityDialects   :: Set Dialect
  , spokenIdentityUndo       :: UndoAnswer
  , spokenIdentityImpediment :: Maybe SpokenError
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenPatchIdentity

speakPatchIdentity :: PatchIdentity -> SpokenPatchIdentity
speakPatchIdentity identity = SpokenPatchIdentity
  { spokenIdentityFormat     = identifiedFormat identity
  , spokenIdentityFormatName = formatLabelName (identifiedFormat identity)
  , spokenIdentityDialects   = applicableDialects identity
  , spokenIdentityUndo       = identifiedUndo identity
  , spokenIdentityImpediment = speakError <$> identifiedImpediment identity
  }

-- | An emit check's 'Verdict', spoken for the crossing; the resolutions stay structural — they name controls, not prose.
data SpokenVerdict
  = SpokenReady
  | SpokenBlocked (NonEmpty SpokenGap)
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenVerdict

data SpokenGap = SpokenGap
  { spokenGapReason      :: SpokenError
  , spokenGapResolutions :: NonEmpty Resolution
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenGap

speakVerdict :: Verdict -> SpokenVerdict
speakVerdict Ready          = SpokenReady
speakVerdict (Blocked gaps) = SpokenBlocked (NonEmpty.map speakGap gaps)
  where
    speakGap gap = SpokenGap
      { spokenGapReason      = speakError (gapReason gap)
      , spokenGapResolutions = gapResolutions gap
      }

-- The acts' answers, split for the crossing: each Spoken form is its answer minus the output bytes,
-- which are megabytes with no structure to keep — they ride behind the envelope as a raw tail, never base64 inside it.

data SpokenPatchedRom = SpokenPatchedRom
  { spokenPatchedRomInputVerdict  :: InputSideVerdict
  , spokenPatchedRomOutputVerdict :: OutputSideVerdict
  , spokenPatchedRomStanding      :: VerdictStanding
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenPatchedRom

speakPatchedRom :: PatchedRom -> (SpokenPatchedRom, ByteString)
speakPatchedRom patched =
  ( SpokenPatchedRom
      { spokenPatchedRomInputVerdict  = patchedRomInputVerdict patched
      , spokenPatchedRomOutputVerdict = patchedRomOutputVerdict patched
      , spokenPatchedRomStanding      = patchedRomVerdictStanding patched
      }
  , unOutputFileContents (patchedRomBytes patched)
  )

data SpokenRevertedRom = SpokenRevertedRom
  { spokenRevertedRomInputVerdict  :: InputSideVerdict
  , spokenRevertedRomOutputVerdict :: OutputSideVerdict
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenRevertedRom

speakRevertedRom :: RevertedRom -> (SpokenRevertedRom, ByteString)
speakRevertedRom reverted =
  ( SpokenRevertedRom
      { spokenRevertedRomInputVerdict  = revertedRomInputVerdict reverted
      , spokenRevertedRomOutputVerdict = revertedRomOutputVerdict reverted
      }
  , unInputFileContents (revertedRomBytes reverted)
  )

data SpokenCreatedPatch = SpokenCreatedPatch
  { spokenCreatedPatchFormat :: CreateFormat
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenCreatedPatch

speakCreatedPatch :: CreatedPatch -> (SpokenCreatedPatch, ByteString)
speakCreatedPatch created =
  ( SpokenCreatedPatch { spokenCreatedPatchFormat = createdPatchFormat created }
  , unPatchFileContents (createdPatchBytes created)
  )

-- | The whole answer, split: the envelope speaking everything but the bytes, and the bytes themselves — empty on a refusal.
encodeEnvelopeAndTail
  :: ToJSON spoken => (answer -> (spoken, ByteString)) -> Outcome (Either SlapError answer) -> (ByteString, ByteString)
encodeEnvelopeAndTail speak outcome =
  ( encodeEnvelope ((fmap . fmap) (fst . speak) outcome)
  , either (const ByteString.empty) (snd . speak) (outcomeValue outcome)
  )
