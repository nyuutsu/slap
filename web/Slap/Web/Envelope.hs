{-# LANGUAGE DerivingVia #-}

-- | The serialized crossing: a 'Slap.Web' answer rendered to one JSON buffer for the reactor's exports.
-- Structure crosses as derived JSON, each error and advisory beside the sentence slap would speak for it,
-- so the page never composes prose from envelope tags. Large payloads (roms, patches) cross as raw buffers, never in here.
module Slap.Web.Envelope
  ( Envelope(..)
  , SpokenError(..)
  , SpokenAdvisory(..)
  , envelopeOf
  , encodeEnvelope
  ) where

import Data.Aeson (ToJSON)
import qualified Data.Aeson as Aeson
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

import Slap.Status (Outcome(..), Severity, SlapAdvisory, SlapError,
                    renderSlapAdvisory, renderSlapError, slapAdvisorySeverity)

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

envelopeOf :: Outcome (Either SlapError answer) -> Envelope answer
envelopeOf (Outcome answer advisories) = Envelope
  { envelopeAnswer     = first speakError answer
  , envelopeAdvisories = map speakAdvisory advisories
  }
  where
    speakError refusal = SpokenError
      { spokenError         = refusal
      , spokenErrorSentence = renderSlapError refusal
      }
    speakAdvisory advisory = SpokenAdvisory
      { spokenAdvisory         = advisory
      , spokenAdvisorySeverity = slapAdvisorySeverity advisory
      , spokenAdvisorySentence = renderSlapAdvisory advisory
      }

encodeEnvelope :: ToJSON answer => Outcome (Either SlapError answer) -> ByteString
encodeEnvelope = LazyByteString.toStrict . Aeson.encode . envelopeOf
