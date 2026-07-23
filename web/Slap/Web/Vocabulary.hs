{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}

-- | The engine speaking its own wire vocabulary: each sum the page keeps a table of, with its constructors'
-- wire spellings. The render census audits the page's tables against this answer, so a transcription slip —
-- a misspelled tag, a constructor the page never learned — fails the build instead of rendering nothing.
module Slap.Web.Vocabulary (SpokenSum(..), spokenVocabulary) where

import Data.Aeson (Options(constructorTagModifier), ToJSON, defaultOptions)
import Data.Proxy (Proxy(Proxy))
import Data.Text (Text)
import qualified Data.Text as Text
import GHC.Generics (C1, D1, Generic, Generically(..), Meta(MetaCons, MetaData), Rep, type (:+:))
import GHC.TypeLits (KnownSymbol, symbolVal)

import Slap.Apply (VerdictStanding)
import Slap.Detect (DroppedFileAnswer)
import Slap.Display.Analysis (AnalysisPayload, AnalysisSection, AnalysisSummary, AnnotDetail, CopySource)
import Slap.Display.Common (ByteCount)
import Slap.Display.EmbeddedContent (EmbeddedField)
import Slap.SomePatch (UndoAnswer)
import Slap.Surface (MetadataFieldKind)
import Slap.Verify (VerificationVerdict)
import Slap.Web (WindowDefault)
import Slap.Web.Envelope (SpokenVerdict)

-- | One sum, as the wire speaks it: the type's own name, and its constructor tags.
data SpokenSum = SpokenSum
  { spokenSumName :: !Text
  , spokenSumTags :: ![Text]
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SpokenSum

-- | The very 'Options' that @deriving via Generically@ encodes with — aeson's instance passes 'defaultOptions' —
-- so a tag spoken here is a tag as the wire spells it, and the two cannot drift apart.
genericallyEncodingOptions :: Options
genericallyEncodingOptions = defaultOptions

-- | The constructor names standing in a sum's 'Rep', read from the type-level metadata.
class GenericConstructorNames representation where
  genericConstructorNames :: [String]

instance KnownSymbol constructorName
  => GenericConstructorNames (C1 ('MetaCons constructorName fixity hasSelectors) fields) where
  genericConstructorNames = [symbolVal (Proxy @constructorName)]

instance (GenericConstructorNames left, GenericConstructorNames right)
  => GenericConstructorNames (left :+: right) where
  genericConstructorNames = genericConstructorNames @left ++ genericConstructorNames @right

-- | A whole sum spoken from its 'Rep': the datatype's name from 'MetaData, the tags from its constructors.
class GenericSpokenSum representation where
  genericSpokenSum :: SpokenSum

instance (KnownSymbol sumTypeName, GenericConstructorNames constructors)
  => GenericSpokenSum (D1 ('MetaData sumTypeName sumModule sumPackage isNewtype) constructors) where
  genericSpokenSum = SpokenSum
    { spokenSumName = Text.pack (symbolVal (Proxy @sumTypeName))
    , spokenSumTags = map (Text.pack . constructorTagModifier genericallyEncodingOptions)
                          (genericConstructorNames @constructors)
    }

spokenSumOf :: forall sum. GenericSpokenSum (Rep sum) => SpokenSum
spokenSumOf = genericSpokenSum @(Rep sum)

spokenVocabulary :: [SpokenSum]
spokenVocabulary =
  [ spokenSumOf @VerificationVerdict
  , spokenSumOf @VerdictStanding
  , spokenSumOf @SpokenVerdict
  , spokenSumOf @UndoAnswer
  , spokenSumOf @AnalysisPayload
  , spokenSumOf @CopySource
  , spokenSumOf @WindowDefault
  , spokenSumOf @MetadataFieldKind
  , spokenSumOf @DroppedFileAnswer
  , spokenSumOf @AnalysisSection
  , spokenSumOf @ByteCount
  , spokenSumOf @AnalysisSummary
  , spokenSumOf @EmbeddedField
  , spokenSumOf @AnnotDetail
  ]
