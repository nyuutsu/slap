{-# LANGUAGE DerivingVia #-}

-- | The per-field surface a frontend builds its controls from: the control kind of each 'MetadataField',
-- and the closed token vocabularies the choice fields draw from.
-- Tokens stay lowercase; readers fold input case before looking one up.
module Slap.Surface
  ( MetadataFieldKind(..)
  , ChoiceVocabulary(..)
  , choiceVocabularyTokens
  , metadataFieldKind
  , romTypeTokens
  , imageTypeTokens
  , textModeTokens
  ) where

import Data.Aeson (ToJSON)
import GHC.Generics (Generic, Generically(..))

import Slap.MetadataField (MetadataField(..))
import Slap.NINJA2.Types (TextMode(..))
import Slap.PPF3.Types (PPF3ImageType(..))
import Slap.PlatformType (PlatformType(..))
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor, secondaryCompressorTokens)

data MetadataFieldKind
  = FreeTextField
  | ToggleField
  | ChoiceField ChoiceVocabulary
  | NumberField
  | FileField
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically MetadataFieldKind

-- | A choice crosses as its whole token table, engine value beside token,
-- so a chosen token carries its own request value — no reverse lookup to drift.
data ChoiceVocabulary
  = RomTypeChoices             [(String, PlatformType)]
  | ImageTypeChoices           [(String, PPF3ImageType)]
  | TextModeChoices            [(String, TextMode)]
  | SecondaryCompressorChoices [(String, XDelta3SecondaryCompressor)]
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically ChoiceVocabulary

choiceVocabularyTokens :: ChoiceVocabulary -> [String]
choiceVocabularyTokens (RomTypeChoices rows)             = map fst rows
choiceVocabularyTokens (ImageTypeChoices rows)           = map fst rows
choiceVocabularyTokens (TextModeChoices rows)            = map fst rows
choiceVocabularyTokens (SecondaryCompressorChoices rows) = map fst rows

metadataFieldKind :: MetadataField -> MetadataFieldKind
metadataFieldKind field = case field of
  MetadataTitle                 -> FreeTextField
  MetadataAuthor                -> FreeTextField
  MetadataDescription           -> FreeTextField
  MetadataVersion               -> FreeTextField
  MetadataUndoInclusion         -> ToggleField
  MetadataVerificationInclusion -> ToggleField
  MetadataPatchCompression      -> ToggleField
  MetadataSecondaryCompressor   -> ChoiceField (SecondaryCompressorChoices secondaryCompressorTokens)
  MetadataStability             -> ToggleField
  MetadataRomType               -> ChoiceField (RomTypeChoices romTypeTokens)
  MetadataImageType             -> ChoiceField (ImageTypeChoices imageTypeTokens)
  MetadataFileIdDiz             -> FileField
  MetadataGenre                 -> FreeTextField
  MetadataLanguage              -> FreeTextField
  MetadataDate                  -> FreeTextField
  MetadataWebsite               -> FreeTextField
  MetadataTextMode              -> ChoiceField (TextModeChoices textModeTokens)
  MetadataEmbeddedBlob          -> FileField
  MetadataXDelta1FromName       -> FreeTextField
  MetadataXDelta1ToName         -> FreeTextField
  MetadataWindowSize            -> NumberField

-- | The @--rom-type@ vocabulary.
romTypeTokens :: [(String, PlatformType)]
romTypeTokens =
  [ ("raw",  PlatformRaw)
  , ("nes",  PlatformNES)
  , ("fds",  PlatformFDS)
  , ("snes", PlatformSNES)
  , ("n64",  PlatformN64)
  , ("gb",   PlatformGB)
  , ("gbc",  PlatformGBC)
  , ("gba",  PlatformGBA)
  , ("ngp",  PlatformNGP)
  , ("ngpc", PlatformNGPC)
  , ("sms",  PlatformSMS)
  , ("gg",   PlatformGameGear)
  , ("mega", PlatformGenesis)
  , ("pce",  PlatformPCEngine)
  , ("ws",   PlatformWonderSwan)
  , ("wsc",  PlatformWonderSwanColor)
  , ("lynx", PlatformLynx)
  , ("jag",  PlatformJaguar)
  , ("gp32", PlatformGP32)
  ]

-- | The @--image-type@ vocabulary.
imageTypeTokens :: [(String, PPF3ImageType)]
imageTypeTokens = [("bin", BIN), ("gi", GI)]

-- | The @--ninja2-text-mode@ vocabulary.
textModeTokens :: [(String, TextMode)]
textModeTokens = [("utf8", TextModeUTF8), ("undeclared", TextModeUndeclared)]
