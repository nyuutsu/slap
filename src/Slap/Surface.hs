-- | The per-field surface a frontend builds its controls from: the control kind of each 'MetadataField',
-- and the closed token vocabularies the choice fields draw from.
-- Tokens stay lowercase; readers fold input case before looking one up.
module Slap.Surface
  ( MetadataFieldKind(..)
  , metadataFieldKind
  , romTypeTokens
  , imageTypeTokens
  , textModeTokens
  ) where

import Slap.MetadataField (MetadataField(..))
import Slap.NINJA2.Types (TextMode(..))
import Slap.PPF3.Types (PPF3ImageType(..))
import Slap.PlatformType (PlatformType(..))
import Slap.VCDIFF.SecondaryCompression (secondaryCompressorTokens)

data MetadataFieldKind
  = FreeTextField
  | ToggleField
  | ChoiceField [String]
  | FileField
  deriving (Eq, Show)

-- | The 'ChoiceField' vocabularies are read off the token tables,
-- so what a frontend offers cannot drift from what the readers accept.
metadataFieldKind :: MetadataField -> MetadataFieldKind
metadataFieldKind field = case field of
  MetadataTitle                 -> FreeTextField
  MetadataAuthor                -> FreeTextField
  MetadataDescription           -> FreeTextField
  MetadataVersion               -> FreeTextField
  MetadataUndoInclusion         -> ToggleField
  MetadataVerificationInclusion -> ToggleField
  MetadataPatchCompression      -> ToggleField
  MetadataSecondaryCompressor   -> ChoiceField (map fst secondaryCompressorTokens)
  MetadataStability             -> ToggleField
  MetadataRomType               -> ChoiceField (map fst romTypeTokens)
  MetadataImageType             -> ChoiceField (map fst imageTypeTokens)
  MetadataFileIdDiz             -> FileField
  MetadataGenre                 -> FreeTextField
  MetadataLanguage              -> FreeTextField
  MetadataDate                  -> FreeTextField
  MetadataWebsite               -> FreeTextField
  MetadataTextMode              -> ChoiceField (map fst textModeTokens)
  MetadataEmbeddedBlob          -> FileField
  MetadataXDelta1FromName       -> FreeTextField
  MetadataXDelta1ToName         -> FreeTextField
  MetadataWindowSize            -> FreeTextField

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
