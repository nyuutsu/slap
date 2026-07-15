-- | The boundary a browser front end talks to: what @app/Main.hs@ orchestrates, minus argv and the filesystem,
-- handing structured answers up instead of rendered text.
-- The library is glue and holds no rules of its own — every rule it appears to know, it is asking the engine for.
module Slap.Web
  ( -- * What exists
    Surface(..)
  , FormatDescription(..)
  , ConsoleHeaderDescription(..)
  , describeSurface
  , DroppedFileClass(..)
  , classifyDroppedFile
  , PatchIdentity(..)
  , UndoAnswer(..)
  , identifyPatch
  , RomFacts(..)
  , describeRom
  ) where

import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)

import Slap.Binary (md5, sha1)
import Slap.Checksum (CRC32, MD5Hash, SHA1Hash)
import Slap.Constraint (Constraint)
import Slap.Convert (CreateFormat, RequestedDialects, TokenVisibility(Canonical), acceptedConstraints,
                     acceptedMetadataFields, createFormatTokens)
import Slap.Detect (DroppedFileClass(..), classifyDroppedFile)
import Slap.FFI (crc32)
import Slap.FileContents (InputFileContents(..), PatchFileContents)
import Slap.Header (ConsoleHeader, consoleHeaderLength, consoleHeaderName, consoleHeaderToken)
import Slap.Measure (FileSize, Length, byteFileSize)
import Slap.MetadataField (MetadataField(MetadataSecondaryCompressor))
import Slap.SomePatch (PatchIdentity(..), UndoAnswer(..), parseSome, patchIdentity)
import Slap.Status (SlapError)
import Slap.Text (AdvertisedEncodingFamily, EncodingName, advertisedEncodings)
import Slap.VCDIFF.SecondaryCompression (secondaryCompressorTokens)

-- | Everything a front end builds its controls from, read off the engine's own tables
-- so what the page offers cannot drift from what slap accepts.
data Surface = Surface
  { surfaceFormats        :: [FormatDescription]
  , surfaceEncodings      :: [AdvertisedEncodingFamily]
  , surfaceConsoleHeaders :: [ConsoleHeaderDescription]
  }
  deriving (Eq, Show)

data FormatDescription = FormatDescription
  { formatCreateTarget     :: CreateFormat
  , formatToken            :: String
  , formatAcceptedFields   :: Set MetadataField
  , formatConstraints      :: Set Constraint
  , formatSecondaryChoices :: [String]
    -- ^ What @--compress-with@ can choose when this is the target; empty for a format without a secondary compressor.
    -- Per-format rather than one global vocabulary, so a second compressor-bearing format's own algorithms would have a home.
  }
  deriving (Eq, Show)

data ConsoleHeaderDescription = ConsoleHeaderDescription
  { describedConsoleHeader :: ConsoleHeader
  , consoleToken           :: String
  , consoleName            :: Text
  , consoleWidth           :: Length
  }
  deriving (Eq, Show)

describeSurface :: Surface
describeSurface = Surface
  { surfaceFormats        = [describeCreateTarget token target | (token, target, Canonical) <- createFormatTokens]
  , surfaceEncodings      = advertisedEncodings
  , surfaceConsoleHeaders = map describeConsoleHeader [minBound .. maxBound]
  }

describeCreateTarget :: String -> CreateFormat -> FormatDescription
describeCreateTarget token target = FormatDescription
  { formatCreateTarget     = target
  , formatToken            = token
  , formatAcceptedFields   = acceptedMetadataFields target
  , formatConstraints      = acceptedConstraints target
  , formatSecondaryChoices =
      if MetadataSecondaryCompressor `Set.member` acceptedMetadataFields target
        then map fst secondaryCompressorTokens
        else []
  }

describeConsoleHeader :: ConsoleHeader -> ConsoleHeaderDescription
describeConsoleHeader console = ConsoleHeaderDescription
  { describedConsoleHeader = console
  , consoleToken           = consoleHeaderToken console
  , consoleName            = consoleHeaderName console
  , consoleWidth           = consoleHeaderLength console
  }

-- | A dialect axis can change the parse itself ('Slap.Dialect.PPF1OriginAxis' decides how record offsets are read),
-- so identity is a projection of the full parse, never of the magic alone.
identifyPatch :: RequestedDialects -> EncodingName -> PatchFileContents -> Either SlapError PatchIdentity
identifyPatch dialects metadataEncoding patchBytes = patchIdentity <$> parseSome dialects metadataEncoding patchBytes

-- | What a front end shows the moment a rom is chosen, before any patch exists.
data RomFacts = RomFacts
  { romSize  :: FileSize
  , romCRC32 :: CRC32
  , romMD5   :: MD5Hash
  , romSHA1  :: SHA1Hash
  }
  deriving (Eq, Show)

describeRom :: InputFileContents -> RomFacts
describeRom (InputFileContents romBytes) = RomFacts
  { romSize  = byteFileSize romBytes
  , romCRC32 = crc32 romBytes
  , romMD5   = md5 romBytes
  , romSHA1  = sha1 romBytes
  }
