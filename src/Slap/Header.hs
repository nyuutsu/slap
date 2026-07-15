{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Add a fake header, or, remove a real header!

module Slap.Header
  ( ConsoleHeader(..)
  , consoleHeaderName
  , consoleHeaderToken
  , consoleHeaderLength
  , addHeader
  , removeHeader
  , InputHeaderDirective(..)
  , HeaderAdjustment(..)
  ) where

import Data.Aeson (ToJSON)
import Data.ByteString (ByteString)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))
import Slap.Binary (dropLength, replicateLength)
import Slap.Measure (Length(..), byteLength)

data ConsoleHeader
  = NESHeader           -- ^ iNES.
  | FrontFarEastHeader  -- ^ Front Far East's Famicom copier.
  | FDSHeader           -- ^ fwNES.
  | GameBoyHeader       -- ^ Smart Card copier.
  | SNESHeader          -- ^ Copier block (SWC and kin).
  | PCEngineHeader      -- ^ Magic Super Griffin copier.
  | LynxHeader          -- ^ LNX.
  | Atari7800Header     -- ^ A78.
  deriving (Eq, Show, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically ConsoleHeader

-- | The name messages call the console.
consoleHeaderName :: ConsoleHeader -> Text
consoleHeaderName NESHeader          = "NES"
consoleHeaderName FrontFarEastHeader = "NES (FFE)"
consoleHeaderName FDSHeader          = "FDS"
consoleHeaderName GameBoyHeader      = "Game Boy"
consoleHeaderName SNESHeader         = "SNES"
consoleHeaderName PCEngineHeader     = "PC Engine"
consoleHeaderName LynxHeader         = "Lynx"
consoleHeaderName Atari7800Header    = "Atari 7800"

-- | The CLI spelling, shared by @--add-header@, @--remove-header@, and their shell completion.
-- Matches @--rom-type@'s vocabulary where the two overlap.
consoleHeaderToken :: ConsoleHeader -> String
consoleHeaderToken NESHeader          = "nes"
consoleHeaderToken FrontFarEastHeader = "nes-ffe"
consoleHeaderToken FDSHeader          = "fds"
consoleHeaderToken GameBoyHeader      = "gb"
consoleHeaderToken SNESHeader         = "snes"
consoleHeaderToken PCEngineHeader     = "pce"
consoleHeaderToken LynxHeader         = "lynx"
consoleHeaderToken Atari7800Header    = "a78"

-- | The byte quantity the console name aliases.
consoleHeaderLength :: ConsoleHeader -> Length
consoleHeaderLength NESHeader          = Length 16
consoleHeaderLength FrontFarEastHeader = Length 512
consoleHeaderLength FDSHeader          = Length 16
consoleHeaderLength GameBoyHeader      = Length 512
consoleHeaderLength SNESHeader         = Length 512
consoleHeaderLength PCEngineHeader     = Length 512
consoleHeaderLength LynxHeader         = Length 64
consoleHeaderLength Atari7800Header    = Length 128

-- | Prepend a blank header: the console's width of zero bytes, for a patch that expects a headered input.
addHeader :: ConsoleHeader -> ByteString -> ByteString
addHeader console inputBytes =
  replicateLength (consoleHeaderLength console) 0x00 <> inputBytes

-- | Drop the console's header from the front of the input;
-- 'Nothing' when the input is shorter than the header it supposedly wears.
removeHeader :: ConsoleHeader -> ByteString -> Maybe ByteString
removeHeader console inputBytes
  | byteLength inputBytes < headerWidth = Nothing
  | otherwise                           = Just (dropLength headerWidth inputBytes)
  where
    headerWidth = consoleHeaderLength console

-- | What the user said about the input's header relative to what the patch expects.
-- The default is that they already agree; the two flags name a console,
-- which is a friendly alias for how many bytes to put on or take off the front.
data InputHeaderDirective
  = TakeInputAsIs
  | AddHeader ConsoleHeader
    -- ^ @--add-header CONSOLE@: the patch expects a headered input and this one is bare.
  | RemoveHeader ConsoleHeader
    -- ^ @--remove-header CONSOLE@: the input wears a header and the patch expects the bytes beneath.
  deriving (Show, Eq)

-- | An arrangement's direction without a chosen console; 'InputHeaderDirective' is the flag-side shape that has picked one.
data HeaderAdjustment = HeaderComesOff | HeaderGoesOn
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically HeaderAdjustment
