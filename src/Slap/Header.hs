{-# LANGUAGE OverloadedStrings #-}

-- | Add a fake header, or, remove a real header!

module Slap.Header
  ( ConsoleHeader(..)
  , consoleHeaderName
  , consoleHeaderToken
  , consoleHeaderLength
  , addHeader
  , removeHeader
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import Slap.Measure (Length(..))

data ConsoleHeader
  = NESHeader           -- ^ iNES.
  | FrontFarEastHeader  -- ^ Front Far East's Famicom copier.
  | FDSHeader           -- ^ fwNES.
  | GameBoyHeader       -- ^ Smart Card copier.
  | SNESHeader          -- ^ Copier block (SWC and kin).
  | PCEngineHeader      -- ^ Magic Super Griffin copier.
  | LynxHeader          -- ^ LNX.
  | Atari7800Header     -- ^ A78.
  deriving (Eq, Show, Enum, Bounded)

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
  ByteString.replicate (unLength (consoleHeaderLength console)) 0x00 <> inputBytes

-- | Drop the console's header from the front of the input;
-- 'Nothing' when the input is shorter than the header it supposedly wears.
removeHeader :: ConsoleHeader -> ByteString -> Maybe ByteString
removeHeader console inputBytes
  | ByteString.length inputBytes < headerWidth = Nothing
  | otherwise                                  = Just (ByteString.drop headerWidth inputBytes)
  where
    headerWidth = unLength (consoleHeaderLength console)
