-- | The reactor a browser instantiates: foreign exports over 'Slap.Web', each callable only after the host runs @wasi.initialize@ then @hs_init@.
module Main (main) where

import qualified Data.ByteString.Char8 as Char8
import Data.Word (Word32)

import Slap.Checksum (CRC32(unCRC32))
import Slap.FileContents (InputFileContents(InputFileContents))
import Slap.Web (RomFacts(romCRC32), describeRom)

foreign export ccall "slap_web_link_check" slapWebLinkCheck :: IO Word32

-- | Hashes a fixed input through 'Slap.Web' so the host can check a known value: the CRC-32 of "123456789" is 0xcbf43926.
-- web-slap depends on slap running under wasm, which nothing had ever done before this.
-- This is the first thing that does, and its only job is to prove it's possible at all.
-- The value it returns is arbitrary; the host checks it against a known answer only so a broken link can't slip through as success.
slapWebLinkCheck :: IO Word32
slapWebLinkCheck = pure (unCRC32 (romCRC32 (describeRom fixedInput)))
  where
    fixedInput = InputFileContents (Char8.pack "123456789")

-- cabal's executable component requires module Main to export a 'main'; the reactor never runs it — the host calls the exports after hs_init.
main :: IO ()
main = pure ()
