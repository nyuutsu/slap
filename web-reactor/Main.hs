-- | The reactor a browser instantiates: foreign exports over 'Slap.Web', each callable only after the host runs @wasi.initialize@ then @hs_init@.
-- The same executable builds natively, where 'main' — which the reactor never runs — is the parity probe:
-- it writes the envelope the wasm export returns, so the parity check can hold the two targets' bytes against each other.
module Main (main) where

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as Char8
import Data.ByteString (ByteString)
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8, Word32)
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (pokeByteOff)
import System.Environment (getArgs)
import System.Exit (die)

import Slap.Checksum (CRC32(unCRC32))
import Slap.Convert (noDialectsRequested)
import Slap.FileContents (InputFileContents(InputFileContents), PatchFileContents(PatchFileContents))
import Slap.Status (noAdvisories)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Web (AnalyzeRequest(..), InspectRequest(..), RomFacts(romCRC32),
                 analyzePatch, describeRom, describeSurface, inspectPatch)
import Slap.Web.Envelope (encodeEnvelope)

foreign export ccall "slap_web_link_check" slapWebLinkCheck :: IO Word32

-- | Hashes a fixed input through 'Slap.Web' so the host can check a known value: the CRC-32 of "123456789" is 0xcbf43926.
-- web-slap depends on slap running under wasm, which nothing had ever done before this.
-- This is the first thing that does, and its only job is to prove it's possible at all.
-- The value it returns is arbitrary; the host checks it against a known answer only so a broken link can't slip through as success.
slapWebLinkCheck :: IO Word32
slapWebLinkCheck = pure (unCRC32 (romCRC32 (describeRom fixedInput)))
  where
    fixedInput = InputFileContents (Char8.pack "123456789")

-- The buffer protocol: the host allocates with 'slap_web_alloc' and copies its bytes in; an export answers with a buffer
-- whose first four bytes are the payload length (little-endian, wasm's own byte order); the host frees both sides with 'slap_web_free'.

foreign export ccall "slap_web_alloc" slapWebAlloc :: Int -> IO (Ptr Word8)

slapWebAlloc :: Int -> IO (Ptr Word8)
slapWebAlloc = mallocBytes

foreign export ccall "slap_web_free" slapWebFree :: Ptr Word8 -> IO ()

slapWebFree :: Ptr Word8 -> IO ()
slapWebFree = free

foreign export ccall "slap_web_describe_surface" slapWebDescribeSurface :: IO (Ptr Word8)

slapWebDescribeSurface :: IO (Ptr Word8)
slapWebDescribeSurface = lengthPrefixedBuffer surfaceEnvelope

foreign export ccall "slap_web_inspect_patch" slapWebInspectPatch :: Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebInspectPatch :: Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebInspectPatch patchPointer patchLength = do
  patchBytes <- ByteString.packCStringLen (castPtr patchPointer, patchLength)
  lengthPrefixedBuffer (inspectEnvelope patchBytes)

foreign export ccall "slap_web_analyze_patch" slapWebAnalyzePatch :: Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebAnalyzePatch :: Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebAnalyzePatch patchPointer patchLength = do
  patchBytes <- ByteString.packCStringLen (castPtr patchPointer, patchLength)
  lengthPrefixedBuffer (analyzeEnvelope patchBytes)

-- | The surface cannot refuse and raises nothing; it rides the envelope anyway so the page reads one wire shape everywhere.
surfaceEnvelope :: ByteString
surfaceEnvelope = encodeEnvelope (noAdvisories (Right describeSurface))

-- Both reads parse under UTF-8 with no dialect toggles, the read verbs' defaults.

inspectEnvelope :: ByteString -> ByteString
inspectEnvelope patchBytes = encodeEnvelope $ inspectPatch InspectRequest
  { inspectPatchBytes       = PatchFileContents patchBytes
  , inspectMetadataEncoding = EncodingUtf8
  , inspectDialects         = noDialectsRequested
  }

analyzeEnvelope :: ByteString -> ByteString
analyzeEnvelope patchBytes = encodeEnvelope $ analyzePatch AnalyzeRequest
  { analyzePatchBytes       = PatchFileContents patchBytes
  , analyzeMetadataEncoding = EncodingUtf8
  , analyzeDialects         = noDialectsRequested
  }

lengthPrefixedBuffer :: ByteString -> IO (Ptr Word8)
lengthPrefixedBuffer payload = do
  buffer <- mallocBytes (4 + ByteString.length payload)
  pokeByteOff buffer 0 (fromIntegral (ByteString.length payload) :: Word32)
  UnsafeByteString.unsafeUseAsCStringLen payload $ \(source, sourceLength) ->
    copyBytes (buffer `plusPtr` 4) (castPtr source) sourceLength
  pure buffer

main :: IO ()
main = do
  arguments <- getArgs
  case arguments of
    ["surface"]            -> ByteString.putStr surfaceEnvelope
    ["inspect", patchPath] -> ByteString.putStr . inspectEnvelope =<< ByteString.readFile patchPath
    ["analyze", patchPath] -> ByteString.putStr . analyzeEnvelope =<< ByteString.readFile patchPath
    _                      -> die "usage: slap-web-reactor surface | inspect PATCH | analyze PATCH  (writes the verb's envelope to stdout)"
