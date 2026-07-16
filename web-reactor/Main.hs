-- | The reactor a browser instantiates: foreign exports over 'Slap.Web', each callable only after the host runs @wasi.initialize@ then @hs_init@.
-- The same executable builds natively, where 'main' — which the reactor never runs — is the parity probe:
-- it writes the envelope the wasm export returns, so the parity check can hold the two targets' bytes against each other.
module Main (main) where

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString (ByteString)
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Maybe (listToMaybe)
import Data.Word (Word8, Word32)
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (pokeByteOff)
import System.Environment (getArgs)
import System.Exit (die)

import Data.Aeson (FromJSON)

import Slap.Checksum (CRC32(unCRC32))
import Slap.Convert (noDialectsRequested)
import Slap.FileContents (InputFileContents(InputFileContents), OutputFileContents(OutputFileContents),
                          PatchFileContents(PatchFileContents))
import Slap.Status (noAdvisories)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Web (AnalyzeRequest(..), InspectRequest(..), RomFacts(romCRC32),
                 analyzePatch, applyPatch, checkApply, checkConvert, checkCreate, checkUndo,
                 convertPatch, createPatch, describeRom, describeSurface, inspectPatch, undoPatch)
import Slap.Web.Declaration (DeclaredApplyRequest, DeclaredConvertRequest(declaredConvertSourceFraming),
                             DeclaredCreateRequest, DeclaredUndoRequest,
                             applyRequestOf, convertRequestOf, createRequestOf,
                             decodedDeclaration, undoRequestOf)
import Slap.Web.Envelope (encodeEnvelope, encodeEnvelopeAndTail,
                          speakCreatedPatch, speakPatchedRom, speakRevertedRom)

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
-- An act's payload opens with one more little-endian u32 — the envelope's own length; the output bytes are everything after the envelope.

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
  patchBytes <- packBuffer patchPointer patchLength
  lengthPrefixedBuffer (inspectEnvelope patchBytes)

foreign export ccall "slap_web_analyze_patch" slapWebAnalyzePatch :: Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebAnalyzePatch :: Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebAnalyzePatch patchPointer patchLength = do
  patchBytes <- packBuffer patchPointer patchLength
  lengthPrefixedBuffer (analyzeEnvelope patchBytes)

foreign export ccall "slap_web_check_apply" slapWebCheckApply
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebCheckApply :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebCheckApply patchPointer patchLength romPointer romLength declarationPointer declarationLength = do
  declared   <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  patchBytes <- PatchFileContents <$> packBuffer patchPointer patchLength
  romBytes   <- InputFileContents <$> packBuffer romPointer romLength
  lengthPrefixedBuffer (checkApplyEnvelope declared patchBytes romBytes)

foreign export ccall "slap_web_check_undo" slapWebCheckUndo
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebCheckUndo :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebCheckUndo patchPointer patchLength patchedPointer patchedLength declarationPointer declarationLength = do
  declared     <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  patchBytes   <- PatchFileContents <$> packBuffer patchPointer patchLength
  patchedBytes <- OutputFileContents <$> packBuffer patchedPointer patchedLength
  lengthPrefixedBuffer (checkUndoEnvelope declared patchBytes patchedBytes)

foreign export ccall "slap_web_check_create" slapWebCheckCreate
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebCheckCreate :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebCheckCreate originalPointer originalLength modifiedPointer modifiedLength declarationPointer declarationLength = do
  declared      <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  originalBytes <- InputFileContents <$> packBuffer originalPointer originalLength
  modifiedBytes <- OutputFileContents <$> packBuffer modifiedPointer modifiedLength
  lengthPrefixedBuffer (checkCreateEnvelope declared originalBytes modifiedBytes)

-- | The source pair is read only when the declaration speaks of a source; a host with none to hand passes null and zero.
foreign export ccall "slap_web_check_convert" slapWebCheckConvert
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebCheckConvert :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebCheckConvert patchPointer patchLength sourcePointer sourceLength declarationPointer declarationLength = do
  declared    <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  patchBytes  <- PatchFileContents <$> packBuffer patchPointer patchLength
  handedSource <- case declaredConvertSourceFraming declared of
    Nothing -> pure Nothing
    Just _  -> Just . InputFileContents <$> packBuffer sourcePointer sourceLength
  lengthPrefixedBuffer (checkConvertEnvelope declared patchBytes handedSource)

-- The acts: each takes the buffers its check takes, and answers with an envelope-and-tail payload.

foreign export ccall "slap_web_apply_patch" slapWebApplyPatch
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebApplyPatch :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebApplyPatch patchPointer patchLength romPointer romLength declarationPointer declarationLength = do
  declared   <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  patchBytes <- PatchFileContents <$> packBuffer patchPointer patchLength
  romBytes   <- InputFileContents <$> packBuffer romPointer romLength
  lengthPrefixedBuffer =<< applyEnvelopeAndTail declared patchBytes romBytes

foreign export ccall "slap_web_undo_patch" slapWebUndoPatch
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebUndoPatch :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebUndoPatch patchPointer patchLength patchedPointer patchedLength declarationPointer declarationLength = do
  declared     <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  patchBytes   <- PatchFileContents <$> packBuffer patchPointer patchLength
  patchedBytes <- OutputFileContents <$> packBuffer patchedPointer patchedLength
  lengthPrefixedBuffer (undoEnvelopeAndTail declared patchBytes patchedBytes)

foreign export ccall "slap_web_create_patch" slapWebCreatePatch
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebCreatePatch :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebCreatePatch originalPointer originalLength modifiedPointer modifiedLength declarationPointer declarationLength = do
  declared      <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  originalBytes <- InputFileContents <$> packBuffer originalPointer originalLength
  modifiedBytes <- OutputFileContents <$> packBuffer modifiedPointer modifiedLength
  lengthPrefixedBuffer (createEnvelopeAndTail declared originalBytes modifiedBytes)

foreign export ccall "slap_web_convert_patch" slapWebConvertPatch
  :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)

slapWebConvertPatch :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO (Ptr Word8)
slapWebConvertPatch patchPointer patchLength sourcePointer sourceLength declarationPointer declarationLength = do
  declared    <- decodedDeclaration <$> packBuffer declarationPointer declarationLength
  patchBytes  <- PatchFileContents <$> packBuffer patchPointer patchLength
  handedSource <- case declaredConvertSourceFraming declared of
    Nothing -> pure Nothing
    Just _  -> Just . InputFileContents <$> packBuffer sourcePointer sourceLength
  lengthPrefixedBuffer =<< convertEnvelopeAndTail declared patchBytes handedSource

packBuffer :: Ptr Word8 -> Int -> IO ByteString
packBuffer pointer bufferLength = ByteString.packCStringLen (castPtr pointer, bufferLength)

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

checkApplyEnvelope :: DeclaredApplyRequest -> PatchFileContents -> InputFileContents -> ByteString
checkApplyEnvelope declared patchBytes romBytes =
  encodeEnvelope (noAdvisories (checkApply (applyRequestOf declared patchBytes romBytes)))

checkUndoEnvelope :: DeclaredUndoRequest -> PatchFileContents -> OutputFileContents -> ByteString
checkUndoEnvelope declared patchBytes patchedBytes =
  encodeEnvelope (noAdvisories (checkUndo (undoRequestOf declared patchBytes patchedBytes)))

checkCreateEnvelope :: DeclaredCreateRequest -> InputFileContents -> OutputFileContents -> ByteString
checkCreateEnvelope declared originalBytes modifiedBytes =
  encodeEnvelope (noAdvisories (Right (checkCreate (createRequestOf declared originalBytes modifiedBytes))))

checkConvertEnvelope :: DeclaredConvertRequest -> PatchFileContents -> Maybe InputFileContents -> ByteString
checkConvertEnvelope declared patchBytes handedSource =
  encodeEnvelope (noAdvisories (checkConvert (convertRequestOf declared patchBytes handedSource)))

applyEnvelopeAndTail :: DeclaredApplyRequest -> PatchFileContents -> InputFileContents -> IO ByteString
applyEnvelopeAndTail declared patchBytes romBytes =
  envelopeAndTailPayload . encodeEnvelopeAndTail speakPatchedRom <$> applyPatch (applyRequestOf declared patchBytes romBytes)

undoEnvelopeAndTail :: DeclaredUndoRequest -> PatchFileContents -> OutputFileContents -> ByteString
undoEnvelopeAndTail declared patchBytes patchedBytes =
  envelopeAndTailPayload (encodeEnvelopeAndTail speakRevertedRom (undoPatch (undoRequestOf declared patchBytes patchedBytes)))

createEnvelopeAndTail :: DeclaredCreateRequest -> InputFileContents -> OutputFileContents -> ByteString
createEnvelopeAndTail declared originalBytes modifiedBytes =
  envelopeAndTailPayload (encodeEnvelopeAndTail speakCreatedPatch (createPatch (createRequestOf declared originalBytes modifiedBytes)))

convertEnvelopeAndTail :: DeclaredConvertRequest -> PatchFileContents -> Maybe InputFileContents -> IO ByteString
convertEnvelopeAndTail declared patchBytes handedSource =
  envelopeAndTailPayload . encodeEnvelopeAndTail speakCreatedPatch <$> convertPatch (convertRequestOf declared patchBytes handedSource)

envelopeAndTailPayload :: (ByteString, ByteString) -> ByteString
envelopeAndTailPayload (envelope, outputBytes) = LazyByteString.toStrict $ Builder.toLazyByteString $
  Builder.word32LE (fromIntegral (ByteString.length envelope)) <> Builder.byteString envelope <> Builder.byteString outputBytes

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
    ["check-apply", patchPath, romPath, declarationPath] -> do
      declared   <- declarationFrom declarationPath
      patchBytes <- PatchFileContents <$> ByteString.readFile patchPath
      romBytes   <- InputFileContents <$> ByteString.readFile romPath
      ByteString.putStr (checkApplyEnvelope declared patchBytes romBytes)
    ["check-undo", patchPath, patchedPath, declarationPath] -> do
      declared     <- declarationFrom declarationPath
      patchBytes   <- PatchFileContents <$> ByteString.readFile patchPath
      patchedBytes <- OutputFileContents <$> ByteString.readFile patchedPath
      ByteString.putStr (checkUndoEnvelope declared patchBytes patchedBytes)
    ["check-create", originalPath, modifiedPath, declarationPath] -> do
      declared      <- declarationFrom declarationPath
      originalBytes <- InputFileContents <$> ByteString.readFile originalPath
      modifiedBytes <- OutputFileContents <$> ByteString.readFile modifiedPath
      ByteString.putStr (checkCreateEnvelope declared originalBytes modifiedBytes)
    "check-convert" : patchPath : declarationPath : maybeSourcePath | length maybeSourcePath <= 1 -> do
      declared     <- declarationFrom declarationPath
      patchBytes   <- PatchFileContents <$> ByteString.readFile patchPath
      handedSource <- traverse (fmap InputFileContents . ByteString.readFile) (listToMaybe maybeSourcePath)
      ByteString.putStr (checkConvertEnvelope declared patchBytes handedSource)
    ["apply", patchPath, romPath, declarationPath] -> do
      declared   <- declarationFrom declarationPath
      patchBytes <- PatchFileContents <$> ByteString.readFile patchPath
      romBytes   <- InputFileContents <$> ByteString.readFile romPath
      ByteString.putStr =<< applyEnvelopeAndTail declared patchBytes romBytes
    ["undo", patchPath, patchedPath, declarationPath] -> do
      declared     <- declarationFrom declarationPath
      patchBytes   <- PatchFileContents <$> ByteString.readFile patchPath
      patchedBytes <- OutputFileContents <$> ByteString.readFile patchedPath
      ByteString.putStr (undoEnvelopeAndTail declared patchBytes patchedBytes)
    ["create", originalPath, modifiedPath, declarationPath] -> do
      declared      <- declarationFrom declarationPath
      originalBytes <- InputFileContents <$> ByteString.readFile originalPath
      modifiedBytes <- OutputFileContents <$> ByteString.readFile modifiedPath
      ByteString.putStr (createEnvelopeAndTail declared originalBytes modifiedBytes)
    "convert" : patchPath : declarationPath : maybeSourcePath | length maybeSourcePath <= 1 -> do
      declared     <- declarationFrom declarationPath
      patchBytes   <- PatchFileContents <$> ByteString.readFile patchPath
      handedSource <- traverse (fmap InputFileContents . ByteString.readFile) (listToMaybe maybeSourcePath)
      ByteString.putStr =<< convertEnvelopeAndTail declared patchBytes handedSource
    _ -> die ("usage: slap-web-reactor VERB...  (writes the verb's envelope — an act's, with its byte tail — to stdout)\n"
           ++ "  surface | inspect PATCH | analyze PATCH\n"
           ++ "  check-apply PATCH ROM DECLARATION | check-undo PATCH PATCHED DECLARATION\n"
           ++ "  check-create ORIGINAL MODIFIED DECLARATION | check-convert PATCH DECLARATION [SOURCE]\n"
           ++ "  apply PATCH ROM DECLARATION | undo PATCH PATCHED DECLARATION\n"
           ++ "  create ORIGINAL MODIFIED DECLARATION | convert PATCH DECLARATION [SOURCE]")

declarationFrom :: FromJSON declaration => FilePath -> IO declaration
declarationFrom path = decodedDeclaration <$> ByteString.readFile path
