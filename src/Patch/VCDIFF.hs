{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.VCDIFF
  ( VCDIFFHeader(..)
  , VCDIFFWindow(..)
  , VCDIFFPatch(..)
  , VCDIFFDecodedInstruction(..)
  , parseVCDIFF
  , applyVCDIFF
  , vcdiffMeta
  , vcdiffInfo
  , decodeWindowInstructions
  ) where

-- Canonical reference: RFC 3284

import Patch.Binary (getVcdiffVarint, copyByteStringRange)
import Patch.Format (renderField)
import Patch.Get (runGet, getByte, getBytes, skip, getPosition, setPosition,
                  atEnd, vcdiffVarint, word32BE, failGet)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Array (Array, listArray, (!))
import Data.Array.ST (STArray, newArray, readArray, writeArray)
import Data.Bits (testBit)
import Control.Monad (when)
import Control.Monad.ST (ST, runST)
import Data.IORef
import Data.Int (Int64)
import Data.STRef (newSTRef, readSTRef, writeSTRef, modifySTRef')
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data VCDIFFInstruction = VcdiffNoop | VcdiffAdd Int | VcdiffRun Int | VcdiffCopy Int Int
  deriving (Show)
  -- VcdiffCopy length mode  (mode indexes into near/same cache decode)

data VCDIFFHeader = VCDIFFHeader
  { vcdiffVersion      :: Word8
  , vcdiffCompressorId :: Maybe Word8
  , vcdiffHasCodeTable :: Bool
  } deriving (Show)

data VCDIFFWindow = VCDIFFWindow
  { vcdiffWindowIndicator :: Word8
  , vcdiffSourceLength    :: Int64
  , vcdiffSourcePosition  :: Int64
  , vcdiffTargetLength    :: Int64
  , vcdiffDeltaIndicator  :: Word8
  , vcdiffAdler32         :: Maybe Word32
  , vcdiffAddRunData      :: ByteString   -- literal data stream
  , vcdiffInstructions    :: ByteString   -- instruction stream (code + sizes)
  , vcdiffAddresses       :: ByteString   -- address stream
  } deriving (Show)

data VCDIFFPatch = VCDIFFPatch
  { vcdiffHeader    :: VCDIFFHeader
  , vcdiffWindows   :: [VCDIFFWindow]
  , vcdiffCodeTable :: Array Word8 CodeEntry  -- default or custom
  , vcdiffNearSize  :: Int                    -- 4 by default
  , vcdiffSameSize  :: Int                    -- 3 by default
  } deriving (Show)

-- | Decoded instruction for the explain path — mirrors execute logic but
--   accumulates instructions instead of writing bytes.
data VCDIFFDecodedInstruction
  = DecodedAdd  Int64 ByteString         -- window-local output offset, literal bytes
  | DecodedRun  Int64 Word8 Int          -- window-local output offset, fill byte, count
  | DecodedCopy Int64 Int (Maybe Int64)  -- window-local output offset, size,
                                         --   Just absoluteSrcFileOffset | Nothing (target/self ref)

----------------------------------------------------------------------------
-- Default code table (RFC 3284 Section 5.6)
----------------------------------------------------------------------------

-- Each entry is a pair of instructions. For size=0 instructions, the
-- actual size follows as a varint in the instruction stream.

type CodeEntry = (VCDIFFInstruction, VCDIFFInstruction)

defaultCodeTable :: Array Word8 CodeEntry
defaultCodeTable = listArray (0, 255) $
  -- 0: RUN 0, Noop
  [(VcdiffRun 0, VcdiffNoop)]
  -- 1-18: ADD size, Noop  (size 0..17)
  ++ [(VcdiffAdd size, VcdiffNoop) | size <- [0..17]]
  -- 19-162: COPY size mode, Noop
  -- 9 modes (0..8), sizes 0..15 for each mode → 144 entries
  -- For each mode 0..8:
  --   size 0: COPY 0 mode, Noop
  --   sizes 4..18: COPY s mode, Noop
  ++ [(VcdiffCopy size mode, VcdiffNoop) | mode <- [0..8], size <- 0 : [4..18]]
  -- 163-234: ADD 1..4, COPY 4..6, modes 0..5  → 72 entries
  ++ [(VcdiffAdd addSize, VcdiffCopy copySize mode) | mode <- [0..5], addSize <- [1..4], copySize <- [4..6]]
  -- 235-246: ADD 1..4, COPY 4, modes 6..8  → 12 entries
  ++ [(VcdiffAdd addSize, VcdiffCopy 4 mode) | mode <- [6..8], addSize <- [1..4]]
  -- 247-255: COPY 4, ADD 1, modes 0..8  → 9 entries
  ++ [(VcdiffCopy 4 mode, VcdiffAdd 1) | mode <- [0..8]]

----------------------------------------------------------------------------
-- Address cache (RFC 3284 Section 5.3)
----------------------------------------------------------------------------

data AddressCache = AddressCache
  { cacheNear     :: !(Array Int (IORef Int64))
  , cacheSame     :: !(Array Int (IORef Int64))
  , cacheNearNext :: !(IORef Int)
  , cacheNearSize :: !Int
  , cacheSameSize :: !Int
  }

defaultNearSize, defaultSameSize :: Int
defaultNearSize = 4
defaultSameSize = 3

newAddressCache :: Int -> Int -> IO AddressCache
newAddressCache nearSize sameSize = do
  nearSlots <- mapM (\_ -> newIORef 0) [0..nearSize-1]
  sameSlots <- mapM (\_ -> newIORef 0) [0..sameSize*256-1]
  nextIndex <- newIORef 0
  pure AddressCache
    { cacheNear     = listArray (0, max 0 nearSize - 1) nearSlots
    , cacheSame     = listArray (0, max 0 (sameSize * 256) - 1) sameSlots
    , cacheNearNext = nextIndex
    , cacheNearSize = nearSize
    , cacheSameSize = sameSize
    }

updateCache :: AddressCache -> Int64 -> IO ()
updateCache cache address = do
  when (cacheNearSize cache > 0) $ do
    index <- readIORef (cacheNearNext cache)
    writeIORef (cacheNear cache ! index) address
    writeIORef (cacheNearNext cache) ((index + 1) `mod` cacheNearSize cache)
  when (cacheSameSize cache > 0) $ do
    let sameIndex = fromIntegral address `mod` (cacheSameSize cache * 256)
    writeIORef (cacheSame cache ! sameIndex) address

-- | Decode an address given the mode, current "here" position,
--   and a function to read from the address stream.
decodeAddr :: AddressCache -> Int -> Int64 -> IORef Int -> ByteString -> IO Int64
decodeAddr cache mode here addrPosRef addressBytes
  | mode == 0 = do
      -- Self mode
      position <- readIORef addrPosRef
      if position >= ByteString.length addressBytes then pure 0
      else do
        let (value, consumed) = getVcdiffVarint position addressBytes
        writeIORef addrPosRef (position + consumed)
        updateCache cache value
        pure value
  | mode == 1 = do
      -- Here mode
      position <- readIORef addrPosRef
      if position >= ByteString.length addressBytes then pure 0
      else do
        let (value, consumed) = getVcdiffVarint position addressBytes
        writeIORef addrPosRef (position + consumed)
        let address = here - value
        updateCache cache address
        pure address
  | mode < cacheNearSize cache + 2 = do
      -- Near mode
      position <- readIORef addrPosRef
      if position >= ByteString.length addressBytes then pure 0
      else do
        let (value, consumed) = getVcdiffVarint position addressBytes
        writeIORef addrPosRef (position + consumed)
        base <- readIORef (cacheNear cache ! (mode - 2))
        let address = base + value
        updateCache cache address
        pure address
  | otherwise = do
      -- Same mode
      position <- readIORef addrPosRef
      if position >= ByteString.length addressBytes then pure 0
      else do
        let byte = fromIntegral (ByteString.index addressBytes position) :: Int
        writeIORef addrPosRef (position + 1)
        let sameIndex = (mode - cacheNearSize cache - 2) * 256 + byte
        if sameIndex >= 0 && sameIndex < cacheSameSize cache * 256
          then do
            address <- readIORef (cacheSame cache ! sameIndex)
            updateCache cache address
            pure address
          else pure 0

----------------------------------------------------------------------------
-- Code table serialization (RFC 3284 §7)
----------------------------------------------------------------------------

-- Instruction type encoding: Noop=0, Add=1, Run=2, Copy=3
instType :: VCDIFFInstruction -> Word8
instType VcdiffNoop       = 0
instType (VcdiffAdd _)    = 1
instType (VcdiffRun _)    = 2
instType (VcdiffCopy _ _) = 3

instSize :: VCDIFFInstruction -> Word8
instSize VcdiffNoop       = 0
instSize (VcdiffAdd size)    = fromIntegral size
instSize (VcdiffRun size)    = fromIntegral size
instSize (VcdiffCopy size _) = fromIntegral size

instMode :: VCDIFFInstruction -> Word8
instMode (VcdiffCopy _ mode) = fromIntegral mode
instMode _                = 0

-- | Serialize the default code table to 1536 bytes (6 × 256):
--   types1 ++ types2 ++ sizes1 ++ sizes2 ++ modes1 ++ modes2
serializedDefaultTable :: ByteString
serializedDefaultTable = ByteString.pack $
  map (instType . fst . (defaultCodeTable !)) [0..255]
  ++ map (instType . snd . (defaultCodeTable !)) [0..255]
  ++ map (instSize . fst . (defaultCodeTable !)) [0..255]
  ++ map (instSize . snd . (defaultCodeTable !)) [0..255]
  ++ map (instMode . fst . (defaultCodeTable !)) [0..255]
  ++ map (instMode . snd . (defaultCodeTable !)) [0..255]

deserializeCodeTable :: ByteString -> Either String (Array Word8 CodeEntry)
deserializeCodeTable tableBytes
  | ByteString.length tableBytes /= 1536 = Left $ "VCDIFF: code table must be 1536 bytes, got " ++ show (ByteString.length tableBytes)
  | otherwise = do
      entries <- mapM makeEntry [0..255]
      pure $ listArray (0, 255) entries
  where
    makeEntry :: Int -> Either String CodeEntry
    makeEntry index = (,) <$> makeInstruction (byteAt index) (byteAt (512+index)) (byteAt (1024+index))
                        <*> makeInstruction (byteAt (256+index)) (byteAt (768+index)) (byteAt (1280+index))
    byteAt = ByteString.index tableBytes
    makeInstruction :: Word8 -> Word8 -> Word8 -> Either String VCDIFFInstruction
    makeInstruction 0 _ _ = Right VcdiffNoop
    makeInstruction 1 size _ = Right (VcdiffAdd (fromIntegral size))
    makeInstruction 2 size _ = Right (VcdiffRun (fromIntegral size))
    makeInstruction 3 size mode = Right (VcdiffCopy (fromIntegral size) (fromIntegral mode))
    makeInstruction typeCode _ _ = Left ("VCDIFF: invalid instruction type in code table: " ++ show typeCode)

-- | Decode a custom code table from the header's code table data.
--   Format: near_size (1 byte), same_size (1 byte), then a VCDIFF delta
--   (using default table) that transforms serializedDefaultTable into the
--   custom table.
decodeCustomTable :: ByteString -> Either String (Array Word8 CodeEntry, Int, Int)
decodeCustomTable input = do
  when (ByteString.length input < 2) $ Left "VCDIFF: custom code table data too short"
  let nearSize = fromIntegral (ByteString.index input 0) :: Int
      sameSize = fromIntegral (ByteString.index input 1) :: Int
      deltaBytes = ByteString.drop 2 input
  inner <- parseVCDIFFWith False deltaBytes
  customSerialized <- applyVCDIFF inner serializedDefaultTable
  table <- deserializeCodeTable customSerialized
  pure (table, nearSize, sameSize)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseVCDIFF :: ByteString -> Either String VCDIFFPatch
parseVCDIFF = parseVCDIFFWith True

parseVCDIFFWith :: Bool -> ByteString -> Either String VCDIFFPatch
parseVCDIFFWith allowCustom input
  | ByteString.length input < 5 = Left "VCDIFF: input too short"
  | ByteString.take 3 input /= "\xd6\xc3\xc4" = Left "not a VCDIFF file (bad magic)"
  | otherwise = do
      (mTableBytes, header, windows) <- runGet parseHeader input
      case mTableBytes of
        Nothing -> Right (VCDIFFPatch header windows defaultCodeTable
                                      defaultNearSize defaultSameSize)
        Just rawTableBytes -> do
          (table, nearSize, sameSize) <- decodeCustomTable rawTableBytes
          Right (VCDIFFPatch header windows table nearSize sameSize)
  where
    parseHeader = do
      skip 3  -- magic
      version <- getByte
      when (version /= 0 && version /= 0x53) $  -- 0x53 = 'S', xdelta3 version indicator
        failGet ("unsupported VCDIFF version: " ++ show version)
      headerIndicator <- getByte
      let hasCompressor = testBit headerIndicator 0
          hasCodeTable  = testBit headerIndicator 1
      compressorIdentifier <- if hasCompressor
        then Just <$> getByte
        else pure Nothing
      mTableBytes <- if hasCodeTable
        then do
          when (not allowCustom) $
            failGet "nested custom code tables are not allowed"
          tableLength <- fromIntegral <$> vcdiffVarint
          Just <$> getBytes tableLength
        else pure Nothing
      -- Skip optional application data (xdelta3 extension)
      when (testBit headerIndicator 2) $ do
        applicationLength <- fromIntegral <$> vcdiffVarint
        skip applicationLength
      let header = VCDIFFHeader version compressorIdentifier hasCodeTable
      windows <- parseWindows (version == 0x53)
      pure (mTableBytes, header, windows)

    parseWindows isXdelta3 = do
      finished <- atEnd
      if finished then pure []
      else do
        window <- parseOneWindow isXdelta3
        remaining <- parseWindows isXdelta3
        pure (window : remaining)

    parseOneWindow isXdelta3 = do
      windowIndicator <- getByte
      let hasSource = testBit windowIndicator 0 || testBit windowIndicator 1
      (sourceLength, sourcePosition) <- if hasSource
        then (,) <$> vcdiffVarint <*> vcdiffVarint
        else pure (0, 0)
      -- Delta encoding length
      deltaLength <- vcdiffVarint
      deltaStart <- getPosition
      let deltaEnd = deltaStart + fromIntegral deltaLength
      -- Inside the delta body:
      targetSize  <- vcdiffVarint
      when (targetSize < 0) $ failGet "VCDIFF: negative window target size"
      deltaInd  <- getByte
      addRunLength <- vcdiffVarint
      instructionLength   <- vcdiffVarint
      addressLength   <- vcdiffVarint
      -- Check for secondary compression
      when (testBit deltaInd 0 || testBit deltaInd 1
            || (not isXdelta3 && testBit deltaInd 2)) $
        failGet "secondary compression in VCDIFF data sections is not supported"
      -- Compute data section start from deltaEnd, not from current position.
      -- xdelta3 writes 4 bytes of Adler32 after the length fields (even in
      -- version 0 mode, sometimes without setting any flag), so working
      -- backwards from the known end avoids guessing what's between lengths
      -- and data.
      afterLengths <- getPosition
      let dataStart = deltaEnd
                      - fromIntegral addRunLength
                      - fromIntegral instructionLength
                      - fromIntegral addressLength
      adler <- if dataStart == afterLengths + 4
        then Just <$> word32BE
        else pure Nothing
      -- Jump to data start and slice the three data streams
      setPosition dataStart
      addRunData <- getBytes (fromIntegral addRunLength)
      instructionData   <- getBytes (fromIntegral instructionLength)
      addressData   <- getBytes (fromIntegral addressLength)
      setPosition deltaEnd
      pure VCDIFFWindow
        { vcdiffWindowIndicator = windowIndicator
        , vcdiffSourceLength    = sourceLength
        , vcdiffSourcePosition    = sourcePosition
        , vcdiffTargetLength    = targetSize
        , vcdiffDeltaIndicator     = deltaInd
        , vcdiffAdler32      = adler
        , vcdiffAddRunData   = addRunData
        , vcdiffInstructions = instructionData
        , vcdiffAddresses    = addressData
        }

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyVCDIFF :: VCDIFFPatch -> ByteString -> Either String ByteString
applyVCDIFF patch source
  | totalSize < 0  = Left "VCDIFF: negative total target size"
  | totalSize == 0 = Right ByteString.empty
  | otherwise =
      Right $ unsafeCreate (fromIntegral totalSize) $ \outputPointer -> do
        globalOutRef <- newIORef (0 :: Int)
        mapM_ (applyWindow codeTable nearSize sameSize source outputPointer globalOutRef (fromIntegral totalSize)) (vcdiffWindows patch)
  where
    totalSize = sum (map vcdiffTargetLength (vcdiffWindows patch))
    codeTable = vcdiffCodeTable patch
    nearSize = vcdiffNearSize patch
    sameSize = vcdiffSameSize patch

applyWindow :: Array Word8 CodeEntry -> Int -> Int
            -> ByteString -> Ptr Word8 -> IORef Int -> Int -> VCDIFFWindow -> IO ()
applyWindow codeTable nearSize sameSize source outputPointer globalOutRef totalTargetLength window = do
  globalOut <- readIORef globalOutRef
  let targetLength = fromIntegral (vcdiffTargetLength window) :: Int
      sourceSegmentLength = fromIntegral (vcdiffSourceLength window) :: Int
      sourceSegmentOffset = fromIntegral (vcdiffSourcePosition window) :: Int
      hasSource = testBit (vcdiffWindowIndicator window) 0
      hasTarget = testBit (vcdiffWindowIndicator window) 1

  -- Build the source window (COPY address space = source segment ++ target-so-far).

  cache <- newAddressCache nearSize sameSize
  addRunPositionReference <- newIORef (0 :: Int)
  instructionPositionReference   <- newIORef (0 :: Int)
  addressPositionReference   <- newIORef (0 :: Int)
  windowOffsetRef <- newIORef (0 :: Int)  -- offset within this window's target

  let instructionBytes = vcdiffInstructions window
      addRunBytes  = vcdiffAddRunData window
      addressBytes = vcdiffAddresses window

      -- Read a byte from the source-segment + target-so-far combined space
      readSourceWindow :: Int -> IO Word8
      readSourceWindow index
        | hasSource && index < sourceSegmentLength =
            if sourceSegmentOffset + index < ByteString.length source
            then pure (ByteString.index source (sourceSegmentOffset + index))
            else pure 0
        | hasTarget && index < sourceSegmentLength =
            -- VCD_TARGET: source is previous target window data
            if sourceSegmentOffset + index < totalTargetLength
            then peekByteOff outputPointer (sourceSegmentOffset + index)
            else pure 0
        | otherwise =
            -- Index into the target data we're building for this window
            let targetIndex = index - sourceSegmentLength
            in if targetIndex >= 0 && globalOut + targetIndex < totalTargetLength
               then peekByteOff outputPointer (globalOut + targetIndex)
               else pure 0

      readNextInstruction :: IO (Maybe Word8)
      readNextInstruction = do
        position <- readIORef instructionPositionReference
        if position >= ByteString.length instructionBytes
          then pure Nothing
          else do
            writeIORef instructionPositionReference (position + 1)
            pure (Just (ByteString.index instructionBytes position))

      readInstructionVarint :: IO Int64
      readInstructionVarint = do
        position <- readIORef instructionPositionReference
        if position >= ByteString.length instructionBytes then pure 0
        else do
          let (value, consumed) = getVcdiffVarint position instructionBytes
          writeIORef instructionPositionReference (position + consumed)
          pure value

      executeInstruction :: VCDIFFInstruction -> IO ()
      executeInstruction VcdiffNoop = pure ()
      executeInstruction (VcdiffAdd rawSize) = do
        size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
        windowOffset <- readIORef windowOffsetRef
        addRunPosition <- readIORef addRunPositionReference
        let count = min size (targetLength - windowOffset)
            -- Clamp to available add/run data
            safeCount = if addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes
                        then min count (ByteString.length addRunBytes - addRunPosition)
                        else 0
        copyByteStringRange outputPointer (globalOut + windowOffset) addRunBytes addRunPosition safeCount
        writeIORef addRunPositionReference (addRunPosition + count)
        writeIORef windowOffsetRef (windowOffset + count)

      executeInstruction (VcdiffRun rawSize) = do
        size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
        windowOffset <- readIORef windowOffsetRef
        addRunPosition <- readIORef addRunPositionReference
        let count = min size (targetLength - windowOffset)
        when (addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes && count > 0) $ do
          let byte = ByteString.index addRunBytes addRunPosition
          mapM_ (\offset -> pokeByteOff outputPointer (globalOut + windowOffset + offset) byte) [0..count-1]
        writeIORef addRunPositionReference (addRunPosition + 1)
        writeIORef windowOffsetRef (windowOffset + count)

      executeInstruction (VcdiffCopy rawSize mode) = do
        size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
        windowOffset <- readIORef windowOffsetRef
        -- "here" = sourceSegmentLength + windowOffset (position in the combined source-window)
        let here = fromIntegral sourceSegmentLength + fromIntegral windowOffset :: Int64
        address <- decodeAddr cache mode here addressPositionReference addressBytes
        let count = min size (targetLength - windowOffset)
        -- Copy byte-by-byte (target region may overlap)
        mapM_ (\offset -> do
          byte <- readSourceWindow (fromIntegral address + offset)
          pokeByteOff outputPointer (globalOut + windowOffset + offset) byte
          ) [0..count-1]
        writeIORef windowOffsetRef (windowOffset + count)

  -- Process instruction stream
  let processLoop = do
        nextCode <- readNextInstruction
        case nextCode of
          Nothing -> pure ()
          Just code -> do
            let (firstInstruction, secondInstruction) = codeTable ! code
            executeInstruction firstInstruction
            executeInstruction secondInstruction
            processLoop
  processLoop

  -- Fill remaining target bytes from source (implicit copy).
  -- xdelta3 and other VCDIFF decoders fill any remaining target bytes
  -- from the corresponding source positions after instructions are exhausted.
  windowOffset <- readIORef windowOffsetRef
  if hasSource && windowOffset < targetLength
    then mapM_ (\offset -> do
      let sourceIndex = sourceSegmentOffset + windowOffset + offset
      byte <- if sourceIndex < ByteString.length source then pure (ByteString.index source sourceIndex) else pure 0
      pokeByteOff outputPointer (globalOut + windowOffset + offset) byte
      ) [0..targetLength - windowOffset - 1]
    else pure ()

  writeIORef globalOutRef (globalOut + targetLength)

----------------------------------------------------------------------------
-- Instruction decoding (pure, for explain path)
----------------------------------------------------------------------------

-- | Decode a window's instruction bytecodes into a list of decoded
--   instructions. Mirrors 'applyWindow' but accumulates results in ST
--   instead of writing bytes.
decodeWindowInstructions :: Array Word8 CodeEntry -> Int -> Int
                         -> VCDIFFWindow -> [VCDIFFDecodedInstruction]
decodeWindowInstructions codeTable nearSize sameSize window = runST decodeBody
  where
    targetLength    = fromIntegral (vcdiffTargetLength window) :: Int
    sourceSegmentLength = fromIntegral (vcdiffSourceLength window) :: Int
    hasSource = testBit (vcdiffWindowIndicator window) 0
    instructionBytes    = vcdiffInstructions window
    addRunBytes     = vcdiffAddRunData window
    addressBytes    = vcdiffAddresses window

    decodeBody :: forall s. ST s [VCDIFFDecodedInstruction]
    decodeBody = do
      instructionPositionRef   <- newSTRef (0 :: Int)
      addRunPositionRef <- newSTRef (0 :: Int)
      addressPositionRef   <- newSTRef (0 :: Int)
      windowOffsetRef <- newSTRef (0 :: Int)
      resultRef    <- newSTRef ([] :: [VCDIFFDecodedInstruction])

      nearArray     <- newArray (0, max 0 nearSize - 1) 0 :: ST s (STArray s Int Int64)
      sameArray     <- newArray (0, max 0 (sameSize * 256) - 1) 0 :: ST s (STArray s Int Int64)
      nearNextRef <- newSTRef (0 :: Int)

      let emit instruction = modifySTRef' resultRef (instruction :)

          updateCacheST :: Int64 -> ST s ()
          updateCacheST address = do
            when (nearSize > 0) $ do
              index <- readSTRef nearNextRef
              writeArray nearArray index address
              writeSTRef nearNextRef ((index + 1) `mod` nearSize)
            when (sameSize > 0) $ do
              let sameIndex = fromIntegral address `mod` (sameSize * 256)
              writeArray sameArray sameIndex address

          decodeAddressST :: Int -> Int64 -> ST s Int64
          decodeAddressST mode here
            | mode == 0 = do
                position <- readSTRef addressPositionRef
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let (value, consumed) = getVcdiffVarint position addressBytes
                  writeSTRef addressPositionRef (position + consumed)
                  updateCacheST value
                  pure value
            | mode == 1 = do
                position <- readSTRef addressPositionRef
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let (value, consumed) = getVcdiffVarint position addressBytes
                  writeSTRef addressPositionRef (position + consumed)
                  let address = here - value
                  updateCacheST address
                  pure address
            | mode < nearSize + 2 = do
                position <- readSTRef addressPositionRef
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let (value, consumed) = getVcdiffVarint position addressBytes
                  writeSTRef addressPositionRef (position + consumed)
                  base <- readArray nearArray (mode - 2)
                  let address = base + value
                  updateCacheST address
                  pure address
            | otherwise = do
                position <- readSTRef addressPositionRef
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let byte = fromIntegral (ByteString.index addressBytes position) :: Int
                  writeSTRef addressPositionRef (position + 1)
                  let sameIndex = (mode - nearSize - 2) * 256 + byte
                  if sameIndex >= 0 && sameIndex < sameSize * 256
                    then do
                      address <- readArray sameArray sameIndex
                      updateCacheST address
                      pure address
                    else pure 0

          readNextInstruction :: ST s (Maybe Word8)
          readNextInstruction = do
            position <- readSTRef instructionPositionRef
            if position >= ByteString.length instructionBytes
              then pure Nothing
              else do
                writeSTRef instructionPositionRef (position + 1)
                pure (Just (ByteString.index instructionBytes position))

          readInstructionVarint :: ST s Int64
          readInstructionVarint = do
            position <- readSTRef instructionPositionRef
            if position >= ByteString.length instructionBytes then pure 0
            else do
              let (value, consumed) = getVcdiffVarint position instructionBytes
              writeSTRef instructionPositionRef (position + consumed)
              pure value

          executeInstruction :: VCDIFFInstruction -> ST s ()
          executeInstruction VcdiffNoop = pure ()
          executeInstruction (VcdiffAdd rawSize) = do
            size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
            windowOffset <- readSTRef windowOffsetRef
            addRunPosition <- readSTRef addRunPositionRef
            let count = min size (targetLength - windowOffset)
                safeCount = if addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes
                            then min count (ByteString.length addRunBytes - addRunPosition)
                            else 0
            when (count > 0) $
              emit (DecodedAdd (fromIntegral windowOffset) (ByteString.take safeCount (ByteString.drop addRunPosition addRunBytes)))
            writeSTRef addRunPositionRef (addRunPosition + count)
            writeSTRef windowOffsetRef (windowOffset + count)

          executeInstruction (VcdiffRun rawSize) = do
            size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
            windowOffset <- readSTRef windowOffsetRef
            addRunPosition <- readSTRef addRunPositionRef
            let count = min size (targetLength - windowOffset)
            when (addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes && count > 0) $
              emit (DecodedRun (fromIntegral windowOffset) (ByteString.index addRunBytes addRunPosition) count)
            writeSTRef addRunPositionRef (addRunPosition + 1)
            writeSTRef windowOffsetRef (windowOffset + count)

          executeInstruction (VcdiffCopy rawSize mode) = do
            size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
            windowOffset <- readSTRef windowOffsetRef
            let here  = fromIntegral sourceSegmentLength + fromIntegral windowOffset :: Int64
                count = min size (targetLength - windowOffset)
            address <- decodeAddressST mode here
            when (count > 0) $ do
              let maybeSourceOffset = if address < fromIntegral sourceSegmentLength && hasSource
                            then Just (vcdiffSourcePosition window + address)
                            else Nothing
              emit (DecodedCopy (fromIntegral windowOffset) count maybeSourceOffset)
            writeSTRef windowOffsetRef (windowOffset + count)

          decodeLoop :: ST s ()
          decodeLoop = do
            nextCode <- readNextInstruction
            case nextCode of
              Nothing -> pure ()
              Just code -> do
                let (firstInstruction, secondInstruction) = codeTable ! code
                executeInstruction firstInstruction
                executeInstruction secondInstruction
                decodeLoop

      decodeLoop

      -- Implicit trailing copy from source
      windowOffset <- readSTRef windowOffsetRef
      when (hasSource && windowOffset < targetLength) $
        emit (DecodedCopy (fromIntegral windowOffset) (targetLength - windowOffset)
                     (Just (vcdiffSourcePosition window + fromIntegral windowOffset)))

      reverse <$> readSTRef resultRef

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

vcdiffMeta :: VCDIFFPatch -> [(String, String)]
vcdiffMeta patch = concat
  [ [("version", show (vcdiffVersion (vcdiffHeader patch)))]
  , case vcdiffCompressorId (vcdiffHeader patch) of
      Nothing -> []
      Just compressor  -> [("compressor", show compressor)]
  , if vcdiffHasCodeTable (vcdiffHeader patch)
    then [("code table", "custom (near=" ++ show (vcdiffNearSize patch)
          ++ ", same=" ++ show (vcdiffSameSize patch) ++ ")")]
    else []
  , [("target size", show (sum (map vcdiffTargetLength (vcdiffWindows patch))))]
  , if any ((/= Nothing) . vcdiffAdler32) (vcdiffWindows patch)
    then [("checksums", "Adler32 (xdelta3)")]
    else []
  ]

vcdiffInfo :: VCDIFFPatch -> String
vcdiffInfo patch = unlines $ filter (not . null) $
  [ "format:      VCDIFF" ++ if vcdiffVersion (vcdiffHeader patch) == 0x53
                              then " (xdelta3)" else "" ]
  ++ map renderField (vcdiffMeta patch)
  ++ [ "windows:     " ++ show (length (vcdiffWindows patch)) ]
