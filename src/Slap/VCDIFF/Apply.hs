module Slap.VCDIFF.Apply
  ( applyVCDIFF
  , applyWindow
  , decodeWindowInstructions
  , newAddressCache
  , updateCache
  , decodeAddress
  ) where

import Slap.VCDIFF.Types
    ( VCDIFFPatch(..), VCDIFFWindow(..), VCDIFFInstruction(..)
    , VCDIFFDecodedInstruction(..), CodeEntry, AddressCache(..)
    )
import Slap.Binary (getVcdiffVarint, copyByteStringRange)
import Slap.Measure (Offset(..), FileSize(..))

import Data.Array (Array, listArray, (!))
import Data.Array.ST (STArray, newArray, readArray, writeArray)
import Data.Bits (testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Control.Monad (when)
import Control.Monad.ST (ST, runST)
import Data.IORef
import Data.Int (Int64)
import Data.STRef (newSTRef, readSTRef, writeSTRef, modifySTRef')
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)

----------------------------------------------------------------------------
-- Address cache operations
----------------------------------------------------------------------------

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
--   an IORef tracking the read position, and the address stream bytes.
decodeAddress :: AddressCache -> Int -> Int64 -> IORef Int -> ByteString -> IO Int64
decodeAddress cache mode here addressPositionReference addressBytes
  | mode == 0 = do
      -- Self mode
      position <- readIORef addressPositionReference
      if position >= ByteString.length addressBytes then pure 0
      else do
        let (value, consumed) = getVcdiffVarint position addressBytes
        writeIORef addressPositionReference (position + consumed)
        updateCache cache value
        pure value
  | mode == 1 = do
      -- Here mode
      position <- readIORef addressPositionReference
      if position >= ByteString.length addressBytes then pure 0
      else do
        let (value, consumed) = getVcdiffVarint position addressBytes
        writeIORef addressPositionReference (position + consumed)
        let address = here - value
        updateCache cache address
        pure address
  | mode < cacheNearSize cache + 2 = do
      -- Near mode
      position <- readIORef addressPositionReference
      if position >= ByteString.length addressBytes then pure 0
      else do
        let (value, consumed) = getVcdiffVarint position addressBytes
        writeIORef addressPositionReference (position + consumed)
        base <- readIORef (cacheNear cache ! (mode - 2))
        let address = base + value
        updateCache cache address
        pure address
  | otherwise = do
      -- Same mode
      position <- readIORef addressPositionReference
      if position >= ByteString.length addressBytes then pure 0
      else do
        let byte = fromIntegral (ByteString.index addressBytes position) :: Int
        writeIORef addressPositionReference (position + 1)
        let sameIndex = (mode - cacheNearSize cache - 2) * 256 + byte
        if sameIndex >= 0 && sameIndex < cacheSameSize cache * 256
          then do
            address <- readIORef (cacheSame cache ! sameIndex)
            updateCache cache address
            pure address
          else pure 0

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyVCDIFF :: VCDIFFPatch -> ByteString -> Either String ByteString
applyVCDIFF patch source
  | totalSize < 0  = Left "VCDIFF: negative total target size"
  | totalSize == 0 = Right ByteString.empty
  | otherwise =
      Right $ unsafeCreate (fromIntegral totalSize) $ \outputPointer -> do
        globalOutputOffsetRef <- newIORef (0 :: Int)
        mapM_ (applyWindow codeTable nearSize sameSize source outputPointer globalOutputOffsetRef (fromIntegral totalSize)) (vcdiffWindows patch)
  where
    totalSize = sum (map (unFileSize . vcdiffTargetLength) (vcdiffWindows patch))
    codeTable = vcdiffCodeTable patch
    nearSize = vcdiffNearSize patch
    sameSize = vcdiffSameSize patch

applyWindow :: Array Word8 CodeEntry -> Int -> Int
            -> ByteString -> Ptr Word8 -> IORef Int -> Int -> VCDIFFWindow -> IO ()
applyWindow codeTable nearSize sameSize source outputPointer globalOutputOffsetRef totalTargetLength window = do
  globalOutputOffset <- readIORef globalOutputOffsetRef
  let targetLength = fromIntegral (unFileSize (vcdiffTargetLength window)) :: Int
      sourceSegmentLength = fromIntegral (unFileSize (vcdiffSourceLength window)) :: Int
      sourceSegmentOffset = fromIntegral (unOffset (vcdiffSourcePosition window)) :: Int
      hasSource = testBit (vcdiffWindowIndicator window) 0
      hasTarget = testBit (vcdiffWindowIndicator window) 1

  -- Initialize stream position counters for this window.

  cache <- newAddressCache nearSize sameSize
  addRunPositionReference <- newIORef (0 :: Int)
  instructionPositionReference   <- newIORef (0 :: Int)
  addressPositionReference   <- newIORef (0 :: Int)
  windowOffsetReference <- newIORef (0 :: Int)  -- offset within this window's target

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
            in if targetIndex >= 0 && globalOutputOffset + targetIndex < totalTargetLength
               then peekByteOff outputPointer (globalOutputOffset + targetIndex)
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
        windowOffset <- readIORef windowOffsetReference
        addRunPosition <- readIORef addRunPositionReference
        let count = min size (targetLength - windowOffset)
            -- Clamp to available add/run data
            safeCount = if addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes
                        then min count (ByteString.length addRunBytes - addRunPosition)
                        else 0
        copyByteStringRange outputPointer (globalOutputOffset + windowOffset) addRunBytes addRunPosition safeCount
        writeIORef addRunPositionReference (addRunPosition + count)
        writeIORef windowOffsetReference (windowOffset + count)

      executeInstruction (VcdiffRun rawSize) = do
        size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
        windowOffset <- readIORef windowOffsetReference
        addRunPosition <- readIORef addRunPositionReference
        let count = min size (targetLength - windowOffset)
        when (addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes && count > 0) $ do
          let byte = ByteString.index addRunBytes addRunPosition
          mapM_ (\offset -> pokeByteOff outputPointer (globalOutputOffset + windowOffset + offset) byte) [0..count-1]
        writeIORef addRunPositionReference (addRunPosition + 1)
        writeIORef windowOffsetReference (windowOffset + count)

      executeInstruction (VcdiffCopy rawSize mode) = do
        size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
        windowOffset <- readIORef windowOffsetReference
        -- "here" = sourceSegmentLength + windowOffset (position in the combined source-window)
        let here = fromIntegral sourceSegmentLength + fromIntegral windowOffset :: Int64
        address <- decodeAddress cache mode here addressPositionReference addressBytes
        let count = min size (targetLength - windowOffset)
        -- Copy byte-by-byte (target region may overlap)
        mapM_ (\offset -> do
          byte <- readSourceWindow (fromIntegral address + offset)
          pokeByteOff outputPointer (globalOutputOffset + windowOffset + offset) byte
          ) [0..count-1]
        writeIORef windowOffsetReference (windowOffset + count)

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
  windowOffset <- readIORef windowOffsetReference
  if hasSource && windowOffset < targetLength
    then mapM_ (\offset -> do
      let sourceIndex = sourceSegmentOffset + windowOffset + offset
      byte <- if sourceIndex < ByteString.length source then pure (ByteString.index source sourceIndex) else pure 0
      pokeByteOff outputPointer (globalOutputOffset + windowOffset + offset) byte
      ) [0..targetLength - windowOffset - 1]
    else pure ()

  writeIORef globalOutputOffsetRef (globalOutputOffset + targetLength)

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
    targetLength    = fromIntegral (unFileSize (vcdiffTargetLength window)) :: Int
    sourceSegmentLength = fromIntegral (unFileSize (vcdiffSourceLength window)) :: Int
    hasSource = testBit (vcdiffWindowIndicator window) 0
    instructionBytes    = vcdiffInstructions window
    addRunBytes     = vcdiffAddRunData window
    addressBytes    = vcdiffAddresses window

    decodeBody :: forall s. ST s [VCDIFFDecodedInstruction]
    decodeBody = do
      instructionPositionReference   <- newSTRef (0 :: Int)
      addRunPositionReference <- newSTRef (0 :: Int)
      addressPositionReference   <- newSTRef (0 :: Int)
      windowOffsetReference <- newSTRef (0 :: Int)
      resultReference    <- newSTRef ([] :: [VCDIFFDecodedInstruction])

      nearArray     <- newArray (0, max 0 nearSize - 1) 0 :: ST s (STArray s Int Int64)
      sameArray     <- newArray (0, max 0 (sameSize * 256) - 1) 0 :: ST s (STArray s Int Int64)
      nearNextReference <- newSTRef (0 :: Int)

      let emit instruction = modifySTRef' resultReference (instruction :)

          updateCacheST :: Int64 -> ST s ()
          updateCacheST address = do
            when (nearSize > 0) $ do
              index <- readSTRef nearNextReference
              writeArray nearArray index address
              writeSTRef nearNextReference ((index + 1) `mod` nearSize)
            when (sameSize > 0) $ do
              let sameIndex = fromIntegral address `mod` (sameSize * 256)
              writeArray sameArray sameIndex address

          decodeAddressessST :: Int -> Int64 -> ST s Int64
          decodeAddressessST mode here
            | mode == 0 = do
                position <- readSTRef addressPositionReference
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let (value, consumed) = getVcdiffVarint position addressBytes
                  writeSTRef addressPositionReference (position + consumed)
                  updateCacheST value
                  pure value
            | mode == 1 = do
                position <- readSTRef addressPositionReference
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let (value, consumed) = getVcdiffVarint position addressBytes
                  writeSTRef addressPositionReference (position + consumed)
                  let address = here - value
                  updateCacheST address
                  pure address
            | mode < nearSize + 2 = do
                position <- readSTRef addressPositionReference
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let (value, consumed) = getVcdiffVarint position addressBytes
                  writeSTRef addressPositionReference (position + consumed)
                  base <- readArray nearArray (mode - 2)
                  let address = base + value
                  updateCacheST address
                  pure address
            | otherwise = do
                position <- readSTRef addressPositionReference
                if position >= ByteString.length addressBytes then pure 0
                else do
                  let byte = fromIntegral (ByteString.index addressBytes position) :: Int
                  writeSTRef addressPositionReference (position + 1)
                  let sameIndex = (mode - nearSize - 2) * 256 + byte
                  if sameIndex >= 0 && sameIndex < sameSize * 256
                    then do
                      address <- readArray sameArray sameIndex
                      updateCacheST address
                      pure address
                    else pure 0

          readNextInstruction :: ST s (Maybe Word8)
          readNextInstruction = do
            position <- readSTRef instructionPositionReference
            if position >= ByteString.length instructionBytes
              then pure Nothing
              else do
                writeSTRef instructionPositionReference (position + 1)
                pure (Just (ByteString.index instructionBytes position))

          readInstructionVarint :: ST s Int64
          readInstructionVarint = do
            position <- readSTRef instructionPositionReference
            if position >= ByteString.length instructionBytes then pure 0
            else do
              let (value, consumed) = getVcdiffVarint position instructionBytes
              writeSTRef instructionPositionReference (position + consumed)
              pure value

          executeInstruction :: VCDIFFInstruction -> ST s ()
          executeInstruction VcdiffNoop = pure ()
          executeInstruction (VcdiffAdd rawSize) = do
            size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
            windowOffset <- readSTRef windowOffsetReference
            addRunPosition <- readSTRef addRunPositionReference
            let count = min size (targetLength - windowOffset)
                safeCount = if addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes
                            then min count (ByteString.length addRunBytes - addRunPosition)
                            else 0
            when (count > 0) $
              emit (DecodedAdd (fromIntegral windowOffset) (ByteString.take safeCount (ByteString.drop addRunPosition addRunBytes)))
            writeSTRef addRunPositionReference (addRunPosition + count)
            writeSTRef windowOffsetReference (windowOffset + count)

          executeInstruction (VcdiffRun rawSize) = do
            size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
            windowOffset <- readSTRef windowOffsetReference
            addRunPosition <- readSTRef addRunPositionReference
            let count = min size (targetLength - windowOffset)
            when (addRunPosition >= 0 && addRunPosition < ByteString.length addRunBytes && count > 0) $
              emit (DecodedRun (fromIntegral windowOffset) (ByteString.index addRunBytes addRunPosition) count)
            writeSTRef addRunPositionReference (addRunPosition + 1)
            writeSTRef windowOffsetReference (windowOffset + count)

          executeInstruction (VcdiffCopy rawSize mode) = do
            size <- if rawSize == 0 then fromIntegral <$> readInstructionVarint else pure rawSize
            windowOffset <- readSTRef windowOffsetReference
            let here  = fromIntegral sourceSegmentLength + fromIntegral windowOffset :: Int64
                count = min size (targetLength - windowOffset)
            address <- decodeAddressessST mode here
            when (count > 0) $ do
              let maybeSourceOffset = if address < fromIntegral sourceSegmentLength && hasSource
                            then Just (unOffset (vcdiffSourcePosition window) + address)
                            else Nothing
              emit (DecodedCopy (fromIntegral windowOffset) count maybeSourceOffset)
            writeSTRef windowOffsetReference (windowOffset + count)

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
      windowOffset <- readSTRef windowOffsetReference
      when (hasSource && windowOffset < targetLength) $
        emit (DecodedCopy (fromIntegral windowOffset) (targetLength - windowOffset)
                     (Just (unOffset (vcdiffSourcePosition window) + fromIntegral windowOffset)))

      reverse <$> readSTRef resultReference
