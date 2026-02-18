{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.VCDIFF
  ( VCDIFFHeader(..)
  , VCDIFFWindow(..)
  , VCDIFFPatch(..)
  , parseVCDIFF
  , applyVCDIFF
  , vcdiffInfo
  ) where

import Patch.Binary (getVcdiffVarint, copyBSRange)
import Patch.Get (runGet, getByte, getBytes, skip, getPosition, setPosition,
                  atEnd, vcdiffVarint, word32BE, failGet)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Internal (unsafeCreate)
import Data.Array (Array, listArray, (!))
import Data.Bits (testBit)
import Control.Monad (when)
import Data.IORef
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data VCDInst = VcdNoop | VcdAdd Int | VcdRun Int | VcdCopy Int Int
  deriving (Show)
  -- VcdCopy length mode  (mode indexes into near/same cache decode)

data VCDIFFHeader = VCDIFFHeader
  { vcdVersion      :: Word8
  , vcdCompressorId :: Maybe Word8
  , vcdHasCodeTable :: Bool
  } deriving (Show)

data VCDIFFWindow = VCDIFFWindow
  { vcdWinIndicator :: Word8
  , vcdSourceLen    :: Int64
  , vcdSourcePos    :: Int64
  , vcdTargetLen    :: Int64
  , vcdDeltaInd     :: Word8
  , vcdAdler32      :: Maybe Word32
  , vcdAddRunData   :: ByteString   -- literal data stream
  , vcdInstructions :: ByteString   -- instruction stream (code + sizes)
  , vcdAddresses    :: ByteString   -- address stream
  } deriving (Show)

data VCDIFFPatch = VCDIFFPatch
  { vcdHeader  :: VCDIFFHeader
  , vcdWindows :: [VCDIFFWindow]
  } deriving (Show)

----------------------------------------------------------------------------
-- Default code table (RFC 3284 Section 5.6)
----------------------------------------------------------------------------

-- Each entry is a pair of instructions. For size=0 instructions, the
-- actual size follows as a varint in the instruction stream.

type CodeEntry = (VCDInst, VCDInst)

defaultCodeTable :: Array Word8 CodeEntry
defaultCodeTable = listArray (0, 255) $
  -- 0: RUN 0, Noop
  [(VcdRun 0, VcdNoop)]
  -- 1-18: ADD size, Noop  (size 0..17)
  ++ [(VcdAdd s, VcdNoop) | s <- [0..17]]
  -- 19-162: COPY size mode, Noop
  -- 9 modes (0..8), sizes 0..15 for each mode → 144 entries
  -- For each mode 0..8:
  --   size 0: COPY 0 mode, Noop
  --   sizes 4..18: COPY s mode, Noop
  ++ [(VcdCopy s m, VcdNoop) | m <- [0..8], s <- 0 : [4..18]]
  -- 163-234: ADD 1..4, COPY 4..6, modes 0..5  → 72 entries
  ++ [(VcdAdd a, VcdCopy c m) | m <- [0..5], a <- [1..4], c <- [4..6]]
  -- 235-246: ADD 1..4, COPY 4, modes 6..8  → 12 entries
  ++ [(VcdAdd a, VcdCopy 4 m) | a <- [1..4], m <- [6..8]]
  -- 247-255: COPY 4, ADD 1, modes 0..8  → 9 entries
  ++ [(VcdCopy 4 m, VcdAdd 1) | m <- [0..8]]

----------------------------------------------------------------------------
-- Address cache (RFC 3284 Section 5.3)
----------------------------------------------------------------------------

data AddrCache = AddrCache
  { acNear     :: !(Array Int (IORef Int64))  -- 4 near slots
  , acSame     :: !(Array Int (IORef Int64))  -- 256*3 same slots
  , acNearNext :: !(IORef Int)                -- round-robin index
  }

nearSize, sameSize :: Int
nearSize = 4
sameSize = 3

newAddrCache :: IO AddrCache
newAddrCache = do
  near <- mapM (\_ -> newIORef 0) [0..nearSize-1]
  same <- mapM (\_ -> newIORef 0) [0..sameSize*256-1]
  nxt  <- newIORef 0
  pure AddrCache
    { acNear     = listArray (0, nearSize-1) near
    , acSame     = listArray (0, sameSize*256-1) same
    , acNearNext = nxt
    }

updateCache :: AddrCache -> Int64 -> IO ()
updateCache ac addr = do
  idx <- readIORef (acNearNext ac)
  writeIORef (acNear ac ! idx) addr
  writeIORef (acNearNext ac) ((idx + 1) `mod` nearSize)
  let sameIdx = fromIntegral addr `mod` (sameSize * 256)
  writeIORef (acSame ac ! sameIdx) addr

-- | Decode an address given the mode, current "here" position,
--   and a function to read from the address stream.
decodeAddr :: AddrCache -> Int -> Int64 -> IORef Int -> ByteString -> IO Int64
decodeAddr ac mode here addrPosRef addrBs = do
  if mode == 0 then do
    -- Self mode: address is varint from address stream
    pos <- readIORef addrPosRef
    let (v, n) = getVcdiffVarint pos addrBs
    writeIORef addrPosRef (pos + n)
    let addr = v
    updateCache ac addr
    pure addr
  else if mode == 1 then do
    -- Here mode: here - varint
    pos <- readIORef addrPosRef
    let (v, n) = getVcdiffVarint pos addrBs
    writeIORef addrPosRef (pos + n)
    let addr = here - v
    updateCache ac addr
    pure addr
  else if mode < nearSize + 2 then do
    -- Near mode: near[mode-2] + varint
    pos <- readIORef addrPosRef
    let (v, n) = getVcdiffVarint pos addrBs
    writeIORef addrPosRef (pos + n)
    base <- readIORef (acNear ac ! (mode - 2))
    let addr = base + v
    updateCache ac addr
    pure addr
  else do
    -- Same mode: same[(mode - nearSize - 2) * 256 + byte]
    pos <- readIORef addrPosRef
    let byte = fromIntegral (BS.index addrBs pos) :: Int
    writeIORef addrPosRef (pos + 1)
    let sameIdx = (mode - nearSize - 2) * 256 + byte
    addr <- readIORef (acSame ac ! sameIdx)
    updateCache ac addr
    pure addr

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseVCDIFF :: ByteString -> Either String VCDIFFPatch
parseVCDIFF bs
  | BS.length bs < 5 = Left "too short for VCDIFF header"
  | BS.take 3 bs /= "\xd6\xc3\xc4" = Left "not a VCDIFF file (bad magic)"
  | otherwise = runGet parseHeader bs
  where
    parseHeader = do
      skip 3  -- magic
      version <- getByte
      when (version /= 0 && version /= 0x53) $
        failGet ("unsupported VCDIFF version: " ++ show version)
      hdrIndicator <- getByte
      let hasCompressor = testBit hdrIndicator 0
          hasCodeTable  = testBit hdrIndicator 1
      compId <- if hasCompressor
        then Just <$> getByte
        else pure Nothing
      -- Skip optional code table
      when hasCodeTable $ do
        tableLen <- fromIntegral <$> vcdiffVarint
        skip tableLen
      -- Skip optional application data (xdelta3 extension)
      when (testBit hdrIndicator 2) $ do
        appLen <- fromIntegral <$> vcdiffVarint
        skip appLen
      when hasCodeTable $
        failGet "custom code tables are not supported"
      let hdr = VCDIFFHeader version compId hasCodeTable
      wins <- parseWindows (version == 0x53)
      pure (VCDIFFPatch hdr wins)

    parseWindows isXd3 = do
      done <- atEnd
      if done then pure []
      else do
        win <- parseOneWindow isXd3
        rest <- parseWindows isXd3
        pure (win : rest)

    parseOneWindow isXd3 = do
      winInd <- getByte
      let hasSource = testBit winInd 0 || testBit winInd 1
      (srcLen, srcPos_) <- if hasSource
        then (,) <$> vcdiffVarint <*> vcdiffVarint
        else pure (0, 0)
      -- Delta encoding length
      deltaLen <- vcdiffVarint
      deltaStart <- getPosition
      let deltaEnd = deltaStart + fromIntegral deltaLen
      -- Inside the delta body:
      targetSz  <- vcdiffVarint
      deltaInd  <- getByte
      addRunLen <- vcdiffVarint
      instLen   <- vcdiffVarint
      addrLen   <- vcdiffVarint
      -- Check for secondary compression
      when (testBit deltaInd 0 || testBit deltaInd 1
            || (not isXd3 && testBit deltaInd 2)) $
        failGet "secondary compression in VCDIFF data sections is not supported"
      -- Compute where data sections start by working backwards from deltaEnd.
      -- This handles xdelta3 Adler32 checksums robustly: xdelta3 writes 4 bytes
      -- of Adler32 after the length fields (even in version 0 mode, sometimes
      -- without setting any flag), so we compute the data start position from
      -- the known end instead of guessing what's between lengths and data.
      afterLengths <- getPosition
      let dataStart = deltaEnd
                      - fromIntegral addRunLen
                      - fromIntegral instLen
                      - fromIntegral addrLen
      adler <- if dataStart == afterLengths + 4
        then Just <$> word32BE
        else pure Nothing
      -- Jump to data start and slice the three data streams
      setPosition dataStart
      addRunData <- getBytes (fromIntegral addRunLen)
      instData   <- getBytes (fromIntegral instLen)
      addrData   <- getBytes (fromIntegral addrLen)
      setPosition deltaEnd
      pure VCDIFFWindow
        { vcdWinIndicator = winInd
        , vcdSourceLen    = srcLen
        , vcdSourcePos    = srcPos_
        , vcdTargetLen    = targetSz
        , vcdDeltaInd     = deltaInd
        , vcdAdler32      = adler
        , vcdAddRunData   = addRunData
        , vcdInstructions = instData
        , vcdAddresses    = addrData
        }

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyVCDIFF :: VCDIFFPatch -> ByteString -> Either String ByteString
applyVCDIFF patch source =
  let totalSize = sum (map vcdTargetLen (vcdWindows patch))
  in Right $ unsafeCreate (fromIntegral totalSize) $ \outPtr -> do
       globalOutRef <- newIORef (0 :: Int)
       mapM_ (applyWindow source outPtr globalOutRef (fromIntegral totalSize)) (vcdWindows patch)

applyWindow :: ByteString -> Ptr Word8 -> IORef Int -> Int -> VCDIFFWindow -> IO ()
applyWindow source outPtr globalOutRef totalTgtLen win = do
  globalOut <- readIORef globalOutRef
  let tgtLen = fromIntegral (vcdTargetLen win) :: Int
      srcSegLen = fromIntegral (vcdSourceLen win) :: Int
      srcSegOff = fromIntegral (vcdSourcePos win) :: Int
      hasSource = testBit (vcdWinIndicator win) 0
      hasTarget = testBit (vcdWinIndicator win) 1

  -- Build the source window: source segment data that COPY addresses reference.
  -- As we build target bytes, they get appended to form the full "source window + target" space.
  -- We read source bytes from the segment, and target bytes from what we've written so far.

  ac <- newAddrCache
  addRunPosRef <- newIORef (0 :: Int)
  instPosRef   <- newIORef (0 :: Int)
  addrPosRef   <- newIORef (0 :: Int)
  winOutRef    <- newIORef (0 :: Int)  -- offset within this window's target

  let instBs = vcdInstructions win
      addBs  = vcdAddRunData win
      addrBs = vcdAddresses win

      -- Read a byte from the source-segment + target-so-far combined space
      readSourceWindow :: Int -> IO Word8
      readSourceWindow i
        | hasSource && i < srcSegLen =
            if srcSegOff + i < BS.length source
            then pure (BS.index source (srcSegOff + i))
            else pure 0
        | hasTarget && i < srcSegLen =
            -- VCD_TARGET: source is previous target window data
            if srcSegOff + i < totalTgtLen
            then peekByteOff outPtr (srcSegOff + i)
            else pure 0
        | otherwise =
            -- Index into the target data we're building for this window
            let tgtIdx = i - srcSegLen
            in if tgtIdx >= 0 && globalOut + tgtIdx < totalTgtLen
               then peekByteOff outPtr (globalOut + tgtIdx)
               else pure 0

      readNextInst :: IO (Maybe Word8)
      readNextInst = do
        p <- readIORef instPosRef
        if p >= BS.length instBs
          then pure Nothing
          else do
            writeIORef instPosRef (p + 1)
            pure (Just (BS.index instBs p))

      readInstVarint :: IO Int64
      readInstVarint = do
        p <- readIORef instPosRef
        let (v, n) = getVcdiffVarint p instBs
        writeIORef instPosRef (p + n)
        pure v

      executeInst :: VCDInst -> IO ()
      executeInst VcdNoop = pure ()
      executeInst (VcdAdd sz0) = do
        sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
        wOut <- readIORef winOutRef
        aPos <- readIORef addRunPosRef
        let count = min sz (tgtLen - wOut)
        copyBSRange outPtr (globalOut + wOut) addBs aPos count
        writeIORef addRunPosRef (aPos + count)
        writeIORef winOutRef (wOut + count)

      executeInst (VcdRun sz0) = do
        sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
        wOut <- readIORef winOutRef
        aPos <- readIORef addRunPosRef
        let count = min sz (tgtLen - wOut)
            byte  = BS.index addBs aPos
        mapM_ (\i -> pokeByteOff outPtr (globalOut + wOut + i) byte) [0..count-1]
        writeIORef addRunPosRef (aPos + 1)
        writeIORef winOutRef (wOut + count)

      executeInst (VcdCopy sz0 mode) = do
        sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
        wOut <- readIORef winOutRef
        -- "here" = srcSegLen + wOut (position in the combined source-window)
        let here = fromIntegral srcSegLen + fromIntegral wOut :: Int64
        addr <- decodeAddr ac mode here addrPosRef addrBs
        let count = min sz (tgtLen - wOut)
        -- Copy byte-by-byte (target region may overlap)
        mapM_ (\i -> do
          b <- readSourceWindow (fromIntegral addr + i)
          pokeByteOff outPtr (globalOut + wOut + i) b
          ) [0..count-1]
        writeIORef winOutRef (wOut + count)

  -- Process instruction stream
  let loop = do
        mb <- readNextInst
        case mb of
          Nothing -> pure ()
          Just code -> do
            let (inst1, inst2) = defaultCodeTable ! code
            executeInst inst1
            executeInst inst2
            loop
  loop

  -- Fill remaining target bytes from source (implicit copy).
  -- xdelta3 and other VCDIFF decoders fill any remaining target bytes
  -- from the corresponding source positions after instructions are exhausted.
  wOut <- readIORef winOutRef
  if hasSource && wOut < tgtLen
    then mapM_ (\i -> do
      let srcIdx = srcSegOff + wOut + i
      b <- if srcIdx < BS.length source then pure (BS.index source srcIdx) else pure 0
      pokeByteOff outPtr (globalOut + wOut + i) b
      ) [0..tgtLen - wOut - 1]
    else pure ()

  writeIORef globalOutRef (globalOut + tgtLen)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

vcdiffInfo :: VCDIFFPatch -> String
vcdiffInfo p = unlines $ filter (not . null)
  [ "format:      VCDIFF" ++ if vcdVersion (vcdHeader p) == 0x53
                              then " (xdelta3)" else ""
  , "version:     " ++ show (vcdVersion (vcdHeader p))
  , compStr
  , codeTableStr
  , "windows:     " ++ show (length (vcdWindows p))
  , totalTargetStr
  , checksumStr
  ]
  where
    compStr = case vcdCompressorId (vcdHeader p) of
      Nothing -> ""
      Just c  -> "compressor:  " ++ show c
    codeTableStr
      | vcdHasCodeTable (vcdHeader p) = "code table:  custom"
      | otherwise = ""
    totalTargetStr =
      let total = sum (map vcdTargetLen (vcdWindows p))
      in "target size: " ++ show total
    checksumStr
      | any ((/= Nothing) . vcdAdler32) (vcdWindows p) = "checksums:   Adler32 (xdelta3)"
      | otherwise = ""
