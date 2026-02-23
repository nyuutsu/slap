{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.VCDIFF
  ( VCDIFFHeader(..)
  , VCDIFFWindow(..)
  , VCDIFFPatch(..)
  , VCDDecodedInst(..)
  , parseVCDIFF
  , applyVCDIFF
  , vcdiffMeta
  , vcdiffInfo
  , decodeWindowInstructions
  ) where

-- Canonical reference: RFC 3284

import Patch.Binary (getVcdiffVarint, copyBSRange)
import Patch.Format (renderField)
import Patch.Get (runGet, getByte, getBytes, skip, getPosition, setPosition,
                  atEnd, vcdiffVarint, word32BE, failGet)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
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
  { vcdHeader    :: VCDIFFHeader
  , vcdWindows   :: [VCDIFFWindow]
  , vcdCodeTable :: Array Word8 CodeEntry  -- default or custom
  , vcdNearSize  :: Int                    -- 4 by default
  , vcdSameSize  :: Int                    -- 3 by default
  } deriving (Show)

-- | Decoded instruction for the explain path — mirrors execute logic but
--   accumulates instructions instead of writing bytes.
data VCDDecodedInst
  = DAdd  Int64 ByteString         -- window-local output offset, literal bytes
  | DRun  Int64 Word8 Int          -- window-local output offset, fill byte, count
  | DCopy Int64 Int (Maybe Int64)  -- window-local output offset, size,
                                   --   Just absoluteSrcFileOffset | Nothing (target/self ref)

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
  { acNear     :: !(Array Int (IORef Int64))
  , acSame     :: !(Array Int (IORef Int64))
  , acNearNext :: !(IORef Int)
  , acNearSize :: !Int
  , acSameSize :: !Int
  }

defaultNearSize, defaultSameSize :: Int
defaultNearSize = 4
defaultSameSize = 3

newAddrCache :: Int -> Int -> IO AddrCache
newAddrCache nSz sSz = do
  near <- mapM (\_ -> newIORef 0) [0..nSz-1]
  same <- mapM (\_ -> newIORef 0) [0..sSz*256-1]
  nxt  <- newIORef 0
  pure AddrCache
    { acNear     = listArray (0, max 0 nSz - 1) near
    , acSame     = listArray (0, max 0 (sSz * 256) - 1) same
    , acNearNext = nxt
    , acNearSize = nSz
    , acSameSize = sSz
    }

updateCache :: AddrCache -> Int64 -> IO ()
updateCache ac addr = do
  when (acNearSize ac > 0) $ do
    idx <- readIORef (acNearNext ac)
    writeIORef (acNear ac ! idx) addr
    writeIORef (acNearNext ac) ((idx + 1) `mod` acNearSize ac)
  when (acSameSize ac > 0) $ do
    let sameIdx = fromIntegral addr `mod` (acSameSize ac * 256)
    writeIORef (acSame ac ! sameIdx) addr

-- | Decode an address given the mode, current "here" position,
--   and a function to read from the address stream.
decodeAddr :: AddrCache -> Int -> Int64 -> IORef Int -> ByteString -> IO Int64
decodeAddr ac mode here addrPosRef addrBs
  | mode == 0 = do
      -- Self mode
      pos <- readIORef addrPosRef
      if pos >= BS.length addrBs then pure 0
      else do
        let (v, n) = getVcdiffVarint pos addrBs
        writeIORef addrPosRef (pos + n)
        updateCache ac v
        pure v
  | mode == 1 = do
      -- Here mode
      pos <- readIORef addrPosRef
      if pos >= BS.length addrBs then pure 0
      else do
        let (v, n) = getVcdiffVarint pos addrBs
        writeIORef addrPosRef (pos + n)
        let addr = here - v
        updateCache ac addr
        pure addr
  | mode < acNearSize ac + 2 = do
      -- Near mode
      pos <- readIORef addrPosRef
      if pos >= BS.length addrBs then pure 0
      else do
        let (v, n) = getVcdiffVarint pos addrBs
        writeIORef addrPosRef (pos + n)
        base <- readIORef (acNear ac ! (mode - 2))
        let addr = base + v
        updateCache ac addr
        pure addr
  | otherwise = do
      -- Same mode
      pos <- readIORef addrPosRef
      if pos >= BS.length addrBs then pure 0
      else do
        let byte = fromIntegral (BS.index addrBs pos) :: Int
        writeIORef addrPosRef (pos + 1)
        let sameIdx = (mode - acNearSize ac - 2) * 256 + byte
        if sameIdx >= 0 && sameIdx < acSameSize ac * 256
          then do
            addr <- readIORef (acSame ac ! sameIdx)
            updateCache ac addr
            pure addr
          else pure 0

----------------------------------------------------------------------------
-- Code table serialization (RFC 3284 §7)
----------------------------------------------------------------------------

-- Instruction type encoding: Noop=0, Add=1, Run=2, Copy=3
instType :: VCDInst -> Word8
instType VcdNoop       = 0
instType (VcdAdd _)    = 1
instType (VcdRun _)    = 2
instType (VcdCopy _ _) = 3

instSize :: VCDInst -> Word8
instSize VcdNoop       = 0
instSize (VcdAdd s)    = fromIntegral s
instSize (VcdRun s)    = fromIntegral s
instSize (VcdCopy s _) = fromIntegral s

instMode :: VCDInst -> Word8
instMode (VcdCopy _ m) = fromIntegral m
instMode _             = 0

-- | Serialize the default code table to 1536 bytes (6 × 256):
--   types1 ++ types2 ++ sizes1 ++ sizes2 ++ modes1 ++ modes2
serializedDefaultTable :: ByteString
serializedDefaultTable = BS.pack $
  map (instType . fst . (defaultCodeTable !)) [0..255]
  ++ map (instType . snd . (defaultCodeTable !)) [0..255]
  ++ map (instSize . fst . (defaultCodeTable !)) [0..255]
  ++ map (instSize . snd . (defaultCodeTable !)) [0..255]
  ++ map (instMode . fst . (defaultCodeTable !)) [0..255]
  ++ map (instMode . snd . (defaultCodeTable !)) [0..255]

deserializeCodeTable :: ByteString -> Either String (Array Word8 CodeEntry)
deserializeCodeTable bs
  | BS.length bs /= 1536 = Left $ "VCDIFF: code table must be 1536 bytes, got " ++ show (BS.length bs)
  | otherwise = do
      entries <- mapM mkEntry [0..255]
      pure $ listArray (0, 255) entries
  where
    mkEntry :: Int -> Either String CodeEntry
    mkEntry i = (,) <$> mkInst (at i) (at (512+i)) (at (1024+i))
                    <*> mkInst (at (256+i)) (at (768+i)) (at (1280+i))
    at = BS.index bs
    mkInst :: Word8 -> Word8 -> Word8 -> Either String VCDInst
    mkInst 0 _ _ = Right VcdNoop
    mkInst 1 s _ = Right (VcdAdd (fromIntegral s))
    mkInst 2 s _ = Right (VcdRun (fromIntegral s))
    mkInst 3 s m = Right (VcdCopy (fromIntegral s) (fromIntegral m))
    mkInst t _ _ = Left ("VCDIFF: invalid instruction type in code table: " ++ show t)

-- | Decode a custom code table from the header's code table data.
--   Format: near_size (1 byte), same_size (1 byte), then a VCDIFF delta
--   (using default table) that transforms serializedDefaultTable into the
--   custom table.
decodeCustomTable :: ByteString -> Either String (Array Word8 CodeEntry, Int, Int)
decodeCustomTable bs = do
  when (BS.length bs < 2) $ Left "VCDIFF: custom code table data too short"
  let near = fromIntegral (BS.index bs 0) :: Int
      same = fromIntegral (BS.index bs 1) :: Int
      deltaBytes = BS.drop 2 bs
  inner <- parseVCDIFF' False deltaBytes
  customSerialized <- applyVCDIFF inner serializedDefaultTable
  tbl <- deserializeCodeTable customSerialized
  pure (tbl, near, same)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseVCDIFF :: ByteString -> Either String VCDIFFPatch
parseVCDIFF = parseVCDIFF' True

parseVCDIFF' :: Bool -> ByteString -> Either String VCDIFFPatch
parseVCDIFF' allowCustom bs
  | BS.length bs < 5 = Left "VCDIFF: input too short"
  | BS.take 3 bs /= "\xd6\xc3\xc4" = Left "not a VCDIFF file (bad magic)"
  | otherwise = do
      (mTableBytes, hdr, wins) <- runGet parseHeader bs
      case mTableBytes of
        Nothing -> Right (VCDIFFPatch hdr wins defaultCodeTable
                                      defaultNearSize defaultSameSize)
        Just tableBytes -> do
          (tbl, near, same) <- decodeCustomTable tableBytes
          Right (VCDIFFPatch hdr wins tbl near same)
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
      mTableBytes <- if hasCodeTable
        then do
          when (not allowCustom) $
            failGet "nested custom code tables are not allowed"
          tableLen <- fromIntegral <$> vcdiffVarint
          Just <$> getBytes tableLen
        else pure Nothing
      -- Skip optional application data (xdelta3 extension)
      when (testBit hdrIndicator 2) $ do
        appLen <- fromIntegral <$> vcdiffVarint
        skip appLen
      let hdr = VCDIFFHeader version compId hasCodeTable
      wins <- parseWindows (version == 0x53)
      pure (mTableBytes, hdr, wins)

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
      when (targetSz < 0) $ failGet "VCDIFF: negative window target size"
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
applyVCDIFF patch source
  | totalSize < 0  = Left "VCDIFF: negative total target size"
  | totalSize == 0 = Right BS.empty
  | otherwise =
      Right $ unsafeCreate (fromIntegral totalSize) $ \outPtr -> do
        globalOutRef <- newIORef (0 :: Int)
        mapM_ (applyWindow ct nSz sSz source outPtr globalOutRef (fromIntegral totalSize)) (vcdWindows patch)
  where
    totalSize = sum (map vcdTargetLen (vcdWindows patch))
    ct = vcdCodeTable patch
    nSz = vcdNearSize patch
    sSz = vcdSameSize patch

applyWindow :: Array Word8 CodeEntry -> Int -> Int
            -> ByteString -> Ptr Word8 -> IORef Int -> Int -> VCDIFFWindow -> IO ()
applyWindow codeTable nSz sSz source outPtr globalOutRef totalTgtLen win = do
  globalOut <- readIORef globalOutRef
  let tgtLen = fromIntegral (vcdTargetLen win) :: Int
      srcSegLen = fromIntegral (vcdSourceLen win) :: Int
      srcSegOff = fromIntegral (vcdSourcePos win) :: Int
      hasSource = testBit (vcdWinIndicator win) 0
      hasTarget = testBit (vcdWinIndicator win) 1

  -- Build the source window: source segment data that COPY addresses reference.
  -- As we build target bytes, they get appended to form the full "source window + target" space.
  -- We read source bytes from the segment, and target bytes from what we've written so far.

  ac <- newAddrCache nSz sSz
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
        if p >= BS.length instBs then pure 0
        else do
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
            -- Clamp to available add/run data
            safeCount = if aPos >= 0 && aPos < BS.length addBs
                        then min count (BS.length addBs - aPos)
                        else 0
        copyBSRange outPtr (globalOut + wOut) addBs aPos safeCount
        writeIORef addRunPosRef (aPos + count)
        writeIORef winOutRef (wOut + count)

      executeInst (VcdRun sz0) = do
        sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
        wOut <- readIORef winOutRef
        aPos <- readIORef addRunPosRef
        let count = min sz (tgtLen - wOut)
        when (aPos >= 0 && aPos < BS.length addBs && count > 0) $ do
          let byte = BS.index addBs aPos
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
            let (inst1, inst2) = codeTable ! code
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
-- Instruction decoding (pure, for explain path)
----------------------------------------------------------------------------

-- | Decode a window's instruction bytecodes into a list of decoded
--   instructions. Mirrors 'applyWindow' but accumulates results in ST
--   instead of writing bytes.
decodeWindowInstructions :: Array Word8 CodeEntry -> Int -> Int
                         -> VCDIFFWindow -> [VCDDecodedInst]
decodeWindowInstructions codeTable nSz sSz win = runST body
  where
    tgtLen    = fromIntegral (vcdTargetLen win) :: Int
    srcSegLen = fromIntegral (vcdSourceLen win) :: Int
    hasSource = testBit (vcdWinIndicator win) 0
    instBs    = vcdInstructions win
    addBs     = vcdAddRunData win
    addrBs    = vcdAddresses win

    body :: forall s. ST s [VCDDecodedInst]
    body = do
      instPosRef   <- newSTRef (0 :: Int)
      addRunPosRef <- newSTRef (0 :: Int)
      addrPosRef   <- newSTRef (0 :: Int)
      winOutRef    <- newSTRef (0 :: Int)
      resultRef    <- newSTRef ([] :: [VCDDecodedInst])

      nearArr     <- newArray (0, max 0 nSz - 1) 0 :: ST s (STArray s Int Int64)
      sameArr     <- newArray (0, max 0 (sSz * 256) - 1) 0 :: ST s (STArray s Int Int64)
      nearNextRef <- newSTRef (0 :: Int)

      let emit inst = modifySTRef' resultRef (inst :)

          updateCacheST :: Int64 -> ST s ()
          updateCacheST addr = do
            when (nSz > 0) $ do
              idx <- readSTRef nearNextRef
              writeArray nearArr idx addr
              writeSTRef nearNextRef ((idx + 1) `mod` nSz)
            when (sSz > 0) $ do
              let sameIdx = fromIntegral addr `mod` (sSz * 256)
              writeArray sameArr sameIdx addr

          decodeAddrST :: Int -> Int64 -> ST s Int64
          decodeAddrST mode here
            | mode == 0 = do
                pos <- readSTRef addrPosRef
                if pos >= BS.length addrBs then pure 0
                else do
                  let (v, n) = getVcdiffVarint pos addrBs
                  writeSTRef addrPosRef (pos + n)
                  updateCacheST v
                  pure v
            | mode == 1 = do
                pos <- readSTRef addrPosRef
                if pos >= BS.length addrBs then pure 0
                else do
                  let (v, n) = getVcdiffVarint pos addrBs
                  writeSTRef addrPosRef (pos + n)
                  let a = here - v
                  updateCacheST a
                  pure a
            | mode < nSz + 2 = do
                pos <- readSTRef addrPosRef
                if pos >= BS.length addrBs then pure 0
                else do
                  let (v, n) = getVcdiffVarint pos addrBs
                  writeSTRef addrPosRef (pos + n)
                  base <- readArray nearArr (mode - 2)
                  let a = base + v
                  updateCacheST a
                  pure a
            | otherwise = do
                pos <- readSTRef addrPosRef
                if pos >= BS.length addrBs then pure 0
                else do
                  let byte = fromIntegral (BS.index addrBs pos) :: Int
                  writeSTRef addrPosRef (pos + 1)
                  let sameIdx = (mode - nSz - 2) * 256 + byte
                  if sameIdx >= 0 && sameIdx < sSz * 256
                    then do
                      a <- readArray sameArr sameIdx
                      updateCacheST a
                      pure a
                    else pure 0

          readNextInst :: ST s (Maybe Word8)
          readNextInst = do
            p <- readSTRef instPosRef
            if p >= BS.length instBs
              then pure Nothing
              else do
                writeSTRef instPosRef (p + 1)
                pure (Just (BS.index instBs p))

          readInstVarint :: ST s Int64
          readInstVarint = do
            p <- readSTRef instPosRef
            if p >= BS.length instBs then pure 0
            else do
              let (v, n) = getVcdiffVarint p instBs
              writeSTRef instPosRef (p + n)
              pure v

          executeInst :: VCDInst -> ST s ()
          executeInst VcdNoop = pure ()
          executeInst (VcdAdd sz0) = do
            sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
            wOut <- readSTRef winOutRef
            aPos <- readSTRef addRunPosRef
            let count = min sz (tgtLen - wOut)
                safeCount = if aPos >= 0 && aPos < BS.length addBs
                            then min count (BS.length addBs - aPos)
                            else 0
            when (count > 0) $
              emit (DAdd (fromIntegral wOut) (BS.take safeCount (BS.drop aPos addBs)))
            writeSTRef addRunPosRef (aPos + count)
            writeSTRef winOutRef (wOut + count)

          executeInst (VcdRun sz0) = do
            sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
            wOut <- readSTRef winOutRef
            aPos <- readSTRef addRunPosRef
            let count = min sz (tgtLen - wOut)
            when (aPos >= 0 && aPos < BS.length addBs && count > 0) $
              emit (DRun (fromIntegral wOut) (BS.index addBs aPos) count)
            writeSTRef addRunPosRef (aPos + 1)
            writeSTRef winOutRef (wOut + count)

          executeInst (VcdCopy sz0 mode) = do
            sz <- if sz0 == 0 then fromIntegral <$> readInstVarint else pure sz0
            wOut <- readSTRef winOutRef
            let here  = fromIntegral srcSegLen + fromIntegral wOut :: Int64
                count = min sz (tgtLen - wOut)
            addr <- decodeAddrST mode here
            when (count > 0) $ do
              let mSrcOff = if addr < fromIntegral srcSegLen && hasSource
                            then Just (vcdSourcePos win + addr)
                            else Nothing
              emit (DCopy (fromIntegral wOut) count mSrcOff)
            writeSTRef winOutRef (wOut + count)

          loop :: ST s ()
          loop = do
            mb <- readNextInst
            case mb of
              Nothing -> pure ()
              Just code -> do
                let (inst1, inst2) = codeTable ! code
                executeInst inst1
                executeInst inst2
                loop

      loop

      -- Implicit trailing copy from source
      wOut <- readSTRef winOutRef
      when (hasSource && wOut < tgtLen) $
        emit (DCopy (fromIntegral wOut) (tgtLen - wOut)
                     (Just (vcdSourcePos win + fromIntegral wOut)))

      reverse <$> readSTRef resultRef

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

vcdiffMeta :: VCDIFFPatch -> [(String, String)]
vcdiffMeta p = concat
  [ [("version", show (vcdVersion (vcdHeader p)))]
  , case vcdCompressorId (vcdHeader p) of
      Nothing -> []
      Just c  -> [("compressor", show c)]
  , if vcdHasCodeTable (vcdHeader p)
    then [("code table", "custom (near=" ++ show (vcdNearSize p)
          ++ ", same=" ++ show (vcdSameSize p) ++ ")")]
    else []
  , [("target size", show (sum (map vcdTargetLen (vcdWindows p))))]
  , if any ((/= Nothing) . vcdAdler32) (vcdWindows p)
    then [("checksums", "Adler32 (xdelta3)")]
    else []
  ]

vcdiffInfo :: VCDIFFPatch -> String
vcdiffInfo p = unlines $ filter (not . null) $
  [ "format:      VCDIFF" ++ if vcdVersion (vcdHeader p) == 0x53
                              then " (xdelta3)" else "" ]
  ++ map renderField (vcdiffMeta p)
  ++ [ "windows:     " ++ show (length (vcdWindows p)) ]
