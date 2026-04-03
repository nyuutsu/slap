{-# LANGUAGE OverloadedStrings #-}

module Slap.VCDIFF.Parse
  ( parseVCDIFF
  , parseVCDIFFWith
  ) where

import Slap.VCDIFF.Types
    ( VCDIFFPatch(..), VCDIFFHeader(..), VCDIFFWindow(..)
    , defaultCodeTable, defaultNearSize, defaultSameSize
    , serializedDefaultTable, decodeCustomTable
    )
import Slap.VCDIFF.Apply (applyVCDIFF)
import Slap.Checksum (Adler32(..))
import Slap.Error (SlapError(..), renderSlapError)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (runGet, getByte, getBytes, skip, getPosition, setPosition,
                  atEnd, vcdiffVarint, word32BE, failGet)
import Slap.Measure (Position(..), Length(..), FileSize(..), Offset(..))

import Data.Bits (testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Control.Monad (when)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseVCDIFF :: ByteString -> Either SlapError VCDIFFPatch
parseVCDIFF = parseVCDIFFWith True

parseVCDIFFWith :: Bool -> ByteString -> Either SlapError VCDIFFPatch
parseVCDIFFWith allowCustom input
  | ByteString.length input < 5 = Left (InputTooShort LabelVCDIFF (Length 5) (Length (ByteString.length input)))
  | ByteString.take 3 input /= "\xd6\xc3\xc4" = Left (BadMagic LabelVCDIFF (ByteString.take 3 input))
  | otherwise = do
      (maybeTableBytes, header, windows) <- wrapParse (runGet parseHeader input)
      case maybeTableBytes of
        Nothing -> Right (VCDIFFPatch header windows defaultCodeTable
                                      defaultNearSize defaultSameSize)
        Just rawTableBytes -> do
          let applyInnerDelta deltaBytes = do
                inner <- renderError (parseVCDIFFWith False deltaBytes)
                renderError (applyVCDIFF inner serializedDefaultTable)
          (table, nearSize, sameSize) <- wrapParse (decodeCustomTable applyInnerDelta rawTableBytes)
          Right (VCDIFFPatch header windows table nearSize sameSize)
  where
    parseHeader = do
      skip (Length 3)  -- magic
      version <- getByte
      when (version /= 0 && version /= 0x53) $  -- 0x53 = 'S', xdelta3 version indicator
        failGet ("unsupported VCDIFF version: " ++ show version)
      headerIndicator <- getByte
      let hasCompressor = testBit headerIndicator 0
          hasCodeTable  = testBit headerIndicator 1
      compressorIdentifier <- if hasCompressor
        then Just <$> getByte
        else pure Nothing
      maybeTableBytes <- if hasCodeTable
        then do
          when (not allowCustom) $
            failGet "nested custom code tables are not allowed"
          tableLength <- fromIntegral <$> vcdiffVarint
          Just <$> getBytes (Length tableLength)
        else pure Nothing
      -- Skip optional application data (VCD_APPHEADER, RFC 3284 §4.1)
      when (testBit headerIndicator 2) $ do
        applicationLength <- fromIntegral <$> vcdiffVarint
        skip (Length applicationLength)
      let header = VCDIFFHeader version compressorIdentifier hasCodeTable
      windows <- parseWindows (version == 0x53)
      pure (maybeTableBytes, header, windows)

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
        then (\rawLength rawPosition -> (FileSize rawLength, Offset rawPosition)) <$> vcdiffVarint <*> vcdiffVarint
        else pure (FileSize 0, Offset 0)
      -- Delta encoding length
      deltaLength <- vcdiffVarint
      deltaStart <- getPosition
      let deltaEnd = Position (unPosition deltaStart + fromIntegral deltaLength)
      -- Inside the delta body:
      rawTargetSize <- vcdiffVarint
      when (rawTargetSize < 0) $ failGet "VCDIFF: negative window target size"
      let targetSize = FileSize rawTargetSize
      deltaIndicator  <- getByte
      addRunLength <- vcdiffVarint
      instructionLength   <- vcdiffVarint
      addressLength   <- vcdiffVarint
      -- Check for secondary compression
      when (testBit deltaIndicator 0 || testBit deltaIndicator 1
            || (not isXdelta3 && testBit deltaIndicator 2)) $
        failGet "secondary compression in VCDIFF data sections is not supported"
      -- Compute data section start from deltaEnd, not from current position.
      -- xdelta3 writes 4 bytes of Adler32 after the length fields (even in
      -- version 0 mode, sometimes without setting any flag), so working
      -- backwards from the known end avoids guessing what's between lengths
      -- and data.
      afterLengths <- getPosition
      let dataStart = Position (unPosition deltaEnd
                      - fromIntegral addRunLength
                      - fromIntegral instructionLength
                      - fromIntegral addressLength)
      adlerChecksum <- if unPosition dataStart == unPosition afterLengths + 4
        then Just . Adler32 <$> word32BE
        else pure Nothing
      -- Jump to data start and slice the three data streams
      setPosition dataStart
      addRunData <- getBytes (Length (fromIntegral addRunLength))
      instructionData   <- getBytes (Length (fromIntegral instructionLength))
      addressData   <- getBytes (Length (fromIntegral addressLength))
      setPosition deltaEnd
      pure VCDIFFWindow
        { vcdiffWindowIndicator = windowIndicator
        , vcdiffSourceLength    = sourceLength
        , vcdiffSourcePosition    = sourcePosition
        , vcdiffTargetLength    = targetSize
        , vcdiffDeltaIndicator     = deltaIndicator
        , vcdiffAdler32      = adlerChecksum
        , vcdiffAddRunData   = addRunData
        , vcdiffInstructions = instructionData
        , vcdiffAddresses    = addressData
        }

    wrapParse :: Either String a -> Either SlapError a
    wrapParse (Left msg)     = Left (ParseError LabelVCDIFF msg)
    wrapParse (Right result) = Right result

    renderError :: Either SlapError a -> Either String a
    renderError (Left err)    = Left (renderSlapError err)
    renderError (Right value) = Right value
