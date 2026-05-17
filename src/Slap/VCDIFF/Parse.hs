{-# LANGUAGE OverloadedStrings #-}

module Slap.VCDIFF.Parse
  ( parseVCDIFF
  , parseVCDIFFWith
  ) where

import Slap.VCDIFF.Types
    ( VCDIFFPatch(..), VCDIFFHeader(..), VCDIFFWindow(..)
    , VCDIFFVersion(..), toVCDIFFVersion
    , VCDIFFWindowSource(..)
    , VCDIFFSecondaryCompression(..)
    , toVCDIFFWindowSource, toVCDIFFSecondaryCompression
    , defaultCodeTable
    , serializedDefaultTable, decodeCustomTable
    , vcdiffMagicBytes
    )
import Slap.VCDIFF.Apply (applyVCDIFF, defaultNearSize, defaultSameSize)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Checksum (Adler32(..))
import Slap.Status (SlapError(..), GetErrorMessage(..), Parsed(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (runGet, getByte, getBytes, skip, getPosition, setPosition,
                  atEnd, vcdiffVarint, word32BE, failGet)
import Slap.Measure (Position(..), Length(..), FileSize(..), Offset(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)

import Data.Bits (testBit)
import qualified Data.ByteString as ByteString
import Control.Monad (when)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseVCDIFF :: PatchFileContents -> Either SlapError (Parsed VCDIFFPatch)
parseVCDIFF = parseVCDIFFWith True

parseVCDIFFWith :: Bool -> PatchFileContents -> Either SlapError (Parsed VCDIFFPatch)
parseVCDIFFWith allowCustom (PatchFileContents input)
  | ByteString.length input < 5 = Left (InputTooShort LabelVCDIFF (RequiredLength (Length 5)) (ActualLength (byteLength input)))
  | ByteString.take 3 input /= vcdiffMagicBytes = Left (BadMagic LabelVCDIFF (ActualMagic (ByteString.take 3 input)))
  | otherwise = do
      validatedVersion <- toVCDIFFVersion (ByteString.index input 3)
      (maybeTableBytes, header, windows) <- wrapParse (runGet (parseHeader validatedVersion) input)
      case maybeTableBytes of
        Nothing -> Right (Parsed (VCDIFFPatch header windows defaultCodeTable
                                              defaultNearSize defaultSameSize) [])
        Just rawTableBytes -> do
          let applyInnerDelta deltaBytes = do
                Parsed inner _innerWarnings <-
                  parseVCDIFFWith False (PatchFileContents deltaBytes)
                fmap unOutputFileContents (applyVCDIFF inner (InputFileContents serializedDefaultTable))
          (table, nearSize, sameSize) <- decodeCustomTable applyInnerDelta rawTableBytes
          Right (Parsed (VCDIFFPatch header windows table nearSize sameSize) [])
  where
    parseHeader validatedVersion = do
      skip (Length 4)  -- magic + version byte (already validated)
      let isXdelta3 = validatedVersion == VCDIFFXDelta3
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
      let header = VCDIFFHeader validatedVersion compressorIdentifier hasCodeTable
      windows <- parseWindows isXdelta3
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
      let windowSource = toVCDIFFWindowSource windowIndicator
          hasSource = windowSource /= WindowNoSource
      (sourceLength, sourcePosition) <- if hasSource
        then (\rawLength rawPosition -> (FileSize (fromIntegral rawLength), Offset (fromIntegral rawPosition))) <$> vcdiffVarint <*> vcdiffVarint
        else pure (FileSize 0, Offset 0)
      -- Delta encoding length
      deltaLength <- vcdiffVarint
      deltaStart <- getPosition
      let deltaEnd = Position (unPosition deltaStart + fromIntegral deltaLength)
      -- Inside the delta body:
      rawTargetSize <- vcdiffVarint
      when (rawTargetSize < 0) $ failGet "negative window target size"
      let targetSize = FileSize (fromIntegral rawTargetSize)
      deltaIndicator <- getByte
      let secondaryCompression = toVCDIFFSecondaryCompression deltaIndicator
      addRunLength <- vcdiffVarint
      instructionLength   <- vcdiffVarint
      addressLength   <- vcdiffVarint
      -- Check for secondary compression
      when (compressAddRunData secondaryCompression
            || compressInstructions secondaryCompression
            || (not isXdelta3 && compressAddresses secondaryCompression)) $
        failGet "secondary compression in data sections is not supported"
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
        { vcdiffWindowSource           = windowSource
        , vcdiffSourceLength           = sourceLength
        , vcdiffSourcePosition         = sourcePosition
        , vcdiffTargetLength           = targetSize
        , vcdiffSecondaryCompression   = secondaryCompression
        , vcdiffAdler32                = adlerChecksum
        , vcdiffAddRunData             = addRunData
        , vcdiffInstructions           = instructionData
        , vcdiffAddresses              = addressData
        }

    wrapParse :: Either String a -> Either SlapError a
    wrapParse (Left errorMessage) = Left (ParseError LabelVCDIFF (GetErrorMessage errorMessage))
    wrapParse (Right result) = Right result
