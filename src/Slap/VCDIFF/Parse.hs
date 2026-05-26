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
import Slap.Status (SlapError(..), ByteParserError, Parsed(..),
                    VCDIFFShapeViolation(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (runByteParser, getByte, getBytes, skip, getPosition, setPosition,
                         atEnd, vcdiffVarint, word32BE)
import Slap.Measure (Position(..), Length(..), FileSize(..), Offset(Offset), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)

import Data.Bits (testBit)
import Data.Int (Int64)
import qualified Data.ByteString as ByteString
import Data.Maybe (isJust)
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
      (maybeTableBytes, header, rawWindows) <-
        wrapParse (runByteParser (parseHeader validatedVersion) input)
      when (not allowCustom && isJust maybeTableBytes) $
        Left (UnsupportedVCDIFFShape VCDIFFNestedCustomCodeTable)
      windows <- traverse (validateWindowShape validatedVersion) rawWindows
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
    -- The byte-parser produces a raw window paired with the
    -- pre-conversion 'Int64' target-size varint, so the
    -- non-negativity rule can be enforced after the byte-level
    -- walk against the value as it appeared on the wire.
    parseHeader validatedVersion = do
      skip (Length 4)  -- magic + version byte (already validated)
      headerIndicator <- getByte
      let hasCompressor = testBit headerIndicator 0
          hasCodeTable  = testBit headerIndicator 1
      compressorIdentifier <- if hasCompressor
        then Just <$> getByte
        else pure Nothing
      maybeTableBytes <- if hasCodeTable
        then do
          tableLength <- fromIntegral <$> vcdiffVarint
          Just <$> getBytes (Length tableLength)
        else pure Nothing
      -- Skip optional application data (VCD_APPHEADER, RFC 3284 §4.1)
      when (testBit headerIndicator 2) $ do
        applicationLength <- fromIntegral <$> vcdiffVarint
        skip (Length applicationLength)
      let header = VCDIFFHeader validatedVersion compressorIdentifier hasCodeTable
      rawWindows <- parseWindows
      pure (maybeTableBytes, header, rawWindows)

    parseWindows = do
      finished <- atEnd
      if finished then pure []
      else do
        rawWindow <- parseOneWindow
        rest      <- parseWindows
        pure (rawWindow : rest)

    parseOneWindow = do
      windowIndicator <- getByte
      let windowSource = toVCDIFFWindowSource windowIndicator
          hasSource = windowSource /= WindowNoSource
      (sourceLength, sourcePosition) <- if hasSource
        then (\rawLength rawPosition -> (FileSize (fromIntegral rawLength), offsetFromParsed rawPosition)) <$> vcdiffVarint <*> vcdiffVarint
        else pure (FileSize 0, Offset 0)
      -- Delta encoding length
      deltaLength <- vcdiffVarint
      deltaStart <- getPosition
      let deltaEnd = Position (unPosition deltaStart + fromIntegral deltaLength)
      -- Inside the delta body:
      rawTargetSize <- vcdiffVarint
      let targetSize = FileSize (fromIntegral rawTargetSize)
      deltaIndicator <- getByte
      let secondaryCompression = toVCDIFFSecondaryCompression deltaIndicator
      addRunLength <- vcdiffVarint
      instructionLength   <- vcdiffVarint
      addressLength   <- vcdiffVarint
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
      let window = VCDIFFWindow
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
      pure (window, rawTargetSize)

    -- Post-parse structural validation of a window: target-size
    -- non-negativity and the secondary-compression rule against
    -- whichever VCDIFF version the header declared.
    validateWindowShape :: VCDIFFVersion
                        -> (VCDIFFWindow, Int64)
                        -> Either SlapError VCDIFFWindow
    validateWindowShape validatedVersion (window, rawTargetSize) = do
      when (rawTargetSize < 0) $
        Left (UnsupportedVCDIFFShape (VCDIFFNegativeWindowTargetSize rawTargetSize))
      let comp      = vcdiffSecondaryCompression window
          isXdelta3 = validatedVersion == VCDIFFXDelta3
      when (compressAddRunData comp
            || compressInstructions comp
            || (not isXdelta3 && compressAddresses comp)) $
        Left (UnsupportedVCDIFFShape VCDIFFSecondaryCompressionUnsupportedInDataSections)
      pure window

    wrapParse :: Either ByteParserError a -> Either SlapError a
    wrapParse (Left parserError) = Left (ParseError LabelVCDIFF parserError)
    wrapParse (Right result) = Right result
