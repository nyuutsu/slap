module Slap.TextEncoding
  ( -- * Encoding (String → ByteString)
    encodeUtf8Field
  , encodeLocaleField
    -- * Decoding (ByteString → String)
  , decodeUtf8Field
  , decodeLocaleField
    -- * Truncation
  , truncateUtf8
  , truncateLocale
    -- * Bounded encode (encode + truncate + null-pad)
  , TruncationInfo(..)
  , BoundedResult(..)
  , encodeBoundedUtf8
  , encodeBoundedLocale
    -- * Validity
  , isValidUtf8
    -- * Process-wide setup
  , makeStdoutAndStderrLenient
  ) where

import Slap.Measure (Length(..), byteLength)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified GHC.Foreign as GHC
import System.IO (TextEncoding, hSetEncoding, localeEncoding,
                  mkTextEncoding, stderr, stdout)
import System.IO.Unsafe (unsafePerformIO)

-- | How a field was truncated: original encoded size vs. what fit.
data TruncationInfo = TruncationInfo
  { truncatedFrom :: !Length   -- original encoded byte count
  , truncatedTo   :: !Length   -- byte count after truncation
  } deriving (Show)

-- | Result of bounded encoding: the padded field plus optional
-- truncation information.
data BoundedResult = BoundedResult
  { boundedField      :: !ByteString          -- exactly fieldWidth bytes
  , boundedTruncation :: !(Maybe TruncationInfo)
  } deriving (Show)

-- | Encode a String as UTF-8 bytes.
encodeUtf8Field :: String -> ByteString
encodeUtf8Field = Text.encodeUtf8 . Text.pack

-- | Encode a String as bytes using the process's locale encoding.
-- On modern systems this is almost always UTF-8. On a system
-- configured for Shift-JIS, this produces Shift-JIS bytes.
-- This is what the C reference implementations did: memcpy from
-- argv, which was locale-encoded by the OS.
encodeLocaleField :: String -> ByteString
encodeLocaleField inputText = unsafePerformIO $
  GHC.withCStringLen localeEncoding inputText ByteString.packCStringLen

-- | Decode UTF-8 bytes to String. Lenient: invalid bytes become U+FFFD.
decodeUtf8Field :: ByteString -> String
decodeUtf8Field = Text.unpack . Text.decodeUtf8Lenient

-- | Decode bytes to String using the process's locale encoding,
-- leniently. Invalid byte sequences (e.g. EUC-JP bytes seen by a
-- UTF-8 reader) become 'U+FFFD' replacement characters rather than
-- throwing an exception. The strict alternative — 'GHC.peekCStringLen
-- localeEncoding' — is what NINJA2 mode-0 fields used to go through;
-- it crashed @slap info@ outright when a foreign-locale patch met a
-- mismatched reader. The @\/\/TRANSLIT@ suffix routes through the
-- iconv variant that accepts any input and emits @\\65533@ on
-- unrepresentable bytes, which is what every modern Unicode tool
-- does.
decodeLocaleField :: ByteString -> String
decodeLocaleField bytes = unsafePerformIO $ do
  ByteString.useAsCStringLen bytes (GHC.peekCStringLen lenientLocaleEncoding)

-- | The process's locale encoding with iconv's @\/\/TRANSLIT@ suffix
-- applied: invalid input bytes decode to 'U+FFFD' and unrepresentable
-- output characters encode to a substitution placeholder rather than
-- throwing.  Re-used by 'decodeLocaleField' (input side) and by
-- 'makeStdoutAndStderrLenient' (output side) so the input and output
-- ends of slap's terminal interaction are governed by the same
-- forgiving codec.
lenientLocaleEncoding :: TextEncoding
lenientLocaleEncoding = unsafePerformIO $
  mkTextEncoding (show localeEncoding ++ "//TRANSLIT")
{-# NOINLINE lenientLocaleEncoding #-}

-- | Re-bind 'stdout' and 'stderr' to the lenient locale encoding so
-- that printing a 'Char' GHC's strict locale codec couldn't represent
-- — most often a 'U+FFFD' that 'decodeLocaleField' inserted while
-- reading a foreign-locale NINJA2 mode-0 metadata field — substitutes
-- a placeholder byte instead of crashing the program with
-- @hPutChar: invalid argument (Invalid or incomplete multibyte or
-- wide character)@.
--
-- Called once at slap startup, before any I/O.
makeStdoutAndStderrLenient :: IO ()
makeStdoutAndStderrLenient = do
  hSetEncoding stdout lenientLocaleEncoding
  hSetEncoding stderr lenientLocaleEncoding

-- | Truncate a UTF-8 ByteString to fit within maxBytes,
-- cutting at the last complete codepoint boundary.
truncateUtf8 :: Int -> ByteString -> ByteString
truncateUtf8 maxBytes value
  | maxBytes <= 0 = ByteString.empty
  | ByteString.length value <= maxBytes = value
  | otherwise =
      let candidate = ByteString.take maxBytes value
          candidateLength = ByteString.length candidate
          startIndex = findCodepointStart candidate (candidateLength - 1)
          startByte = ByteString.index candidate startIndex
      in if isUTF8Continuation startByte
         then ByteString.take startIndex candidate
         else let expectedLength = utf8CharLength startByte
                  availableLength = candidateLength - startIndex
              in if availableLength >= expectedLength
                 then candidate
                 else ByteString.take startIndex candidate
  where
    findCodepointStart bytes index
      | index <= 0 = 0
      | isUTF8Continuation (ByteString.index bytes index) =
          findCodepointStart bytes (index - 1)
      | otherwise = index
    isUTF8Continuation byte = byte >= 0x80 && byte <= 0xBF
    utf8CharLength byte
      | byte < 0x80 = 1
      | byte < 0xE0 = 2
      | byte < 0xF0 = 3
      | otherwise   = 4

-- | Truncate locale-encoded bytes at a byte boundary.
-- Locale encodings can be variable-width (Shift-JIS, UTF-8)
-- and we can't determine codepoint boundaries without knowing
-- which encoding the locale uses. Byte-level truncation is
-- what the C reference implementations did.
truncateLocale :: Int -> ByteString -> ByteString
truncateLocale = ByteString.take

-- | Encode a String as UTF-8, truncate at codepoint boundary,
-- null-pad to exactly fieldWidth bytes.
encodeBoundedUtf8 :: Int -> String -> BoundedResult
encodeBoundedUtf8 fieldWidth inputText =
  let encoded = encodeUtf8Field inputText
      truncated = truncateUtf8 fieldWidth encoded
      padded = truncated <> ByteString.replicate
                 (max 0 (fieldWidth - ByteString.length truncated)) 0
      truncation = if ByteString.length encoded > fieldWidth
                   then Just TruncationInfo
                              { truncatedFrom = byteLength encoded
                              , truncatedTo   = byteLength truncated }
                   else Nothing
  in BoundedResult padded truncation

-- | Encode a String using the locale, truncate at byte boundary,
-- null-pad to exactly fieldWidth bytes.
encodeBoundedLocale :: Int -> String -> BoundedResult
encodeBoundedLocale fieldWidth inputText =
  let encoded = encodeLocaleField inputText
      truncated = truncateLocale fieldWidth encoded
      padded = truncated <> ByteString.replicate
                 (max 0 (fieldWidth - ByteString.length truncated)) 0
      truncation = if ByteString.length encoded > fieldWidth
                   then Just TruncationInfo
                              { truncatedFrom = byteLength encoded
                              , truncatedTo   = byteLength truncated }
                   else Nothing
  in BoundedResult padded truncation

-- | Check whether a ByteString is valid UTF-8.
-- Used during conversion from opaque-bytes formats to
-- encoding-flagged formats (e.g. PPF → NINJA2): if the bytes
-- pass UTF-8 validation, we can set PATCH_ENC=1 confidently.
isValidUtf8 :: ByteString -> Bool
isValidUtf8 bytes = case Text.decodeUtf8' bytes of
  Right _ -> True
  Left _  -> False
