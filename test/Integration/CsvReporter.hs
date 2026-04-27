-- | A minimal tasty test-reporter ingredient that writes one CSV row
-- per test case. Activated by passing @--csv=PATH@ on the test
-- command line; without that flag the ingredient is silently inert
-- and 'composeReporters' falls through to the console reporter alone.
--
-- Why we ship our own ingredient: the canonical @tasty-stats@ package
-- still pins @tasty < 1.2@ in its Hackage release, which doesn't fit
-- the @tasty 1.5@ already in this project's dependency graph. The
-- needed surface is small enough that vendoring the ~50 lines of CSV
-- formatting is cleaner than dragging in an upper-bound override.
module Integration.CsvReporter
  ( csvReporter
  ) where

import Control.Concurrent.STM (STM, TVar, atomically, readTVar, retry)
import Data.Char (isPrint, isSpace)
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.List (intercalate)
import Data.Proxy (Proxy(..))
import Data.Tagged (Tagged(..))
import System.IO (IOMode(..), hPutStrLn, withFile)
import Test.Tasty.Ingredients (Ingredient(..))
import Test.Tasty.Options (IsOption(..), OptionDescription(..), lookupOption)
import Test.Tasty.Runners
  ( Outcome(..)
  , Result(..)
  , Status(..)
  , resultSuccessful
  , testsNames
  )

----------------------------------------------------------------------------
-- The --csv=PATH option
----------------------------------------------------------------------------

-- | Filesystem path the per-test CSV will be written to.
newtype CsvPath = CsvPath FilePath

instance IsOption (Maybe CsvPath) where
  defaultValue = Nothing
  parseValue   = Just . Just . CsvPath
  optionName   = Tagged "csv"
  optionHelp   = Tagged "Per-test CSV file (one row per test case)"

----------------------------------------------------------------------------
-- The ingredient
----------------------------------------------------------------------------

-- | Tasty ingredient that, when @--csv=PATH@ is supplied, writes one
-- row per test case to that path with columns
-- @index,name,duration_seconds,outcome,short_description@.
--
-- When the flag is absent the runner returns 'Nothing' and the
-- ingredient gracefully bows out — let 'composeReporters' chain it
-- with the console reporter so both run when the flag IS set.
csvReporter :: Ingredient
csvReporter =
  TestReporter [Option (Proxy :: Proxy (Maybe CsvPath))] $ \opts tree -> do
    CsvPath outputPath <- lookupOption opts
    let testNamesByIndex = IntMap.fromList (zip [0 ..] (testsNames opts tree))
    pure $ \statusMap -> do
      results <- atomically (traverse waitFinished statusMap)
      writeCsv outputPath testNamesByIndex results
      pure (\_elapsedTotal -> pure (all resultSuccessful (IntMap.elems results)))

-- | Block until a test reaches 'Done' and return its 'Result'.
waitFinished :: TVar Status -> STM Result
waitFinished statusVar = do
  current <- readTVar statusVar
  case current of
    Done finishedResult -> pure finishedResult
    _                   -> retry

----------------------------------------------------------------------------
-- CSV emission
----------------------------------------------------------------------------

-- | Write the per-test CSV to @path@. Format: a header row, then one
-- row per test case in tasty's natural index order. Quoting follows
-- RFC 4180-ish rules: any field containing a comma, quote, or
-- whitespace is wrapped in double quotes with embedded quotes
-- doubled.
writeCsv :: FilePath -> IntMap String -> IntMap Result -> IO ()
writeCsv outputPath testNamesByIndex resultsByIndex =
  withFile outputPath WriteMode $ \handle -> do
    hPutStrLn handle (renderRow csvHeader)
    mapM_ (hPutStrLn handle . renderRow)
          (resultRows testNamesByIndex resultsByIndex)

csvHeader :: [String]
csvHeader = ["index", "name", "duration_seconds", "outcome", "short_description"]

resultRows :: IntMap String -> IntMap Result -> [[String]]
resultRows testNamesByIndex resultsByIndex =
  [ [ show idx
    , IntMap.findWithDefault "<unknown-test>" idx testNamesByIndex
    , show (resultTime result)
    , outcomeLabel (resultOutcome result)
    , resultShortDescription result
    ]
  | (idx, result) <- IntMap.toAscList resultsByIndex
  ]

-- | "pass" / "fail" in a stable, machine-greppable form. We collapse
-- 'FailureReason' into a single label here; the human-readable detail
-- already lives in 'resultShortDescription'.
outcomeLabel :: Outcome -> String
outcomeLabel Success     = "pass"
outcomeLabel (Failure _) = "fail"

renderRow :: [String] -> String
renderRow fields = intercalate "," (map renderField fields)

-- | Quote a CSV field if it contains a comma, double quote, or any
-- whitespace / non-printable character; otherwise pass through.
-- Embedded quotes are escaped by doubling.
renderField :: String -> String
renderField input
  | needsQuoting input = '"' : escape input ++ "\""
  | otherwise          = input
  where
    needsQuoting characters = any unsafeForBareField characters
    unsafeForBareField character =
         character == ','
      || character == '"'
      || isSpace character
      || not (isPrint character)
    escape []           = []
    escape ('"':rest)   = '"' : '"' : escape rest
    escape (other:rest) = other  : escape rest
