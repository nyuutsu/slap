-- | Predicates that mark a fixture as expensive enough that the test
-- exercising it should start as soon as a core is free, instead of
-- waiting at the back of tasty's parallel queue. The integration
-- runner reads these predicates from each test-builder during plan
-- construction and routes the resulting trees into a separate heavy
-- bucket.
--
-- The bucket exists because the suite's wall-clock floor is set by
-- a small handful of slow tests; if those land late in the schedule,
-- cores idle while they finish. Pulling them to the front of the
-- queue lets the cheap tests fill in around them and trims wall
-- clock from ~60 s to ~33.5 s on this machine.
--
-- Today the only criterion is 'bpsCreateIsExpensive', which is true
-- for the stadium2-class fixtures. The module exists so future heavy
-- classes can be added without touching every test-builder.
module Integration.HeavyTests
  ( FixtureName(..)
  , bpsCreateIsExpensive
  ) where

import Data.List (isInfixOf)

-- | Short name identifying a fixture or fixture pair the integration
-- tests touch. Each call site builds one from whatever it has handy:
-- the @scenario@ field of a spec row (e.g. @\"stadium2-fair\"@), a
-- relative path under @test/data/@, or the source ROM path of a
-- hand-written test case. The wrapper exists so call sites can name
-- their argument clearly rather than passing a bare 'String'.
newtype FixtureName = FixtureName String
  deriving (Eq, Show)

-- | True when creating a BPS patch from the named fixture is slow
-- enough that scheduling it early in tasty's parallel queue
-- meaningfully reduces suite wall-clock. Currently the
-- stadium2-class fixtures (@stadium2-fair@, @stadium2-size@): both
-- build their patch from the ~64 MB stadium2 base ROM and a
-- comparably-sized target, and the suffix-array construction over
-- their concatenation is the long pole of the suite at ~11 s
-- single-thread each.
--
-- The match is by substring against any of 'heavyRomNames', so an
-- argument carrying the ROM name in any common form — scenario,
-- relative path, source-ROM path — will be classified consistently.
bpsCreateIsExpensive :: FixtureName -> Bool
bpsCreateIsExpensive (FixtureName text) =
  any (`isInfixOf` text) heavyRomNames

-- | ROM short names that mark their fixtures as BPS-create-heavy.
-- A 'FixtureName' counts as expensive whenever any of these appears
-- as a substring of its wrapped text.
heavyRomNames :: [String]
heavyRomNames = ["stadium2"]
