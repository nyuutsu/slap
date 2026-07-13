-- | What slap does with the input before an apply: 'reframeInput' carries out the user's header directive,
-- and the header rescue searches every console header arrangement for one the patch agrees with.
module Slap.Preflight
  ( reframeInput
  , HeaderRescueCandidate(..)
  , headerRescueCandidates
  ) where

import Slap.FileContents (InputFileContents(..))
import Slap.Header (ConsoleHeader, HeaderAdjustment(..), InputHeaderDirective(..),
                    addHeader, removeHeader, consoleHeaderLength)
import Slap.Measure (ActualSize(..), byteFileSize)
import Slap.Normalize (NormalizedSource(..), normalizeApplySource)
import Slap.SomePatch (SomePatch(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), Outcome(..), DeclaredCheckKind)
import Slap.Verify (VerificationVerdict(..), verdictOnWeighing, weighSource)

import Data.ByteString (ByteString)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty

-- | Carry out the user's @--add-header@ / @--remove-header@ instruction on the handed input.
-- The reframe never happens silently: a successful adjustment carries its narrating note.
reframeInput :: InputHeaderDirective -> ByteString -> Outcome (Either SlapError ByteString)
reframeInput TakeInputAsIs handedBytes = Outcome (Right handedBytes) []
reframeInput (AddHeader console) handedBytes =
  Outcome (Right (addHeader console handedBytes)) [InputHeaderAdded console]
reframeInput (RemoveHeader console) handedBytes = case removeHeader console handedBytes of
  Nothing -> Outcome (Left (HeaderRemovalExceedsInput console (ActualSize (byteFileSize handedBytes)))) []
  Just bytesBeneath -> Outcome (Right bytesBeneath) [InputHeaderRemoved console]

-- | A header arrangement that reconciles a differing input with the patch: adjusted this way,
-- the input matches every check the patch declares, and the kinds say what that rests on.
data HeaderRescueCandidate = HeaderRescueCandidate
  { rescueAdjustment :: !HeaderAdjustment
  , rescueConsoles   :: !(NonEmpty ConsoleHeader)
    -- ^ Every console whose header shares this arrangement's byte width — any of them does the job.
    -- 'NonEmpty.groupAllWith' 'consoleHeaderLength' is what gathers them.
  , rescueHeldKinds  :: !(NonEmpty DeclaredCheckKind)
  }
  deriving (Eq, Show)

-- | Try the input under every console header arrangement and keep the ones the patch agrees with.
-- Nothing here parses or detects a header: 'addHeader' puts zeros on, 'removeHeader' takes bytes off,
-- and each candidate is judged by the same 'normalizeApplySource'-then-'weighSource' pair the run
-- itself weighs with — the match is stumbled into, not identified.
--
-- Only a full 'VerdictMatches' counts. A candidate that merely avoids refusal, its advisory-class
-- disagreements riding along, would earn a hint the retry then undercuts with warnings — and for a patch
-- whose checks are all advisory-class, every arrangement avoids refusal, which is no find at all.
headerRescueCandidates :: SomePatch -> ByteString -> [HeaderRescueCandidate]
headerRescueCandidates parsed handedBytes =
  [ HeaderRescueCandidate adjustment consoles heldKinds
  | (adjustment, consoles, candidateBytes) <- arrangements
  , VerdictMatches heldKinds <- [candidateVerdict candidateBytes] ]
  where
    widthGroups = NonEmpty.groupAllWith consoleHeaderLength [minBound .. maxBound]
    arrangements =
      [ (HeaderComesOff, consoles, bytesBeneath)
      | consoles <- widthGroups
      , Just bytesBeneath <- [removeHeader (NonEmpty.head consoles) handedBytes] ]
      ++
      [ (HeaderGoesOn, consoles, addHeader (NonEmpty.head consoles) handedBytes)
      | consoles <- widthGroups ]
    candidateVerdict candidateBytes =
      let normalized = normalizeApplySource (patchSourceNormalization parsed) (InputFileContents candidateBytes)
      in verdictOnWeighing (weighSource (patchVerification parsed) (normalizedSourceBytes normalized))
