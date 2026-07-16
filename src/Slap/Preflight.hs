{-# LANGUAGE DerivingVia #-}

-- | What slap does with the input before a run: 'reframeInput' carries out the user's header directive,
-- the header rescue searches every console header arrangement for one the patch agrees with,
-- and 'checkApply' / 'checkUndo' answer whether the handed file is the one the patch expects.
module Slap.Preflight
  ( reframeInput
  , HeaderRescueCandidate(..)
  , headerRescueCandidates
  , headerRescueAdvisories
  , SourceReport(..)
  , checkApply
  , checkUndo
  , weighUndoInput
  , PreparedApplySource(..)
  , prepareApplySource
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Header (ConsoleHeader, HeaderAdjustment(..), InputHeaderDirective(..),
                    addHeader, removeHeader, consoleHeaderLength)
import Slap.Measure (ActualSize(..), byteFileSize)
import Slap.Normalize (NormalizedSource(..), normalizeApplySource)
import Slap.SomePatch (SomePatch(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), Outcome(..), DeclaredCheckKind)
import Slap.Verify (VerificationPolicy(..), VerificationVerdict(..), Weighing,
                    flipSpokenSides, verdictOnWeighing, weighSource, weighTarget)

import Data.Aeson (ToJSON)
import Data.ByteString (ByteString)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import GHC.Generics (Generic, Generically(..))

-- | Carry out the user's @--add-header@ / @--remove-header@ instruction on the handed input.
-- The reframe never happens silently: a successful adjustment carries its narrating note.
reframeInput :: InputHeaderDirective -> ByteString -> Outcome (Either SlapError ByteString)
reframeInput TakeInputAsIs handedBytes = Outcome (Right handedBytes) []
reframeInput (AddHeader console) handedBytes =
  Outcome (Right (addHeader console handedBytes)) [InputHeaderAdded console]
reframeInput (RemoveHeader console) handedBytes = case removeHeader console handedBytes of
  Nothing -> Outcome (Left (HeaderRemovalExceedsInput console (ActualSize (byteFileSize handedBytes)))) []
  Just bytesBeneath -> Outcome (Right bytesBeneath) [InputHeaderRemoved console]

----------------------------------------------------------------------------
-- The header rescue
----------------------------------------------------------------------------

-- | A header arrangement that reconciles a differing input with the patch: adjusted this way,
-- the input matches every check the patch declares, and the kinds say what that rests on.
data HeaderRescueCandidate = HeaderRescueCandidate
  { rescueAdjustment :: !HeaderAdjustment
  , rescueConsoles   :: !(NonEmpty ConsoleHeader)
    -- ^ Every console whose header shares this arrangement's byte width — any of them does the job.
    -- 'NonEmpty.groupAllWith' 'consoleHeaderLength' is what gathers them.
  , rescueHeldKinds  :: !(NonEmpty DeclaredCheckKind)
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically HeaderRescueCandidate

-- | Try the input under every console header arrangement and keep the ones the patch agrees with.
-- Nothing here parses or detects a header: 'addHeader' puts zeros on, 'removeHeader' takes bytes off,
-- and each candidate is judged by the same 'normalizeApplySource'-then-'weighSource' pair the run
-- itself weighs with — the match is stumbled into, not identified.
--
-- Only a full 'VerdictMatches' counts. A candidate that merely avoided refusal, its advisory-class disagreements riding along,
-- would send the run into warnings it promised to clear — and for a patch whose checks are all advisory-class,
-- every arrangement avoids refusal, which is no find at all.
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

-- | The rescue's finds as advisories, spoken beside a refusal: each arrangement's hint, or the word that no arrangement helps.
headerRescueAdvisories :: [HeaderRescueCandidate] -> [SlapAdvisory]
headerRescueAdvisories [] = [NoHeaderAdjustmentMatches]
headerRescueAdvisories candidates =
  [ SourceMatchesAfterHeaderAdjustment (rescueAdjustment candidate) (rescueConsoles candidate) (rescueHeldKinds candidate)
  | candidate <- candidates ]

----------------------------------------------------------------------------
-- The check, and the source apply proceeds on
----------------------------------------------------------------------------

-- | The verdict on the handed input, with the rescue's finds beside it —
-- beside, not inside, because the verdict type has no reason to know headers exist.
data SourceReport = SourceReport
  { sourceVerdict :: !VerificationVerdict
  , sourceRescue  :: ![HeaderRescueCandidate]
    -- ^ Searched only when the verdict differs and no header directive was given:
    -- a user who typed @--remove-header snes@ is never second-guessed.
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically SourceReport

-- | Is this the file the patch expects? Answered through the same reframe-normalize-weigh pipeline
-- the apply itself runs, so the answer and the act cannot disagree.
checkApply :: SomePatch -> InputHeaderDirective -> ByteString -> Either SlapError SourceReport
checkApply parsed directive handedBytes =
  reportOnWeighing parsed directive handedBytes . arrangedWeighing
    <$> arrangeUnderDirective parsed directive handedBytes

-- | The undo-side question: the verdict on the handed file.
checkUndo :: SomePatch -> ByteString -> VerificationVerdict
checkUndo parsed = verdictOnWeighing . weighUndoInput parsed

weighUndoInput :: SomePatch -> ByteString -> Weighing
weighUndoInput parsed handedBytes =
  flipSpokenSides (weighTarget (patchVerification parsed) (OutputFileContents handedBytes))

-- | The source as apply will run it.
data PreparedApplySource = PreparedApplySource
  { preparedFramedInput :: !ByteString
    -- ^ The input after its header arrangement, before normalization.
  , preparedSource      :: !NormalizedSource
  , preparedWeighing    :: !Weighing
  , preparedAdvisories  :: ![SlapAdvisory]
    -- ^ Everything the preparation wants said, in speaking order:
    -- the arrangement's narration, then normalization's own advisories.
  , preparedReport      :: !SourceReport
    -- ^ 'checkApply's answer about the handed bytes.
  }

-- | Prepare apply's source, carrying out the one fix slap performs unasked:
-- when the input differs as handed, no header directive was given, verification is enforced,
-- and exactly one header arrangement fully reconciles the input with the patch,
-- the run proceeds with the input reframed that way, narrated by 'InputReframedToMatchPatch'.
-- Anything short of that changes nothing: the caller judges the handed form as it always has.
prepareApplySource
  :: VerificationPolicy -> SomePatch -> InputHeaderDirective -> ByteString -> Either SlapError PreparedApplySource
prepareApplySource verificationPolicy parsed directive handedBytes = do
  arranged <- arrangeUnderDirective parsed directive handedBytes
  let report = reportOnWeighing parsed directive handedBytes (arrangedWeighing arranged)
  case (verificationPolicy, sourceRescue report) of
    (EnforceVerification, [provenCandidate]) ->
      preparedFrom report <$> reframeToCandidate parsed provenCandidate handedBytes
    _ -> pure (preparedFrom report arranged)
  where
    preparedFrom report arranged = PreparedApplySource
      { preparedFramedInput = arrangedInput arranged
      , preparedSource      = arrangedNormalized arranged
      , preparedWeighing    = arrangedWeighing arranged
      , preparedAdvisories  = arrangedNarration arranged ++ normalizedSourceAdvisories (arrangedNormalized arranged)
      , preparedReport      = report
      }

----------------------------------------------------------------------------
-- The shared pipeline
----------------------------------------------------------------------------

-- | The input taken through the pipeline apply weighs with: the header directive carried out,
-- rom-type normalization applied, every declared check weighed.
-- Normalization precedes the weighing so the hashes cover the bytes the patch's checksums were computed over.
data ArrangedSource = ArrangedSource
  { arrangedInput      :: ByteString
  , arrangedNarration  :: [SlapAdvisory]
  , arrangedNormalized :: NormalizedSource
  , arrangedWeighing   :: Weighing
  }

arrangeUnderDirective :: SomePatch -> InputHeaderDirective -> ByteString -> Either SlapError ArrangedSource
arrangeUnderDirective parsed directive handedBytes = do
  let reframeOutcome = reframeInput directive handedBytes
  reframedBytes <- outcomeValue reframeOutcome
  let normalized = normalizeApplySource (patchSourceNormalization parsed) (InputFileContents reframedBytes)
  pure ArrangedSource
    { arrangedInput      = reframedBytes
    , arrangedNarration  = outcomeAdvisories reframeOutcome
    , arrangedNormalized = normalized
    , arrangedWeighing   = weighSource (patchVerification parsed) (normalizedSourceBytes normalized)
    }

reportOnWeighing :: SomePatch -> InputHeaderDirective -> ByteString -> Weighing -> SourceReport
reportOnWeighing parsed directive handedBytes weighing = SourceReport
  { sourceVerdict = verdict
  , sourceRescue  = case (directive, verdict) of
      (TakeInputAsIs, VerdictDiffers _) -> headerRescueCandidates parsed handedBytes
      _                                 -> []
  }
  where
    verdict = verdictOnWeighing weighing

-- | Carry out a proven candidate's arrangement, down the same road a typed directive takes,
-- with the generic note swapped for the fix's own narration.
reframeToCandidate :: SomePatch -> HeaderRescueCandidate -> ByteString -> Either SlapError ArrangedSource
reframeToCandidate parsed candidate handedBytes = do
  arranged <- arrangeUnderDirective parsed (candidateDirective candidate) handedBytes
  pure arranged
    { arrangedNarration =
        [InputReframedToMatchPatch (rescueAdjustment candidate) (rescueConsoles candidate) (rescueHeldKinds candidate)] }

candidateDirective :: HeaderRescueCandidate -> InputHeaderDirective
candidateDirective candidate = case rescueAdjustment candidate of
  HeaderComesOff -> RemoveHeader (NonEmpty.head (rescueConsoles candidate))
  HeaderGoesOn   -> AddHeader (NonEmpty.head (rescueConsoles candidate))
