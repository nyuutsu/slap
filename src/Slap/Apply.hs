-- | The run itself: everything between a prepared source and the patched file a frontend hands back.
-- One home, so whatever apply does — now and later — convert's @--with@ lane and every frontend inherit by construction.
module Slap.Apply
  ( PatchedRom(..)
  , VerdictStanding(..)
  , runPreparedApply
  ) where

import Slap.Display.Info (InputSideVerdict(..), OutputSideVerdict(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents)
import Slap.Header (InputHeaderDirective(TakeInputAsIs))
import Slap.Normalize (normalizedSourceBytes, normalizedSourceRestore, restoreStrippedContent)
import Slap.Preflight (PreparedApplySource(..), SourceReport(..), headerRescueAdvisories)
import Slap.SomePatch (SomePatch, patchApply, patchFormat, patchVerification, runApply)
import Slap.Status (Outcome(..), SlapAdvisory, SlapError)
import Slap.Verify (VerificationPolicy, judgeWeighing, verdictOnWeighing, weighTarget)

data PatchedRom = PatchedRom
  { patchedRomBytes           :: OutputFileContents
  , patchedRomInputVerdict    :: InputSideVerdict
  , patchedRomOutputVerdict   :: OutputSideVerdict
  , patchedRomVerdictStanding :: VerdictStanding
  }
  deriving (Eq, Show)

-- | Whether the two verdicts describe the bytes handed in and written out.
-- Normalization or restore can make the weighed form a different artifact from the exchanged one;
-- a frontend withholds its report in exactly that case — the advisories tell the reshaping's story instead.
data VerdictStanding
  = VerdictsDescribeTheFiles
  | VerdictsWithheldReshaped
  deriving (Eq, Show)

-- | Run a prepared source through the whole of apply: judge the source, run the records, judge the target,
-- restore what normalization set aside. Narrates only what the run itself says —
-- the parse's and the preparation's advisories are the caller's to speak, at its own timing.
-- The directive gates the rescue hints a refusal speaks beside itself:
-- an empty rescue means "searched, found nothing" only when no directive was given, and the hints would lie under a typed one.
runPreparedApply
  :: VerificationPolicy -> InputHeaderDirective -> SomePatch -> PreparedApplySource
  -> IO (Outcome (Either SlapError PatchedRom))
runPreparedApply verificationPolicy directive parsed prepared = case outcomeValue sourceJudgment of
  Left refusal -> pure (Outcome (Left refusal) (outcomeAdvisories sourceJudgment ++ rescueHints))
  Right () -> do
    applied <- runApply (patchApply parsed) (normalizedSourceBytes (preparedSource prepared))
    pure $ case applied of
      Left applyRefusal  -> Outcome (Left applyRefusal) (outcomeAdvisories sourceJudgment)
      Right applyOutcome ->
        judgeAppliedTarget verificationPolicy parsed prepared
          (outcomeAdvisories sourceJudgment ++ outcomeAdvisories applyOutcome) (outcomeValue applyOutcome)
  where
    sourceJudgment = judgeWeighing verificationPolicy (preparedWeighing prepared)
    rescueHints
      | TakeInputAsIs <- directive = headerRescueAdvisories (sourceRescue (preparedReport prepared))
      | otherwise = []

judgeAppliedTarget
  :: VerificationPolicy -> SomePatch -> PreparedApplySource -> [SlapAdvisory] -> OutputFileContents
  -> Outcome (Either SlapError PatchedRom)
judgeAppliedTarget verificationPolicy parsed prepared narration target = case outcomeValue targetJudgment of
  Left refusal -> Outcome (Left refusal) narrated
  Right ()     -> Outcome (Right patchedRom) (narrated ++ restoreAdvisories)
  where
    -- The patch's stored target hash describes the pre-restore form, so the weighing covers 'target', never 'restoredTarget'.
    targetWeighing = weighTarget (patchVerification parsed) target
    targetJudgment = judgeWeighing verificationPolicy targetWeighing
    narrated       = narration ++ outcomeAdvisories targetJudgment
    (restoredTarget, restoreAdvisories) =
      restoreStrippedContent (patchFormat parsed) (normalizedSourceRestore (preparedSource prepared)) target
    patchedRom = PatchedRom
      { patchedRomBytes           = restoredTarget
      , patchedRomInputVerdict    = InputSideVerdict (verdictOnWeighing (preparedWeighing prepared))
      , patchedRomOutputVerdict   = OutputSideVerdict (verdictOnWeighing targetWeighing)
      , patchedRomVerdictStanding = standing
      }
    standing
      | unInputFileContents (normalizedSourceBytes (preparedSource prepared)) == preparedFramedInput prepared
          && restoredTarget == target = VerdictsDescribeTheFiles
      | otherwise                     = VerdictsWithheldReshaped
