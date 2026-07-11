{-# LANGUAGE OverloadedStrings #-}

-- | The valence scale every status item sits on.
module Slap.Status.Severity
  ( Severity(..)
  , severityLabel
  ) where

import Data.Text (Text)

-- | The valence of a status item: error halts, warning and note do not.
-- Every 'Slap.Status.SlapError' is 'SeverityError'; a 'Slap.Status.SlapAdvisory' varies by constructor,
-- projected by 'Slap.Status.slapAdvisorySeverity'.
data Severity = SeverityError | SeverityWarning | SeverityNote
  deriving (Eq, Show)

severityLabel :: Severity -> Text
severityLabel SeverityError   = "error"
severityLabel SeverityWarning = "warning"
severityLabel SeverityNote    = "note"
