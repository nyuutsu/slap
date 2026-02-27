module Main (main) where

import Test.Tasty (defaultMain, testGroup)
import Integration.Apply (applyTests)
import Integration.Create (createTests)
import Integration.CrossVal (crossValTests)
import Integration.Convert (convertTests)
import Integration.Metadata (metadataTests)
import Integration.Undo (undoTests)
import Integration.CLI (cliTests)
import Integration.FailureMode (failureModeTests)

import Control.Concurrent (newEmptyMVar, putMVar, takeMVar, forkIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS

parSequence :: [IO a] -> IO [a]
parSequence actions = do
  mvars <- mapM (\act -> do
    mv <- newEmptyMVar
    _ <- forkIO (act >>= putMVar mv)
    pure mv) actions
  mapM takeMVar mvars

main :: IO ()
main = do
  romCache <- newIORef (Map.empty :: Map.Map FilePath BS.ByteString)
  trees <- parSequence
    [applyTests romCache, createTests romCache, crossValTests romCache,
     convertTests romCache, metadataTests romCache, undoTests romCache,
     cliTests romCache, failureModeTests romCache]
  defaultMain (testGroup "integration" trees)
