module Patch.Explain
  ( explainPPF
  , explainIPS
  , explainBPS
  , explainUPS
  , explainVCDIFF
  , explainAPS
  , explainRUP
  , explainBSDiff
  , explainGDIFF
  , explainXDelta1
  , explainPMSR
  , explainDPS
  , explainNINJA1
  , explainPCHTXT
  ) where

import qualified Patch.PPF.Types as PPF
import qualified Patch.IPS as IPS
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.APS as APS
import qualified Patch.RUP as RUP
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.BSDiff as BSDiff
import qualified Patch.GDIFF as GDIFF
import qualified Patch.XDelta1 as XDelta1
import qualified Patch.PMSR as PMSR
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.PCHTXT as PCHTXT

import Patch.Format (showCRC, padHex, padNum, padR, showSigned, hexDump)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.List (mapAccumL)
import Data.Int (Int64)

----------------------------------------------------------------------------
-- PPF
----------------------------------------------------------------------------

explainPPF :: PPF.Patch -> String
explainPPF p = unlines $
  [ "format:      " ++ ppfVerStr (PPF.patchVersion p)
  , "records:     " ++ show nRecs
  , ""
  ] ++ zipWith showPPFRecord [1..] (PPF.patchRecords p)
    ++ [summary]
  where
    nRecs = length (PPF.patchRecords p)
    totalBytes = sum (map (BS.length . PPF.recData) (PPF.patchRecords p))
    summary = show nRecs ++ " records, " ++ show totalBytes ++ " bytes total"

ppfVerStr :: PPF.Version -> String
ppfVerStr PPF.PPF1 = "PPF1"
ppfVerStr PPF.PPF2 = "PPF2"
ppfVerStr PPF.PPF3 = "PPF3"
ppfVerStr PPF.PPF4 = "PPF \"4\" (Pyriel internal format)"

showPPFRecord :: Int -> PPF.Record -> String
showPPFRecord n r =
  padNum n ++ "  " ++ cmdStr ++ padR 10 (show (BS.length (PPF.recData r)) ++ " B")
  ++ "  at 0x" ++ padHex 6 (PPF.recOffset r)
  ++ undoStr
  ++ "\n" ++ hexDump (PPF.recData r)
  where
    cmdStr = case PPF.recCmd r of
      PPF.Replace -> "Write  "
      PPF.Append  -> "Append "
    undoStr = case PPF.recUndo r of
      Nothing -> ""
      Just _  -> "  (undo data)"

----------------------------------------------------------------------------
-- IPS
----------------------------------------------------------------------------

explainIPS :: IPS.IPSPatch -> String
explainIPS p = unlines $
  [ "format:      " ++ case IPS.ipsVariant p of
      IPS.StandardIPS -> case IPS.ipsEBPMeta p of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS.IPS32       -> "IPS32"
  , "records:     " ++ show nRecs
  , ""
  ] ++ zipWith showIPSRecord [1..] (IPS.ipsRecords p)
    ++ [truncStr, summary]
  where
    nRecs = length (IPS.ipsRecords p)
    totalBytes = sum (map ipsRecSize (IPS.ipsRecords p))
    summary = show nRecs ++ " records, " ++ show totalBytes ++ " bytes total"
    truncStr = case IPS.ipsTruncate p of
      Nothing -> ""
      Just sz -> "truncate to " ++ show sz ++ " bytes"

showIPSRecord :: Int -> IPS.IPSRecord -> String
showIPSRecord n (IPS.IPSRecord off dat) =
  padNum n ++ "  Write  " ++ padR 10 (show (BS.length dat) ++ " B")
  ++ "  at 0x" ++ padHex 6 off
  ++ "\n" ++ hexDump dat
showIPSRecord n (IPS.IPSRecordRLE off count val) =
  padNum n ++ "  Fill " ++ show count ++ " x 0x" ++ padHex 2 (fromIntegral val :: Int64)
  ++ "  at 0x" ++ padHex 6 off ++ "  (RLE)"

ipsRecSize :: IPS.IPSRecord -> Int
ipsRecSize (IPS.IPSRecord _ d)       = BS.length d
ipsRecSize (IPS.IPSRecordRLE _ c _)  = c

----------------------------------------------------------------------------
-- BPS
----------------------------------------------------------------------------

explainBPS :: BPS.BPSPatch -> String
explainBPS p = unlines $
  [ "format:      BPS"
  , "source size: " ++ show (BPS.bpsSourceSize p) ++ " (CRC 0x" ++ showCRC (BPS.bpsSourceCRC p) ++ ")"
  , "target size: " ++ show (BPS.bpsTargetSize p) ++ " (CRC 0x" ++ showCRC (BPS.bpsTargetCRC p) ++ ")"
  , ""
  ] ++ snd (mapAccumL showBPSAction 0 (zip [1..] (BPS.bpsActions p)))
    ++ [summary]
  where
    nActs = length (BPS.bpsActions p)
    summary = show nActs ++ " actions, " ++ show (BPS.bpsTargetSize p) ++ " bytes total output"

showBPSAction :: Int64 -> (Int, BPS.BPSAction) -> (Int64, String)
showBPSAction outPos (n, act) = case act of
  BPS.SourceRead len ->
    ( outPos + fromIntegral len
    , padNum n ++ "  SourceRead " ++ padR 10 (show len ++ " B")
      ++ "  at output 0x" ++ padHex 6 outPos )
  BPS.TargetRead dat ->
    let len = BS.length dat
    in ( outPos + fromIntegral len
       , padNum n ++ "  TargetRead " ++ padR 10 (show len ++ " B")
         ++ "  at output 0x" ++ padHex 6 outPos
         ++ "\n" ++ hexDump dat )
  BPS.SourceCopy len delta ->
    ( outPos + fromIntegral len
    , padNum n ++ "  SourceCopy " ++ padR 10 (show len ++ " B")
      ++ "  at output 0x" ++ padHex 6 outPos
      ++ "  (delta " ++ showSigned delta ++ ")" )
  BPS.TargetCopy len delta ->
    ( outPos + fromIntegral len
    , padNum n ++ "  TargetCopy " ++ padR 10 (show len ++ " B")
      ++ "  at output 0x" ++ padHex 6 outPos
      ++ "  (delta " ++ showSigned delta ++ ")" )

----------------------------------------------------------------------------
-- UPS
----------------------------------------------------------------------------

explainUPS :: UPS.UPSPatch -> String
explainUPS p = unlines $
  [ "format:      UPS"
  , "source size: " ++ show (UPS.upsSourceSize p) ++ " (CRC 0x" ++ showCRC (UPS.upsSourceCRC p) ++ ")"
  , "target size: " ++ show (UPS.upsTargetSize p) ++ " (CRC 0x" ++ showCRC (UPS.upsTargetCRC p) ++ ")"
  , ""
  ] ++ snd (mapAccumL showUPSBlock 0 (zip [1..] (UPS.upsBlocks p)))
    ++ [summary]
  where
    nBlocks = length (UPS.upsBlocks p)
    summary = show nBlocks ++ " blocks"

showUPSBlock :: Int64 -> (Int, UPS.UPSBlock) -> (Int64, String)
showUPSBlock pos (n, UPS.UPSBlock skip xd) =
  let xorOff = pos + skip
      len    = BS.length xd
  in ( xorOff + fromIntegral len
     , padNum n ++ "  XOR  " ++ padR 10 (show len ++ " B")
       ++ "  at 0x" ++ padHex 6 xorOff
       ++ "  (skip " ++ show skip ++ ")" )

----------------------------------------------------------------------------
-- VCDIFF
----------------------------------------------------------------------------

explainVCDIFF :: VCDIFF.VCDIFFPatch -> String
explainVCDIFF p = unlines $
  [ "format:      VCDIFF" ++ if VCDIFF.vcdVersion (VCDIFF.vcdHeader p) == 0x53
                              then " (xdelta3)" else ""
  , "windows:     " ++ show nWins
  , "target size: " ++ show totalTgt
  , ""
  ] ++ concatMap showVCDIFFWindow (zip [1..] (VCDIFF.vcdWindows p))
    ++ [show nWins ++ " windows, " ++ show totalTgt ++ " bytes total output"]
  where
    nWins = length (VCDIFF.vcdWindows p)
    totalTgt = sum (map VCDIFF.vcdTargetLen (VCDIFF.vcdWindows p))

showVCDIFFWindow :: (Int, VCDIFF.VCDIFFWindow) -> [String]
showVCDIFFWindow (n, w) =
  [ "window " ++ show n ++ ":"
  , "  target size:    " ++ show (VCDIFF.vcdTargetLen w)
  , "  source segment: " ++ show (VCDIFF.vcdSourceLen w) ++ " bytes at 0x"
    ++ padHex 6 (VCDIFF.vcdSourcePos w)
  , "  add/run data:   " ++ show (BS.length (VCDIFF.vcdAddRunData w)) ++ " bytes"
  , "  instructions:   " ++ show (BS.length (VCDIFF.vcdInstructions w)) ++ " bytes"
  , "  addresses:      " ++ show (BS.length (VCDIFF.vcdAddresses w)) ++ " bytes"
  , adlerStr
  , ""
  ]
  where
    adlerStr = case VCDIFF.vcdAdler32 w of
      Nothing -> ""
      Just a  -> "  adler32:        0x" ++ padHex 8 (fromIntegral a :: Int64)

----------------------------------------------------------------------------
-- APS
----------------------------------------------------------------------------

explainAPS :: APS.APSPatch -> String
explainAPS (APS.APSPatch variant) = case variant of
  APS.APSN64 _hdr recs -> unlines $
    [ "format:      APS (N64)"
    , "records:     " ++ show (length recs)
    , ""
    ] ++ zipWith showN64Record [1..] recs
      ++ [show (length recs) ++ " records"]
  APS.APSGBA hdr recs -> unlines $
    [ "format:      APS (GBA)"
    , "source size: " ++ show (APS.gbaSourceSize hdr)
    , "target size: " ++ show (APS.gbaTargetSize hdr)
    , ""
    ] ++ zipWith showGBARecord [1..] recs
      ++ [show (length recs) ++ " blocks"]

showN64Record :: Int -> APS.APSN64Record -> String
showN64Record n (APS.APSN64Normal off dat) =
  padNum n ++ "  Write  " ++ padR 10 (show (BS.length dat) ++ " B")
  ++ "  at 0x" ++ padHex 6 off
  ++ "\n" ++ hexDump dat
showN64Record n (APS.APSN64RLE off val count) =
  padNum n ++ "  Fill " ++ show count ++ " x 0x" ++ padHex 2 (fromIntegral val :: Int64)
  ++ "  at 0x" ++ padHex 6 off ++ "  (RLE)"

showGBARecord :: Int -> APS.APSGBARecord -> String
showGBARecord n r =
  padNum n ++ "  XOR block  65536 B  at 0x" ++ padHex 6 (fromIntegral (APS.gbaOffset r) :: Int64)
  ++ "  (src CRC16 " ++ padHex 4 (fromIntegral (APS.gbaSourceCRC r) :: Int64)
  ++ ", tgt CRC16 " ++ padHex 4 (fromIntegral (APS.gbaTargetCRC r) :: Int64) ++ ")"

----------------------------------------------------------------------------
-- RUP
----------------------------------------------------------------------------

explainRUP :: RUP.RUPPatch -> String
explainRUP p = unlines $
  [ "format:      RUP (NINJA2)"
  , "records:     " ++ show nRecs
  , ""
  ] ++ zipWith showRUPRecord [1..] (RUP.rupRecords p)
    ++ [show nRecs ++ " records"]
  where
    nRecs = length (RUP.rupRecords p)

showRUPRecord :: Int -> RUP.RUPRecord -> String
showRUPRecord n (RUP.RUPRecord off xd) =
  padNum n ++ "  XOR  " ++ padR 10 (show (BS.length xd) ++ " B")
  ++ "  at 0x" ++ padHex 6 off

----------------------------------------------------------------------------
-- GDIFF
----------------------------------------------------------------------------

explainGDIFF :: GDIFF.GDiffPatch -> String
explainGDIFF p = unlines $
  [ "format:      GDIFF (W3C)"
  , "commands:    " ++ show nCmds
  , ""
  ] ++ snd (mapAccumL showGDIFFCmd 0 (zip [1..] (GDIFF.gdiffCmds p)))
    ++ [show nCmds ++ " commands"]
  where
    nCmds = length (GDIFF.gdiffCmds p)

showGDIFFCmd :: Int64 -> (Int, GDIFF.GDiffCmd) -> (Int64, String)
showGDIFFCmd outPos (n, cmd) = case cmd of
  GDIFF.GDiffData dat ->
    let len = BS.length dat
    in ( outPos + fromIntegral len
       , padNum n ++ "  DATA  " ++ padR 10 (show len ++ " B")
         ++ "  at output 0x" ++ padHex 6 outPos
         ++ "\n" ++ hexDump dat )
  GDIFF.GDiffCopy off len ->
    ( outPos + len
    , padNum n ++ "  COPY  " ++ padR 10 (show len ++ " B")
      ++ "  at output 0x" ++ padHex 6 outPos
      ++ "  (source 0x" ++ padHex 6 off ++ ")" )

----------------------------------------------------------------------------
-- BSDiff
----------------------------------------------------------------------------

explainBSDiff :: BSDiff.BSDiffPatch -> String
explainBSDiff p = unlines $
  [ "format:      BSDiff / BDF (BSDIFF40)"
  , "new size:    " ++ show (BSDiff.bsdNewSize p)
  , "ctrl block:  " ++ show (BSDiff.bsdCtrlSize p) ++ " bytes (compressed)"
  , "diff block:  " ++ show (BSDiff.bsdDiffSize p) ++ " bytes (compressed)"
  , ""
  ] ++ if null (BSDiff.bsdControls p)
       then ["(control data not decoded)"]
       else zipWith showBSDiffCtrl [1..] (BSDiff.bsdControls p)
         ++ [show (length (BSDiff.bsdControls p)) ++ " control tuples"]

showBSDiffCtrl :: Int -> BSDiff.BSDiffControl -> String
showBSDiffCtrl n ctrl =
  padNum n ++ "  add " ++ padR 10 (show (BSDiff.ctrlAdd ctrl) ++ " B")
  ++ "  copy " ++ padR 10 (show (BSDiff.ctrlCopy ctrl) ++ " B")
  ++ "  seek " ++ showSigned (BSDiff.ctrlSeek ctrl)

----------------------------------------------------------------------------
-- XDelta1
----------------------------------------------------------------------------

explainXDelta1 :: XDelta1.XDelta1Patch -> String
explainXDelta1 p = unlines $
  [ "format:      xdelta1"
  , "from:        " ++ BS8.unpack (XDelta1.xd1FromName p)
  , "to:          " ++ BS8.unpack (XDelta1.xd1ToName p)
  , "target size: " ++ show (XDelta1.xd1ToLen p)
  , "sources:     " ++ show (length (XDelta1.xd1Sources p))
  , ""
  ] ++ zipWith showXD1Source [0..] (XDelta1.xd1Sources p)
    ++ ["", "instructions: " ++ show nInsts, ""]
    ++ zipWith showXD1Inst [1..] (XDelta1.xd1Instructions p)
    ++ [show nInsts ++ " instructions, " ++ show (XDelta1.xd1ToLen p) ++ " bytes total output"]
  where
    nInsts = length (XDelta1.xd1Instructions p)

showXD1Source :: Int -> XDelta1.XD1Source -> String
showXD1Source n s =
  "  [" ++ show n ++ "] " ++ BS8.unpack (XDelta1.xd1SrcName s)
  ++ (if XDelta1.xd1SrcIsData s then " (data)" else " (file)")
  ++ (if XDelta1.xd1SrcSequential s then " seq" else "")
  ++ "  " ++ show (XDelta1.xd1SrcLen s) ++ " bytes"

showXD1Inst :: Int -> XDelta1.XD1Instruction -> String
showXD1Inst n inst =
  padNum n ++ "  Copy  " ++ padR 10 (show (XDelta1.xd1InstLength inst) ++ " B")
  ++ "  from source " ++ show (XDelta1.xd1InstIndex inst)
  ++ "  at 0x" ++ padHex 6 (XDelta1.xd1InstOffset inst)

----------------------------------------------------------------------------
-- PMSR
----------------------------------------------------------------------------

explainPMSR :: PMSR.PMSRPatch -> String
explainPMSR p = unlines $
  [ "format:      PMSR (Paper Mario Star Rod)"
  , "records:     " ++ show nRecs
  , ""
  ] ++ zipWith showPMSRRecord [1..] (PMSR.pmsrRecords p)
    ++ [summary]
  where
    nRecs = length (PMSR.pmsrRecords p)
    totalBytes = sum (map (BS.length . PMSR.pmsrData) (PMSR.pmsrRecords p))
    summary = show nRecs ++ " records, " ++ show totalBytes ++ " bytes total"

showPMSRRecord :: Int -> PMSR.PMSRRecord -> String
showPMSRRecord n r =
  padNum n ++ "  Write  " ++ padR 10 (show (BS.length (PMSR.pmsrData r)) ++ " B")
  ++ "  at 0x" ++ padHex 6 (PMSR.pmsrOffset r)
  ++ "\n" ++ hexDump (PMSR.pmsrData r)

----------------------------------------------------------------------------
-- DPS
----------------------------------------------------------------------------

explainDPS :: DPS.DPSPatch -> String
explainDPS p = unlines $
  [ "format:      DPS (Deufeufeu Patching System)"
  , "records:     " ++ show nRecs
  , ""
  ] ++ zipWith showDPSRecord [1..] (DPS.dpsRecords p)
    ++ [summary]
  where
    nRecs = length (DPS.dpsRecords p)
    totalBytes = sum (map recBytes (DPS.dpsRecords p))
    summary = show nRecs ++ " records, " ++ show totalBytes ++ " bytes total"
    recBytes r = case DPS.dpsRecPayload r of
      DPS.PayloadData dat    -> BS.length dat
      DPS.PayloadCopy _ len  -> fromIntegral len

showDPSRecord :: Int -> DPS.DPSRecord -> String
showDPSRecord n r = case DPS.dpsRecPayload r of
  DPS.PayloadData dat ->
    padNum n ++ "  Data   " ++ padR 10 (show (BS.length dat) ++ " B")
    ++ "  at 0x" ++ padHex 6 (DPS.dpsRecOutOffset r)
    ++ "\n" ++ hexDump dat
  DPS.PayloadCopy srcOff len ->
    padNum n ++ "  Copy   " ++ padR 10 (show len ++ " B")
    ++ "  at 0x" ++ padHex 6 (DPS.dpsRecOutOffset r)
    ++ "  (source 0x" ++ padHex 6 srcOff ++ ")"

----------------------------------------------------------------------------
-- NINJA1
----------------------------------------------------------------------------

explainNINJA1 :: NINJA1.NINJA1Patch -> String
explainNINJA1 p = unlines $
  [ "format:      NINJA1 (" ++ subFmtStr ++ ")"
  , "records:     " ++ show nRecs
  , ""
  ] ++ zipWith showN1Record [1..] (NINJA1.n1Records p)
    ++ [summary]
  where
    nRecs = length (NINJA1.n1Records p)
    subFmtStr = case NINJA1.n1SubFormat p of
      NINJA1.N1Binary  -> "binary"
      NINJA1.N1BinaryZ -> "binary, compressed"
      NINJA1.N1Text    -> "text"
      NINJA1.N1TextZ   -> "text, compressed"
    totalBytes = sum (map (BS.length . NINJA1.n1RecData) (NINJA1.n1Records p))
    summary = show nRecs ++ " records, " ++ show totalBytes ++ " bytes total"

showN1Record :: Int -> NINJA1.NINJA1Record -> String
showN1Record n (NINJA1.NINJA1Record off dat) =
  padNum n ++ "  Write  " ++ padR 10 (show (BS.length dat) ++ " B")
  ++ "  at 0x" ++ padHex 6 off
  ++ "\n" ++ hexDump dat

----------------------------------------------------------------------------
-- PCHTXT
----------------------------------------------------------------------------

explainPCHTXT :: PCHTXT.PCHTXTPatch -> String
explainPCHTXT p = unlines $
  [ "format:      PCHTXT (Nintendo Switch)"
  ] ++ nsobidLine
  ++ [ "blocks:      " ++ show (length (PCHTXT.pchtxtBlocks p))
     , ""
     ]
  ++ concatMap showBlock (zip [1..] (PCHTXT.pchtxtBlocks p))
  ++ [summary]
  where
    nsobidLine = case PCHTXT.pchtxtNsobid p of
      Just nso -> ["nsobid:      " ++ nso]
      Nothing  -> []
    enabledEntries = concatMap PCHTXT.pchtxtBlockEntries
                       (filter PCHTXT.pchtxtBlockEnabled (PCHTXT.pchtxtBlocks p))
    totalBytes = sum (map (BS.length . PCHTXT.pchtxtData) enabledEntries)
    summary = show (length enabledEntries) ++ " enabled entries, "
              ++ show totalBytes ++ " bytes total"

    showBlock :: (Int, PCHTXT.PCHTXTBlock) -> [String]
    showBlock (n, block) =
      let status = if PCHTXT.pchtxtBlockEnabled block then "enabled" else "disabled"
          desc = maybe "" (" -- " ++) (PCHTXT.pchtxtBlockDesc block)
      in ("block " ++ show n ++ " (" ++ status ++ ")" ++ desc)
         : map showEntry (PCHTXT.pchtxtBlockEntries block)
         ++ [""]

    showEntry :: PCHTXT.PCHTXTEntry -> String
    showEntry e =
      "    " ++ padHex 8 (PCHTXT.pchtxtOffset e) ++ "  Write  "
      ++ padR 10 (show (BS.length (PCHTXT.pchtxtData e)) ++ " B")
      ++ "\n" ++ hexDump (PCHTXT.pchtxtData e)

