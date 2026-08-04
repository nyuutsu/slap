// The page's render census: every fixture patch's real envelopes, run under node through every renderer that reads them.
// A shape surprise — a null the shape allowed, an arm only one format exercises — throws here, not in someone's browser.
// `make web-check` runs it; new fixtures join for free.
//
//   node check.mjs <native-probe> <rom> <patches...>

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import './lit-html-stunt-hook.mjs';

const { markupOf } = await import('./lit-html-stunt.mjs');
const { UndoAnswer, spokenTagsOf, spokenVocabularies, wireSumNameOf } = await import('./page/engine-vocabulary.mjs');
const { engineSurface } = await import('./page/engine-surface.mjs');
const { infoReadoutMarkup, embeddedContentsOf, embeddedContentMarkup,
        heatModel, heatBarMarkup, heatCaption, walkMarkup, structureOverviewMarkup,
        analysisRegionsOf, analysisAsidesMarkup } = await import('./page/read-panels.mjs');
const { applyFactsCardMarkup, undoFactsCardMarkup } = await import('./page/facts-card.mjs');
const { patchedVoice, revertedVoice, bottledVoice, convertedVoice, blockedVoice,
        advisoryMarkup } = await import('./page/answer-surface.mjs');

const [probePath, romPath, ...patchPaths] = process.argv.slice(2);
if (!probePath || !romPath || patchPaths.length === 0) {
  console.error('usage: node check.mjs <native-probe> <rom> <patches...>');
  process.exit(2);
}

const declarationDir = mkdtempSync(join(tmpdir(), 'slap-web-check-'));
const declarationPathFor = (verb, declaration) => {
  const path = join(declarationDir, `${verb}.json`);
  writeFileSync(path, JSON.stringify(declaration));
  return path;
};
const declarationPaths = {
  inspect: declarationPathFor('inspect', { declaredInspectMetadataEncoding: 'utf-8',
                                           declaredInspectDialects: { requestedPatchOrigin: 'OriginPC' } }),
  analyze: declarationPathFor('analyze', { declaredAnalyzeMetadataEncoding: 'utf-8',
                                           declaredAnalyzeDialects: { requestedPatchOrigin: 'OriginPC' } }),
  identify: declarationPathFor('identify', { declaredIdentifyDialects: { requestedPatchOrigin: 'OriginPC' },
                                             declaredIdentifyMetadataEncoding: 'utf-8' }),
  apply: declarationPathFor('apply', { declaredApplyFraming: { tag: 'TakeInputAsIs' },
                                       declaredApplyVerificationPolicy: 'EnforceVerification',
                                       declaredApplyDialects: { requestedPatchOrigin: 'OriginPC' } }),
  undo: declarationPathFor('undo', { declaredUndoVerificationPolicy: 'EnforceVerification',
                                     declaredUndoDialects: { requestedPatchOrigin: 'OriginPC' } }),
};
const plainCreateDeclaration = (formatTag, formatConstructor) => ({
  declaredCreateTargetFormat: { tag: formatTag, contents: formatConstructor },
  declaredCreateOriginalName: 'original.bin',
  declaredCreateModifiedName: 'modified.bin',
  declaredCreateMetadata: { requestedFileIdDiz: { tag: 'InheritFileIdDiz' },
                            requestedEmbeddedBlob: { tag: 'InheritEmbeddedBlob' } },
  declaredCreateConstraints: { requestedSMCShape: 'AllowAnyTruncationShape' },
});
declarationPaths.create = declarationPathFor('create', plainCreateDeclaration('CreateDifferential', 'CreateBPS'));

// a check reads the act's own declaration
declarationPaths['check-undo'] = declarationPaths.undo;
declarationPaths['check-apply'] = declarationPaths.apply;
declarationPaths['check-create'] = declarationPaths.create;

const probeBytes = (...probeArguments) => execFileSync(probePath, probeArguments, { maxBuffer: 1 << 30 });
const askProbe = (verb, ...seatPaths) => JSON.parse(probeBytes(verb, ...seatPaths, declarationPaths[verb]).toString());

// an act answers [u32 envelope length LE][envelope][tail]
const splitAct = (framedPayload) => {
  const envelopeLength = framedPayload.readUInt32LE(0);
  return { envelope: JSON.parse(framedPayload.subarray(4, 4 + envelopeLength).toString()),
           tail: framedPayload.subarray(4 + envelopeLength) };
};

// The verbs' states rebuilt small: just the fields their cards read.
const applyCardFor = (identified, report) => applyFactsCardMarkup({
  patch: { name: 'patch' }, patchIdentity: { answered: identified },
  rom: { name: 'rom', size: 0 }, romFacts: null,
  sourceReport: report, verificationPolicy: 'EnforceVerification', framing: { tag: 'TakeInputAsIs' },
}, []);

const undoCardFor = (identified, verdict, verificationPolicy) => undoFactsCardMarkup({
  patch: { name: 'patch' }, patchIdentity: { answered: identified },
  patched: { name: 'rom', size: 0 }, patchedFacts: null,
  verdict, verificationPolicy,
}, true);

const mustRender = (what, markup) => {
  if (typeof markupOf(markup) !== 'string') throw new Error(`${what} rendered nothing`);
};

// The page's tables are transcriptions of the engine's sums, and the engine is the one authority that can
// audit a transcription: every table must carry exactly the constructors the engine speaks for its sum.
const engineSums = new Map(JSON.parse(probeBytes('vocabulary').toString()).envelopeAnswer.Right
  .map((spokenSum) => [spokenSum.spokenSumName, spokenSum.spokenSumTags]));
for (const table of spokenVocabularies) {
  const engineTags = engineSums.get(wireSumNameOf(table));
  if (!engineTags) throw new Error(`the engine speaks no sum named ${wireSumNameOf(table)}`);
  const pageTags = spokenTagsOf(table);
  const unlearned = engineTags.filter((wireTag) => !pageTags.includes(wireTag));
  const invented  = pageTags.filter((wireTag) => !engineTags.includes(wireTag));
  if (unlearned.length > 0 || invented.length > 0)
    throw new Error(`the ${wireSumNameOf(table)} table disagrees with the engine`
      + (unlearned.length > 0 ? ` — constructors the page never learned: ${unlearned.join(', ')}` : '')
      + (invented.length > 0 ? ` — spellings the engine does not speak: ${invented.join(', ')}` : ''));
}

// The baked surface is the engine's own words from bake time; only word-for-word agreement keeps it a transcription.
const engineSpokenSurface = JSON.parse(probeBytes('surface').toString()).envelopeAnswer.Right;
if (JSON.stringify(engineSpokenSurface) !== JSON.stringify(engineSurface))
  throw new Error('page/engine-surface.mjs disagrees with the engine — rebake it: make web-bake-surface');

let renderedCount = 0, peeledCount = 0, refusedCount = 0;
for (const patchPath of patchPaths) {
  const inspected = askProbe('inspect', patchPath).envelopeAnswer;
  if ('Left' in inspected) {
    if (typeof inspected.Left.spokenErrorSentence !== 'string') throw new Error(`${patchPath}: a refusal with no sentence`);
    refusedCount += 1;
    continue;
  }
  mustRender(`${patchPath} info readout`, infoReadoutMarkup(inspected.Right, 'CHECK'));
  embeddedContentsOf(inspected.Right);
  if (!Array.isArray(inspected.Right.infoUndeclaredTextFields))
    throw new Error(`${patchPath}: the encoding gate's signal is missing`);

  const explanation = askProbe('analyze', patchPath).envelopeAnswer.Right;
  const analysis = explanation.explanationAnalysis;
  const regions = analysisRegionsOf(analysis);
  mustRender(`${patchPath} info-plus readout`, infoReadoutMarkup(explanation.explanationInfo, 'CHECK'));
  mustRender(`${patchPath} overview`, structureOverviewMarkup(regions, explanation.explanationInfo.infoLines));
  const model = heatModel(regions, analysis.analysisSummary);
  if (model) {
    mustRender(`${patchPath} heat bar`, heatBarMarkup(model));
    heatCaption(model, 0);
    heatCaption(model, model.bucketCount - 1);
  }
  for (const aside of analysisAsidesMarkup(analysis)) if (aside) mustRender(`${patchPath} aside`, aside);
  for (const blob of embeddedContentMarkup(explanation.explanationInfo)) mustRender(`${patchPath} blob`, blob);
  mustRender(`${patchPath} walk`, walkMarkup(regions, Math.min(regions.length, 3000)));

  const identified = askProbe('identify', patchPath).envelopeAnswer.Right;
  const spokenUndo = identified.spokenIdentityUndo;
  if (!spokenTagsOf(UndoAnswer).includes(spokenUndo))
    throw new Error(`${patchPath}: an undo answer the page doesn't know: ${spokenUndo}`);

  mustRender(`${patchPath} apply verdict`,
    applyCardFor(identified, askProbe('check-apply', patchPath, romPath).envelopeAnswer.Right));

  if (spokenUndo === UndoAnswer.PatchIsItsOwnReverse || spokenUndo === UndoAnswer.PatchCarriesUndoData) {
    const appliedAct = splitAct(probeBytes('apply', patchPath, romPath, declarationPaths.apply));
    if (!('Right' in appliedAct.envelope.envelopeAnswer))
      throw new Error(`${patchPath}: the census rom does not take this patch — ${appliedAct.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
    mustRender(`${patchPath} patched voice`, patchedVoice({ spoken: appliedAct.envelope.envelopeAnswer.Right,
      advisories: [], downloadName: 'rom', downloadHref: '', inputReframed: false }));
    const patchedPath = join(declarationDir, 'patched.bin');
    writeFileSync(patchedPath, appliedAct.tail);

    // the patched output stands in for a wrong rom, driving the differs arms
    mustRender(`${patchPath} apply verdict, wrong rom`,
      applyCardFor(identified, askProbe('check-apply', patchPath, patchedPath).envelopeAnswer.Right));
    const rightRom = askProbe('check-undo', patchPath, patchedPath).envelopeAnswer.Right;
    mustRender(`${patchPath} undo verdict`, undoCardFor(identified, rightRom, 'EnforceVerification'));
    const wrongRom = askProbe('check-undo', patchPath, romPath).envelopeAnswer.Right;
    mustRender(`${patchPath} undo verdict, wrong rom`, undoCardFor(identified, wrongRom, 'EnforceVerification'));
    mustRender(`${patchPath} undo verdict, wrong rom, verification off`, undoCardFor(identified, wrongRom, 'SkipVerification'));

    const undoAct = splitAct(probeBytes('undo', patchPath, patchedPath, declarationPaths.undo));
    if (!('Right' in undoAct.envelope.envelopeAnswer))
      throw new Error(`${patchPath}: the peel refused in the census — ${undoAct.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
    mustRender(`${patchPath} reverted voice`, revertedVoice({ spoken: undoAct.envelope.envelopeAnswer.Right,
      advisories: [], downloadName: 'rom', downloadHref: '' }));
    peeledCount += 1;
  }

  renderedCount += 1;
}

// The create lanes: a real pair drives the ready check, the act, and the bottled voice;
// the same pair grows, so aiming it at PPF1 drives a blocked verdict through the gap renderer.
const grownPath = join(declarationDir, 'grown.bin');
writeFileSync(grownPath, Buffer.concat([readFileSync(romPath), Buffer.alloc(16, 0xAB)]));

const readyVerdict = askProbe('check-create', romPath, grownPath).envelopeAnswer.Right;
if (readyVerdict.tag !== 'SpokenReady')
  throw new Error(`the census pair does not bottle as BPS: ${JSON.stringify(readyVerdict)}`);

const blockedDeclarationPath = declarationPathFor('check-create-blocked', plainCreateDeclaration('CreateDirect', 'CreatePPF1'));
const blockedVerdict = JSON.parse(probeBytes('check-create', romPath, grownPath, blockedDeclarationPath).toString()).envelopeAnswer.Right;
if (blockedVerdict.tag !== 'SpokenBlocked')
  throw new Error('a growing PPF1 pair judged Ready in the census');
mustRender('blocked check voice', blockedVoice(blockedVerdict.contents));

const createdAct = splitAct(probeBytes('create', romPath, grownPath, declarationPaths.create));
if (!('Right' in createdAct.envelope.envelopeAnswer))
  throw new Error(`the census create refused — ${createdAct.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
if (createdAct.tail.length === 0) throw new Error('the census create wrote no patch bytes');
mustRender('bottled voice', bottledVoice({ formatName: 'BPS', advisories: [], downloadName: 'grown.bps', downloadHref: '' }));

// The convert lanes: the minted BPS asks for its source and converts with it; a minted IPS converts alone.
// The probe seats the convert pair as PATCH DECLARATION [SOURCE].
const plainConvertDeclaration = (formatTag, formatConstructor, sourceFraming) => ({
  declaredConvertTargetFormat: { tag: formatTag, contents: formatConstructor },
  declaredConvertSourceFraming: sourceFraming,
  declaredConvertVerificationPolicy: 'EnforceVerification',
  declaredConvertMetadata: { requestedFileIdDiz: { tag: 'InheritFileIdDiz' },
                             requestedEmbeddedBlob: { tag: 'InheritEmbeddedBlob' } },
  declaredConvertConstraints: { requestedSMCShape: 'AllowAnyTruncationShape' },
  declaredConvertMetadataEncoding: 'utf-8',
  declaredConvertDialects: { requestedPatchOrigin: 'OriginPC' },
});

const mintedBpsPath = join(declarationDir, 'minted.bps');
writeFileSync(mintedBpsPath, createdAct.tail);
const sourcelessUpsDecl = declarationPathFor('convert-to-ups',
                                             plainConvertDeclaration('CreateDifferential', 'CreateUPS', null));
const withSourceUpsDecl = declarationPathFor('convert-to-ups-with-source',
                                             plainConvertDeclaration('CreateDifferential', 'CreateUPS', { tag: 'TakeInputAsIs' }));

const blockedConvert = JSON.parse(probeBytes('check-convert', mintedBpsPath, sourcelessUpsDecl).toString()).envelopeAnswer.Right;
if (blockedConvert.tag !== 'SpokenBlocked')
  throw new Error('a source-less BPS conversion judged Ready in the census');
mustRender('blocked convert voice', blockedVoice(blockedConvert.contents));

const readyConvert = JSON.parse(probeBytes('check-convert', mintedBpsPath, withSourceUpsDecl, romPath).toString()).envelopeAnswer.Right;
if (readyConvert.tag !== 'SpokenReady')
  throw new Error(`the census BPS does not convert with its source in hand: ${JSON.stringify(readyConvert)}`);

const convertedWithSource = splitAct(probeBytes('convert', mintedBpsPath, withSourceUpsDecl, romPath));
if (!('Right' in convertedWithSource.envelope.envelopeAnswer))
  throw new Error(`the census with-source convert refused — ${convertedWithSource.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
if (convertedWithSource.tail.length === 0) throw new Error('the with-source convert wrote no patch bytes');

const mintedIpsDecl = declarationPathFor('create-ips', plainCreateDeclaration('CreateDirect', 'CreateIPS'));
const mintedIpsAct = splitAct(probeBytes('create', romPath, grownPath, mintedIpsDecl));
if (!('Right' in mintedIpsAct.envelope.envelopeAnswer))
  throw new Error(`the census IPS create refused — ${mintedIpsAct.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
const mintedIpsPath = join(declarationDir, 'minted.ips');
writeFileSync(mintedIpsPath, mintedIpsAct.tail);
const directDecl = declarationPathFor('convert-to-ips32', plainConvertDeclaration('CreateDirect', 'CreateIPS32', null));
const convertedDirect = splitAct(probeBytes('convert', mintedIpsPath, directDecl));
if (!('Right' in convertedDirect.envelope.envelopeAnswer))
  throw new Error(`the census direct convert refused — ${convertedDirect.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
if (convertedDirect.tail.length === 0) throw new Error('the direct convert wrote no patch bytes');
mustRender('converted voice', convertedVoice({ formatName: 'IPS32', advisories: [], downloadName: 'minted.ips32', downloadHref: '' }));

// A forewarning lane: an over-long title toward NINJA2 answers Ready with the coming truncation spoken beside it.
const forewarnedDecl = declarationPathFor('check-create-forewarned', {
  ...plainCreateDeclaration('CreateDifferential', 'CreateNINJA2'),
  declaredCreateMetadata: { requestedFileIdDiz: { tag: 'InheritFileIdDiz' },
                            requestedEmbeddedBlob: { tag: 'InheritEmbeddedBlob' },
                            requestedTitle: { encodedTextEncoding: 'utf-8',
                                              encodedTextContent: 'T'.repeat(4000) } },
});
const forewarned = JSON.parse(probeBytes('check-create', romPath, grownPath, forewarnedDecl).toString());
if (forewarned.envelopeAdvisories.length === 0)
  throw new Error('the over-long NINJA2 title raised no forewarning');
for (const advisory of advisoryMarkup(forewarned.envelopeAdvisories)) mustRender('forewarning', advisory);

console.log(`render census: ${spokenVocabularies.length} vocabulary tables audited against the engine's own, `
  + 'the baked surface matched the engine word for word, '
  + `${renderedCount} patches rendered whole, ${peeledCount} peels spoken, ${refusedCount} refused with a sentence, `
  + 'create checked both ways and bottled with a forewarning spoken, convert asked both ways and re-bottled both lanes, '
  + 'and a ROM type reshaped the rom both ways, its header put back once and let go once');

// A ROM type applies the patch to a canonical form of the rom, so the verdicts describe bytes nobody handed over
// and the page must say so before speaking them. No fixture carries one, so both restore disciplines are built here.

const normalizationBody = Buffer.from(
  Array.from({ length: 0x8000 }, (_, offset) => (offset * 7 + 11) & 0xFF));
const normalizationBodyChanged = Buffer.from(normalizationBody);
normalizationBodyChanged.fill(0xEE, 0x40, 0x60);

const wrappedRom = (name, wrapper, body) => {
  const path = join(declarationDir, name);
  writeFileSync(path, Buffer.concat([wrapper, body]));
  return path;
};
const iNESHeader = Buffer.concat([Buffer.from('NES\x1a', 'binary'), Buffer.alloc(12)]);
const smartCardHeader = Buffer.alloc(0x200);

const romTypeCreateDeclaration = (verbKey, formatTag, formatConstructor, platform) =>
  declarationPathFor(verbKey, {
    ...plainCreateDeclaration(formatTag, formatConstructor),
    declaredCreateMetadata: { requestedFileIdDiz: { tag: 'InheritFileIdDiz' },
                              requestedEmbeddedBlob: { tag: 'InheritEmbeddedBlob' },
                              requestedRomType: platform },
  });

const mintedNormalizingPatch = (name, originalPath, modifiedPath, createDeclarationPath) => {
  const minted = splitAct(probeBytes('create', originalPath, modifiedPath, createDeclarationPath));
  if (!('Right' in minted.envelope.envelopeAnswer))
    throw new Error(`the ${name} normalizing create refused — ${minted.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
  const path = join(declarationDir, `${name}.patch`);
  writeFileSync(path, minted.tail);
  return path;
};

const reshapedApply = (name, patchPath, sourcePath) => {
  const applied = splitAct(probeBytes('apply', patchPath, sourcePath, declarationPaths.apply));
  if (!('Right' in applied.envelope.envelopeAnswer))
    throw new Error(`the ${name} normalizing apply refused — ${applied.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
  const spoken = applied.envelope.envelopeAnswer.Right;
  const advisories = applied.envelope.envelopeAdvisories;
  if (spoken.spokenPatchedRomStanding !== 'VerdictsWithheldReshaped')
    throw new Error(`the ${name} apply did not reshape: ${spoken.spokenPatchedRomStanding}`);
  if (!advisories.some((advisory) => advisory.spokenAdvisory.tag === 'RomImageNormalized'))
    throw new Error(`the ${name} apply reshaped without narrating a normalization`);
  return { spoken, advisories, outputLength: applied.tail.length,
           voice: markupOf(patchedVoice({ spoken, advisories, downloadName: 'rom', downloadHref: '',
                                          inputReframed: false })) };
};

const nesRestored = reshapedApply('NES',
  mintedNormalizingPatch('nes', wrappedRom('nes-original.nes', iNESHeader, normalizationBody),
                         wrappedRom('nes-modified.nes', iNESHeader, normalizationBodyChanged),
                         romTypeCreateDeclaration('create-nes', 'CreateDifferential', 'CreateNINJA2', 'PlatformNES')),
  join(declarationDir, 'nes-original.nes'));

const gameBoyDropped = reshapedApply('Game Boy',
  mintedNormalizingPatch('gb', wrappedRom('gb-original.gb', smartCardHeader, normalizationBody),
                         wrappedRom('gb-modified.gb', smartCardHeader, normalizationBodyChanged),
                         romTypeCreateDeclaration('create-gb', 'CreateDirect', 'CreateNINJA1', 'PlatformGB')),
  join(declarationDir, 'gb-original.gb'));

if (!nesRestored.advisories.some((advisory) => advisory.spokenAdvisory.tag === 'RomImageContentRestored'))
  throw new Error('the NES apply restored nothing, so the put-back arm went unrendered');
if (gameBoyDropped.advisories.some((advisory) => advisory.spokenAdvisory.tag === 'RomImageContentRestored'))
  throw new Error('the Game Boy apply restored something, so the dropped arm went unrendered');
if (nesRestored.outputLength !== iNESHeader.length + normalizationBody.length)
  throw new Error('the NES output did not come back wearing its header');
if (gameBoyDropped.outputLength !== normalizationBody.length)
  throw new Error('the Game Boy output did not come back without its header');
if (!nesRestored.voice.includes('went back on'))
  throw new Error('the restored voice did not say the wrapping came back');
if (!gameBoyDropped.voice.includes('cleaned-up form'))
  throw new Error('the dropped voice did not say the cleaned-up form is what returns');
