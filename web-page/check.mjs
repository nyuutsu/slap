// The page's render census: every fixture patch's real envelopes, run under node through every renderer that reads them.
// A shape surprise — a null the shape allowed, an arm only one format exercises — throws here, not in someone's browser.
// `make web-check` runs it; new fixtures join for free.
//
//   node check.mjs <native-probe> <rom> <patches...>

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { markupOf } from './page/dom.mjs';
import { infoReadoutMarkup, embeddedContentsOf, embeddedContentMarkup,
         heatModel, heatBarMarkup, heatCaption, walkMarkup, structureOverviewMarkup,
         analysisRegionsOf, analysisAsidesMarkup } from './page/read-panels.mjs';
import { applyFactsCardMarkup, undoFactsCardMarkup } from './page/facts-card.mjs';
import { patchedVoice, revertedVoice } from './page/answer-surface.mjs';

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
                                           declaredInspectDialects: { requestedPPF1Origin: 'PPF1OriginPC' } }),
  analyze: declarationPathFor('analyze', { declaredAnalyzeMetadataEncoding: 'utf-8',
                                           declaredAnalyzeDialects: { requestedPPF1Origin: 'PPF1OriginPC' } }),
  identify: declarationPathFor('identify', { declaredIdentifyDialects: { requestedPPF1Origin: 'PPF1OriginPC' },
                                             declaredIdentifyMetadataEncoding: 'utf-8' }),
  apply: declarationPathFor('apply', { declaredApplyFraming: { tag: 'TakeInputAsIs' },
                                       declaredApplyVerificationPolicy: 'EnforceVerification',
                                       declaredApplyDialects: { requestedPPF1Origin: 'PPF1OriginPC' } }),
  undo: declarationPathFor('undo', { declaredUndoVerificationPolicy: 'EnforceVerification',
                                     declaredUndoDialects: { requestedPPF1Origin: 'PPF1OriginPC' } }),
};
// a check reads the act's own declaration
declarationPaths['check-undo'] = declarationPaths.undo;
declarationPaths['check-apply'] = declarationPaths.apply;

const probeBytes = (...probeArguments) => execFileSync(probePath, probeArguments, { maxBuffer: 1 << 30 });
const askProbe = (verb, ...seatPaths) => JSON.parse(probeBytes(verb, ...seatPaths, declarationPaths[verb]).toString());

// an act answers [u32 envelope length LE][envelope][tail]
const splitAct = (framedPayload) => {
  const envelopeLength = framedPayload.readUInt32LE(0);
  return { envelope: JSON.parse(framedPayload.subarray(4, 4 + envelopeLength).toString()),
           tail: framedPayload.subarray(4 + envelopeLength) };
};

const knownUndoAnswers = ['PatchIsItsOwnReverse', 'PatchCarriesUndoData', 'AuthorOmittedUndoData', 'FormatHasNoUndo'];

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
  if (!knownUndoAnswers.includes(spokenUndo))
    throw new Error(`${patchPath}: an undo answer the page doesn't know: ${spokenUndo}`);

  mustRender(`${patchPath} apply verdict`,
    applyCardFor(identified, askProbe('check-apply', patchPath, romPath).envelopeAnswer.Right));

  if (spokenUndo === 'PatchIsItsOwnReverse' || spokenUndo === 'PatchCarriesUndoData') {
    const appliedAct = splitAct(probeBytes('apply', patchPath, romPath, declarationPaths.apply));
    if (!('Right' in appliedAct.envelope.envelopeAnswer))
      throw new Error(`${patchPath}: the census rom does not take this patch — ${appliedAct.envelope.envelopeAnswer.Left.spokenErrorSentence}`);
    mustRender(`${patchPath} patched voice`, patchedVoice({ spoken: appliedAct.envelope.envelopeAnswer.Right,
      advisories: [], downloadName: 'rom', downloadHref: '', romCrc32: null, inputReframed: false }));
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

console.log(`render census: ${renderedCount} patches rendered whole, ${peeledCount} peels spoken, ${refusedCount} refused with a sentence`);
