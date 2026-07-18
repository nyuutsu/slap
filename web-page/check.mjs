// The page's render census: every fixture patch's real envelopes, driven through every read renderer under node.
// The renderers are pure markup folds, so anything that would wedge the page —
// a null the shape allowed, an arm only some format exercises — throws here instead of in someone's browser.
// `make web-check` runs it; new fixtures join for free.
//
//   node check.mjs <native-probe> <patches...>

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { markupOf } from './page/dom.mjs';
import { infoReadoutMarkup, embeddedContentsOf, embeddedContentMarkup,
         heatModel, heatBarMarkup, heatCaption, walkMarkup, structureOverviewMarkup,
         analysisRegionsOf, analysisAsidesMarkup } from './page/read-panels.mjs';

const [probePath, ...patchPaths] = process.argv.slice(2);
if (!probePath || patchPaths.length === 0) {
  console.error('usage: node check.mjs <native-probe> <patches...>');
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
};

const askProbe = (verb, patchPath) => JSON.parse(
  execFileSync(probePath, [verb, patchPath, declarationPaths[verb]], { maxBuffer: 1 << 30 }).toString());

const mustRender = (what, markup) => {
  if (typeof markupOf(markup) !== 'string') throw new Error(`${what} rendered nothing`);
};

let renderedCount = 0, refusedCount = 0;
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
  renderedCount += 1;
}

console.log(`render census: ${renderedCount} patches rendered whole, ${refusedCount} refused with a sentence`);
