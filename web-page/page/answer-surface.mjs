// The one home for slap's voice: everything the engine says — refusals, success verdicts,
// advisories riding either — lands in this box, and the fellow beside it gives it a face.

import { html } from '../vendor/lit-html/lit-html.js';
import { Verdict, Standing, matcherOver } from './engine-vocabulary.mjs';
import { admonitionMarkup } from './controls.mjs';
import { buildStamp } from './build-stamp.mjs';
import { spokenRefusalMarkup, spokenAdvisorySentence } from './verification-speech.mjs';
import { dialectControls } from './dialect-controls.mjs';
import { constraintLabel } from './constraint-controls.mjs';
import { fieldLabel } from './metadata-controls.mjs';

// The fellow's short lines, lowercase and unhurried. One clause each; the cards carry the detail.
export const voiceLines = {
  stillGettingSet: 'still waking up. hand me those again in a second?',
  resting: 'hand me a patch and a rom. i\'ll sort out which is which.',
  romOnly: 'got the rom. now i need the patch that goes on it.',
  patchOnly: 'got the patch. now i need the rom it\'s for.',
  sizingUp: 'sizing them up…',
  match: 'yep, they match. slap it on?',
  headeredButRescued: 'almost. these two are off by a header. i\'ll square that up.',
  differsHopeless: 'hmm. that doesn\'t look like the rom this patch wants.',
  differsManyWays: 'huh. more than one header arrangement fits these two. that\'s rare. i\'ll take your word for which.',
  uncheckable: 'this patch doesn\'t say which rom it wants, so i can\'t check this one for you.',
  verificationOff: 'alright, no checking. i\'ll take the files just as they are.',
  undoResting: 'hand me a patch and the rom it made. i\'ll take the patch off.',
  undoRomOnly: 'got the rom. now i need the patch to peel off it.',
  undoSelfInverse: 'this patch is its own reverse. now i need the rom it made.',
  undoCarriesData: 'this patch carries its undo data. now i need the rom it made.',
  undoOneWay: 'this patch is one-way. it says how to get there, but not how to get back.',
  undoDataOmitted: 'this one was made without its undo data, so the way back isn\'t in it.',
  undoMatch: 'yep, they match. peel it off?',
  undoDiffers: 'hmm. that doesn\'t look like the rom this patch makes.',
  undoUncheckable: 'this patch doesn\'t say what it makes, so i can\'t check this one for you.',
  bottling: 'bottling it…',
  rebottling: 'rebottling it…',
  patching: 'patching…',
  peeling: 'peeling it off…',
  cancelled: 'okay, stopped. nothing was made.',
  infoResting: 'hand me a patch and i\'ll tell you what it says about itself.',
  explainResting: 'hand me a patch and i\'ll show you what it does.',
  reading: 'reading…',
  infoRead: 'here\'s what it says about itself.',
  explainRead: 'here\'s the shape of it.',
  sortsAsRom: 'that one reads as a rom. got a patch for me?',
  createResting: 'hand me the before and the after and i\'ll bottle the difference.',
  createOriginalOnly: 'got the original. now i need the changed one.',
  createModifiedOnly: 'got the changed one. now i need the original.',
  createNeedsFormat: 'both in hand. what should i bottle it as?',
  createReady: 'all set. bottle it?',
  convertResting: 'hand me a patch and i\'ll rebottle it as another format.',
  convertRomOnly: 'got the rom. now i need the patch to rebottle.',
  convertNeedsFormat: 'what should it become?',
  convertReady: 'all set. rebottle it?',
};

export const refusalOpenings = {
  apply:   'i couldn\'t patch it.',
  undo:    'i couldn\'t peel it.',
  create:  'i couldn\'t bottle it.',
  convert: 'i couldn\'t rebottle it.',
  fell:    'something broke on my end.',
};

export const plainVoice = (line) => html`<p class="plain-line">${line}</p>`;

// The empty-handed voice: the verb's inducement, and under it the fellow explaining the story mark.
export const restingVoice = (inducement) => html`${plainVoice(inducement)}
  <p class="plain-line story-hint">rest on anything wearing a <span class="story-mark">*</span>
    or <span class="pill-mark">this outline</span> and i'll explain it.</p>`;

export const workingVoice = (line) => html`
  <p class="plain-line"><span class="breathing">${line}</span> <span class="elapsed" id="work-elapsed"></span></p>
  <div class="afterward"><button type="button" class="quiet-button" data-action="cancel-run">cancel</button></div>`;

const bootFailureSentences = (bootFailureShape) => {
  switch (bootFailureShape.tag) {
    case 'WebAssemblySwitchedOff': return html`
      <p class="plain-line">this browser has webassembly switched off.
        that's the bit i'm made of, so i can't do anything here.</p>
      ${admonitionMarkup('note', html`that's nearly always because of a setting, rather than the browser not
        supporting it. in edge it's the <code>enhanced security mode</code>, and adding this site to that
        mode's exceptions turns webassembly back on.`)}`;
    case 'ReactorNeverArrived': return html`
      <p class="plain-line">the rest of me didn't download. a reload usually sorts that out.</p>
      <p class="refusal boot-detail">${bootFailureShape.detail}</p>`;
    case 'BootFell': return html`
      <p class="plain-line">i couldn't get myself started in this browser.</p>
      <p class="refusal boot-detail">${bootFailureShape.detail}</p>`;
  }
};

export const bootFailureVoice = (bootFailureShape) => html`
  ${bootFailureSentences(bootFailureShape)}
  <p class="boot-stamp">${buildStamp}</p>`;

export const advisoryMarkup = (advisories) => advisories.map((advisory) => admonitionMarkup(
  advisory.spokenAdvisorySeverity === 'SeverityNote' ? 'note' : 'warning', spokenAdvisorySentence(advisory)));

const inputVerdictSentence = matcherOver(Verdict, {
  // A reframed input's own sentence is the advisory below: the verdicts describe the framed form,
  // and quoting the handed file's hash beside them would misattribute the match.
  Matches: (_checkKinds, { inputReframed }) =>
    (inputReframed ? null : html`<p class="said">yep, that was the right rom.</p>`),
  Differs: () =>
    html`<p class="said">that wasn't the rom this patch wanted.</p>`,
  Uncheckable: () =>
    html`<p class="said">this patch doesn't say which rom it wants, so there was nothing to check yours against.</p>`,
});

const outputVerdictSentence = matcherOver(Verdict, {
  Matches: (_checkKinds, { anInputSentencePrecedes }) =>
    html`<p class="said">${anInputSentencePrecedes ? 'and ' : ''}what came out is just what the patch promised.</p>`,
  Differs: (_mismatches, { anInputSentencePrecedes }) =>
    html`<p class="said">${anInputSentencePrecedes ? 'and ' : ''}what came out isn't what the patch promised.</p>`,
  // Only reached beside a checkable input: a patch silent on both sides is spoken whole, above.
  Uncheckable: (_declaredNothing, { anInputSentencePrecedes }) =>
    html`<p class="said">${anInputSentencePrecedes ? 'and ' : ''}that's everything this patch checks.
      it records the rom going in, not the one coming out.</p>`,
});

// What the verdicts below are about, whenever the patch worked on a form of the rom other than the file itself.
// The advisories beneath name the procedure; this only has to say that one ran, and whether anything came back.
const reshapingSentence = (advisories) => {
  const spokenTags = advisories.map((advisory) => advisory.spokenAdvisory.tag);
  if (!spokenTags.includes('RomImageNormalized')) return null;
  const somethingRestored = spokenTags.includes('RomImageContentRestored');
  return html`<p class="said">this patch was made against a cleaned-up form of the rom,
    so i cleaned yours up the same way before patching.
    ${somethingRestored ? 'what i set aside went back on afterwards.' : "what's coming back is that cleaned-up form."}</p>`;
};

const verdictSentences = (spoken, inputReframed, reshaping) => {
  const input = spoken.spokenPatchedRomInputVerdict;
  const output = spoken.spokenPatchedRomOutputVerdict;

  // The verdicts weigh the normalized form; they may only be spoken once a sentence has said so.
  if (spoken.spokenPatchedRomStanding !== Standing.DescribeTheFiles && !reshaping)
    return [html`<p class="said">Here's your patched rom.</p>`];

  const sentences = [reshaping].filter(Boolean);

  if (input.tag === Verdict.Uncheckable && output.tag === Verdict.Uncheckable)
    return [...sentences, html`<p class="said">no checks in this patch, so there was nothing to compare.
      if your rom was right, so is this.</p>`];

  const inputSentence = inputVerdictSentence(input, { inputReframed });
  if (inputSentence) sentences.push(inputSentence);
  const outputSentence = outputVerdictSentence(output, { anInputSentencePrecedes: inputSentence !== null });
  if (outputSentence) sentences.push(outputSentence);
  return sentences;
};

const downloadRowMarkup = (downloadName, downloadHref) => html`
  <div class="download">
    <span class="arrow">↓</span>
    <a href="${downloadHref}" download="${downloadName}">${downloadName}</a>
    <span class="aside">is in your downloads</span>
  </div>`;

export const patchedVoice = ({ spoken, advisories, downloadName, downloadHref, inputReframed }) => html`
  <p class="headline">patched! <span class="sparkle" aria-hidden="true">✦ ✧</span></p>
  ${verdictSentences(spoken, inputReframed, reshapingSentence(advisories))}
  ${advisoryMarkup(advisories)}
  ${downloadRowMarkup(downloadName, downloadHref)}
  <div class="afterward"><button type="button" class="chip" data-action="start-over">do another</button></div>`;

const handedVerdictSentence = matcherOver(Verdict, {
  Matches: () =>
    html`<p class="said">yep, that was the rom this patch makes.</p>`,
  Differs: () =>
    html`<p class="said">that wasn't the rom this patch makes.</p>`,
  Uncheckable: () =>
    html`<p class="said">this patch doesn't say what it makes, so there was nothing to check yours against.</p>`,
});

// A handed-rom sentence always comes first, so these open with "and": every handed verdict speaks one.
const restoredVerdictSentence = matcherOver(Verdict, {
  Matches: () =>
    html`<p class="said">and what came back is the original this patch was made from.</p>`,
  Differs: () =>
    html`<p class="said">and what came back isn't the original this patch records.</p>`,
  Uncheckable: () =>
    html`<p class="said">and that's everything this patch checks.
      it records the rom it makes, not the one it started from.</p>`,
});

// Undo's two verdicts read crosswise: the handed rom is weighed as the patch's product,
// and the reverted rom as the original it was made from.
const revertedSentences = (spoken) => {
  const handed = spoken.spokenRevertedRomInputVerdict;
  const restored = spoken.spokenRevertedRomOutputVerdict;

  if (handed.tag === Verdict.Uncheckable && restored.tag === Verdict.Uncheckable)
    return [html`<p class="said">no checks in this patch, so there was nothing to compare.
      if that was the rom it makes, this is the original.</p>`];

  return [handedVerdictSentence(handed), restoredVerdictSentence(restored)];
};

export const revertedVoice = ({ spoken, advisories, downloadName, downloadHref }) => html`
  <p class="headline">peeled! <span class="sparkle" aria-hidden="true">✦ ✧</span></p>
  ${revertedSentences(spoken)}
  ${advisoryMarkup(advisories)}
  ${downloadRowMarkup(downloadName, downloadHref)}
  <div class="afterward"><button type="button" class="chip" data-action="start-over">do another</button></div>`;

export const refusalVoice = ({ tag, spokenError, sentence, advisories }, verbName) => html`
  ${plainVoice(refusalOpenings[tag === 'Fell' ? 'fell' : verbName])}
  ${spokenRefusalMarkup(spokenError, sentence, verbName)}
  ${advisoryMarkup(advisories)}
  <div class="afterward"><button type="button" class="chip" data-action="start-over">start over</button></div>`;

export const bottledVoice = ({ formatName, advisories, downloadName, downloadHref }) => html`
  <p class="headline">bottled! <span class="sparkle" aria-hidden="true">✦ ✧</span></p>
  <p class="said">that's the difference between your two files, bottled as ${formatName}.</p>
  ${advisoryMarkup(advisories)}
  ${downloadRowMarkup(downloadName, downloadHref)}
  <div class="afterward">
    <button type="button" class="chip" data-action="look-inside">look inside it</button>
    <button type="button" class="chip" data-action="start-over">do another</button>
  </div>`;

export const convertedVoice = ({ formatName, advisories, downloadName, downloadHref }) => html`
  <p class="headline">converted! <span class="sparkle" aria-hidden="true">✦ ✧</span></p>
  <p class="said">same patch, ${formatName} this time. it patches the same way.</p>
  ${advisoryMarkup(advisories)}
  ${downloadRowMarkup(downloadName, downloadHref)}
  <div class="afterward">
    <button type="button" class="chip" data-action="look-inside">look inside it</button>
    <button type="button" class="chip" data-action="start-over">do another</button>
  </div>`;

// An emit check's way out, in the words of the page's own controls — total over the engine's sum,
// and a resolution the page hasn't met yet shows its bare tag rather than nothing.
const resolutionLine = (resolution) => {
  switch (resolution.tag) {
    case 'ProvideSourceRom':       return html`give me the rom it's for and i can work out the rest.`;
    case 'ChooseDifferentFormat':  return html`another format could manage this one.`;
    case 'ChooseTargetPreserving': return html`some other formats would keep it.`;
    case 'DropConstraint':         return html`switching <i>${constraintLabel(resolution.contents)}</i> off would do it.`;
    case 'DropMetadataField':      return html`clearing <i>${fieldLabel(resolution.contents)}</i> would do it.`;
    case 'ProvideMetadataField':   return html`filling in <i>${fieldLabel(resolution.contents)}</i> would do it.`;
    case 'AmendMetadataField':     return html`a shorter <i>${fieldLabel(resolution.contents)}</i> would fit.`;
    case 'DropDialect':            return html`switching
      <i>${dialectControls[resolution.contents]?.controlLabel ?? resolution.contents}</i> off would do it.`;
    default:                       return resolution.tag;
  }
};

// A blocked emit is not a refusal of the whole request — each gap speaks slap's sentence, then its ways out.
export const blockedVoice = (gaps) => html`${gaps.map((gap) => html`
  <p class="refusal">${gap.spokenGapReason.spokenErrorSentence}</p>
  ${gap.spokenGapResolutions.map((resolution) => html`<p class="way-out">${resolutionLine(resolution)}</p>`)}`)}`;
