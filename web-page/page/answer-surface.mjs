// The one home for slap's voice: everything the engine says — refusals, success verdicts,
// advisories riding either — lands in this box, and the fellow beside it gives it a face.

import { html } from './dom.mjs';
import { checkKindNoun, crc32Hex, matchVerbFor, proseList } from './readouts.mjs';
import { spokenRefusalMarkup, spokenAdvisorySentence } from './verification-speech.mjs';

// The fellow's short lines, lowercase and unhurried. One clause each; the cards carry the detail.
export const voiceLines = {
  gettingSet: 'getting set up…',
  resting: 'drop a patch and a rom — i\'ll sort out which is which.',
  romOnly: 'got the rom — now the patch that goes on it.',
  patchOnly: 'got the patch — now the rom it\'s for.',
  sizingUp: 'sizing them up…',
  match: 'yep — that\'s the one. slap it on.',
  headeredButRescued: 'almost — it\'s headered. i\'ll set the header aside and patch what\'s under it.',
  differsHopeless: 'hmm — that doesn\'t look like the rom this patch wants.',
  differsManyWays: 'a header\'s involved, but more than one arrangement fits — pick one below.',
  uncheckable: 'this patch doesn\'t say which rom it wants, so i can\'t check it for you.',
  verificationOff: 'verification\'s off — i\'ll take these bytes exactly as handed.',
  undoResting: 'drop a patch and the rom it made — i\'ll take the patch back off.',
  undoRomOnly: 'got the rom — now the patch to peel off it.',
  undoSelfInverse: 'this patch is its own reverse — now the rom it made.',
  undoCarriesData: 'this patch carries its undo data — now the rom it made.',
  undoOneWay: 'this patch is one-way — it says how to get there, not how to get back.',
  undoDataOmitted: 'this patch was made without undo data — that was its author\'s choice, not something you can recover.',
  undoMatch: 'yep — that\'s the rom this patch makes. peel it off.',
  undoDiffers: 'hmm — that doesn\'t look like the rom this patch makes.',
  undoUncheckable: 'this patch doesn\'t say what it makes, so i can\'t check this rom for you.',
  working: 'working…',
  cancelled: 'cancelled — nothing was written.',
  unwired: 'this tab isn\'t wired up yet — the terminal does it today.',
  bootFailed: 'this browser couldn\'t start slap — it needs WebAssembly and module workers.',
  infoResting: 'hand me a patch — i\'ll tell you what it says about itself.',
  explainResting: 'hand me a patch — i\'ll show you what it does.',
  reading: 'reading…',
  infoRead: 'here\'s what it says about itself.',
  explainRead: 'here\'s the shape of it.',
  sortsAsRom: 'that one reads as a rom — this tab wants a patch.',
};

export const plainVoice = (line) => html`<p class="plain-line">${line}</p>`;

export const workingVoice = () => html`
  <p class="plain-line">${voiceLines.working}</p>
  <div class="afterward"><button class="quiet-button" data-action="cancel-run">cancel</button></div>`;

export const advisoryMarkup = (advisories) => advisories.map((advisory) => html`
  <p class="advisory${advisory.spokenAdvisorySeverity === 'SeverityNote' ? ' note' : ''}">${spokenAdvisorySentence(advisory)}</p>`);

const verdictSentences = (spoken, romCrcHexValue, inputReframed) => {
  const input = spoken.spokenPatchedRomInputVerdict;
  const output = spoken.spokenPatchedRomOutputVerdict;

  if (spoken.spokenPatchedRomStanding !== 'VerdictsDescribeTheFiles')
    return [html`<p class="said">Here's your patched rom.</p>`];

  if (input.tag === 'VerdictUncheckable' && output.tag === 'VerdictUncheckable')
    return [html`<p class="said">This patch carries no checks at all, so there was nothing to prove —
      given your files, this is the correct result for them.</p>`];

  const sentences = [];
  // A reframed input's own sentence is the advisory below: the verdicts describe the framed form,
  // and quoting the handed file's hash beside them would misattribute the match.
  if (input.tag === 'VerdictMatches' && !inputReframed) {
    sentences.push(input.contents.includes('DeclaredCRC32') && romCrcHexValue
      ? html`<p class="said">Your rom hashed to <code>${romCrcHexValue}</code> — exactly what the patch expected.</p>`
      : html`<p class="said">Your rom matches everything the patch declares about it —
          its ${proseList(input.contents.map(checkKindNoun))}.</p>`);
  }
  if (input.tag === 'VerdictDiffers')
    sentences.push(html`<p class="said">Your rom isn't what the patch declared — you asked slap to go ahead anyway, so it did.</p>`);
  if (input.tag === 'VerdictUncheckable')
    sentences.push(html`<p class="said">The patch declares nothing about its source, so there was nothing to check your rom against.</p>`);

  if (output.tag === 'VerdictMatches')
    sentences.push(html`<p class="said">${sentences.length ? 'And the' : 'The'} result is exactly what the patch promised. It worked.</p>`);
  if (output.tag === 'VerdictDiffers')
    sentences.push(html`<p class="said">The result differs from what the patch promised — with verification off, it was written anyway.</p>`);

  return sentences;
};

const downloadRowMarkup = (downloadName, downloadHref) => html`
  <div class="download">
    <span class="arrow">↓</span>
    <a href="${downloadHref}" download="${downloadName}">${downloadName}</a>
    <span class="aside">is in your downloads</span>
  </div>`;

export const patchedVoice = ({ spoken, advisories, downloadName, downloadHref, romCrc32, inputReframed }) => html`
  <p class="headline">patched! <span class="sparkle">✦ ✧</span></p>
  ${verdictSentences(spoken, romCrc32 === null ? null : crc32Hex(romCrc32), inputReframed)}
  ${advisoryMarkup(advisories)}
  ${downloadRowMarkup(downloadName, downloadHref)}
  <div class="afterward"><button class="chip" data-action="start-over">do another</button></div>`;

// Undo's two verdicts read crosswise: the handed rom is weighed as the patch's product,
// and the reverted rom as the original it was made from.
const revertedSentences = (spoken) => {
  const handed = spoken.spokenRevertedRomInputVerdict;
  const restored = spoken.spokenRevertedRomOutputVerdict;

  if (handed.tag === 'VerdictUncheckable' && restored.tag === 'VerdictUncheckable')
    return [html`<p class="said">This patch carries no checks at all, so there was nothing to prove —
      given your files, this is the correct reversal for them.</p>`];

  const sentences = [];
  if (handed.tag === 'VerdictMatches')
    sentences.push(html`<p class="said">Your rom is exactly what this patch produces —
      its ${proseList(handed.contents.map(checkKindNoun))} ${matchVerbFor(handed.contents)}.</p>`);
  if (handed.tag === 'VerdictDiffers')
    sentences.push(html`<p class="said">Your rom isn't what the patch produces — you asked slap to go ahead anyway, so it did.</p>`);
  if (handed.tag === 'VerdictUncheckable')
    sentences.push(html`<p class="said">The patch doesn't record what it produces, so your rom went in unchecked.</p>`);

  if (restored.tag === 'VerdictMatches')
    sentences.push(html`<p class="said">${sentences.length ? 'And the' : 'The'} reverted rom is exactly
      the original the patch was made from. It worked.</p>`);
  if (restored.tag === 'VerdictDiffers')
    sentences.push(html`<p class="said">The reverted rom differs from the original the patch records —
      with verification off, it was written anyway.</p>`);
  if (restored.tag === 'VerdictUncheckable')
    sentences.push(html`<p class="said">The patch doesn't record the original, so the reverted rom is yours to judge.</p>`);

  return sentences;
};

export const revertedVoice = ({ spoken, advisories, downloadName, downloadHref }) => html`
  <p class="headline">peeled! <span class="sparkle">✦ ✧</span></p>
  ${revertedSentences(spoken)}
  ${advisoryMarkup(advisories)}
  ${downloadRowMarkup(downloadName, downloadHref)}
  <div class="afterward"><button class="chip" data-action="start-over">do another</button></div>`;

export const refusalVoice = ({ spokenError, sentence, advisories }, verbName) => html`
  ${spokenRefusalMarkup(spokenError, sentence, verbName)}
  ${advisoryMarkup(advisories)}
  <div class="afterward"><button class="chip" data-action="start-over">start over</button></div>`;
