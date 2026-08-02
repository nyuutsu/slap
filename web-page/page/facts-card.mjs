// What slap knows, said the moment it knows it: the rom's facts appear when the rom does,
// and the verdict the moment a patch sits beside it — apply asks "is this the rom the patch expects?",
// undo asks "did this rom come out of it?". The verdicts are the engine's ('checkApply' / 'checkUndo');
// the cards only put them into sentences.

import { html, nothing } from '../vendor/lit-html/lit-html.js';
import { Verdict, matcherOver } from './engine-vocabulary.mjs';
import { base64ToHex, crc32Hex, checkKindNoun, humanByteSize, matchVerbFor, proseList } from './readouts.mjs';
import { mismatchSentence } from './verification-speech.mjs';

const factsFrame = (file, facts, verdictRow) => html`<div class="facts-card">
  <div class="file-line">
    <span class="file-name">${file.name}</span>
    <span class="file-size">${humanByteSize(file.size)}</span>
  </div>
  ${facts ? html`<div class="hashes">
    CRC32&nbsp; <b>${crc32Hex(facts.romCRC32)}</b><br>
    MD5&nbsp;&nbsp;&nbsp; <b>${base64ToHex(facts.romMD5)}</b><br>
    SHA1&nbsp;&nbsp; <b>${base64ToHex(facts.romSHA1)}</b>
  </div>` : nothing}
  ${verdictRow}
</div>`;

/* ------------------------------------------------------------------ apply ---- */

// Consoles cross as engine names; the surface's rows carry the display names beside them, so the join is a lookup, never a guess.
const consolePhrase = (engineNames, consoleRows) =>
  engineNames
    .map((engineName) => consoleRows.find((row) => row.describedConsoleHeader === engineName)?.consoleName ?? engineName)
    .join(' / ');

const rescueMotion = (find) => find.rescueAdjustment === 'HeaderComesOff' ? 'comes off' : 'goes on';

const rescueStory = (rescue, consoleRows, verificationEnforced, framingUntouched) => {
  if (rescue.length === 0)
    return html`<p class="rescue-line">No header arrangement reconciles them. This is most likely a different rom.
      If you'd rather apply it anyway, <i>skip verification</i> does exactly that.</p>`;
  if (rescue.length > 1)
    return html`<p class="rescue-line">More than one header arrangement reconciles them:</p>
      ${rescue.map((find) => html`<p class="rescue-way">· a <b>${consolePhrase(find.rescueConsoles, consoleRows)}</b>
        header ${rescueMotion(find)}</p>`)}
      <p class="rescue-line">Only one is how your copy really is, and the patch's checks can't tell which.</p>`;

  const [find] = rescue;
  if (verificationEnforced && framingUntouched)
    return html`<p class="rescue-line">But it matches once a <b>${consolePhrase(find.rescueConsoles, consoleRows)}</b>
      header ${rescueMotion(find)}. That happens before patching, and your file on disk stays as it is.
      The change is only to what goes in, never to what comes out.</p>`;
  return html`<p class="rescue-line">It would match once a <b>${consolePhrase(find.rescueConsoles, consoleRows)}</b>
    header ${rescueMotion(find)}. Verification is off, so nothing is adjusted unasked,
    and these bytes go in as they are.</p>`;
};

const applyWeighingRow = matcherOver(Verdict, {
  Matches: (checkKinds, { apply }) => html`<div class="verdict good"><span class="mark">✓</span>
      <span>This is the rom <b>${apply.patch.name}</b> expects.
        Its ${proseList(checkKinds.map(checkKindNoun))} ${matchVerbFor(checkKinds)}.</span></div>`,

  Uncheckable: (_declaredNothing, { apply }) => html`<div class="verdict shrug"><span class="mark">~</span>
      <span><b>${apply.patch.name}</b> doesn't record which rom it's for,
        so there's nothing to check yours against.</span></div>`,

  Differs: (mismatches, { apply, consoleRows }) => html`<div class="verdict puzzled"><span class="mark">!</span>
    <span><b>${apply.patch.name}</b> isn't sure about this rom.
      ${mismatches.map((mismatch) => html`<span class="mismatch-line">${mismatchSentence(mismatch)}</span>`)}
      ${rescueStory(apply.sourceReport.sourceRescue, consoleRows,
                    apply.verificationPolicy === 'EnforceVerification',
                    apply.framing.tag === 'TakeInputAsIs')}
    </span></div>`,
});

const applyVerdictRow = (apply, consoleRows) => {
  if (!apply.patch)
    return html`<div class="verdict waiting"><span class="mark">·</span>
      <span>Once a patch is in, you'll see here whether this rom is the one it wants.</span></div>`;
  // a file that read as no patch at all, and one that read as a patch it cannot use, are both the voice's story
  if (apply.patchIdentity?.refused || apply.patchIdentity?.answered?.spokenIdentityImpediment) return null;
  if (!apply.sourceReport)
    return html`<div class="verdict waiting"><span class="mark">·</span><span>checking…</span></div>`;
  return applyWeighingRow(apply.sourceReport.sourceVerdict, { apply, consoleRows });
};

export const applyFactsCardMarkup = (apply, consoleRows) =>
  apply.rom ? factsFrame(apply.rom, apply.romFacts, applyVerdictRow(apply, consoleRows)) : html``;

/* ------------------------------------------------------------------- undo ---- */

const undoWeighingRow = matcherOver(Verdict, {
  Matches: (checkKinds, { undo }) => html`<div class="verdict good"><span class="mark">✓</span>
      <span>This is the rom <b>${undo.patch.name}</b> produces.
        Its ${proseList(checkKinds.map(checkKindNoun))} ${matchVerbFor(checkKinds)}.</span></div>`,

  Uncheckable: (_declaredNothing, { undo }) => html`<div class="verdict shrug"><span class="mark">~</span>
      <span><b>${undo.patch.name}</b> doesn't record what it produces,
        so there's nothing to check yours against.</span></div>`,

  Differs: (mismatches, { undo }) => html`<div class="verdict puzzled"><span class="mark">!</span>
    <span><b>${undo.patch.name}</b> doesn't recognize this as a rom it produces.
      ${mismatches.map((mismatch) => html`<span class="mismatch-line">${mismatchSentence(mismatch)}</span>`)}
      <p class="rescue-line">${undo.verificationPolicy === 'EnforceVerification'
        ? html`If you'd rather peel it anyway, <i>skip verification</i> does exactly that.`
        : html`Verification is off, so the patch comes off these bytes as they are.`}</p>
    </span></div>`,
});

const undoVerdictRow = (undo, patchPeels) => {
  if (!undo.patch)
    return html`<div class="verdict waiting"><span class="mark">·</span>
      <span>Once a patch is in, you'll see here whether this rom came out of it.</span></div>`;
  // the eligibility story is the voice's
  if (undo.patchIdentity && !patchPeels) return null;
  if (!undo.verdict)
    return html`<div class="verdict waiting"><span class="mark">·</span><span>checking…</span></div>`;
  return undoWeighingRow(undo.verdict, { undo });
};

export const undoFactsCardMarkup = (undo, patchPeels) =>
  undo.patched ? factsFrame(undo.patched, undo.patchedFacts, undoVerdictRow(undo, patchPeels)) : html``;
