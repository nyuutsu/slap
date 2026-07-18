// What slap knows, said the moment it knows it: the rom's facts appear when the rom does,
// and the verdict — is this the rom the patch expects? — the moment a patch sits beside it.
// The verdict is the engine's ('checkApply'); the card only puts it into sentences.

import { html } from './dom.mjs';
import { base64ToHex, crc32Hex, checkKindNoun, humanByteSize, proseList } from './readouts.mjs';
import { mismatchSentence } from './verification-speech.mjs';

// Consoles cross as engine names; the surface's console rows carry the display names beside
// them, so the join is a lookup, never a guess.
const consolePhrase = (engineNames, consoleRows) =>
  engineNames
    .map((engineName) => consoleRows.find((row) => row.describedConsoleHeader === engineName)?.consoleName ?? engineName)
    .join(' / ');

const rescueMotion = (find) => find.rescueAdjustment === 'HeaderComesOff' ? 'comes off' : 'goes on';

const rescueStory = (rescue, consoleRows, verificationEnforced, framingUntouched) => {
  if (rescue.length === 0)
    return html`<p class="rescue-line">slap tried every header it knows and none of them reconcile these two —
      this is most likely a different rom. You can still <i>skip verification</i> below and apply it as handed.</p>`;
  if (rescue.length > 1)
    return html`<p class="rescue-line">More than one header arrangement reconciles them:</p>
      ${rescue.map((find) => html`<p class="rescue-way">· a <b>${consolePhrase(find.rescueConsoles, consoleRows)}</b>
        header ${rescueMotion(find)}</p>`)}
      <p class="rescue-way">slap won't pick between them — choose one with the header control below.</p>`;

  const [find] = rescue;
  if (verificationEnforced && framingUntouched)
    return html`<p class="rescue-line">But it matches once a <b>${consolePhrase(find.rescueConsoles, consoleRows)}</b>
      header ${rescueMotion(find)} — so that's what apply will do. The header is set aside before patching; your file
      on disk stays as it is, and the patched rom won't carry it.</p>`;
  return html`<p class="rescue-line">It would match once a <b>${consolePhrase(find.rescueConsoles, consoleRows)}</b>
    header ${rescueMotion(find)} — but verification is off, so slap will apply to these bytes exactly as handed.</p>`;
};

const verdictRow = (apply, consoleRows) => {
  if (!apply.patch)
    return html`<div class="verdict waiting"><span class="mark">·</span>
      <span>Pick a patch and slap will check this rom against it.</span></div>`;
  if (!apply.sourceReport)
    return html`<div class="verdict waiting"><span class="mark">·</span><span>checking…</span></div>`;

  const verdict = apply.sourceReport.sourceVerdict;
  const patchName = apply.patch.name;

  if (verdict.tag === 'VerdictMatches')
    return html`<div class="verdict good"><span class="mark">✓</span>
      <span>This is the rom <b>${patchName}</b> expects — its ${proseList(verdict.contents.map(checkKindNoun))} match.</span></div>`;

  if (verdict.tag === 'VerdictUncheckable')
    return html`<div class="verdict shrug"><span class="mark">~</span>
      <span><b>${patchName}</b> doesn't record which rom it's for, so slap can't check this one for you.</span></div>`;

  const verificationEnforced = apply.verificationPolicy === 'EnforceVerification';
  const framingUntouched = apply.framing.tag === 'TakeInputAsIs';
  return html`<div class="verdict puzzled"><span class="mark">!</span>
    <span><b>${patchName}</b> isn't sure about this rom.
      ${verdict.contents.map((mismatch) => html`<span class="mismatch-line">${mismatchSentence(mismatch)}</span>`)}
      ${rescueStory(apply.sourceReport.sourceRescue, consoleRows, verificationEnforced, framingUntouched)}
    </span></div>`;
};

export const factsCardMarkup = (apply, consoleRows) => {
  if (!apply.rom) return html``;
  const facts = apply.romFacts;
  return html`<div class="facts-card">
    <div class="file-line">
      <span class="file-name">${apply.rom.name}</span>
      <span class="file-size">${humanByteSize(apply.rom.size)}</span>
    </div>
    ${facts && html`<div class="hashes">
      CRC32&nbsp; <b>${crc32Hex(facts.romCRC32)}</b><br>
      MD5&nbsp;&nbsp;&nbsp; <b>${base64ToHex(facts.romMD5)}</b><br>
      SHA1&nbsp;&nbsp; <b>${base64ToHex(facts.romSHA1)}</b>
    </div>`}
    ${verdictRow(apply, consoleRows)}
  </div>`;
};
