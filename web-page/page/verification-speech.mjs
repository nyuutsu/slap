// The page's substitution shim for engine sentences, and the whole of it:
// the two tables below enumerate every place the page speaks instead of rendering what the engine said.
// A row earns its place only where the web must differ in substance, not tone —
// these name the page's "skip verification" control where the engine names a flag.
// Everything else crosses verbatim, so a warmed engine message reaches the page with no work here,
// and one that makes a row redundant means deleting the row, never syncing it.

import { html } from '../vendor/lit-html/lit-html.js';
import { crc32Hex, groupedCount } from './readouts.mjs';

// A mismatch's typed payload, said plainly. The two commonest kinds get their values spelled out;
// the rest name themselves rather than guess at a rendering the engine already owns.
export const mismatchSentence = (mismatch) => {
  switch (mismatch.tag) {
    case 'VerificationCRCMismatch': {
      const [, expected, actual] = mismatch.contents;
      return html`It expects a rom whose CRC32 is <code>${crc32Hex(expected)}</code> — this one's is <code>${crc32Hex(actual)}</code>.`;
    }
    case 'VerificationFileSizeMismatch': {
      const [, expected, actual] = mismatch.contents;
      return html`It expects ${groupedCount(expected)} bytes — this file is ${groupedCount(actual)}.`;
    }
    case 'VerificationFileSizeAdvisory': {
      const [expected, actual] = mismatch.contents;
      return html`It expects ${groupedCount(expected)} bytes — this file is ${groupedCount(actual)}.`;
    }
    default:
      return html`One of its declared checks (${mismatch.tag.replace(/^Verification/, '')}) doesn't agree with this file.`;
  }
};

// The same mismatch means a rom that isn't the patch's source on apply and convert's with lane,
// and one that isn't its product on undo — hence a row per verb.
const refusalOverrides = {
  VerificationFatal: {
    apply: (mismatch) => html`
      <p class="said">That rom isn't the one this patch declares — so nothing was written.</p>
      <p class="said">${mismatchSentence(mismatch)}</p>
      <p class="said"><i>skip verification</i>, up in the options, applies it anyway — the mismatches become warnings.</p>`,
    undo: (mismatch) => html`
      <p class="said">The rom doesn't match what this patch declares — so nothing was written.</p>
      <p class="said">${mismatchSentence(mismatch)}</p>
      <p class="said"><i>skip verification</i>, up in the options, peels it anyway — the mismatches become warnings.</p>`,
    convert: (mismatch) => html`
      <p class="said">That rom isn't the one this patch declares — so nothing was written.</p>
      <p class="said">${mismatchSentence(mismatch)}</p>
      <p class="said"><i>skip verification</i>, up in the options, converts with it anyway — the mismatches become warnings.</p>`,
  },
};

// Advisories the page speaks for, likewise.
const advisoryOverrides = {
  DeclaredCheckMismatched: (mismatch) => mismatchSentence(mismatch),
};

export const spokenRefusalMarkup = (spokenError, sentence, verbName) =>
  refusalOverrides[spokenError?.tag]?.[verbName]?.(spokenError.contents) ?? html`<p class="refusal">${sentence}</p>`;

export const spokenAdvisorySentence = (advisory) =>
  advisoryOverrides[advisory.spokenAdvisory.tag]?.(advisory.spokenAdvisory.contents)
    ?? html`${advisory.spokenAdvisorySentence}`;
