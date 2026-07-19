// The surface says what formats exist; the opinion — which tiles to recommend, and with what words — lives here.
// A format with no words still shows, under "more formats", unadorned.

import { html } from './dom.mjs';
import { groupMarkup } from './controls.mjs';

const recommendedTokens = ['bps', 'xdelta3', 'ppf3'];
const curioToken = 'rfc-vcdiff';

const tileCopy = {
  bps: "The safe default. Checks it's patching the right file, survives size changes, and every modern patcher reads it.",
  xdelta3: 'For big files. Compresses the patch, so disc images and large roms stay manageable.',
  ppf3: 'For PlayStation disc images. Can carry undo data and a FILE_ID.DIZ.',
  'rfc-vcdiff': 'The VCDIFF standard itself. It works — but nothing out there applies it except slap. Here because it is interesting, not because you should ship it.',
};

// A note describes; it does not rank. Only some formats carry one, and silence is fine.
const formatNotes = {
  'rfc-vcdiff': 'RFC 3284, straight from the standard. slap is the only patcher we know of that reads one.',
  ips: 'The lingua franca: almost every patcher ever written can apply an IPS. Offsets are 24 bits wide, so a record reaches about 16 MB.',
  ips32: 'IPS with 32-bit offsets, reaching well past the 16 MB mark.',
  ppf1: 'Icarus of Paradox, for the PlayStation scene — the first of the three PPFs.',
  ppf2: "Paradox's second pass: adds a validation block and room for a FILE_ID.DIZ.",
  ups: 'byuu\'s symmetric format: a UPS patch is its own reverse, so it always peels back off.',
  xdelta1: "Joshua MacDonald's original xdelta, 1997 to 2003.",
};

export const formatNoteMarkup = (chosenToken) => {
  const note = formatNotes[chosenToken];
  return note && html`<p class="format-note"><span class="note-mark">note</span><span>${note}</span></p>`;
};

const tileMarkup = (row, chosenToken, curio) => html`<button
  class="tile${curio ? ' curio' : ''}${row.formatToken === chosenToken ? ' on' : ''}"
  aria-pressed="${row.formatToken === chosenToken}"
  data-action="choose-format" data-token="${row.formatToken}">
  <span class="tile-name">${row.formatDisplayName}</span>
  <span class="tile-copy">${tileCopy[row.formatToken] ?? ''}</span></button>`;

export const formatPickerMarkup = (surfaceRows, chosenToken, moreFormatsOpen) => {
  if (surfaceRows.length === 0) return null;
  const rowByToken = (token) => surfaceRows.find((row) => row.formatToken === token);
  const recommendedRows = recommendedTokens.map(rowByToken).filter(Boolean);
  const curioRow = rowByToken(curioToken);
  const spotlit = new Set([...recommendedTokens, curioToken]);
  const quieterRows = surfaceRows.filter((row) => !spotlit.has(row.formatToken));
  const chosenIsQuieter = quieterRows.some((row) => row.formatToken === chosenToken);
  const moreOpen = moreFormatsOpen || chosenIsQuieter;
  return groupMarkup('format', html`
    <div class="tiles">${recommendedRows.map((row) => tileMarkup(row, chosenToken, false))}</div>
    ${curioRow && tileMarkup(curioRow, chosenToken, true)}
    ${!chosenIsQuieter && html`<button class="quiet-button" data-action="more-formats">
      ${moreOpen ? 'fewer formats' : `more formats (${quieterRows.length})`}</button>`}
    ${moreOpen && html`<div class="choice-row">${quieterRows.map((row) => html`<button
      class="chip${row.formatToken === chosenToken ? ' on' : ''}"
      aria-pressed="${row.formatToken === chosenToken}"
      data-action="choose-format" data-token="${row.formatToken}">${row.formatToken}</button>`)}</div>`}`);
};
