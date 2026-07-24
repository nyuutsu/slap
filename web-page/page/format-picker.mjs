// The surface says what formats exist; the opinion — which formats get tiles, and with what words — lives here.
// A format with no words still shows, under "more formats", unadorned.

import { html, nothing } from '../vendor/lit-html/lit-html.js';
import { groupMarkup, admonitionMarkup, chipRadioMarkup } from './controls.mjs';

const tileTokens = ['bps', 'xdelta3', 'ppf3', 'rfc-vcdiff'];

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

const chosenFormatNoteMarkup = (chosenToken) => {
  const note = formatNotes[chosenToken];
  return note ? admonitionMarkup('note', note) : nothing;
};

export const pickerStories = {
  MoreFormats:
    'every format slap can write is on this shelf — the quieter ones unfold as chips. '
    + 'reach for one when the patcher or community on the receiving end expects it; '
    + 'otherwise the tiles above are the recommendation.',
};

// A tile is the format radio group's grandest label; the quiet chips below answer to the same group.
const tileMarkup = (row, chosenToken) => html`<input class="choice-input" type="radio" name="format"
  id="format-${row.formatToken}" data-setting="format" value="${row.formatToken}"
  .checked=${row.formatToken === chosenToken}>
  <label class="tile${row.formatToken === chosenToken ? ' on' : ''}"
    for="format-${row.formatToken}">
  <span class="tile-name">${row.formatDisplayName}</span>
  <span class="tile-copy">${tileCopy[row.formatToken] ?? ''}</span></label>`;

export const formatPickerMarkup = (surfaceRows, chosenToken, moreFormatsOpen) => {
  if (surfaceRows.length === 0) return null;
  const rowByToken = (token) => surfaceRows.find((row) => row.formatToken === token);
  const tileRows = tileTokens.map(rowByToken).filter(Boolean);
  const spotlit = new Set(tileTokens);
  const quieterRows = surfaceRows.filter((row) => !spotlit.has(row.formatToken));
  const chosenIsQuieter = quieterRows.some((row) => row.formatToken === chosenToken);
  const moreOpen = moreFormatsOpen || chosenIsQuieter;
  return groupMarkup('format', html`
    <fieldset class="choice-fieldset"><legend class="visually-hidden">format</legend>
    <div class="tiles">${tileRows.map((row) => tileMarkup(row, chosenToken))}</div>
    ${!chosenIsQuieter ? html`<button type="button" class="more-chip${moreOpen ? ' open' : ''}" aria-expanded="${moreOpen}"
      data-action="more-formats" data-story="MoreFormats">
      ${moreOpen ? 'fewer formats' : `more formats (${quieterRows.length})`}</button>` : nothing}
    ${moreOpen ? html`<div class="choice-row">${quieterRows.map((row) =>
      chipRadioMarkup({ groupName: 'format', setting: 'format', token: row.formatToken,
                        checked: row.formatToken === chosenToken, label: row.formatToken }))}</div>` : nothing}
    </fieldset>
    ${chosenFormatNoteMarkup(chosenToken)}`);
};
