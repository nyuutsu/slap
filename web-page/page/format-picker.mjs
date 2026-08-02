// The surface says what formats exist; the opinion — which formats get tiles, and with what words — lives here.
// A format with no words still shows, under "more formats", unadorned.

import { html, nothing } from '../vendor/lit-html/lit-html.js';
import { groupMarkup, admonitionMarkup, chipRadioMarkup } from './controls.mjs';

const tileTokens = ['bps', 'xdelta3', 'ppf3', 'rfc-vcdiff'];

export const formatGroupId = 'format-group';

// The sentence's other blanks are seats: press one and it opens. This one is answered in the group below,
// so it wears that group's dress rather than a seat's underline, and points there instead of opening.
export const formatSeatMarkup = (chosenToken) => html`<button type="button"
  class="format-seat has-story${chosenToken ? ' chosen' : ''}"
  data-story="ChooseFormat" data-points-at="${formatGroupId}">${chosenToken ?? 'format'}</button>`;

const tileCopy = {
  bps: 'A safe default. Verifies the input, output, and itself, handles size changes, and is widely understood.',
  xdelta3: 'Popular, lots of features, and particularly good with large files.',
  ppf3: 'Designed with PlayStation disc images in mind. Can carry undo data and a description file.',
  'rfc-vcdiff': 'The VCDIFF standard, exactly. Considerable overlap with, but distinct from, xdelta3. Included as a curio.',
};

// A note describes; it does not rank. Only some formats carry one, and silence is fine.
const formatNotes = {
  ips:
    'The original. Nigh every patcher ever written can apply, and probably make, this. '
    + 'Can describe changes to roughly the first 16MiB of a file. '
    + 'In practice this means IPS is for files of size 16MiB or less.',
  ips32: 'IPS, but wider. Used internally by a certain Nintendo Switch firmware replacement.',
  ebp: "The format used by Lyrositor's EBPatcher. Basically IPS-with-metadata.",
  ups: "near/byuu's symmetric format: a UPS patch, when applied a second time, gives back the original file.",
  ppf1:
    'The first of three formats created by Icarus (of the "Paradox" warez/demoscene group), '
    + 'for the PlayStation scene.',
  ppf2:
    'The second of three formats created by Icarus (of the "Paradox" warez/demoscene group), '
    + 'for the PlayStation scene. Adds a validity check and room for a description file.',
  ppf4:
    'Created by Pyriel and used for their Suikoden-franchise-on-the-Playstation patches. '
    + 'First-class support for growing the output file; this is unusual, since the PlayStation is disc-based.',
  pmsr: 'The format used by Star Rod, a toolkit for editing the Paper Mario (N64) decompilation.',
  dps: 'Created by Deufeufeu for their Nintendo DS patches.',
  ninja1:
    'Derrick Sobodash\'s first format, 2004. Unusual in that it can carry a directive to '
    + '"put the input rom into a normalized form" (such as de-interleaving, removing headers, etc) before patching.',
  ninja2:
    'Derrick Sobodash\'s second format. Reversible, like UPS. Unusual in that it can carry a directive to '
    + '"put the input rom into a normalized form" (such as de-interleaving, removing headers, etc) before patching. '
    + 'Lots of metadata options.',
  gdiff: 'Submitted to the W3C by Marimba, Inc in 1997. Used for software updates.',
  bsdiff: 'Colin Percival\'s format, created for FreeBSD\'s binary updates and adopted by many update systems since.',
  xdelta1:
    'The first of Joshua MacDonald\'s xdeltas, from the late nineties. '
    + 'Its control data rides in EDSIO, a serialization framework of the author\'s own.',
  'aps-n64':
    'Silo & Fractal (of the "Black Bag" warez/demoscene group)\'s "Advanced Patching System". '
    + 'Designed with the N64 in mind. No relation to APS-GBA.',
  'aps-gba':
    'HackMew\'s "Alternate Patching System". Designed with the GBA in mind. No relation to APS-N64.',
  'rfc-vcdiff': html`Includes genuinely esoteric stuff that, to our knowledge, we are the first to implement
    an <i>encoder</i> for. Namely: when it makes the patch smaller, we'll include "custom code-tables"
    and/or use "vcd_target". Decoders for those parts exist but are obscure. Google made one.
    xdelta3 refuses them outright.`,
};

const chosenFormatNoteMarkup = (chosenToken) => {
  const note = formatNotes[chosenToken];
  return note ? admonitionMarkup('note', note) : nothing;
};

export const pickerStories = {
  TheBench:
    'nothing in here is required. whatever you leave blank, the format answers for itself. '
    + 'some of it changes what the patch says about itself, like a title or a note. '
    + 'the rest changes how it gets made.',
  SourceRom:
    'some patches carry everything i need to rebottle them. others want the rom they\'re for, '
    + 'and i\'ll say so under the blank if this one does. '
    + 'with the rom in hand, i apply the patch and bottle the difference fresh.',
  ChooseFormat:
    'this word fills itself in. the choosing happens where i\'m pointing.',
  MoreFormats:
    'every format i can write is here. '
    + 'the quiet ones are for when whoever\'s getting the patch expects one in particular. '
    + 'when nobody\'s asking, the ones i put up front are my recommendation.',
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
      aria-controls="quieter-formats" data-action="more-formats" data-story="MoreFormats">
      ${moreOpen ? 'show fewer formats' : `show more formats (${quieterRows.length})`}</button>` : nothing}
    <div class="choice-row" id="quieter-formats">${moreOpen ? quieterRows.map((row) =>
      chipRadioMarkup({ groupName: 'format', setting: 'format', token: row.formatToken,
                        checked: row.formatToken === chosenToken, label: row.formatDisplayName })) : nothing}</div>
    </fieldset>
    ${chosenFormatNoteMarkup(chosenToken)}`, formatGroupId);
};
