// The control shapes every verb builds its stage from, one home each.

import { html } from './dom.mjs';

export const groupMarkup = (heading, body) => html`<div class="group"><h3>${heading}</h3>${body}</div>`;

// One garment for every aside the context raises, so text that came from what you just chose looks the part.
const admonitionFaces = { note: 'art/note.webp', warning: 'art/warning.webp' };
export const admonitionMarkup = (kind, spokenContents) => html`<p class="advisory${kind === 'note' ? ' note' : ''}">
  <img class="advisory-face" src="${admonitionFaces[kind]}" alt="" width="20" height="20">
  <span>${spokenContents}</span></p>`;

// The checkbox is dressed as a chip but kept, hidden and real,
// so the toggling, the label click and the announced state stay the browser's own.
export const toggleMarkup = ({ id, setting, checked, label, why, field }) => html`<div class="toggle">
  <input class="toggle-input" type="checkbox" id="${id}" data-setting="${setting}" ${field && html`data-field="${field}"`} ${checked && html`checked`}>
  <label class="chip toggle-chip" for="${id}">${label}</label>
  ${why && html`<span class="why">— ${why}</span>`}
</div>`;

// An empty slot wears its role word, so the empty sentence teaches the operation.

export const inertSlotMarkup = (roleWord) => html`<span class="slot empty inert">${roleWord}</span>`;

export const swapSeatsMarkup = html`<p class="swap-line"><button class="quiet-button"
  data-action="swap-seats">the wrong way round? swap them</button></p>`;

export const seatSlotMarkup = (seat, roleWord, file, chipWord) => file
  ? html`<button class="slot filled" data-action="pick-file" data-seat="${seat}">${file.name}</button>${
      chipWord && html`<span class="format-chip">${chipWord}</span>`}`
  : html`<button class="slot empty" data-action="pick-file" data-seat="${seat}">${roleWord}</button>`;

// While an act runs, the seats it reads are held: shown, not clickable.
export const heldSeatMarkup = (file, chipWord) => html`<span class="slot filled inert">${file.name}</span>${
  chipWord && html`<span class="format-chip">${chipWord}</span>`}`;

// Two same-type seats keep their role words in view once filled — order alone is ambiguous — as a whisper under the name.
export const roleWhisperedSlotMarkup = (seat, roleWord, file) => file
  ? html`<span class="slot-stack"><button class="slot filled" data-action="pick-file"
      data-seat="${seat}">${file.name}</button><span class="role-whisper">${roleWord}</span></span>`
  : html`<button class="slot empty" data-action="pick-file" data-seat="${seat}">${roleWord}</button>`;

// The header directive control: apply's source and convert's --with wear the same one.
export const headerControlMarkup = (framing, consoleRows) => {
  const chosenMode = framing.tag;
  const modeChip = (tag, label) => html`<button class="chip${chosenMode === tag ? ' on' : ''}"
    aria-pressed="${chosenMode === tag}" data-action="set-framing" data-framing="${tag}">${label}</button>`;
  return groupMarkup("the rom's header", html`
    <div class="choice-row">
      ${modeChip('TakeInputAsIs', 'take it as it is')}
      ${modeChip('RemoveHeader', 'it has one — take it off')}
      ${modeChip('AddHeader', "it hasn't got one — pretend it has")}
    </div>
    ${chosenMode !== 'TakeInputAsIs' && html`
      <p class="choice-label">which console</p>
      <div class="choice-row">${consoleRows.map((row) => html`<button
        class="chip${framing.console?.consoleToken === row.consoleToken ? ' on' : ''}"
        aria-pressed="${framing.console?.consoleToken === row.consoleToken}"
        data-action="set-console" data-console="${row.consoleToken}">${row.consoleName}</button>`)}</div>
      <p class="aside">slap can't know whether your copy is headered — you can. It'll say what it did.</p>`}`);
};

// The console a fresh directive starts on; snes, because headered roms usually are snes roms.
export const preseededConsoleRow = (consoleRows) =>
  consoleRows.find((row) => row.consoleToken === 'snes') ?? consoleRows[0];

// The encodings unfold the way the quieter formats do, and an encoding already chosen holds them open:
// the one on show is the answer to "did it take", which a closed drawer would have to repeat.
export const encodingPickerMarkup = (encodingFamilies, chosenEncoding, moreEncodingsOpen) => {
  const chosenIsUncommon = chosenEncoding !== 'utf-8';
  const encodingsOpen = moreEncodingsOpen || chosenIsUncommon;
  return groupMarkup('text encoding', html`
    <p class="aside explainer">Some formats store text — descriptions, author names — without
    recording its encoding, and slap reads it as UTF-8. If a patch came from, say, a Japanese release and
    its text looks wrong, that's something slap can't know but you might: pick the encoding and slap re-reads.</p>
    ${!chosenIsUncommon && html`<button class="more-chip${encodingsOpen ? ' open' : ''}"
      aria-expanded="${encodingsOpen}" data-action="more-encodings">
      ${encodingsOpen ? 'fewer encodings' : 'choose an encoding'}</button>`}
    ${encodingsOpen && encodingFamilies.map((family) => html`<div class="encoding-family">
      <span class="family-label">${family.advertisedFamilyLabel}</span>
      <div class="choice-row">${family.advertisedFamilyMembers.map((token) => html`<button
        class="chip${chosenEncoding === token ? ' on' : ''}"
        aria-pressed="${chosenEncoding === token}"
        data-action="set-encoding" data-token="${token}">${token}</button>`)}</div>
    </div>`)}`);
};
