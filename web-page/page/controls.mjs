// The control shapes every verb builds its stage from, one home each.

import { html } from './dom.mjs';

export const groupMarkup = (heading, body) => html`<div class="group"><h3>${heading}</h3>${body}</div>`;

export const toggleMarkup = ({ id, setting, checked, label, why }) => html`<div class="toggle">
  <input type="checkbox" id="${id}" data-setting="${setting}" ${checked && html`checked`}>
  <label for="${id}">${label}${why && html` <span class="why">— ${why}</span>`}</label>
</div>`;

// An empty slot wears its role word, so the empty sentence teaches the operation.

export const inertSlotMarkup = (roleWord) => html`<span class="slot empty inert">${roleWord}</span>`;

export const seatSlotMarkup = (seat, roleWord, file, chipWord) => file
  ? html`<button class="slot filled" data-action="pick-file" data-seat="${seat}">${file.name}</button>${
      chipWord && html`<span class="format-chip">${chipWord}</span>`}`
  : html`<button class="slot empty" data-action="pick-file" data-seat="${seat}">${roleWord}</button>`;
