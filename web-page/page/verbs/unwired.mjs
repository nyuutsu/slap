// A verb the page hasn't wired up yet: its sentence stands inert, so the tab still teaches the operation,
// and it says plainly that the terminal does the work today. Each of these dissolves when its real module lands.

import { html } from './../dom.mjs';
import { inertSlotMarkup } from './../controls.mjs';
import { voiceLines, plainVoice } from './../answer-surface.mjs';
import { verbWord, flagWord, placeholderWord } from './../command-tutor.mjs';

const restingSentences = {
  create: () => html`<p class="sentence">bottle the difference between ${inertSlotMarkup('original')}
    and ${inertSlotMarkup('modified')} as ${inertSlotMarkup('format')}</p>`,
  convert: () => html`<p class="sentence">convert ${inertSlotMarkup('patch')} to ${inertSlotMarkup('format')}</p>`,
};

const restingCommandWords = {
  create: () => [verbWord('slap'), verbWord('create'), flagWord('--format'), placeholderWord('FORMAT'),
                 placeholderWord('ORIGINAL'), placeholderWord('MODIFIED'), placeholderWord('OUTPUT')],
  convert: () => [verbWord('slap'), verbWord('convert'), placeholderWord('PATCH'), flagWord('--to'),
                  placeholderWord('FORMAT'), placeholderWord('OUTPUT')],
};

export const makeUnwiredVerb = (host, verbName) => ({
  stageMarkup: () => html`
    ${restingSentences[verbName]()}
    <div class="group"><p class="aside">This tab isn't wired up yet — the page grows verb by
      verb, and <b>slap ${verbName}</b> in a terminal does it today.</p></div>`,
  voiceMarkup: () => plainVoice(host.notice()
    ?? (host.hasSession() ? voiceLines.unwired : voiceLines.gettingSet)),
  commandWords: restingCommandWords[verbName],
  actMarkup: () => html``,
  admitDroppedFile: () => { host.setNotice(voiceLines.unwired); host.render(); },
  admitPickedFile: () => {},
  askAgain: () => {},
  actions: {},
  settings: {},
});
