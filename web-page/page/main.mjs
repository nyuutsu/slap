// slap's page root. One shared footing — the verb on stage, the session, the ask epoch, the transient notice —
// and a table of verb modules, each the same small shape, the way slap's formats are each the same family of declarations.
// The root owns wiring and IO; every verb owns its own state, stage, voice, and tutor fold;
// and every fact on screen is asked of the engine through the session, because the page holds opinions, never knowledge.

import { markupOf, html } from './dom.mjs';
import { openReactorSession, answerOf, advisoriesOf, ReactorJobCancelled } from './reactor-session.mjs';
import { seatMascot } from './mascot.mjs';
import { voiceLines, plainVoice } from './answer-surface.mjs';
import { commandMarkup } from './command-tutor.mjs';
import { makeApplyVerb } from './verbs/apply.mjs';
import { makeUndoVerb } from './verbs/undo.mjs';
import { makeInfoVerb, makeExplainVerb } from './verbs/reads.mjs';
import { makeUnwiredVerb } from './verbs/unwired.mjs';

// apply, create and explain are what slap is for; the rest are welcome, just quieter.
const headlinerVerbs = ['apply', 'create', 'explain'];
const quieterVerbs = ['undo', 'convert', 'info'];
const allVerbs = [...headlinerVerbs, ...quieterVerbs];

let currentVerb = 'apply';
let session = null;
let epoch = 0;
let noticeLine = null;   // one transient line (e.g. "cancelled"); any fresh interaction retires it
let fellow = null;

const element = (id) => document.getElementById(id);

/* ------------------------------------------------------------- the host ---- */
/* What a verb module may do to the world, and all of it: ask the engine, run a job,
   guard an answer against staleness, move the fellow, speak a notice, and ask for a render. */

const openEnvelope = (envelope) => ({ ...answerOf(envelope), advisories: advisoriesOf(envelope) });

const host = {
  // resolves to the opened envelope — { answered | refused, advisories } — or null before the session is up
  ask: (wireVerb, seats) => session && session.ask(wireVerb, seats).then(({ envelope }) => openEnvelope(envelope)),
  startJob: (wireVerb, seats) => session && session.startJob(wireVerb, seats),
  openEnvelope,
  wasCancelled: (jobFailure) => jobFailure instanceof ReactorJobCancelled,

  // an answer from an older epoch arrives about files no longer on screen, and is dropped unheard
  wheneverStillCurrent: (deliver) => {
    const epochAtAsk = epoch;
    return (value) => { if (epoch === epochAtAsk) { deliver(value); render(); } };
  },
  supersedeAsks: () => { epoch += 1; },

  // a failed ask — a reactor trap, a Worker death — surfaces in the voice box;
  // a swallowed failure would leave a "reading…" line up forever, promising an answer that is never coming
  askFailed: (askFailure) => {
    console.error(askFailure);
    noticeLine = String(askFailure?.message ?? askFailure);
    fellow?.droop();
    render();
  },

  notice: () => noticeLine,
  setNotice: (line) => { noticeLine = line; },
  render: () => render(),
  surface: () => session?.surface ?? null,
  hasSession: () => session !== null,
  fellow: Object.fromEntries(['nod', 'lean', 'smile', 'droop', 'settle', 'beginFidgeting']
    .map((mood) => [mood, () => fellow?.[mood]()])),
  download: (href, downloadName) => {
    const link = document.createElement('a');
    link.href = href; link.download = downloadName;
    link.click();
  },
  stage: () => element('stage'),
};

const verbs = {
  apply: makeApplyVerb(host),
  undo: makeUndoVerb(host),
  info: makeInfoVerb(host),
  explain: makeExplainVerb(host),
  create: makeUnwiredVerb(host, 'create'),
  convert: makeUnwiredVerb(host, 'convert'),
};

/* --------------------------------------------------------------- render ---- */

const verbTabsMarkup = () => {
  const tab = (verbName, quieter) => html`<button
    class="verb${quieter ? ' lesser' : ''}${verbName === currentVerb ? ' on' : ''}"
    data-action="choose-verb" data-verb="${verbName}">${verbName}</button>`;
  return html`${headlinerVerbs.map((verbName) => tab(verbName, false))}<span class="verb-gap"></span>
    ${quieterVerbs.map((verbName) => tab(verbName, true))}`;
};

const render = () => {
  const verb = verbs[currentVerb];
  element('verbs').innerHTML = markupOf(verbTabsMarkup());
  element('stage').innerHTML = markupOf(verb.stageMarkup());
  element('voice').innerHTML = markupOf(verb.voiceMarkup());
  element('command').innerHTML = markupOf(commandMarkup(verb.commandWords()));
  element('act').innerHTML = markupOf(verb.actMarkup());
};

/* --------------------------------------------------------------- wiring ---- */

const filePicker = element('file-picker');

document.addEventListener('click', (event) => {
  const control = event.target.closest('[data-action]');
  if (!control) return;
  noticeLine = null;
  const action = control.dataset.action;
  if (action === 'choose-verb') {
    // the hash is the one authority on the shown verb; arriveAtVerb answers its change
    location.hash = control.dataset.verb;
    return;
  }
  if (action === 'pick-file') {
    filePicker.dataset.seat = control.dataset.seat;
    filePicker.click();
    return;
  }
  verbs[currentVerb].actions[action]?.(control.dataset);
});

document.addEventListener('change', (event) => {
  const setting = event.target.dataset.setting;
  if (!setting) return;
  noticeLine = null;
  verbs[currentVerb].settings[setting]?.(event.target.checked);
});

filePicker.addEventListener('change', () => {
  const [file] = filePicker.files;
  if (file) {
    noticeLine = null;
    verbs[currentVerb].admitPickedFile(filePicker.dataset.seat, file);
  }
  filePicker.value = '';
});

/* Drop anywhere: the whole page is the target, and slap sorts the files itself. */
const routeDroppedFiles = async (files) => {
  if (!session) return;
  noticeLine = null;
  for (const file of [...files].slice(0, 2)) {
    const { answered } = await host.ask('classify', { file });
    verbs[currentVerb].admitDroppedFile(answered, file);
  }
};

let dragDepth = 0;
const veil = element('dropveil');
addEventListener('dragenter', (event) => { event.preventDefault(); dragDepth += 1; veil.hidden = false; });
addEventListener('dragover', (event) => event.preventDefault());
addEventListener('dragleave', () => { if ((dragDepth -= 1) <= 0) { dragDepth = 0; veil.hidden = true; } });
addEventListener('drop', (event) => {
  event.preventDefault();
  dragDepth = 0; veil.hidden = true;
  if (event.dataTransfer.files.length) routeDroppedFiles(event.dataTransfer.files).catch(host.askFailed);
});

/* ----------------------------------------------------------------- boot ---- */

const verbNamedByHash = () => {
  const named = location.hash.slice(1);
  return allVerbs.includes(named) ? named : null;
};

const arriveAtVerb = (verbName) => {
  if (verbName === currentVerb) return;
  currentVerb = verbName;
  noticeLine = null;
  fellow?.settle();
  render();
};

addEventListener('hashchange', () => arriveAtVerb(verbNamedByHash() ?? 'apply'));

const countWord = (formatCount) => formatCount === 20 ? 'twenty' : String(formatCount);

currentVerb = verbNamedByHash() ?? 'apply';
render();
seatMascot(element('fellow')).then((seated) => { fellow = seated; }).catch(console.error);
openReactorSession().then((openedSession) => {
  session = openedSession;
  element('format-count').textContent = countWord(session.surface.surfaceFormats.length);
  Object.values(verbs).forEach((verb) => verb.askAgain());
  render();
}).catch((bootFailure) => {
  console.error(bootFailure);
  element('voice').innerHTML = markupOf(plainVoice(voiceLines.bootFailed));
});
