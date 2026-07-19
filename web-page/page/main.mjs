// slap's page root. Every fact on screen is asked of the engine: the page holds opinions, never knowledge.

import { markupOf, html } from './dom.mjs';
import { openReactorSession, classifyBootFailure, answerOf, advisoriesOf, ReactorJobCancelled } from './reactor-session.mjs';
import { seatMascot } from './mascot.mjs';
import { voiceLines, bootFailureVoice } from './answer-surface.mjs';
import { commandMarkup } from './command-tutor.mjs';
import { makeApplyVerb } from './verbs/apply.mjs';
import { makeUndoVerb } from './verbs/undo.mjs';
import { makeCreateVerb } from './verbs/create.mjs';
import { makeConvertVerb } from './verbs/convert.mjs';
import { makeInfoVerb, makeExplainVerb } from './verbs/reads.mjs';
import { wireMetadataBenchListeners } from './metadata-form.mjs';

// apply, create and explain are what slap is for; the rest are welcome, just quieter.
const headlinerVerbs = ['apply', 'create', 'explain'];
const quieterVerbs = ['undo', 'convert', 'info'];
const allVerbs = [...headlinerVerbs, ...quieterVerbs];

let currentVerb = 'apply';
let sessionStanding = { tag: 'SessionOpening' };
let epoch = 0;
let noticeLine = null;   // one transient line (e.g. "cancelled"); any fresh interaction retires it
let fellow = null;

const element = (id) => document.getElementById(id);

/* ------------------------------------------------------------- the host ---- */
/* What a verb module may do to the world, and all of it: ask the engine, run a job,
   guard an answer against staleness, move the fellow, speak a notice or a murmur, ask for a render,
   and hand a file it minted to explain. */

const openEnvelope = (envelope) => ({ ...answerOf(envelope), advisories: advisoriesOf(envelope) });

const sessionIfOpen = () => sessionStanding.tag === 'SessionOpen' ? sessionStanding.session : null;

const host = {
  // resolves to the opened envelope: { answered | refused, advisories }
  ask: (wireVerb, seats) => sessionIfOpen()?.ask(wireVerb, seats).then(({ envelope }) => openEnvelope(envelope)),
  startJob: (wireVerb, seats) => sessionIfOpen()?.startJob(wireVerb, seats),
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
  surface: () => sessionIfOpen()?.surface ?? null,
  hasSession: () => sessionStanding.tag === 'SessionOpen',
  fellow: Object.fromEntries(['nod', 'lean', 'smile', 'droop', 'settle', 'beginFidgeting']
    .map((mood) => [mood, () => fellow?.[mood]()])),
  download: (href, downloadName) => {
    const link = document.createElement('a');
    link.href = href; link.download = downloadName;
    link.click();
  },
  // seat the file first, then arrive: the hash change redraws explain already holding it
  lookInside: (file) => {
    verbs.explain.admitPickedFile('patch', file);
    location.hash = 'explain';
  },
  // a view-transient line in the voice box; the next render puts the state's voice back
  murmur: (spokenMarkup) => { element('voice').innerHTML = markupOf(spokenMarkup); },
  stage: () => element('stage'),
};

const verbs = {
  apply: makeApplyVerb(host),
  undo: makeUndoVerb(host),
  create: makeCreateVerb(host),
  info: makeInfoVerb(host),
  explain: makeExplainVerb(host),
  convert: makeConvertVerb(host),
};

// The emit verbs' stories and byte counters ride data attributes, so one wiring serves whichever is mounted.
wireMetadataBenchListeners(host, () => verbs[currentVerb].storiesQuiet?.() ?? false);

/* --------------------------------------------------------------- render ---- */

const verbTabsMarkup = () => {
  const tab = (verbName, quieter) => html`<button
    class="verb${quieter ? ' lesser' : ''}${verbName === currentVerb ? ' on' : ''}"
    ${verbName === currentVerb && html`aria-current="page"`}
    data-action="choose-verb" data-verb="${verbName}">${verbName}</button>`;
  return html`${headlinerVerbs.map((verbName) => tab(verbName, false))}<span class="verb-gap"></span>
    ${quieterVerbs.map((verbName) => tab(verbName, true))}`;
};

const render = () => {
  const verb = verbs[currentVerb];
  element('verbs').innerHTML = markupOf(verbTabsMarkup());
  element('stage').innerHTML = markupOf(verb.stageMarkup());
  // a failed boot owns the voice box: a verb's voice would put a friendly face on a dead page
  element('voice').innerHTML = markupOf(sessionStanding.tag === 'SessionFailedToOpen'
    ? bootFailureVoice(sessionStanding.bootFailureShape)
    : verb.voiceMarkup());
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

// A setting's value is its checkbox state or its typed text; the dataset rides along for per-field settings.
document.addEventListener('change', (event) => {
  const setting = event.target.dataset.setting;
  if (!setting) return;
  noticeLine = null;
  const control = event.target;
  verbs[currentVerb].settings[setting]?.(control.type === 'checkbox' ? control.checked : control.value, control.dataset);
});

// A details fold speaks through 'toggle', not 'change'; its value is whether it stands open.
document.addEventListener('toggle', (event) => {
  const setting = event.target.dataset?.setting;
  if (!setting) return;
  verbs[currentVerb].settings[setting]?.(event.target.open, event.target.dataset);
}, true);

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
  if (sessionStanding.tag === 'SessionFailedToOpen') return;   // the boot-failure card is already the answer
  if (sessionStanding.tag === 'SessionOpening') {
    noticeLine = voiceLines.stillGettingSet;
    render();
    return;
  }
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
  // an answer dropped while this verb was off stage — another verb's supersede — never comes back by itself
  verbs[verbName].askAgain();
  render();
};

addEventListener('hashchange', () => arriveAtVerb(verbNamedByHash() ?? 'apply'));

const countWord = (formatCount) => formatCount === 20 ? 'twenty' : String(formatCount);

currentVerb = verbNamedByHash() ?? 'apply';
render();
seatMascot(element('fellow')).then((seated) => { fellow = seated; }).catch(console.error);
openReactorSession().then((openedSession) => {
  sessionStanding = { tag: 'SessionOpen', session: openedSession };
  noticeLine = null;   // a "still getting set" answer is stale the moment the page is set
  element('format-count').textContent = countWord(openedSession.surface.surfaceFormats.length);
  Object.values(verbs).forEach((verb) => verb.askAgain());
  render();
}).catch((bootFailure) => {
  console.error(bootFailure);
  sessionStanding = { tag: 'SessionFailedToOpen', bootFailureShape: classifyBootFailure(bootFailure) };
  fellow?.droop();
  render();
});
