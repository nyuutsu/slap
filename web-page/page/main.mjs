// slap's page root. Every fact on screen is asked of the engine: the page holds opinions, never knowledge.

import { html, nothing, render } from '../vendor/lit-html/lit-html.js';
import { openReactorSession, classifyBootFailure, answerOf, advisoriesOf, ReactorJobCancelled } from './reactor-session.mjs';
import { engineSurface } from './engine-surface.mjs';
import { seatMascot } from './mascot.mjs';
import { voiceLines, bootFailureVoice } from './answer-surface.mjs';
import { commandMarkup, tutorStories } from './command-tutor.mjs';
import { makeApplyVerb } from './verbs/apply.mjs';
import { makeUndoVerb } from './verbs/undo.mjs';
import { makeCreateVerb } from './verbs/create.mjs';
import { makeConvertVerb } from './verbs/convert.mjs';
import { makeInfoVerb, makeExplainVerb } from './verbs/reads.mjs';
import { wireStoryListeners } from './stories.mjs';
import { watchForNewerPage, takeTheNewerPage } from './newer-page.mjs';
import { fieldStories } from './metadata-controls.mjs';
import { pickerStories } from './format-picker.mjs';

// apply, create and explain are what slap is for; the rest are welcome, just quieter.
const headlinerVerbs = ['apply', 'create', 'explain'];
const quieterVerbs = ['undo', 'convert', 'info'];
const allVerbs = [...headlinerVerbs, ...quieterVerbs];

// The page's own state, whole. Everything else that varies in this module is machinery:
// timers, a drag counter, the copy button's word, the fellow's handle.
const page = {
  verbOnStage: 'apply',                // follows the hash, the one authority; written only by arriveAtVerb
  session: { tag: 'SessionOpening' },  // → SessionOpen{session} | SessionFailedToOpen{bootFailureShape}
  noticeLine: null,                    // one transient line (e.g. "cancelled"); any fresh interaction retires it
  askEpoch: 0,
};
let fellow = null;

const element = (id) => document.getElementById(id);

/* ------------------------------------------------------------- the host ---- */
/* What a verb module may do to the world, and all of it: ask the engine, run a job,
   guard an answer against staleness, move the fellow, speak a notice or a murmur, ask for a render,
   and hand a file it minted to explain. */

const openEnvelope = (envelope) => ({ ...answerOf(envelope), advisories: advisoriesOf(envelope) });

const sessionIfOpen = () => page.session.tag === 'SessionOpen' ? page.session.session : null;

const host = {
  // resolves to the opened envelope: { answered | refused, advisories }
  ask: (wireVerb, seats) => sessionIfOpen()?.ask(wireVerb, seats).then(({ envelope }) => openEnvelope(envelope)),
  startJob: (wireVerb, seats) => sessionIfOpen()?.startJob(wireVerb, seats),
  openEnvelope,
  wasCancelled: (jobFailure) => jobFailure instanceof ReactorJobCancelled,

  // an answer from an older epoch arrives about files no longer on screen, and is dropped unheard
  wheneverStillCurrent: (deliver) => {
    const epochAtAsk = page.askEpoch;
    return (value) => { if (page.askEpoch === epochAtAsk) { deliver(value); renderPage(); } };
  },
  supersedeAsks: () => { page.askEpoch += 1; },

  // a failed ask — a reactor trap, a Worker death — surfaces in the voice box;
  // a swallowed failure would leave a "reading…" line up forever, promising an answer that is never coming
  askFailed: (askFailure) => {
    console.error(askFailure);
    page.noticeLine = String(askFailure?.message ?? askFailure);
    fellow?.droop();
    renderPage();
  },

  notice: () => page.noticeLine,
  setNotice: (line) => { page.noticeLine = line; },
  render: () => renderPage(),
  // A settled act removes the run button whoever pressed it was standing on, so the answer takes the focus in.
  carryFocusToAnswer: () => element('voice').focus(),
  // baked at build, so the furniture renders before the reactor arrives
  surface: () => engineSurface,
  hasSession: () => page.session.tag === 'SessionOpen',
  fellow: {
    ...Object.fromEntries(['nod', 'lean', 'smile', 'droop'].map((mood) => [mood, () => fellow?.[mood]()])),
    beginFidgeting: () => { fellow?.beginFidgeting(); startElapsedClock(); },
    settle: () => { fellow?.settle(); stopElapsedClock(); },
  },
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
  // a story's card floats over the voice box, rendered inside it so the live region announces the story;
  // the state's words hold the flow beneath, so speaking never moves the page, and the next render lifts the card away
  murmur: (spokenMarkup) => {
    render(html`${stateVoiceMarkup()}<div class="story-card">${spokenMarkup}</div>`, element('voice'));
  },
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

// Most keys name an engine metadata field; the page's own furniture brings nouns of its own.
const storybook = { ...fieldStories, ...pickerStories, ...tutorStories };
wireStoryListeners(host, storybook, () => verbs[page.verbOnStage].storiesQuiet?.() ?? false);

/* --------------------------------------------------------------- render ---- */

// Real tabs: the shown one holds the group's tab stop, arrow keys walk the rest (wired below).
const verbTabsMarkup = () => {
  const tab = (verbName, quieter) => html`<button type="button" role="tab" id="tab-${verbName}"
    class="verb${quieter ? ' lesser' : ''}${verbName === page.verbOnStage ? ' on' : ''}"
    aria-selected="${verbName === page.verbOnStage}" aria-controls="stage"
    tabindex=${verbName === page.verbOnStage ? '0' : '-1'}
    data-action="choose-verb" data-verb="${verbName}">${verbName}</button>`;
  return html`${headlinerVerbs.map((verbName) => tab(verbName, false))}<span class="verb-gap" aria-hidden="true"></span>
    ${quieterVerbs.map((verbName) => tab(verbName, true))}`;
};

// The crunch runs on a Worker, so the page thread stays free to tick the elapsed count.
let elapsedClock = null;
let workBeganAt = 0;
const spellElapsed = (seconds) =>
  seconds < 60 ? `${seconds}s`
               : `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, '0')}s`;
const paintElapsed = () => {
  const elapsedSpot = element('work-elapsed');
  if (!elapsedSpot) return;
  const seconds = Math.floor((performance.now() - workBeganAt) / 1000);
  elapsedSpot.textContent = seconds >= 1 ? spellElapsed(seconds) : '';
};
const startElapsedClock = () => {
  if (elapsedClock !== null) return;
  workBeganAt = performance.now();
  elapsedClock = setInterval(paintElapsed, 500);
};
const stopElapsedClock = () => { if (elapsedClock !== null) { clearInterval(elapsedClock); elapsedClock = null; } };

// The copy button's word answers on the button itself, where the eyes already are, then reverts after a breath.
let copyButtonWord = 'copy';
let copyWordTimer = null;

const tutorMarkup = (words) => html`
  <p class="tutor-label">
    <button type="button" class="has-story" aria-expanded="false" data-story="CliTutor">cli tutor</button>
    <button type="button" class="quiet-button" data-action="copy-command">${copyButtonWord}</button>
  </p>
  <pre class="terminal" id="command" data-action="copy-command">${commandMarkup(words)}</pre>`;

// a failed boot owns the voice box: a verb's voice would put a friendly face on a dead page
const stateVoiceMarkup = () => page.session.tag === 'SessionFailedToOpen'
  ? bootFailureVoice(page.session.bootFailureShape)
  : verbs[page.verbOnStage].voiceMarkup();

const renderPage = () => {
  const verb = verbs[page.verbOnStage];
  render(verbTabsMarkup(), element('verbs'));
  render(html`<h2 class="visually-hidden">${page.verbOnStage}</h2>${verb.stageMarkup()}`, element('stage'));
  element('stage').setAttribute('aria-labelledby', `tab-${page.verbOnStage}`);
  render(stateVoiceMarkup(), element('voice'));
  render(tutorMarkup(verb.commandWords()), element('tutor'));
  render(verb.actMarkup(), element('act'));
};

/* --------------------------------------------------------------- wiring ---- */

const sayOnTheButton = (word) => {
  copyButtonWord = word;
  clearTimeout(copyWordTimer);
  copyWordTimer = setTimeout(() => { copyButtonWord = 'copy'; renderPage(); }, 1600);
  renderPage();
};

const copyCommand = async () => {
  try {
    await navigator.clipboard.writeText(element('command').textContent.trim());
    sayOnTheButton('copied');
  } catch {
    sayOnTheButton('copy it by hand');
  }
};

element('verbs').addEventListener('keydown', (event) => {
  const stepped = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
  const landed = { Home: 0, End: allVerbs.length - 1 }[event.key];
  if (stepped === undefined && landed === undefined) return;
  event.preventDefault();
  const from = allVerbs.indexOf(page.verbOnStage);
  const walkedToVerb = allVerbs[landed ?? (from + stepped + allVerbs.length) % allVerbs.length];
  location.hash = walkedToVerb;
  element(`tab-${walkedToVerb}`)?.focus();
});

// Enter in a field runs the verb through the form's own submission — the run button is its submit button.
// A run still waiting does not fire; resting on it has already outlined what it waits for.
element('stage').addEventListener('submit', (event) => {
  event.preventDefault();
  const verb = verbs[page.verbOnStage];
  if ((verb.runReadiness?.() ?? { tag: 'Ready' }).tag === 'Ready') verb.actions.run?.();
});

const filePicker = element('file-picker');

document.addEventListener('click', (event) => {
  const control = event.target.closest('[data-action]');
  if (!control) return;
  page.noticeLine = null;
  const action = control.dataset.action;
  if (action === 'choose-verb') {
    location.hash = control.dataset.verb;
    return;
  }
  if (action === 'pick-file') {
    filePicker.dataset.seat = control.dataset.seat;
    filePicker.click();
    return;
  }
  if (action === 'copy-command') {
    // The strip answers the gesture people try on it anyway, and stands aside for a selection:
    // dragging across part of a command is someone taking that part by hand, and copying over them would be rude.
    if (control.matches('pre') && document.getSelection()?.isCollapsed === false) return;
    copyCommand();
    return;
  }
  if (action === 'take-newer-page') {
    takeTheNewerPage();
    return;
  }
  verbs[page.verbOnStage].actions[action]?.(control.dataset);
});

// A setting's value is its checkbox state or its typed text; the dataset rides along for per-field settings.
document.addEventListener('change', (event) => {
  const setting = event.target.dataset.setting;
  if (!setting) return;
  page.noticeLine = null;
  const control = event.target;
  verbs[page.verbOnStage].settings[setting]?.(control.type === 'checkbox' ? control.checked : control.value, control.dataset);
});

// The typing lane: each keystroke redraws what the page computes itself — byte counts, the command strip —
// while the engine re-asks wait for 'change', the settled value being the one worth judging.
document.addEventListener('input', (event) => {
  const setting = event.target.dataset.setting;
  if (!setting) return;
  verbs[page.verbOnStage].typings?.[setting]?.(event.target.value, event.target.dataset);
});

filePicker.addEventListener('change', () => {
  const [file] = filePicker.files;
  if (file) {
    page.noticeLine = null;
    verbs[page.verbOnStage].admitPickedFile(filePicker.dataset.seat, file);
  }
  filePicker.value = '';
});

/* Drop anywhere: the whole page is the target, and slap sorts the files itself. */
const routeDroppedFiles = async (files) => {
  if (page.session.tag === 'SessionFailedToOpen') return;   // the boot-failure card is already the answer
  if (page.session.tag === 'SessionOpening') {
    page.noticeLine = voiceLines.stillGettingSet;
    renderPage();
    return;
  }
  page.noticeLine = null;
  for (const file of [...files].slice(0, 2)) {
    const { answered } = await host.ask('classify', { file });
    verbs[page.verbOnStage].admitDroppedFile(answered, file);
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
  if (verbName === page.verbOnStage) return;
  page.verbOnStage = verbName;
  page.noticeLine = null;
  fellow?.settle();
  // an answer dropped while this verb was off stage — another verb's supersede — never comes back by itself
  verbs[verbName].askAgain();
  renderPage();
};

// the hash is the one authority on the shown verb; tab clicks and arrow keys only drive it
addEventListener('hashchange', () => arriveAtVerb(verbNamedByHash() ?? 'apply'));

page.verbOnStage = verbNamedByHash() ?? 'apply';
renderPage();
// A boot that fails before his artwork arrives has no one to tell; he reads the settled state on arriving instead.
seatMascot(element('fellow')).then((seated) => {
  fellow = seated;
  if (page.session.tag === 'SessionFailedToOpen') fellow.reel();
}).catch(console.error);
// the fellow's offer of a newer page lives in restingVoice, so learning of one is a render
watchForNewerPage(renderPage);
openReactorSession().then((openedSession) => {
  // the page was built against one engine's surface; an engine that booted speaking another must not answer for it
  if (JSON.stringify(openedSession.surface) !== JSON.stringify(engineSurface))
    throw new Error('the engine that booted speaks a different surface than the one baked into the page');
  page.session = { tag: 'SessionOpen', session: openedSession };
  page.noticeLine = null;   // a "still getting set" answer is stale the moment the page is set
  Object.values(verbs).forEach((verb) => verb.askAgain());
  renderPage();
}).catch((bootFailure) => {
  console.error(bootFailure);
  page.session = { tag: 'SessionFailedToOpen', bootFailureShape: classifyBootFailure(bootFailure) };
  fellow?.reel();
  renderPage();
});
