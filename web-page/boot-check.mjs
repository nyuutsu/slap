// Boots the assembled page under a stub DOM, proving what a syntax check cannot: every module resolves,
// every verb constructs, the first render survives. Then the reactor's download fails on purpose,
// and the boot-failure card must take the voice box and outlive a verb change.
// Run from dist-web, where the reactor's modules sit at the paths the page imports them by.

// The stunt stands in for lit — and it throws where lit would quietly misrender, so this boot doubles as a template check.
import { readFileSync } from 'node:fs';
import './lit-html-stunt-hook.mjs';
import { ReactorNeverArrived } from './reactor/reactor-client.mjs';

const fakeElement = () => ({
  innerHTML: '', textContent: '', dataset: {}, style: {}, files: [],
  addEventListener() {}, click() {}, focus() {}, setAttribute() {}, querySelector() { return null; },
});
const elements = new Map();
const elementNamed = (id) => {
  if (!elements.has(id)) elements.set(id, fakeElement());
  return elements.get(id);
};
globalThis.document = {
  getElementById: elementNamed,
  addEventListener() {},
  createElement: () => fakeElement(),
};
const windowListeners = {};
globalThis.addEventListener = (eventName, listener) => { windowListeners[eventName] = listener; };
globalThis.location = { hash: '' };
globalThis.matchMedia = () => ({ matches: false });
// the artwork hangs forever and boot must not need it; the reactor's download is the one made to fail
globalThis.fetch = (url) => String(url).endsWith('slap-web-reactor.wasm')
  ? Promise.reject(new TypeError('the boot check serves no reactor'))
  : new Promise(() => {});
// the arranged failure is expected noise; any other console.error is real and passes through
const consoleFailure = console.error;
console.error = (failure, ...rest) => { if (!(failure instanceof ReactorNeverArrived)) consoleFailure(failure, ...rest); };

await import('./page/main.mjs');
await new Promise((wakeAfterBootSettles) => setTimeout(wakeAfterBootSettles, 0));

const { markupOf } = await import('./lit-html-stunt.mjs');
const { bootFailureVoice } = await import('./page/answer-surface.mjs');

// the exact card the arranged failure must produce: a boot that lands in the wrong arm fails here
const reactorNeverArrivedCard = markupOf(bootFailureVoice(
  { tag: 'ReactorNeverArrived', detail: 'TypeError: the boot check serves no reactor' }));
const voiceBox = elementNamed('voice');
if (voiceBox.innerHTML !== reactorNeverArrivedCard)
  throw new Error('the failed download did not land as the ReactorNeverArrived card in the voice box');
globalThis.location.hash = '#create';
windowListeners.hashchange();
if (voiceBox.innerHTML !== reactorNeverArrivedCard)
  throw new Error('a verb change talked over the boot-failure card');

// the two arms a failed download cannot drive: each must speak a headline and carry its detail verbatim
for (const shape of [{ tag: 'WebAssemblySwitchedOff' }, { tag: 'BootFell', detail: 'CheckError: contrived for the census' }]) {
  const cardMarkup = markupOf(bootFailureVoice(shape));
  if (!cardMarkup.includes('plain-line')) throw new Error(`the ${shape.tag} card has no headline`);
  if (shape.detail && !cardMarkup.includes(shape.detail)) throw new Error(`the ${shape.tag} card dropped its detail`);
}

// The one sentence strangers read before arriving is written out four times, in three syntaxes,
// with nothing but this to keep them the same sentence.
const describedAs = (text, where) => {
  const spellings = [...text.matchAll(/"description":\s*"([^"]+)"|name="description" content="([^"]+)"|property="og:description" content="([^"]+)"/g)]
    .map((found) => found[1] ?? found[2] ?? found[3]);
  if (spellings.length === 0) throw new Error(`${where} carries no description`);
  return spellings;
};
const descriptions = [...describedAs(readFileSync('index.html', 'utf8'), 'index.html'),
                      ...describedAs(readFileSync('manifest.json', 'utf8'), 'manifest.json')];
if (descriptions.length !== 4) throw new Error(`expected four descriptions, found ${descriptions.length}`);
if (new Set(descriptions).size !== 1)
  throw new Error(`the four descriptions have drifted apart:\n  ${[...new Set(descriptions)].join('\n  ')}`);

console.log('boot check: every module resolved, every verb constructed, the first render survived, '
  + 'a failed boot keeps its card up, and all four descriptions still say the same sentence');
