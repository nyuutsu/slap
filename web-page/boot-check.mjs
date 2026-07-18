// Boots the assembled page under a stub DOM: every module resolves, every verb constructs,
// and the first render survives — the failures a syntax check cannot see.
// Run from dist-web, where the reactor's modules sit at the paths the page imports them by.

const fakeElement = () => ({
  innerHTML: '', textContent: '', dataset: {}, style: {}, files: [],
  addEventListener() {}, click() {}, querySelector() { return null; },
});
globalThis.document = {
  getElementById: () => fakeElement(),
  addEventListener() {},
  createElement: () => fakeElement(),
};
globalThis.addEventListener = () => {};
globalThis.location = { hash: '' };
globalThis.matchMedia = () => ({ matches: false });
globalThis.fetch = () => new Promise(() => {});   // the mascot's artwork and the reactor never arrive; boot must not need them

await import('./page/main.mjs');
console.log('boot check: every module resolved, every verb constructed, the first render survived');
