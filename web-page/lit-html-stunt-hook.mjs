// Importing this module stands the stunt in for lit-html: real lit asks for a live DOM the moment it loads,
// which node does not have. The page modules must arrive by dynamic import after this one has been evaluated —
// a static sibling import would resolve lit before the hook exists.

import { registerHooks } from 'node:module';

registerHooks({
  resolve: (specifier, context, nextResolve) => {
    const resolved = nextResolve(specifier, context);
    return resolved.url.endsWith('/vendor/lit-html/lit-html.js')
      ? { ...resolved, url: new URL('./lit-html-stunt.mjs', import.meta.url).href, shortCircuit: true }
      : resolved;
  },
});
