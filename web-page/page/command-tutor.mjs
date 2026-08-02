// Each verb folds its own command words from the same state its form and its declaration read, so the three cannot disagree;
// and a fold never shows a filename nobody chose: a file that isn't real yet stays a role-word placeholder.

import { html } from '../vendor/lit-html/lit-html.js';

export const verbWord = (word) => ({ kind: 'verb-word', word });
export const flagWord = (word) => ({ kind: 'flag-word', word });
export const valueWord = (word) => ({ kind: 'value-word', word });
export const quotedWord = (word) => ({ kind: 'value-word', word: shellQuoted(word) });
export const fileWord = (word) => ({ kind: 'file-word', word: shellQuoted(optionSafe(word)) });
export const placeholderWord = (word) => ({ kind: 'placeholder', word });

// Single quotes make everything literal; a literal ' is written '\''.
const shellQuoted = (name) =>
  /^[A-Za-z0-9._+=:,@%/-]+$/.test(name) ? name : `'${name.replaceAll("'", "'\\''")}'`;

// A dash-led name would parse as an option — quotes can't save it — but its ./ spelling names the same file.
const optionSafe = (name) => (name.startsWith('-') ? `./${name}` : name);

export const namedOr = (file, roleWord) => (file ? fileWord(file.name) : placeholderWord(roleWord));

export const commandMarkup = (words) => html`${words.map(({ kind, word }) =>
  kind === 'file-word' ? html`<span>${word}</span> ` : html`<span class="${kind}">${word}</span> `
)}`;

export const tutorStories = {
  CliTutor:
    'i also work in the terminal. this command keeps up with everything you set here. '
    + 'take it with you and it\'ll do exactly what i was about to.',
};
