// The metadata bench the two emit verbs stand on. Every fact behind these controls arrives from describeSurface;
// the page brings only its labels and glosses. The blob and DIZ lanes stay with their verbs, whose intents differ.

import { html, nothing } from '../vendor/lit-html/lit-html.js';
import { ControlKind, WindowDefault, matcherOver } from './engine-vocabulary.mjs';
import { groupMarkup, toggleMarkup } from './controls.mjs';
import { flagWord, valueWord, quotedWord } from './command-tutor.mjs';
import { requestKeyOf, utf8Text, toggleRequests, fieldLabel, fieldWhy,
         choiceGloss, fieldStories, concealedWhileToggled, windowUnits } from './metadata-controls.mjs';
import { constraintControls } from './constraint-controls.mjs';
import { humanByteSize } from './readouts.mjs';

const wholePositive = (typed) => {
  const parsed = Number(typed);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
};

const byteCountOf = (typed) => new TextEncoder().encode(typed).length;

// btoa takes a binary string; built in slices so a large blob cannot overrun the argument list.
export const base64OfBuffer = (buffer) => {
  const blobBytes = new Uint8Array(buffer);
  let binary = '';
  for (let at = 0; at < blobBytes.length; at += 0x8000)
    binary += String.fromCharCode(...blobBytes.subarray(at, at + 0x8000));
  return btoa(binary);
};

// The story trigger hugs its words — a block label's empty width must not speak — and takes focus so a keyboard hears it too.
export const storiedText = (fieldName, labelText) => (fieldStories[fieldName]
  ? html`<span class="has-story" tabindex="0" data-story="${fieldName}">${labelText}</span>`
  : labelText);

export const countedTextareaMarkup = ({ setting, placeholder, typed, ceiling }) => (ceiling
  ? html`<div class="counted-lane">
      <textarea class="field-textarea" data-setting="${setting}"
        aria-describedby="${setting}-count" placeholder="${placeholder}" .value=${typed}></textarea>
      <span class="byte-count${byteCountOf(typed) > ceiling ? ' over-ceiling' : ''}"
        id="${setting}-count">${byteCountOf(typed)} / ${ceiling} bytes</span></div>`
  : html`<textarea class="field-textarea" data-setting="${setting}" placeholder="${placeholder}" .value=${typed}></textarea>`);

export const makeMetadataBench = (host, { surfaceRow, recheck }) => {
  const atRest = () => ({
    fieldValues: {},     // free-text and number fields, as typed
    windowUnit: 'bytes',
    toggledFields: {},
    chosenChoices: {},   // choice fields, by chosen token; the engine value is looked up at declaration time
    chosenConstraints: {},
  });
  let bench = atRest();

  const fieldRoster = () => host.surface()?.surfaceMetadataFields ?? [];
  const formatAcceptsField = (fieldName) => (surfaceRow()?.formatAcceptedFields ?? []).includes(fieldName);
  const acceptedRosterRows = () => fieldRoster().filter((row) => formatAcceptsField(row.describedMetadataField));
  const fieldConcealed = (fieldName) =>
    concealedWhileToggled[fieldName] && bench.toggledFields[concealedWhileToggled[fieldName]];

  /* ------------------------------------------------------ declaration ---- */
  /* Only what the chosen format accepts is spoken: a field typed under one format
     stays in hand across a tile change, but never rides a declaration it doesn't belong in. */

  const chosenWindowUnit = () => windowUnits.find((unit) => unit.token === bench.windowUnit);

  const windowSizeBytes = () => {
    const counted = wholePositive(bench.fieldValues.MetadataWindowSize);
    if (!counted) return null;
    const scaledBytes = counted * chosenWindowUnit().bytesPer;
    return Number.isSafeInteger(scaledBytes) ? scaledBytes : null;
  };

  const chosenChoiceValue = (fieldName, choicePairs) => {
    const chosenToken = bench.chosenChoices[fieldName];
    const chosenPair = choicePairs.find(([token]) => token === chosenToken);
    return chosenPair ? chosenPair[1] : null;
  };

  // Each arm answers with the value the declaration should carry, or null for a field with nothing to say.
  const declaredValueForKind = matcherOver(ControlKind, {
    FreeText: (_noContents, { fieldName }) =>
      bench.fieldValues[fieldName] ? utf8Text(bench.fieldValues[fieldName]) : null,
    Number: (_noContents, { fieldName }) =>
      fieldName === 'MetadataWindowSize' ? windowSizeBytes() : wholePositive(bench.fieldValues[fieldName]),
    Toggle: (_noContents, { fieldName }) =>
      bench.toggledFields[fieldName] ? toggleRequests[fieldName] ?? null : null,
    Choice: (choiceVocabulary, { fieldName }) =>
      fieldConcealed(fieldName) ? null : chosenChoiceValue(fieldName, choiceVocabulary.contents),
    // the blob and the DIZ ride lanes of their own, with the verbs
    File: () => null,
  });

  const declarationFields = () => {
    const requested = {};
    for (const row of acceptedRosterRows()) {
      const fieldName = row.describedMetadataField;
      const declaredValue = declaredValueForKind(row.metadataFieldControlKind, { fieldName });
      if (declaredValue !== null) requested[requestKeyOf(fieldName)] = declaredValue;
    }
    return requested;
  };

  // Every constraint key is spoken on every declaration — the resting value is a value, not an omission.
  const constraintsDeclaration = () => {
    const declared = {};
    for (const [constraintName, control] of Object.entries(constraintControls)) {
      const chosen = bench.chosenConstraints[constraintName]
        && (surfaceRow()?.formatConstraints ?? []).includes(constraintName);
      declared[control.requestKey] = chosen ? control.chosenRequirement : control.restingRequirement;
    }
    return declared;
  };

  /* ------------------------------------------------------------ stage ---- */

  // Window size is the one control with a crossed fact to show at rest, and it speaks in the choices' words:
  // a default belongs beside the control rather than inside it, where typing would erase it.
  const fieldGloss = (fieldName) => {
    if (fieldName !== 'MetadataWindowSize') return null;
    const windowDefault = surfaceRow()?.formatWindowDefault;
    if (!windowDefault) return null;
    return windowDefault.tag === WindowDefault.WindowsOfBytes
      ? `${humanByteSize(windowDefault.contents)} windows unless you say otherwise.`
      : 'one window, the whole file, unless you say otherwise.';
  };

  const whySpan = (fieldName) => (fieldWhy(fieldName) ? html` <span class="why">— ${fieldWhy(fieldName)}</span>` : nothing);

  const fieldCeiling = (fieldName) =>
    (surfaceRow()?.formatTextFieldCeilings ?? []).find(([ceilingField]) => ceilingField === fieldName)?.[1] ?? null;

  const textFieldMarkup = (row, inputType) => {
    const fieldName = row.describedMetadataField;
    const ceiling = inputType === 'text' ? fieldCeiling(fieldName) : null;
    const typed = bench.fieldValues[fieldName] ?? '';
    return html`<div class="field">
      <label class="field-label" for="meta-${fieldName}">${storiedText(fieldName, fieldLabel(fieldName, row.metadataFieldFlag))}</label>
      <input class="field-input" type="${inputType}"
        min=${inputType === 'number' ? '1' : nothing} step=${inputType === 'number' ? '1' : nothing}
        aria-describedby=${ceiling ? `meta-${fieldName}-count` : nothing}
        data-story=${fieldStories[fieldName] ? fieldName : nothing}
        id="meta-${fieldName}" data-setting="field" data-field="${fieldName}" .value=${typed}>
      ${ceiling ? html`<span class="byte-count${byteCountOf(typed) > ceiling ? ' over-ceiling' : ''}"
        id="meta-${fieldName}-count">${byteCountOf(typed)} / ${ceiling} bytes</span>` : nothing}
      ${fieldName === 'MetadataWindowSize' ? html`<span class="choice-row">${windowUnits.map((unit) => html`<button
        class="chip${bench.windowUnit === unit.token ? ' on' : ''}" aria-pressed="${bench.windowUnit === unit.token}"
        data-action="window-unit" data-unit="${unit.token}">${unit.token}</button>`)}</span>` : nothing}
      ${whySpan(fieldName)}
      ${fieldGloss(fieldName) ? html`<p class="field-gloss">${fieldGloss(fieldName)}</p>` : nothing}
    </div>`;
  };

  const choiceRowMarkup = (row, choicePairs) => {
    const fieldName = row.describedMetadataField;
    const defaultToken = (surfaceRow()?.formatChoiceDefaults ?? [])
      .find(([defaultField]) => defaultField === fieldName)?.[1] ?? null;
    const gloss = choiceGloss(fieldName, bench.chosenChoices[fieldName], defaultToken);
    const chip = (token) => html`<button
      class="chip${bench.chosenChoices[fieldName] === token ? ' on' : ''}"
      aria-pressed="${bench.chosenChoices[fieldName] === token}"
      data-action="choose-meta" data-field="${fieldName}" data-token="${token}">${token}</button>`;
    return html`<div>
      <p class="choice-label">${storiedText(fieldName, fieldLabel(fieldName, row.metadataFieldFlag))}${whySpan(fieldName)}</p>
      <div class="choice-row">${choicePairs.map(([token]) => (token === defaultToken
        ? html`<span class="chip-stack">${chip(token)}<span class="role-whisper">default</span></span>`
        : chip(token)))}</div>
      ${gloss ? html`<p class="choice-gloss">${gloss}</p>` : nothing}</div>`;
  };

  // A toggle field with no request spelling gets no control: quiet, never wrong (toggleRequests' own doctrine).
  const controlForKind = matcherOver(ControlKind, {
    FreeText: (_noContents, { row }) => textFieldMarkup(row, 'text'),
    Number:   (_noContents, { row }) => textFieldMarkup(row, 'number'),
    Toggle: (_noContents, { row }) => {
      const fieldName = row.describedMetadataField;
      return toggleRequests[fieldName] ? toggleMarkup({
        id: `meta-${fieldName}`, setting: 'toggle', field: fieldName,
        checked: !!bench.toggledFields[fieldName],
        label: fieldLabel(fieldName, row.metadataFieldFlag), why: fieldWhy(fieldName),
      }) : null;
    },
    Choice: (choiceVocabulary, { row }) => choiceRowMarkup(row, choiceVocabulary.contents),
    File: (_noContents, { row, fileFieldMarkup }) => fileFieldMarkup(row.describedMetadataField),
  });

  const controlMarkup = (row, fileFieldMarkup) =>
    fieldConcealed(row.describedMetadataField)
      ? null
      : controlForKind(row.metadataFieldControlKind, { row, fileFieldMarkup });

  const metadataGroupMarkup = (fileFieldMarkup) => {
    const rows = acceptedRosterRows();
    if (rows.length === 0) return null;
    return groupMarkup('metadata', html`${rows.map((row) => controlMarkup(row, fileFieldMarkup))}`);
  };

  const constraintsGroupMarkup = () => {
    const toggles = (surfaceRow()?.formatConstraints ?? []).flatMap((constraintName) => {
      const control = constraintControls[constraintName];
      if (!control) return [];
      return [toggleMarkup({
        id: `constraint-${constraintName}`, setting: 'constraint', field: constraintName,
        checked: !!bench.chosenConstraints[constraintName],
        label: control.controlLabel, why: control.controlWhy,
      })];
    });
    return toggles.length === 0 ? null : groupMarkup('constraints', html`${toggles}`);
  };

  /* ------------------------------------------------------------ tutor ---- */

  // Gated exactly as the declaration is, so a value the declaration dropped is never tutored.
  const tutorWordsForKind = matcherOver(ControlKind, {
    FreeText: (_noContents, { fieldName, flag }) =>
      bench.fieldValues[fieldName] ? [flagWord(flag), quotedWord(bench.fieldValues[fieldName])] : [],
    Number: (_noContents, { fieldName, flag }) => {
      if (!(fieldName === 'MetadataWindowSize' ? windowSizeBytes() : wholePositive(bench.fieldValues[fieldName]))) return [];
      const suffix = fieldName === 'MetadataWindowSize' ? chosenWindowUnit().suffix : '';
      return [flagWord(flag), valueWord(`${wholePositive(bench.fieldValues[fieldName])}${suffix}`)];
    },
    Toggle: (_noContents, { fieldName, flag }) =>
      bench.toggledFields[fieldName] && toggleRequests[fieldName] ? [flagWord(flag)] : [],
    Choice: (_choiceVocabulary, { fieldName, flag }) =>
      bench.chosenChoices[fieldName] && !fieldConcealed(fieldName)
        ? [flagWord(flag), valueWord(bench.chosenChoices[fieldName])] : [],
    File: (_noContents, { fieldName, flag, fileFieldWords }) => fileFieldWords(fieldName, flag),
  });

  const commandWords = (fileFieldWords) => {
    const words = [];
    for (const row of acceptedRosterRows())
      words.push(...tutorWordsForKind(row.metadataFieldControlKind, {
        fieldName: row.describedMetadataField, flag: `--${row.metadataFieldFlag}`, fileFieldWords,
      }));
    for (const [constraintName, control] of Object.entries(constraintControls))
      if (bench.chosenConstraints[constraintName] && (surfaceRow()?.formatConstraints ?? []).includes(constraintName))
        words.push(flagWord(control.terminalFlag));
    return words;
  };

  return {
    reset: () => { bench = atRest(); },
    formatAcceptsField,
    fieldCeiling,
    declarationFields,
    constraintsDeclaration,
    metadataGroupMarkup,
    constraintsGroupMarkup,
    commandWords,
    actions: {
      'choose-meta': ({ field, token }) => recheck(() => {
        bench.chosenChoices[field] = bench.chosenChoices[field] === token ? null : token;
      }),
      'window-unit': ({ unit }) => recheck(() => { bench.windowUnit = unit; }),
    },
    settings: {
      field: (value, { field }) => recheck(() => { bench.fieldValues[field] = value; }),
      toggle: (checked, { field }) => recheck(() => { bench.toggledFields[field] = checked; }),
      constraint: (checked, { field }) => recheck(() => { bench.chosenConstraints[field] = checked; }),
    },
    typings: {
      field: (value, { field }) => { bench.fieldValues[field] = value; host.render(); },
    },
  };
};
