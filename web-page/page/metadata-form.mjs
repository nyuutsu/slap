// The metadata bench the two emit verbs stand on. Every fact behind these controls arrives from describeSurface;
// the page brings only its labels and glosses. The blob and DIZ lanes stay with their verbs, whose intents differ.

import { html } from './dom.mjs';
import { groupMarkup, toggleMarkup } from './controls.mjs';
import { plainVoice } from './answer-surface.mjs';
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
  ? html`<span class="has-story" tabindex="0" data-story-field="${fieldName}">${labelText}</span>`
  : labelText);

const storiedAttribute = (fieldName) => fieldStories[fieldName] && html`data-story-field="${fieldName}"`;

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

  const declarationFields = () => {
    const requested = {};
    for (const row of acceptedRosterRows()) {
      const fieldName = row.describedMetadataField;
      const kind = row.metadataFieldControlKind;
      if (kind.tag === 'FreeTextField') {
        if (bench.fieldValues[fieldName]) requested[requestKeyOf(fieldName)] = utf8Text(bench.fieldValues[fieldName]);
      } else if (kind.tag === 'NumberField') {
        const declaredCount = fieldName === 'MetadataWindowSize'
          ? windowSizeBytes()
          : wholePositive(bench.fieldValues[fieldName]);
        if (declaredCount) requested[requestKeyOf(fieldName)] = declaredCount;
      } else if (kind.tag === 'ToggleField') {
        if (bench.toggledFields[fieldName] && toggleRequests[fieldName])
          requested[requestKeyOf(fieldName)] = toggleRequests[fieldName];
      } else if (kind.tag === 'ChoiceField' && !fieldConcealed(fieldName)) {
        const chosenValue = chosenChoiceValue(fieldName, kind.contents.contents);
        if (chosenValue !== null) requested[requestKeyOf(fieldName)] = chosenValue;
      }
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

  // Window size is the one control with a crossed fact to show at rest; any other placeholder would be page words.
  const fieldPlaceholder = (fieldName) => {
    if (fieldName !== 'MetadataWindowSize') return null;
    const windowDefault = surfaceRow()?.formatWindowDefault;
    if (!windowDefault) return null;
    return windowDefault.tag === 'WindowsOfBytes'
      ? `auto: ${humanByteSize(windowDefault.contents)} windows`
      : 'auto: one window, the whole file';
  };

  const whySpan = (fieldName) => fieldWhy(fieldName) && html` <span class="why">— ${fieldWhy(fieldName)}</span>`;

  const fieldCeiling = (fieldName) =>
    (surfaceRow()?.formatTextFieldCeilings ?? []).find(([ceilingField]) => ceilingField === fieldName)?.[1] ?? null;

  const textFieldMarkup = (row, inputType) => {
    const fieldName = row.describedMetadataField;
    const ceiling = inputType === 'text' ? fieldCeiling(fieldName) : null;
    const typed = bench.fieldValues[fieldName] ?? '';
    return html`<div class="field">
      <label class="field-label" for="meta-${fieldName}">${storiedText(fieldName, fieldLabel(fieldName, row.metadataFieldFlag))}</label>
      <input class="field-input" type="${inputType}" ${inputType === 'number' && html`min="1" step="1"`}
        ${fieldPlaceholder(fieldName) && html`placeholder="${fieldPlaceholder(fieldName)}"`}
        ${ceiling && html`data-ceiling="${ceiling}" aria-describedby="meta-${fieldName}-count"`}
        ${storiedAttribute(fieldName)}
        id="meta-${fieldName}" data-setting="field" data-field="${fieldName}" value="${typed}">
      ${ceiling && html`<span class="byte-count${byteCountOf(typed) > ceiling ? ' over-ceiling' : ''}"
        id="meta-${fieldName}-count">${byteCountOf(typed)} / ${ceiling} bytes</span>`}
      ${fieldName === 'MetadataWindowSize' && html`<span class="choice-row">${windowUnits.map((unit) => html`<button
        class="chip${bench.windowUnit === unit.token ? ' on' : ''}" aria-pressed="${bench.windowUnit === unit.token}"
        data-action="window-unit" data-unit="${unit.token}">${unit.token}</button>`)}</span>`}
      ${whySpan(fieldName)}
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
      ${gloss && html`<p class="choice-gloss">${gloss}</p>`}</div>`;
  };

  const controlMarkup = (row, fileFieldMarkup) => {
    const fieldName = row.describedMetadataField;
    const kind = row.metadataFieldControlKind;
    if (fieldConcealed(fieldName)) return null;
    if (kind.tag === 'ToggleField')
      return toggleRequests[fieldName] && toggleMarkup({
        id: `meta-${fieldName}`, setting: 'toggle', field: fieldName,
        checked: !!bench.toggledFields[fieldName],
        label: fieldLabel(fieldName, row.metadataFieldFlag), why: fieldWhy(fieldName),
      });
    if (kind.tag === 'ChoiceField') return choiceRowMarkup(row, kind.contents.contents);
    if (kind.tag === 'FileField') return fileFieldMarkup(fieldName);
    return textFieldMarkup(row, kind.tag === 'NumberField' ? 'number' : 'text');
  };

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

  const commandWords = (fileFieldWords) => {
    const words = [];
    for (const row of acceptedRosterRows()) {
      const fieldName = row.describedMetadataField;
      const kind = row.metadataFieldControlKind;
      const flag = `--${row.metadataFieldFlag}`;
      if (kind.tag === 'FreeTextField' && bench.fieldValues[fieldName])
        words.push(flagWord(flag), quotedWord(bench.fieldValues[fieldName]));
      // gated exactly as the declaration is, so a value it dropped is never tutored
      if (kind.tag === 'NumberField'
          && (fieldName === 'MetadataWindowSize' ? windowSizeBytes() : wholePositive(bench.fieldValues[fieldName]))) {
        const suffix = fieldName === 'MetadataWindowSize' ? chosenWindowUnit().suffix : '';
        words.push(flagWord(flag), valueWord(`${wholePositive(bench.fieldValues[fieldName])}${suffix}`));
      }
      if (kind.tag === 'ToggleField' && bench.toggledFields[fieldName] && toggleRequests[fieldName])
        words.push(flagWord(flag));
      if (kind.tag === 'ChoiceField' && bench.chosenChoices[fieldName] && !fieldConcealed(fieldName))
        words.push(flagWord(flag), valueWord(bench.chosenChoices[fieldName]));
      if (kind.tag === 'FileField')
        words.push(...fileFieldWords(fieldName, flag));
    }
    for (const [constraintName, control] of Object.entries(constraintControls))
      if (bench.chosenConstraints[constraintName] && (surfaceRow()?.formatConstraints ?? []).includes(constraintName))
        words.push(flagWord(control.terminalFlag));
    return words;
  };

  return {
    reset: () => { bench = atRest(); },
    formatAcceptsField,
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
  };
};

/* ------------------------------------------------------- stage listeners ---- */
/* Wired once, against the one stage: data attributes serve whichever emit verb is mounted, and a story never speaks twice. */

// The long stories are view-transients, never state: hovering or focusing a storied control lets the fellow
// speak it, and leaving renders the box back to what the state says. A control being typed in keeps its story —
// the render would tear focus out of the input.
export const wireMetadataBenchListeners = (host, storiesQuietNow) => {
  const speakStory = (event) => {
    if (storiesQuietNow()) return;
    const storied = event.target.closest('[data-story-field]');
    const story = storied && fieldStories[storied.dataset.storyField];
    if (!story) return;
    host.fellow.lean();
    host.murmur(plainVoice(story));
  };
  const settleStory = (event) => {
    const storied = event.target.closest?.('[data-story-field]');
    if (!storied) return;
    if (event.relatedTarget && storied.contains(event.relatedTarget)) return;
    if (storied.contains(document.activeElement)) return;
    host.fellow.settle();
    host.render();
  };
  host.stage().addEventListener('mouseover', speakStory);
  host.stage().addEventListener('focusin', speakStory);
  host.stage().addEventListener('mouseout', settleStory);
  host.stage().addEventListener('focusout', settleStory);

  // The byte count is a view-transient like the stories: typed text is measured where it lands,
  // and the engine's own sentence arrives from the check when the field commits.
  host.stage().addEventListener('input', (event) => {
    const input = event.target.closest?.('.field-input[data-ceiling]');
    if (!input) return;
    const counter = input.parentElement.querySelector('.byte-count');
    if (!counter) return;
    const typedBytes = byteCountOf(input.value);
    const ceiling = Number(input.dataset.ceiling);
    counter.textContent = `${typedBytes} / ${ceiling} bytes`;
    counter.classList.toggle('over-ceiling', typedBytes > ceiling);
  });
};
