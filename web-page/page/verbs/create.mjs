// The format list, each format's accepted fields, every control's kind, and the choice vocabularies
// all arrive from describeSurface; the page adds only its opinions — which tiles to recommend, and the words on them.
// Both seats are defining inputs, not matched ones: slap cannot know which file is the original,
// so a drop lands in the original seat first and the swap link is the recourse.

import { html } from './../dom.mjs';
import { groupMarkup, toggleMarkup, roleWhisperedSlotMarkup, heldSeatMarkup, swapSeatsMarkup } from './../controls.mjs';
import { voiceLines, plainVoice, workingVoice, bottledVoice, blockedVoice, refusalVoice,
         advisoryMarkup } from './../answer-surface.mjs';
import { verbWord, flagWord, valueWord, quotedWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { requestKeyOf, utf8Text, toggleRequests, typedTextFlags, fieldLabel, fieldWhy,
         choiceGloss, fieldStories, concealedWhileToggled, windowUnits } from './../metadata-controls.mjs';
import { constraintControls } from './../constraint-controls.mjs';
import { humanByteSize } from './../readouts.mjs';

const runLabel = 'Bottle';

// The page's one editorial table: the list comes from the surface, the opinion lives here.
// A format with no words still shows — under "more formats", unadorned. All of this copy is a draft.
const recommendedTokens = ['bps', 'xdelta3', 'ppf3'];
const curioToken = 'rfc-vcdiff';

const tileCopy = {
  bps: "The safe default. Checks it's patching the right file, survives size changes, and every modern patcher reads it.",
  xdelta3: 'For big files. Compresses the patch, so disc images and large roms stay manageable.',
  ppf3: 'For PlayStation disc images. Can carry undo data and a FILE_ID.DIZ.',
  'rfc-vcdiff': 'The VCDIFF standard itself. It works — but nothing out there applies it except slap. Here because it is interesting, not because you should ship it.',
};

// A note describes; it does not rank. Only some formats carry one, and silence is fine.
const formatNotes = {
  'rfc-vcdiff': 'RFC 3284, straight from the standard. slap is the only patcher we know of that reads one.',
  ips: 'The lingua franca: almost every patcher ever written can apply an IPS. Offsets are 24 bits wide, so a record reaches about 16 MB.',
  ips32: 'IPS with 32-bit offsets, reaching well past the 16 MB mark.',
  ppf1: 'Icarus of Paradox, for the PlayStation scene — the first of the three PPFs.',
  ppf2: "Paradox's second pass: adds a validation block and room for a FILE_ID.DIZ.",
  ups: 'byuu\'s symmetric format: a UPS patch is its own reverse, so it always peels back off.',
  xdelta1: "Joshua MacDonald's original xdelta, 1997 to 2003.",
};

const atRest = () => ({
  original: null, modified: null,
  formatToken: null,   // the format is an operand: nothing is chosen for you, and the workflow appears once you choose
  moreFormatsOpen: false,
  fieldValues: {},     // free-text and number fields, as typed
  windowUnit: 'bytes',
  toggledFields: {},
  chosenChoices: {},   // choice fields, by chosen token; the engine value is looked up at declaration time
  blob: { lane: 'typed', text: '', file: null, fileBase64: null },
  diz:  { lane: 'typed', text: '', file: null, fileText: null },
  chosenConstraints: {},
  checkAnswer: null,
  running: null,
  outcome: null,
});

const stemOf = (fileName) => {
  const lastDot = fileName.lastIndexOf('.');
  return lastDot > 0 ? fileName.slice(0, lastDot) : fileName;
};

const wholePositive = (typed) => {
  const parsed = Number(typed);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
};

// btoa takes a binary string; built in slices so a large blob cannot overrun the argument list.
const base64OfBuffer = (buffer) => {
  const blobBytes = new Uint8Array(buffer);
  let binary = '';
  for (let at = 0; at < blobBytes.length; at += 0x8000)
    binary += String.fromCharCode(...blobBytes.subarray(at, at + 0x8000));
  return btoa(binary);
};

export const makeCreateVerb = (host) => {
  let create = atRest();

  const surfaceRow = () => host.surface()?.surfaceFormats.find((row) => row.formatToken === create.formatToken) ?? null;
  const fieldRoster = () => host.surface()?.surfaceMetadataFields ?? [];
  const formatAcceptsField = (fieldName) => (surfaceRow()?.formatAcceptedFields ?? []).includes(fieldName);
  const acceptedRosterRows = () => fieldRoster().filter((row) => formatAcceptsField(row.describedMetadataField));
  const fieldConcealed = (fieldName) =>
    concealedWhileToggled[fieldName] && create.toggledFields[concealedWhileToggled[fieldName]];

  /* ------------------------------------------------------ declaration ---- */
  /* Only what the chosen format accepts is spoken: a field typed under one format
     stays in hand across a tile change, but never rides a declaration it doesn't belong in. */

  const blobRequest = () => {
    if (!formatAcceptsField('MetadataEmbeddedBlob')) return { tag: 'InheritEmbeddedBlob' };
    if (create.blob.lane === 'typed' && create.blob.text) return { tag: 'SetEmbeddedTypedText', contents: create.blob.text };
    if (create.blob.lane === 'file' && create.blob.fileBase64 !== null) return { tag: 'SetEmbeddedBlob', contents: create.blob.fileBase64 };
    return { tag: 'InheritEmbeddedBlob' };
  };

  const dizRequest = () => {
    if (!formatAcceptsField('MetadataFileIdDiz')) return { tag: 'InheritFileIdDiz' };
    if (create.diz.lane === 'typed' && create.diz.text) return { tag: 'SetFileIdDizFromText', contents: utf8Text(create.diz.text) };
    if (create.diz.lane === 'file' && create.diz.fileText !== null) return { tag: 'SetFileIdDiz', contents: utf8Text(create.diz.fileText) };
    return { tag: 'InheritFileIdDiz' };
  };

  const chosenWindowUnit = () => windowUnits.find((unit) => unit.token === create.windowUnit);

  const windowSizeBytes = () => {
    const counted = wholePositive(create.fieldValues.MetadataWindowSize);
    if (!counted) return null;
    const scaledBytes = counted * chosenWindowUnit().bytesPer;
    return Number.isSafeInteger(scaledBytes) ? scaledBytes : null;
  };

  const chosenChoiceValue = (fieldName, choicePairs) => {
    const chosenToken = create.chosenChoices[fieldName];
    const chosenPair = choicePairs.find(([token]) => token === chosenToken);
    return chosenPair ? chosenPair[1] : null;
  };

  const metadataDeclaration = () => {
    const requested = {
      requestedFileIdDiz:    dizRequest(),
      requestedEmbeddedBlob: blobRequest(),
    };
    for (const row of acceptedRosterRows()) {
      const fieldName = row.describedMetadataField;
      const kind = row.metadataFieldControlKind;
      if (kind.tag === 'FreeTextField') {
        if (create.fieldValues[fieldName]) requested[requestKeyOf(fieldName)] = utf8Text(create.fieldValues[fieldName]);
      } else if (kind.tag === 'NumberField') {
        const declaredCount = fieldName === 'MetadataWindowSize'
          ? windowSizeBytes()
          : wholePositive(create.fieldValues[fieldName]);
        if (declaredCount) requested[requestKeyOf(fieldName)] = declaredCount;
      } else if (kind.tag === 'ToggleField') {
        if (create.toggledFields[fieldName] && toggleRequests[fieldName])
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
      const chosen = create.chosenConstraints[constraintName]
        && (surfaceRow()?.formatConstraints ?? []).includes(constraintName);
      declared[control.requestKey] = chosen ? control.chosenRequirement : control.restingRequirement;
    }
    return declared;
  };

  const declaration = () => ({
    declaredCreateTargetFormat: surfaceRow().formatCreateTarget,
    declaredCreateOriginalName: create.original.name,
    declaredCreateModifiedName: create.modified.name,
    declaredCreateMetadata:     metadataDeclaration(),
    declaredCreateConstraints:  constraintsDeclaration(),
  });

  /* ------------------------------------------------------------- asks ---- */

  const askCheck = () => {
    if (!host.hasSession() || !create.formatToken || !create.original || !create.modified) return;
    host.ask('check-create', { original: create.original, modified: create.modified, declaration: declaration() })
      ?.then(host.wheneverStillCurrent((answer) => { create.checkAnswer = answer; }))
      .catch(host.askFailed);
  };

  const askUnanswered = () => {
    if (!create.checkAnswer) askCheck();
  };

  // Every input change re-judges the whole request; which changes matter is the engine's knowledge, not the page's.
  const recheck = (change) => {
    host.supersedeAsks();
    change();
    create.checkAnswer = null;
    askUnanswered();
    host.render();
  };

  /* ------------------------------------------------------------ seats ---- */

  const abandonOutcome = () => {
    if (create.outcome?.bottled) URL.revokeObjectURL(create.outcome.bottled.downloadHref);
    create.outcome = null;
  };

  const admitFile = (seat, file) => {
    if (create.running) return;
    host.supersedeAsks();
    abandonOutcome();
    if (seat === 'original') create.original = file;
    else create.modified = file;
    create.checkAnswer = null;
    host.fellow.nod();
    askUnanswered();
    host.render();
  };

  // A file read lands later; one that lands after a reset, or mid-run, must not resurrect itself into the fresh state.
  const admitBlobFile = (file) => {
    const stateAtPick = create;
    file.arrayBuffer()
      .then((buffer) => {
        if (create !== stateAtPick || create.running) return;
        recheck(() => { create.blob = { lane: 'file', text: create.blob.text, file, fileBase64: base64OfBuffer(buffer) }; });
      })
      .catch(host.askFailed);
  };

  const admitDizFile = (file) => {
    const stateAtPick = create;
    file.text()
      .then((dizText) => {
        if (create !== stateAtPick || create.running) return;
        recheck(() => { create.diz = { lane: 'file', text: create.diz.text, file, fileText: dizText }; });
      })
      .catch(host.askFailed);
  };

  /* ---------------------------------------------------------- the act ---- */

  const bottledName = () => `${stemOf(create.modified.name)}${surfaceRow().formatFileExtension}`;

  const runCreate = () => {
    if (!create.formatToken || !create.original || !create.modified || create.running) return;
    const job = host.startJob('create', { original: create.original, modified: create.modified, declaration: declaration() });
    if (!job) return;
    create.running = { cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      create.running = null;
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = bottledName();
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        create.outcome = { bottled: {
          formatName: surfaceRow().formatDisplayName, advisories, downloadName, downloadHref, patchBytes: tail,
        } };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        create.outcome = { refused: { spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories } };
        host.fellow.droop();
      }
      host.render();
    }).catch((jobFailure) => {
      create.running = null;
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        host.setNotice(voiceLines.cancelled);
      } else {
        create.outcome = { failed: { sentence: jobFailure.message, advisories: [] } };
        host.fellow.droop();
      }
      host.render();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const slotFor = (seat, roleWord, file) =>
    create.running ? heldSeatMarkup(file, null) : roleWhisperedSlotMarkup(seat, roleWord, file);

  const sentenceMarkup = () => html`<p class="sentence">bottle the difference between
    ${slotFor('original', 'original', create.original)} and
    ${slotFor('modified', 'modified', create.modified)} as
    ${create.formatToken
      ? html`<span class="slot filled inert">${create.formatToken}</span>`
      : html`<span class="slot empty inert">format</span>`}</p>`;

  const formatNoteMarkup = () => {
    const note = formatNotes[create.formatToken];
    return note && html`<p class="format-note"><span class="note-mark">note</span><span>${note}</span></p>`;
  };

  const tileMarkup = (row, curio) => html`<button
    class="tile${curio ? ' curio' : ''}${row.formatToken === create.formatToken ? ' on' : ''}"
    aria-pressed="${row.formatToken === create.formatToken}"
    data-action="choose-format" data-token="${row.formatToken}">
    <span class="tile-name">${row.formatDisplayName}</span>
    <span class="tile-copy">${tileCopy[row.formatToken] ?? ''}</span></button>`;

  const pickerMarkup = () => {
    const rows = host.surface()?.surfaceFormats ?? [];
    if (rows.length === 0) return null;
    const rowByToken = (token) => rows.find((row) => row.formatToken === token);
    const recommendedRows = recommendedTokens.map(rowByToken).filter(Boolean);
    const curioRow = rowByToken(curioToken);
    const spotlit = new Set([...recommendedTokens, curioToken]);
    const quieterRows = rows.filter((row) => !spotlit.has(row.formatToken));
    const chosenIsQuieter = quieterRows.some((row) => row.formatToken === create.formatToken);
    const moreOpen = create.moreFormatsOpen || chosenIsQuieter;
    return groupMarkup('format', html`
      <div class="tiles">${recommendedRows.map((row) => tileMarkup(row, false))}</div>
      ${curioRow && tileMarkup(curioRow, true)}
      ${!chosenIsQuieter && html`<button class="quiet-button" data-action="more-formats">
        ${moreOpen ? 'fewer formats' : `more formats (${quieterRows.length})`}</button>`}
      ${moreOpen && html`<div class="choice-row">${quieterRows.map((row) => html`<button
        class="chip${row.formatToken === create.formatToken ? ' on' : ''}"
        aria-pressed="${row.formatToken === create.formatToken}"
        data-action="choose-format" data-token="${row.formatToken}">${row.formatToken}</button>`)}</div>`}`);
  };

  // Window size is the one control with a crossed fact to show at rest; any other placeholder would be page words.
  const fieldPlaceholder = (fieldName) => {
    if (fieldName !== 'MetadataWindowSize') return null;
    const windowDefault = surfaceRow()?.formatWindowDefault;
    if (!windowDefault) return null;
    return windowDefault.tag === 'WindowsOfBytes'
      ? `auto: ${humanByteSize(windowDefault.contents)} windows`
      : 'auto: one window, the whole file';
  };

  const storiedAttribute = (fieldName) => fieldStories[fieldName] && html`data-story-field="${fieldName}"`;
  const whySpan = (fieldName) => fieldWhy(fieldName) && html` <span class="why">— ${fieldWhy(fieldName)}</span>`;

  // The story trigger hugs its words — a block label's empty width must not speak — and takes focus so a keyboard hears it too.
  const storiedText = (fieldName, labelText) => (fieldStories[fieldName]
    ? html`<span class="has-story" tabindex="0" data-story-field="${fieldName}">${labelText}</span>`
    : labelText);

  const fieldCeiling = (fieldName) =>
    (surfaceRow()?.formatTextFieldCeilings ?? []).find(([ceilingField]) => ceilingField === fieldName)?.[1] ?? null;
  const byteCountOf = (typed) => new TextEncoder().encode(typed).length;

  const textFieldMarkup = (row, inputType) => {
    const fieldName = row.describedMetadataField;
    const ceiling = inputType === 'text' ? fieldCeiling(fieldName) : null;
    const typed = create.fieldValues[fieldName] ?? '';
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
        class="chip${create.windowUnit === unit.token ? ' on' : ''}" aria-pressed="${create.windowUnit === unit.token}"
        data-action="window-unit" data-unit="${unit.token}">${unit.token}</button>`)}</span>`}
      ${whySpan(fieldName)}
    </div>`;
  };

  const choiceRowMarkup = (row, choicePairs) => {
    const fieldName = row.describedMetadataField;
    const gloss = choiceGloss(fieldName, create.chosenChoices[fieldName]);
    return html`<div>
      <p class="choice-label">${storiedText(fieldName, fieldLabel(fieldName, row.metadataFieldFlag))}${whySpan(fieldName)}</p>
      <div class="choice-row">${choicePairs.map(([token]) => html`<button
        class="chip${create.chosenChoices[fieldName] === token ? ' on' : ''}"
        aria-pressed="${create.chosenChoices[fieldName] === token}"
        data-action="choose-meta" data-field="${fieldName}" data-token="${token}">${token}</button>`)}</div>
      ${gloss && html`<p class="choice-gloss">${gloss}</p>`}</div>`;
  };

  const laneChips = (laneAction, currentLane) => html`<div class="choice-row">
    <button class="chip${currentLane === 'typed' ? ' on' : ''}" aria-pressed="${currentLane === 'typed'}"
      data-action="${laneAction}" data-lane="typed">type it</button>
    <button class="chip${currentLane === 'file' ? ' on' : ''}" aria-pressed="${currentLane === 'file'}"
      data-action="${laneAction}" data-lane="file">use a file</button>
  </div>`;

  const blobLanesMarkup = () => html`
    <p class="choice-label">${storiedText('MetadataEmbeddedBlob', fieldLabel('MetadataEmbeddedBlob'))}</p>
    ${laneChips('blob-lane', create.blob.lane)}
    ${create.blob.lane === 'typed'
      ? html`<textarea class="field-textarea" data-setting="blob-text"
          placeholder="a name, a version, a note: whatever you'd want found in here">${create.blob.text}</textarea>`
      : html`<div class="choice-row"><button class="chip" data-action="pick-file"
          data-seat="blob-file">${create.blob.file?.name ?? 'choose a file…'}</button></div>
        <p class="aside">Any file at all; the bytes go in exactly as they are.</p>`}`;

  const dizLanesMarkup = () => html`
    <p class="choice-label">${storiedText('MetadataFileIdDiz', fieldLabel('MetadataFileIdDiz'))}</p>
    ${laneChips('diz-lane', create.diz.lane)}
    ${create.diz.lane === 'typed'
      ? html`<textarea class="field-textarea" data-setting="diz-text"
          placeholder="the FILE_ID.DIZ text, as you'd like it carried">${create.diz.text}</textarea>`
      : html`<div class="choice-row"><button class="chip" data-action="pick-file"
          data-seat="diz-file">${create.diz.file?.name ?? 'choose a file…'}</button></div>`}`;

  const fileFieldMarkup = (fieldName) => {
    if (fieldName === 'MetadataEmbeddedBlob') return blobLanesMarkup();
    if (fieldName === 'MetadataFileIdDiz') return dizLanesMarkup();
    return null;
  };

  const controlMarkup = (row) => {
    const fieldName = row.describedMetadataField;
    const kind = row.metadataFieldControlKind;
    if (fieldConcealed(fieldName)) return null;
    if (kind.tag === 'ToggleField')
      return toggleRequests[fieldName] && toggleMarkup({
        id: `meta-${fieldName}`, setting: 'toggle', field: fieldName,
        checked: !!create.toggledFields[fieldName],
        label: fieldLabel(fieldName, row.metadataFieldFlag), why: fieldWhy(fieldName),
      });
    if (kind.tag === 'ChoiceField') return choiceRowMarkup(row, kind.contents.contents);
    if (kind.tag === 'FileField') return fileFieldMarkup(fieldName);
    return textFieldMarkup(row, kind.tag === 'NumberField' ? 'number' : 'text');
  };

  const metadataGroupMarkup = () => {
    const rows = acceptedRosterRows();
    if (rows.length === 0) return null;
    return groupMarkup('metadata', html`${rows.map(controlMarkup)}`);
  };

  const constraintsGroupMarkup = () => {
    const toggles = (surfaceRow()?.formatConstraints ?? []).flatMap((constraintName) => {
      const control = constraintControls[constraintName];
      if (!control) return [];
      return [toggleMarkup({
        id: `constraint-${constraintName}`, setting: 'constraint', field: constraintName,
        checked: !!create.chosenConstraints[constraintName],
        label: control.controlLabel, why: control.controlWhy,
      })];
    });
    return toggles.length === 0 ? null : groupMarkup('constraints', html`${toggles}`);
  };

  const stageMarkup = () => {
    if (create.outcome) return sentenceMarkup();
    return html`
      ${sentenceMarkup()}
      ${create.original && create.modified && !create.running && swapSeatsMarkup}
      ${formatNoteMarkup()}
      ${pickerMarkup()}
      ${metadataGroupMarkup()}
      ${constraintsGroupMarkup()}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (create.outcome?.bottled) return bottledVoice(create.outcome.bottled);
    if (create.outcome?.refused) return refusalVoice(create.outcome.refused, 'create');
    if (create.outcome?.failed) return refusalVoice(create.outcome.failed, 'create');
    if (create.running) return workingVoice();
    if (host.notice()) return plainVoice(host.notice());
    if (!create.original && !create.modified) return plainVoice(voiceLines.createResting);
    if (!create.modified) return plainVoice(voiceLines.createOriginalOnly);
    if (!create.original) return plainVoice(voiceLines.createModifiedOnly);
    if (!create.formatToken) return plainVoice(voiceLines.createNeedsFormat);
    if (!create.checkAnswer) return plainVoice(voiceLines.sizingUp);
    if (create.checkAnswer.refused)
      return html`<p class="refusal">${create.checkAnswer.refused.spokenErrorSentence}</p>`;
    const forewarnings = advisoryMarkup(create.checkAnswer.advisories ?? []);
    const verdict = create.checkAnswer.answered;
    if (verdict?.tag === 'SpokenBlocked') return html`${blockedVoice(verdict.contents)}${forewarnings}`;
    return html`${plainVoice(voiceLines.createReady)}${forewarnings}`;
  };

  /* ------------------------------------------------------------ tutor ---- */

  const commandWords = () => {
    const words = [verbWord('slap'), verbWord('create')];
    if (!create.formatToken) words.push(flagWord('--format'), placeholderWord('FORMAT'));
    else if (create.formatToken !== 'bps') words.push(flagWord('--format'), valueWord(create.formatToken));
    words.push(namedOr(create.original, 'ORIGINAL'), namedOr(create.modified, 'MODIFIED'));
    words.push(create.modified && surfaceRow() ? fileWord(bottledName()) : placeholderWord('OUTPUT'));
    for (const row of acceptedRosterRows()) {
      const fieldName = row.describedMetadataField;
      const kind = row.metadataFieldControlKind;
      const flag = `--${row.metadataFieldFlag}`;
      if (kind.tag === 'FreeTextField' && create.fieldValues[fieldName])
        words.push(flagWord(flag), quotedWord(create.fieldValues[fieldName]));
      if (kind.tag === 'NumberField' && wholePositive(create.fieldValues[fieldName])) {
        const suffix = fieldName === 'MetadataWindowSize' ? chosenWindowUnit().suffix : '';
        words.push(flagWord(flag), valueWord(`${wholePositive(create.fieldValues[fieldName])}${suffix}`));
      }
      if (kind.tag === 'ToggleField' && create.toggledFields[fieldName] && toggleRequests[fieldName])
        words.push(flagWord(flag));
      if (kind.tag === 'ChoiceField' && create.chosenChoices[fieldName] && !fieldConcealed(fieldName))
        words.push(flagWord(flag), valueWord(create.chosenChoices[fieldName]));
      if (kind.tag === 'FileField') {
        const laneState = fieldName === 'MetadataEmbeddedBlob' ? create.blob : create.diz;
        if (laneState.lane === 'typed' && laneState.text)
          words.push(flagWord(typedTextFlags[fieldName]), quotedWord(laneState.text));
        if (laneState.lane === 'file' && laneState.file)
          words.push(flagWord(flag), fileWord(laneState.file.name));
      }
    }
    for (const [constraintName, control] of Object.entries(constraintControls))
      if (create.chosenConstraints[constraintName] && (surfaceRow()?.formatConstraints ?? []).includes(constraintName))
        words.push(flagWord(control.terminalFlag));
    return words;
  };

  /* ---------------------------------------------------------- surface ---- */

  const refusalCertain = () =>
    !!create.checkAnswer?.refused || create.checkAnswer?.answered?.tag === 'SpokenBlocked';

  // The long stories are view-transients, never state: hovering or focusing a storied control lets the fellow
  // speak it, and leaving renders the box back to what the state says. A control being typed in keeps its story —
  // the render would tear focus out of the input.
  const speakStory = (event) => {
    if (create.outcome || create.running) return;
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

  return {
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (create.outcome || create.running) return html``;
      const ready = host.hasSession() && create.formatToken && create.original && create.modified && !refusalCertain();
      return html`<button class="run" data-action="run" ${!ready && html`disabled`}>${runLabel}</button>`;
    },
    // Both seats are roms, so the sorting is unused; the original seat fills first because
    // "the first one I dropped" reads as the original. A full bench starts a fresh pair, original first again,
    // so a re-dropped pair never buries its first file in the modified seat.
    admitDroppedFile: (_sorting, file) => {
      if (create.running) return;
      if (create.original && create.modified) create.modified = null;
      admitFile(!create.original ? 'original' : 'modified', file);
    },
    admitPickedFile: (seat, file) => {
      if (seat === 'blob-file') admitBlobFile(file);
      else if (seat === 'diz-file') admitDizFile(file);
      else admitFile(seat, file);
    },
    askAgain: askUnanswered,
    actions: {
      'choose-format': ({ token }) => {
        if (create.running) return;
        recheck(() => { create.formatToken = token; });
      },
      'more-formats': () => { create.moreFormatsOpen = !create.moreFormatsOpen; host.render(); },
      'choose-meta': ({ field, token }) => recheck(() => {
        create.chosenChoices[field] = create.chosenChoices[field] === token ? null : token;
      }),
      'blob-lane': ({ lane }) => recheck(() => { create.blob.lane = lane; }),
      'diz-lane': ({ lane }) => recheck(() => { create.diz.lane = lane; }),
      'window-unit': ({ unit }) => recheck(() => { create.windowUnit = unit; }),
      run: runCreate,
      'cancel-run': () => create.running?.cancel(),
      'look-inside': () => {
        const bottled = create.outcome?.bottled;
        if (bottled) host.lookInside(new File([bottled.patchBytes], bottled.downloadName));
      },
      'swap-seats': () => {
        if (create.running) return;
        abandonOutcome();
        recheck(() => { [create.original, create.modified] = [create.modified, create.original]; });
        host.fellow.nod();
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonOutcome();
        create = atRest();
        host.fellow.settle();
        host.render();
      },
    },
    settings: {
      field: (value, { field }) => recheck(() => { create.fieldValues[field] = value; }),
      toggle: (checked, { field }) => recheck(() => { create.toggledFields[field] = checked; }),
      constraint: (checked, { field }) => recheck(() => { create.chosenConstraints[field] = checked; }),
      'blob-text': (value) => recheck(() => { create.blob.text = value; }),
      'diz-text': (value) => recheck(() => { create.diz.text = value; }),
    },
  };
};
