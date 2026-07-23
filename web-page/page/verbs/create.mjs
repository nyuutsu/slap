// Both seats are defining inputs, not matched ones: slap cannot know which file is the original,
// so a drop lands in the original seat first and the swap link is the recourse.

import { html, nothing } from '../../vendor/lit-html/lit-html.js';
import { CheckVerdict } from './../engine-vocabulary.mjs';
import { roleWhisperedSlotMarkup, heldSeatMarkup, swapSeatsMarkup, chipRadioMarkup } from './../controls.mjs';
import { voiceLines, plainVoice, workingVoice, bottledVoice, blockedVoice, refusalVoice,
         advisoryMarkup } from './../answer-surface.mjs';
import { verbWord, flagWord, valueWord, quotedWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { utf8Text, typedTextFlags, fieldLabel } from './../metadata-controls.mjs';
import { makeMetadataBench, storiedText, base64OfBuffer, countedTextareaMarkup } from './../metadata-form.mjs';
import { formatPickerMarkup } from './../format-picker.mjs';
import { stemOf } from './../readouts.mjs';

const runLabel = 'Bottle';

const atRest = () => ({
  original: null, modified: null,
  formatToken: null,   // the format is an operand: nothing is chosen for you, and the workflow appears once you choose
  moreFormatsOpen: false,
  blob: { lane: 'typed', text: '', file: null, fileBase64: null },
  diz:  { lane: 'typed', text: '', file: null, fileText: null },
  checkAnswer: null,
  // apply's act doctrine: AtRest | Running{cancel} | Bottled | Refused | Fell
  act: { tag: 'AtRest' },
});

export const makeCreateVerb = (host) => {
  let create = atRest();

  const surfaceRow = () => host.surface()?.surfaceFormats.find((row) => row.formatToken === create.formatToken) ?? null;

  // Every input change re-judges the whole request; which changes matter is the engine's knowledge, not the page's.
  const recheck = (change) => {
    host.supersedeAsks();
    change();
    create.checkAnswer = null;
    askUnanswered();
    host.render();
  };

  const bench = makeMetadataBench(host, { surfaceRow, recheck });

  /* ------------------------------------------------------ declaration ---- */

  const blobRequest = () => {
    if (!bench.formatAcceptsField('MetadataEmbeddedBlob')) return { tag: 'InheritEmbeddedBlob' };
    if (create.blob.lane === 'typed' && create.blob.text) return { tag: 'SetEmbeddedTypedText', contents: create.blob.text };
    if (create.blob.lane === 'file' && create.blob.fileBase64 !== null) return { tag: 'SetEmbeddedBlob', contents: create.blob.fileBase64 };
    return { tag: 'InheritEmbeddedBlob' };
  };

  const dizRequest = () => {
    if (!bench.formatAcceptsField('MetadataFileIdDiz')) return { tag: 'InheritFileIdDiz' };
    if (create.diz.lane === 'typed' && create.diz.text) return { tag: 'SetFileIdDizFromText', contents: utf8Text(create.diz.text) };
    if (create.diz.lane === 'file' && create.diz.fileText !== null) return { tag: 'SetFileIdDiz', contents: utf8Text(create.diz.fileText) };
    return { tag: 'InheritFileIdDiz' };
  };

  const declaration = () => ({
    declaredCreateTargetFormat: surfaceRow().formatCreateTarget,
    declaredCreateOriginalName: create.original.name,
    declaredCreateModifiedName: create.modified.name,
    declaredCreateMetadata:     { requestedFileIdDiz:    dizRequest(),
                                  requestedEmbeddedBlob: blobRequest(),
                                  ...bench.declarationFields() },
    declaredCreateConstraints:  bench.constraintsDeclaration(),
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

  /* ------------------------------------------------------------ seats ---- */

  const actRunning  = () => create.act.tag === 'Running';
  const actAnswered = () => create.act.tag !== 'AtRest' && !actRunning();

  const abandonAct = () => {
    if (create.act.tag === 'Bottled') URL.revokeObjectURL(create.act.downloadHref);
    create.act = { tag: 'AtRest' };
  };

  const admitFile = (seat, file) => {
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
    if (seat === 'original') create.original = file;
    else create.modified = file;
    create.checkAnswer = null;
    host.fellow.nod();
    askUnanswered();
    host.render();
  };

  // A file read lands later; one that outlived its moment must not resurrect itself into the fresh state.
  const admitBlobFile = (file) => {
    const stateAtPick = create;
    file.arrayBuffer()
      .then(host.wheneverStillCurrent((buffer) => {
        if (create !== stateAtPick || create.act.tag !== 'AtRest') return;
        recheck(() => { create.blob = { lane: 'file', text: create.blob.text, file, fileBase64: base64OfBuffer(buffer) }; });
      }))
      .catch(host.askFailed);
  };

  const admitDizFile = (file) => {
    const stateAtPick = create;
    file.text()
      .then(host.wheneverStillCurrent((dizText) => {
        if (create !== stateAtPick || create.act.tag !== 'AtRest') return;
        recheck(() => { create.diz = { lane: 'file', text: create.diz.text, file, fileText: dizText }; });
      }))
      .catch(host.askFailed);
  };

  /* ---------------------------------------------------------- the act ---- */

  const bottledName = () => `${stemOf(create.modified.name)}${surfaceRow().formatFileExtension}`;

  const runCreate = () => {
    if (!create.formatToken || !create.original || !create.modified || actRunning()) return;
    const job = host.startJob('create', { original: create.original, modified: create.modified, declaration: declaration() });
    if (!job) return;
    create.act = { tag: 'Running', cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = bottledName();
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        create.act = {
          tag: 'Bottled',
          formatName: surfaceRow().formatDisplayName, advisories, downloadName, downloadHref, patchBytes: tail,
        };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        create.act = { tag: 'Refused', spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories };
        host.fellow.droop();
      }
      host.render();
      host.carryFocusToAnswer();
    }).catch((jobFailure) => {
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        create.act = { tag: 'AtRest' };
        host.setNotice(voiceLines.cancelled);
        host.render();
        return;
      }
      create.act = { tag: 'Fell', sentence: jobFailure.message, advisories: [] };
      host.fellow.droop();
      host.render();
      host.carryFocusToAnswer();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const slotFor = (seat, roleWord, file) =>
    actRunning() ? heldSeatMarkup(file, null) : roleWhisperedSlotMarkup(seat, roleWord, file);

  const sentenceMarkup = () => html`<p class="sentence">bottle the difference between
    ${slotFor('original', 'original', create.original)} and
    ${slotFor('modified', 'modified', create.modified)} as
    ${create.formatToken
      ? html`<span class="slot filled inert">${create.formatToken}</span>`
      : html`<span class="slot empty inert">format</span>`}</p>`;

  const laneChoiceMarkup = (settingName, fieldName, currentLane) => html`
    <fieldset class="choice-fieldset"><legend class="visually-hidden">${fieldLabel(fieldName)}</legend>
    <div class="choice-row">
      ${chipRadioMarkup({ groupName: settingName, setting: settingName, token: 'typed',
                          checked: currentLane === 'typed', label: 'type it' })}
      ${chipRadioMarkup({ groupName: settingName, setting: settingName, token: 'file',
                          checked: currentLane === 'file', label: 'use a file' })}
    </div></fieldset>`;

  const blobLanesMarkup = () => html`
    <p class="choice-label">${storiedText('MetadataEmbeddedBlob', fieldLabel('MetadataEmbeddedBlob'))}</p>
    ${laneChoiceMarkup('blob-lane', 'MetadataEmbeddedBlob', create.blob.lane)}
    ${create.blob.lane === 'typed'
      ? html`<textarea class="field-textarea" data-setting="blob-text" aria-labelledby="story-MetadataEmbeddedBlob"
          placeholder="a name, a version, a note: whatever you'd want found in here" .value=${create.blob.text}></textarea>`
      : html`<div class="choice-row"><button type="button" class="chip" data-action="pick-file"
          data-seat="blob-file">${create.blob.file?.name ?? 'choose a file…'}</button></div>
        <p class="aside">Any file at all; the bytes go in exactly as they are.</p>`}`;

  const dizLanesMarkup = () => html`
    <p class="choice-label">${storiedText('MetadataFileIdDiz', fieldLabel('MetadataFileIdDiz'))}</p>
    ${laneChoiceMarkup('diz-lane', 'MetadataFileIdDiz', create.diz.lane)}
    ${create.diz.lane === 'typed'
      ? countedTextareaMarkup({ setting: 'diz-text', placeholder: "the FILE_ID.DIZ text, as you'd like it carried",
          typed: create.diz.text, ceiling: bench.fieldCeiling('MetadataFileIdDiz'), labelledBy: 'story-MetadataFileIdDiz' })
      : html`<div class="choice-row"><button type="button" class="chip" data-action="pick-file"
          data-seat="diz-file">${create.diz.file?.name ?? 'choose a file…'}</button></div>`}`;

  const fileFieldMarkup = (fieldName) => {
    if (fieldName === 'MetadataEmbeddedBlob') return blobLanesMarkup();
    if (fieldName === 'MetadataFileIdDiz') return dizLanesMarkup();
    return null;
  };

  const stageMarkup = () => {
    if (actAnswered()) return sentenceMarkup();
    return html`
      ${sentenceMarkup()}
      ${create.original && create.modified && !actRunning() ? swapSeatsMarkup : nothing}
      ${formatPickerMarkup(host.surface()?.surfaceFormats ?? [], create.formatToken, create.moreFormatsOpen)}
      ${bench.metadataGroupMarkup(fileFieldMarkup)}
      ${bench.constraintsGroupMarkup()}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (create.act.tag === 'Bottled') return bottledVoice(create.act);
    if (create.act.tag === 'Refused' || create.act.tag === 'Fell') return refusalVoice(create.act, 'create');
    if (actRunning()) return workingVoice(voiceLines.bottling);
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
    if (verdict?.tag === CheckVerdict.Blocked) return html`${blockedVoice(verdict.contents)}${forewarnings}`;
    return html`${plainVoice(voiceLines.createReady)}${forewarnings}`;
  };

  /* ------------------------------------------------------------ tutor ---- */

  const fileFieldWords = (fieldName, flag) => {
    const laneState = fieldName === 'MetadataEmbeddedBlob' ? create.blob : create.diz;
    if (laneState.lane === 'typed' && laneState.text) return [flagWord(typedTextFlags[fieldName]), quotedWord(laneState.text)];
    if (laneState.lane === 'file' && laneState.file) return [flagWord(flag), fileWord(laneState.file.name)];
    return [];
  };

  const commandWords = () => {
    const words = [verbWord('slap'), verbWord('create')];
    if (!create.formatToken) words.push(flagWord('--format'), placeholderWord('FORMAT'));
    else if (create.formatToken !== 'bps') words.push(flagWord('--format'), valueWord(create.formatToken));
    words.push(namedOr(create.original, 'ORIGINAL'), namedOr(create.modified, 'MODIFIED'));
    words.push(create.modified && surfaceRow() ? fileWord(bottledName()) : placeholderWord('OUTPUT'));
    words.push(...bench.commandWords(fileFieldWords));
    return words;
  };

  /* ---------------------------------------------------------- surface ---- */

  const refusalCertain = () =>
    !!create.checkAnswer?.refused || create.checkAnswer?.answered?.tag === CheckVerdict.Blocked;

  return {
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (create.act.tag !== 'AtRest') return html``;
      const ready = host.hasSession() && create.formatToken && create.original && create.modified && !refusalCertain();
      return html`<button class="run" type="submit" form="stage" ?disabled=${!ready}>${runLabel}</button>`;
    },
    // Both seats are roms, so the sorting is unused; the original seat fills first because
    // "the first one I dropped" reads as the original. A full bench starts a fresh pair, original first again,
    // so a re-dropped pair never buries its first file in the modified seat.
    admitDroppedFile: (_sorting, file) => {
      if (actRunning()) return;
      if (create.original && create.modified) create.modified = null;
      admitFile(!create.original ? 'original' : 'modified', file);
    },
    admitPickedFile: (seat, file) => {
      if (seat === 'blob-file') admitBlobFile(file);
      else if (seat === 'diz-file') admitDizFile(file);
      else admitFile(seat, file);
    },
    askAgain: askUnanswered,
    storiesQuiet: () => create.act.tag !== 'AtRest',
    actions: {
      'more-formats': () => { create.moreFormatsOpen = !create.moreFormatsOpen; host.render(); },
      run: runCreate,
      'cancel-run': () => { if (actRunning()) create.act.cancel(); },
      'look-inside': () => {
        if (create.act.tag === 'Bottled') host.lookInside(new File([create.act.patchBytes], create.act.downloadName));
      },
      'swap-seats': () => {
        if (actRunning()) return;
        abandonAct();
        recheck(() => { [create.original, create.modified] = [create.modified, create.original]; });
        host.fellow.nod();
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonAct();
        create = atRest();
        bench.reset();
        host.fellow.settle();
        host.render();
      },
    },
    settings: {
      ...bench.settings,
      format: (formatToken) => {
        if (actRunning()) return;
        recheck(() => { create.formatToken = formatToken; });
      },
      'blob-lane': (lane) => recheck(() => { create.blob.lane = lane; }),
      'diz-lane': (lane) => recheck(() => { create.diz.lane = lane; }),
      'blob-text': (value) => recheck(() => { create.blob.text = value; }),
      'diz-text': (value) => recheck(() => { create.diz.text = value; }),
    },
    typings: {
      ...bench.typings,
      'blob-text': (value) => { create.blob.text = value; host.render(); },
      'diz-text': (value) => { create.diz.text = value; host.render(); },
    },
  };
};
