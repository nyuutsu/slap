// A seated rom turns the run into apply-and-recreate, so the rom seat wears apply's whole preflight.

import { html, nothing } from '../../vendor/lit-html/lit-html.js';
import { Verdict, CheckVerdict, Sorting, EmbeddedField } from './../engine-vocabulary.mjs';
import { groupMarkup, toggleMarkup, seatSlotMarkup, heldSeatMarkup, inertSlotMarkup,
         headerControlMarkup, encodingPickerMarkup, preseededConsoleRow, chipRadioMarkup } from './../controls.mjs';
import { applyFactsCardMarkup } from './../facts-card.mjs';
import { voiceLines, plainVoice, restingVoice, workingVoice, convertedVoice, blockedVoice, refusalVoice,
         advisoryMarkup } from './../answer-surface.mjs';
import { verbWord, flagWord, valueWord, quotedWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { utf8Text, typedTextFlags, dropFlags, carriedFieldLabels, fieldLabel } from './../metadata-controls.mjs';
import { dialectControls, dialectTogglesMarkup } from './../dialect-controls.mjs';
import { identifyDeclaration } from './../declarations.mjs';
import { makeMetadataBench, storiedText, base64OfBuffer, countedTextareaMarkup } from './../metadata-form.mjs';
import { formatPickerMarkup, formatSeatMarkup, formatGroupId } from './../format-picker.mjs';
import { stemOf } from './../readouts.mjs';

const runLabel = 'Rebottle';

const atRest = () => ({
  patch: null, patchIdentity: null, patchReading: null,
  formatToken: null,
  moreFormatsOpen: false,
  source: null, sourceFacts: null, sourceReport: null,
  framing: { tag: 'TakeInputAsIs', console: null },
  verificationPolicy: 'EnforceVerification',
  ppf1Origin: 'PPF1OriginPC',
  metadataEncoding: 'utf-8',
  moreEncodingsOpen: false,
  blob: { lane: null, text: '', file: null, fileBase64: null },
  diz:  { lane: null, text: '', file: null, fileBytes: null },
  checkAnswer: null,
  // apply's act doctrine: AtRest | Running{cancel} | Converted | Refused | Fell
  act: { tag: 'AtRest' },
});

export const makeConvertVerb = (host) => {
  let convert = atRest();

  const surfaceRow = () => host.surface().surfaceFormats.find((row) => row.formatToken === convert.formatToken) ?? null;

  const recheck = (change) => {
    host.supersedeAsks();
    change();
    convert.checkAnswer = null;
    askUnanswered();
    host.render();
  };

  // The check judges PPF2's floor at the framed size, so a framing change re-asks the check too.
  const reweighSource = (change) => {
    host.supersedeAsks();
    change();
    convert.sourceReport = null;
    convert.checkAnswer = null;
    askUnanswered();
    host.render();
  };

  const rereadPatch = (change) => {
    host.supersedeAsks();
    change();
    convert.patchIdentity = null;
    convert.patchReading = null;
    convert.sourceReport = null;
    convert.checkAnswer = null;
    askUnanswered();
    host.render();
  };

  const bench = makeMetadataBench(host, { surfaceRow, recheck });

  /* --------------------------------------------------------- presence ---- */

  const fieldCarried = (fieldName) =>
    (convert.patchReading?.answered?.infoEmbedded ?? []).some((embed) =>
      embed.embeddedField.tag !== EmbeddedField.Absent && carriedFieldLabels[embed.embeddedLabel] === fieldName);

  const laneOf = (laneState, carried) => laneState.lane ?? (carried ? 'keep' : 'typed');


  /* ------------------------------------------------------ declaration ---- */

  const blobRequest = () => {
    if (!bench.formatAcceptsField('MetadataEmbeddedBlob')) return { tag: 'InheritEmbeddedBlob' };
    const lane = laneOf(convert.blob, fieldCarried('MetadataEmbeddedBlob'));
    if (lane === 'drop') return { tag: 'DropEmbeddedBlob' };
    if (lane === 'typed' && convert.blob.text) return { tag: 'SetEmbeddedTypedText', contents: convert.blob.text };
    if (lane === 'file' && convert.blob.fileBase64 !== null) return { tag: 'SetEmbeddedBlob', contents: convert.blob.fileBase64 };
    return { tag: 'InheritEmbeddedBlob' };
  };

  // Decoding waits until declaration time, so a late encoding choice still reaches the bytes.
  // The CLI reads --diz FILE the same way; an encoding the browser lacks falls back to UTF-8.
  const decodedDizFile = () => {
    try {
      return { encodedTextEncoding: convert.metadataEncoding,
               encodedTextContent: new TextDecoder(convert.metadataEncoding).decode(convert.diz.fileBytes) };
    } catch {
      return utf8Text(new TextDecoder().decode(convert.diz.fileBytes));
    }
  };

  const dizRequest = () => {
    if (!bench.formatAcceptsField('MetadataFileIdDiz')) return { tag: 'InheritFileIdDiz' };
    const lane = laneOf(convert.diz, fieldCarried('MetadataFileIdDiz'));
    if (lane === 'drop') return { tag: 'DropFileIdDiz' };
    if (lane === 'typed' && convert.diz.text) return { tag: 'SetFileIdDizFromText', contents: utf8Text(convert.diz.text) };
    if (lane === 'file' && convert.diz.fileBytes !== null) return { tag: 'SetFileIdDiz', contents: decodedDizFile() };
    return { tag: 'InheritFileIdDiz' };
  };

  // Two things are read under the chosen encoding, and the command line reads the same two: the source patch's
  // own text where it records no encoding for it, and a DIZ handed over as a file, whose bytes it decodes.
  // With neither in hand the choice stays put and says nothing, having nothing to read.
  const encodingSpeaks = () =>
    (convert.patchReading?.answered?.infoUndeclaredTextFields ?? []).length > 0
    || dizRequest().tag === 'SetFileIdDiz';

  const framingDeclaration = () => convert.framing.tag === 'TakeInputAsIs'
    ? { tag: 'TakeInputAsIs' }
    : { tag: convert.framing.tag, contents: convert.framing.console.describedConsoleHeader };

  const declaration = () => ({
    declaredConvertTargetFormat:       surfaceRow().formatCreateTarget,
    declaredConvertSourceFraming:      convert.source ? framingDeclaration() : null,
    declaredConvertVerificationPolicy: convert.verificationPolicy,
    declaredConvertMetadata:           { requestedFileIdDiz:    dizRequest(),
                                         requestedEmbeddedBlob: blobRequest(),
                                         ...bench.declarationFields() },
    declaredConvertConstraints:        bench.constraintsDeclaration(),
    declaredConvertMetadataEncoding:   convert.metadataEncoding,
    declaredConvertDialects:           { requestedPPF1Origin: convert.ppf1Origin },
  });

  const applyDeclaration = () => ({
    declaredApplyFraming:            framingDeclaration(),
    declaredApplyVerificationPolicy: convert.verificationPolicy,
    declaredApplyDialects:           { requestedPPF1Origin: convert.ppf1Origin },
  });

  /* ------------------------------------------------------------- asks ---- */

  const impedimentSpoken = () => convert.patchIdentity?.answered?.spokenIdentityImpediment ?? null;

  const askIdentity = () => {
    if (!convert.patch) return;
    host.ask('identify', { patch: convert.patch, declaration: identifyDeclaration(convert.ppf1Origin, convert.metadataEncoding) })
      ?.then(host.wheneverStillCurrent((answer) => { convert.patchIdentity = answer; }))
      .catch(host.askFailed);
  };

  const askReading = () => {
    if (!convert.patch) return;
    host.ask('inspect', { patch: convert.patch, declaration: {
        declaredInspectMetadataEncoding: convert.metadataEncoding,
        declaredInspectDialects: { requestedPPF1Origin: convert.ppf1Origin } } })
      ?.then(host.wheneverStillCurrent((answer) => {
        convert.patchReading = answer;
        // the reading is a declaration input, so a check asked before it landed is stale
        convert.checkAnswer = null;
        askCheck();
      }))
      .catch(host.askFailed);
  };

  const askCheck = () => {
    if (!host.hasSession() || !convert.patch || !convert.formatToken || impedimentSpoken()) return;
    host.ask('check-convert', { patch: convert.patch, source: convert.source, declaration: declaration() })
      ?.then(host.wheneverStillCurrent((answer) => { convert.checkAnswer = answer; }))
      .catch(host.askFailed);
  };

  const askSourceFacts = () => {
    if (!convert.source) return;
    host.ask('describe-rom', { rom: convert.source })
      ?.then(host.wheneverStillCurrent(({ answered }) => { convert.sourceFacts = answered; }))
      .catch(host.askFailed);
  };

  const askSourceReport = () => {
    if (!convert.patch || !convert.source || impedimentSpoken()) return;
    host.ask('check-apply', { patch: convert.patch, rom: convert.source, declaration: applyDeclaration() })
      ?.then(host.wheneverStillCurrent(({ answered }) => { convert.sourceReport = answered; }))
      .catch(host.askFailed);
  };

  const askUnanswered = () => {
    if (!convert.patchIdentity) askIdentity();
    if (!convert.patchReading) askReading();
    if (!convert.sourceFacts) askSourceFacts();
    if (!convert.sourceReport) askSourceReport();
    if (!convert.checkAnswer) askCheck();
  };

  /* ------------------------------------------------------------ seats ---- */

  const actRunning  = () => convert.act.tag === 'Running';
  const actAnswered = () => convert.act.tag !== 'AtRest' && !actRunning();

  const abandonAct = () => {
    if (convert.act.tag === 'Converted') URL.revokeObjectURL(convert.act.downloadHref);
    convert.act = { tag: 'AtRest' };
  };

  const admitPatch = (file) => {
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
    convert.patch = file;
    convert.patchIdentity = null;
    convert.patchReading = null;
    // the dialect toggle and the carry-or-drop lanes describe a patch no longer here
    convert.ppf1Origin = 'PPF1OriginPC';
    convert.blob.lane = null;
    convert.diz.lane = null;
    convert.sourceReport = null;
    convert.checkAnswer = null;
    host.fellow.nod();
    askUnanswered();
    host.render();
  };

  const admitSource = (file) => {
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
    convert.source = file;
    convert.sourceFacts = null;
    convert.sourceReport = null;
    convert.checkAnswer = null;
    host.fellow.nod();
    askUnanswered();
    host.render();
  };

  const admitBlobFile = (file) => {
    const stateAtPick = convert;
    file.arrayBuffer()
      .then(host.wheneverStillCurrent((buffer) => {
        if (convert !== stateAtPick || convert.act.tag !== 'AtRest') return;
        recheck(() => { convert.blob = { lane: 'file', text: convert.blob.text, file, fileBase64: base64OfBuffer(buffer) }; });
      }))
      .catch(host.askFailed);
  };

  const admitDizFile = (file) => {
    const stateAtPick = convert;
    file.arrayBuffer()
      .then(host.wheneverStillCurrent((buffer) => {
        if (convert !== stateAtPick || convert.act.tag !== 'AtRest') return;
        recheck(() => { convert.diz = { lane: 'file', text: convert.diz.text, file, fileBytes: new Uint8Array(buffer) }; });
      }))
      .catch(host.askFailed);
  };

  /* ---------------------------------------------------------- the act ---- */

  // What the run still waits on, as the places it would point at. Resting on a waiting run outlines all of them
  // at once — the fellow's box among them, since the words for why are already in his mouth.
  const runReadiness = () => {
    if (!host.hasSession() || refusalCertain()) return { tag: 'Waiting', pointAt: ['voice'] };
    const awaited = [!convert.patch && 'seat-patch', !convert.formatToken && formatGroupId,
                     romStanding().owed && !convert.source && 'seat-source'].filter(Boolean);
    return awaited.length === 0 ? { tag: 'Ready' } : { tag: 'Waiting', pointAt: ['voice', ...awaited] };
  };

  const convertedName = () => `${stemOf(convert.patch.name)}${surfaceRow().formatFileExtension}`;

  const runConvert = () => {
    if (!convert.patch || !convert.formatToken || actRunning()) return;
    const job = host.startJob('convert', { patch: convert.patch, source: convert.source, declaration: declaration() });
    if (!job) return;
    convert.act = { tag: 'Running', cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = convertedName();
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        convert.act = {
          tag: 'Converted',
          formatName: surfaceRow().formatDisplayName, advisories, downloadName, downloadHref, patchBytes: tail,
        };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        convert.act = { tag: 'Refused', spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories };
        host.fellow.droop();
      }
      host.render();
      host.carryFocusToAnswer();
    }).catch((jobFailure) => {
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        convert.act = { tag: 'AtRest' };
        host.setNotice(voiceLines.cancelled);
        host.render();
        return;
      }
      convert.act = { tag: 'Fell', sentence: jobFailure.message, advisories: [] };
      host.fellow.droop();
      host.render();
      host.carryFocusToAnswer();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const chipWord = () => convert.patchIdentity?.answered?.spokenIdentityFormatName ?? null;

  // The three things slap can know about the rom, each carrying the word it says and whether the blank is owed.
  // (Copy: DRAFT.)
  const RomStanding = Object.freeze({
    MayBeWanted: Object.freeze({ whisper: 'only needed for some formats', owed: false }),
    Wanted:      Object.freeze({ whisper: 'needed for this one',         owed: true  }),
    NotWanted:   Object.freeze({ whisper: 'not needed for this one',     owed: false }),
  });

  // Which one holds turns on the chosen format as much as on the patch, so it is asked of the engine on every
  // change: a blocked request offering ProvideSourceRom is slap saying the rom would settle it.
  const romStanding = () => {
    const verdict = convert.checkAnswer?.answered;
    if (!convert.patch || !convert.formatToken || !verdict) return RomStanding.MayBeWanted;
    if (verdict.tag !== CheckVerdict.Blocked) return RomStanding.NotWanted;
    return verdict.contents.some((gap) => gap.spokenGapResolutions.some((way) => way.tag === 'ProvideSourceRom'))
      ? RomStanding.Wanted : RomStanding.NotWanted;
  };

  // The rom is an operand, not a setting, so it stands in the sentence: the second line is the same sentence, continued.
  const sentenceMarkup = () => {
    const standing = romStanding();
    return html`<p class="sentence">convert
      ${actRunning() ? heldSeatMarkup(convert.patch, chipWord()) : seatSlotMarkup('patch', 'patch', convert.patch, chipWord())} to
      ${formatSeatMarkup(convert.formatToken)}</p>
    <p class="sentence second">with ${actRunning()
      ? (convert.source ? heldSeatMarkup(convert.source, null) : inertSlotMarkup("the rom it's for"))
      : html`<span class="slot-stack">${romSeatMarkup(standing)}<span class="role-whisper"
          id="rom-standing">${standing.whisper}</span></span>`}</p>`;
  };

  // The blank names the rom it wants, so the prose need not, and wears the owed colour only while slap knows it is owed.
  const romSeatMarkup = (standing) => (convert.source
    ? html`<button type="button" class="slot filled has-story" id="seat-source" aria-describedby="rom-standing"
        data-action="pick-file" data-seat="source" data-story="SourceRom">${convert.source.name}</button>`
    : html`<button type="button" class="slot empty has-story${standing.owed ? ' owed' : ''}"
        id="seat-source" aria-describedby="rom-standing"
        data-action="pick-file" data-seat="source" data-story="SourceRom">the rom it's for</button>`);

  const romFactsMarkup = () => applyFactsCardMarkup({
    patch: convert.patch, patchIdentity: convert.patchIdentity,
    rom: convert.source, romFacts: convert.sourceFacts,
    sourceReport: convert.sourceReport, verificationPolicy: convert.verificationPolicy, framing: convert.framing,
  }, host.surface().surfaceConsoleHeaders);

  const headerControlSurfaces = () => {
    if (!convert.patch || !convert.source || impedimentSpoken()) return false;
    const verdict = convert.sourceReport?.sourceVerdict;
    return convert.framing.tag !== 'TakeInputAsIs'
      || verdict?.tag === Verdict.Uncheckable
      || (verdict?.tag === Verdict.Differs
          && (convert.sourceReport.sourceRescue.length > 1
              || convert.verificationPolicy === 'SkipVerification'));
  };

  const laneChoiceMarkup = (settingName, fieldName, laneState, carried) => {
    const lane = laneOf(laneState, carried);
    const chip = (token, label) =>
      chipRadioMarkup({ groupName: settingName, setting: settingName, token, checked: lane === token, label });
    return html`<fieldset class="choice-fieldset"><legend class="visually-hidden">${fieldLabel(fieldName)}</legend>
    <div class="choice-row">
      ${carried ? chip('keep', 'keep theirs') : nothing}
      ${chip('typed', carried ? 'replace it' : 'type it')}
      ${chip('file', 'use a file')}
      ${carried ? chip('drop', 'drop it') : nothing}
    </div></fieldset>`;
  };

  const blobLanesMarkup = () => {
    const lane = laneOf(convert.blob, fieldCarried('MetadataEmbeddedBlob'));
    return html`
      <p class="choice-label">${storiedText('MetadataEmbeddedBlob', fieldLabel('MetadataEmbeddedBlob'))}</p>
      ${laneChoiceMarkup('blob-lane', 'MetadataEmbeddedBlob', convert.blob, fieldCarried('MetadataEmbeddedBlob'))}
      ${lane === 'typed' ? html`<textarea class="field-textarea" data-setting="blob-text" aria-labelledby="story-MetadataEmbeddedBlob"
          placeholder="a name, a version, a note: whatever you'd want found in here" .value=${convert.blob.text}></textarea>` : nothing}
      ${lane === 'file' ? html`<div class="choice-row"><button type="button" class="chip" data-action="pick-file"
          data-seat="blob-file">${convert.blob.file?.name ?? 'choose a file…'}</button></div>
        <p class="aside">Any file at all; the bytes go in exactly as they are.</p>` : nothing}`;
  };

  const dizLanesMarkup = () => {
    const lane = laneOf(convert.diz, fieldCarried('MetadataFileIdDiz'));
    return html`
      <p class="choice-label">${storiedText('MetadataFileIdDiz', fieldLabel('MetadataFileIdDiz'))}</p>
      ${laneChoiceMarkup('diz-lane', 'MetadataFileIdDiz', convert.diz, fieldCarried('MetadataFileIdDiz'))}
      ${lane === 'typed' ? countedTextareaMarkup({ setting: 'diz-text',
          placeholder: "the text you'd like carried along inside the patch",
          typed: convert.diz.text, ceiling: bench.fieldCeiling('MetadataFileIdDiz'),
          labelledBy: 'story-MetadataFileIdDiz' }) : nothing}
      ${lane === 'file' ? html`<div class="choice-row"><button type="button" class="chip" data-action="pick-file"
          data-seat="diz-file">${convert.diz.file?.name ?? 'choose a file…'}</button></div>` : nothing}`;
  };

  const fileFieldMarkup = (fieldName) => {
    if (fieldName === 'MetadataEmbeddedBlob') return blobLanesMarkup();
    if (fieldName === 'MetadataFileIdDiz') return dizLanesMarkup();
    return null;
  };

  const optionsMarkup = () => {
    // skip-verification serves only the with lane, as the CLI couples --no-verify to --with
    const rows = [
      ...(convert.source ? [toggleMarkup({ id: 'skip-verification', setting: 'verification',
                                           checked: convert.verificationPolicy === 'SkipVerification',
                                           label: 'skip verification', why: 'mismatches become warnings' })] : []),
      ...dialectTogglesMarkup(convert.patchIdentity?.answered?.spokenIdentityDialects ?? [], convert.ppf1Origin),
    ];
    return rows.length === 0 ? null : groupMarkup('options', html`${rows}`);
  };

  const stageMarkup = () => {
    if (actAnswered()) return sentenceMarkup();
    return html`
      ${sentenceMarkup()}
      ${romFactsMarkup()}
      ${formatPickerMarkup(host.surface().surfaceFormats, convert.formatToken, convert.moreFormatsOpen)}
      ${headerControlSurfaces() ? headerControlMarkup(convert.framing, host.surface().surfaceConsoleHeaders) : nothing}
      ${bench.foldedBenchMarkup(fileFieldMarkup)}
      ${encodingSpeaks() ? encodingPickerMarkup(host.surface().surfaceEncodings,
                                                convert.metadataEncoding, convert.moreEncodingsOpen) : nothing}
      ${convert.patch && !impedimentSpoken() ? optionsMarkup() : nothing}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (convert.act.tag === 'Converted') return convertedVoice(convert.act);
    if (convert.act.tag === 'Refused' || convert.act.tag === 'Fell') return refusalVoice(convert.act, 'convert');
    if (actRunning()) return workingVoice(voiceLines.rebottling);
    if (host.notice()) return plainVoice(host.notice());
    if (convert.patchIdentity?.refused)
      return html`<p class="refusal">${convert.patchIdentity.refused.spokenErrorSentence}</p>`;
    const blocked = impedimentSpoken();
    if (blocked) return html`<p class="refusal">${blocked.spokenErrorSentence}</p>`;
    if (!convert.patch) return convert.source ? plainVoice(voiceLines.convertRomOnly) : restingVoice(voiceLines.convertResting);
    if (!convert.formatToken) return plainVoice(voiceLines.convertNeedsFormat);
    if (!convert.checkAnswer) return plainVoice(voiceLines.sizingUp);
    if (convert.checkAnswer.refused)
      return html`<p class="refusal">${convert.checkAnswer.refused.spokenErrorSentence}</p>`;
    const forewarnings = advisoryMarkup(convert.checkAnswer.advisories ?? []);
    const verdict = convert.checkAnswer.answered;
    if (verdict?.tag === CheckVerdict.Blocked) return html`${blockedVoice(verdict.contents)}${forewarnings}`;
    // the seated rom's own verdict outranks the ready line: a mismatch will refuse at apply's door
    if (convert.source && convert.verificationPolicy === 'EnforceVerification'
        && convert.sourceReport?.sourceVerdict?.tag === Verdict.Differs) {
      const rescue = convert.sourceReport.sourceRescue;
      if (rescue.length === 1 && convert.framing.tag === 'TakeInputAsIs')
        return html`${plainVoice(voiceLines.headeredButRescued)}${forewarnings}`;
      return html`${plainVoice(rescue.length > 1 ? voiceLines.differsManyWays : voiceLines.differsHopeless)}${forewarnings}`;
    }
    return html`${plainVoice(voiceLines.convertReady)}${forewarnings}`;
  };

  /* ------------------------------------------------------------ tutor ---- */

  const fileFieldWords = (fieldName, flag) => {
    const laneState = fieldName === 'MetadataEmbeddedBlob' ? convert.blob : convert.diz;
    const lane = laneOf(laneState, fieldCarried(fieldName));
    if (lane === 'drop') return [flagWord(dropFlags[fieldName])];
    if (lane === 'typed' && laneState.text) return [flagWord(typedTextFlags[fieldName]), quotedWord(laneState.text)];
    if (lane === 'file' && laneState.file) return [flagWord(flag), fileWord(laneState.file.name)];
    return [];
  };

  // No output word: the CLI's derived name is exactly the one this page downloads.
  const commandWords = () => {
    const ppf1Origin = dialectControls.PPF1OriginAxis;
    const words = [verbWord('slap'), verbWord('convert'), namedOr(convert.patch, 'PATCH'), flagWord('--to')];
    words.push(convert.formatToken ? valueWord(convert.formatToken) : placeholderWord('FORMAT'));
    if (convert.source) {
      words.push(flagWord('--with'), fileWord(convert.source.name));
      if (convert.verificationPolicy === 'SkipVerification') words.push(flagWord('--no-verify'));
      if (convert.framing.tag === 'RemoveHeader') words.push(flagWord('--remove-header'), valueWord(convert.framing.console.consoleToken));
      if (convert.framing.tag === 'AddHeader') words.push(flagWord('--add-header'), valueWord(convert.framing.console.consoleToken));
    }
    if (encodingSpeaks() && convert.metadataEncoding !== 'utf-8')
      words.push(flagWord('--metadata-encoding'), valueWord(convert.metadataEncoding));
    if (convert.ppf1Origin === ppf1Origin.chosenOrigin) words.push(flagWord(ppf1Origin.terminalFlag));
    words.push(...bench.commandWords(fileFieldWords));
    return words;
  };

  /* ---------------------------------------------------------- surface ---- */

  const refusalCertain = () => {
    if (convert.patchIdentity?.refused || impedimentSpoken()) return true;
    if (convert.checkAnswer?.refused || convert.checkAnswer?.answered?.tag === CheckVerdict.Blocked) return true;
    if (convert.verificationPolicy === 'SkipVerification') return false;
    if (convert.sourceReport?.sourceVerdict?.tag !== Verdict.Differs) return false;
    return !(convert.framing.tag === 'TakeInputAsIs' && convert.sourceReport.sourceRescue.length === 1);
  };

  return {
    runReadiness,
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (convert.act.tag !== 'AtRest') return html``;
      const readiness = runReadiness();
      return html`<button class="run" type="submit" form="stage" aria-disabled="${readiness.tag === 'Waiting'}"
        data-points-at=${readiness.tag === 'Waiting' ? readiness.pointAt.join(' ') : nothing}>${runLabel}</button>`;
    },
    admitDroppedFile: (sorting, file) => (sorting === Sorting.AsPatch ? admitPatch(file) : admitSource(file)),
    admitPickedFile: (seat, file) => {
      if (seat === 'blob-file') admitBlobFile(file);
      else if (seat === 'diz-file') admitDizFile(file);
      else if (seat === 'source') admitSource(file);
      else admitPatch(file);
    },
    askAgain: askUnanswered,
    storiesQuiet: () => convert.act.tag !== 'AtRest',
    actions: {
      'more-formats': () => { convert.moreFormatsOpen = !convert.moreFormatsOpen; host.render(); },
      'fold-bench': () => { bench.toggleBench(); host.render(); },
      'more-encodings': () => { convert.moreEncodingsOpen = !convert.moreEncodingsOpen; host.render(); },
      run: runConvert,
      'cancel-run': () => { if (actRunning()) convert.act.cancel(); },
      'look-inside': () => {
        if (convert.act.tag === 'Converted') host.lookInside(new File([convert.act.patchBytes], convert.act.downloadName));
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonAct();
        convert = atRest();
        bench.reset();
        host.fellow.settle();
        host.render();
      },
    },
    settings: {
      ...bench.settings,
      format: (formatToken) => {
        if (actRunning()) return;
        recheck(() => { convert.formatToken = formatToken; });
      },
      'blob-lane': (lane) => recheck(() => { convert.blob.lane = lane; }),
      'diz-lane': (lane) => recheck(() => { convert.diz.lane = lane; }),
      'blob-text': (value) => recheck(() => { convert.blob.text = value; }),
      'diz-text': (value) => recheck(() => { convert.diz.text = value; }),
      framing: (framingTag) => reweighSource(() => {
        convert.framing = framingTag === 'TakeInputAsIs'
          ? { tag: 'TakeInputAsIs', console: null }
          : { tag: framingTag, console: convert.framing.console ?? preseededConsoleRow(host.surface().surfaceConsoleHeaders) };
      }),
      console: (consoleToken) => reweighSource(() => {
        convert.framing.console = host.surface().surfaceConsoleHeaders
          .find((row) => row.consoleToken === consoleToken);
      }),
      encoding: (encodingToken) => rereadPatch(() => { convert.metadataEncoding = encodingToken; }),
      verification: (checked) => {
        convert.verificationPolicy = checked ? 'SkipVerification' : 'EnforceVerification';
        host.render();
      },
      dialect: (checked) => rereadPatch(() => {
        convert.ppf1Origin = checked ? 'PPF1OriginAmiga' : 'PPF1OriginPC';
      }),
    },
    typings: {
      ...bench.typings,
      'blob-text': (value) => { convert.blob.text = value; host.render(); },
      'diz-text': (value) => { convert.diz.text = value; host.render(); },
    },
  };
};
