// The read verbs, a family of two. info answers "what is this patch" as a facts glance;
// explain answers "what does it do to the bytes" as info-plus — the same readout, then the structure.

import { html } from './../dom.mjs';
import { groupMarkup, toggleMarkup, seatSlotMarkup, encodingPickerMarkup } from './../controls.mjs';
import { voiceLines, plainVoice, advisoryMarkup } from './../answer-surface.mjs';
import { verbWord, flagWord, valueWord, namedOr } from './../command-tutor.mjs';
import { dialectControls, dialectTogglesMarkup } from './../dialect-controls.mjs';
import { identifyDeclaration } from './../declarations.mjs';
import { infoReadoutMarkup, embeddedContentsOf, embeddedContentMarkup,
         heatModel, heatBarMarkup, heatCaption, walkMarkup, structureOverviewMarkup,
         analysisRegionsOf, analysisAsidesMarkup } from './../read-panels.mjs';
import { formatLabelWord } from './../readouts.mjs';

const walkRowsAtFirst = 500;

const atRest = () => ({
  patch: null, identity: null,
  metadataEncoding: 'utf-8',
  ppf1Origin: 'PPF1OriginPC',
  reading: null,
  everyRecord: false,
  walkRowsShown: walkRowsAtFirst,
  moreEncodingsOpen: false,
});

const makeReadCore = (host, { verbName, wireVerb, declaration, restingLine, readLine, undeclaredTextFieldsOf }) => {
  let read = atRest();

  // Only a patch keeping text whose encoding it never recorded has anything to read under a chosen encoding;
  // on any other the choice stays in hand — swap back and it is still there — and says nothing, in neither the control nor the command.
  const encodingSpeaks = () =>
    (read.reading?.answered ? undeclaredTextFieldsOf(read.reading.answered).length : 0) > 0;

  const askIdentity = () => {
    if (!read.patch) return;
    host.ask('identify', { patch: read.patch, declaration: identifyDeclaration(read.ppf1Origin, read.metadataEncoding) })
      ?.then(host.wheneverStillCurrent((answer) => { read.identity = answer; }))
      .catch(host.askFailed);
  };

  const askReading = () => {
    if (!read.patch) return;
    host.ask(wireVerb, { patch: read.patch, declaration: declaration(read) })
      ?.then(host.wheneverStillCurrent((answer) => {
        read.reading = answer;
        if (answer.refused) host.fellow.droop();
      }))
      .catch(host.askFailed);
  };

  const admitPatch = (file) => {
    host.supersedeAsks();
    read.patch = file;
    read.identity = null;
    read.reading = null;
    read.ppf1Origin = 'PPF1OriginPC';
    read.walkRowsShown = walkRowsAtFirst;
    host.fellow.nod();
    askIdentity();
    askReading();
    host.render();
  };

  const rereadPatch = (change) => {
    host.supersedeAsks();
    change(read);
    read.reading = null;
    read.walkRowsShown = walkRowsAtFirst;
    if (!read.identity) askIdentity();
    askReading();
    host.render();
  };

  const chipWord = () => read.identity?.answered?.spokenIdentityFormatName ?? null;

  const applicableDialects = () => read.identity?.answered?.spokenIdentityDialects ?? [];

  const voiceMarkup = () => {
    if (host.notice()) return plainVoice(host.notice());
    if (!read.patch) return plainVoice(restingLine);
    if (read.reading?.refused) return html`
      <p class="refusal">${read.reading.refused.spokenErrorSentence}</p>
      ${advisoryMarkup(read.reading.advisories)}`;
    if (!read.reading) return plainVoice(voiceLines.reading);
    return html`
      <p class="plain-line">${readLine}</p>
      ${advisoryMarkup(read.reading.advisories)}`;
  };

  const commandWords = () => {
    const ppf1Origin = dialectControls.PPF1OriginAxis;
    const words = [verbWord('slap'), verbWord(verbName), namedOr(read.patch, 'PATCH')];
    if (read.everyRecord) words.push(flagWord('--records'));
    if (encodingSpeaks() && read.metadataEncoding !== 'utf-8')
      words.push(flagWord('--metadata-encoding'), valueWord(read.metadataEncoding));
    if (read.ppf1Origin === ppf1Origin.chosenOrigin) words.push(flagWord(ppf1Origin.terminalFlag));
    return words;
  };

  const dialectGroupMarkup = () => {
    const toggles = dialectTogglesMarkup(applicableDialects(), read.ppf1Origin);
    return toggles.length === 0 ? null : groupMarkup('options', html`${toggles}`);
  };

  const settings = {
    dialect: (checked) => rereadPatch(() => {
      read.ppf1Origin = checked ? 'PPF1OriginAmiga' : 'PPF1OriginPC';
      read.identity = null;
    }),
  };

  return {
    state: () => read,
    chipWord, applicableDialects, voiceMarkup, commandWords, dialectGroupMarkup, encodingSpeaks,
    admitPatch, rereadPatch, askIdentity, askReading, settings,
  };
};

// A dropped rom has no seat on a read verb; the patch seat takes what sorts as a patch.
const admitSorted = (host, core) => (sorting, file) => {
  if (sorting === 'SortsAsPatch') core.admitPatch(file);
  else { host.setNotice(voiceLines.sortsAsRom); host.render(); }
};

/* ---------------------------------------------------------------- info ---- */

export const makeInfoVerb = (host) => {
  const core = makeReadCore(host, {
    verbName: 'info',
    wireVerb: 'inspect',
    declaration: (read) => ({
      declaredInspectMetadataEncoding: read.metadataEncoding,
      declaredInspectDialects: { requestedPPF1Origin: read.ppf1Origin },
    }),
    undeclaredTextFieldsOf: (answered) => answered.infoUndeclaredTextFields,
    restingLine: voiceLines.infoResting,
    readLine: voiceLines.infoRead,
  });

  const extractEmbedded = (seatIndex) => {
    const read = core.state();
    const carried = embeddedContentsOf(read.reading.answered)
      .find((candidate) => candidate.seatIndex === seatIndex);
    if (!carried) return;
    const bytes = Uint8Array.from(atob(carried.wireBase64), (char) => char.charCodeAt(0));
    const href = URL.createObjectURL(new Blob([bytes]));
    // a FILE_ID.DIZ is a file with a name of its own; everything else borrows the patch's
    const downloadName = carried.label === 'file_id.diz'
      ? 'FILE_ID.DIZ'
      : `${read.patch.name}.${carried.label.replaceAll(' ', '-')}`;
    host.download(href, downloadName);
    URL.revokeObjectURL(href);
  };

  const extractGroupMarkup = () => {
    const carried = embeddedContentsOf(core.state().reading.answered);
    if (carried.length === 0) return null;
    return groupMarkup('extract', html`
      <div class="choice-row">${carried.map(({ seatIndex, label }) => html`<button class="chip"
        data-action="extract-embed" data-seat-index="${seatIndex}">download ${label}</button>`)}</div>
      <p class="aside">Byte-exact — the patch's own bytes, not a re-encode.</p>`);
  };

  const stageMarkup = () => {
    const read = core.state();
    const sentence = html`<p class="sentence">show info for
      ${seatSlotMarkup('patch', 'patch', read.patch, core.chipWord())}</p>`;
    if (!read.patch) return sentence;
    const answered = read.reading?.answered;
    if (!answered) return html`${sentence}${core.dialectGroupMarkup()}`;
    return html`
      ${sentence}
      ${infoReadoutMarkup(answered, core.chipWord() ?? formatLabelWord(answered.infoFormat.formatLabel))}
      ${extractGroupMarkup()}
      ${core.dialectGroupMarkup()}`;
  };

  return {
    stageMarkup,
    voiceMarkup: core.voiceMarkup,
    commandWords: core.commandWords,
    actMarkup: () => html``,
    admitDroppedFile: admitSorted(host, core),
    admitPickedFile: (_seat, file) => core.admitPatch(file),
    askAgain: () => { core.askIdentity(); core.askReading(); },
    actions: {
      'extract-embed': ({ seatIndex }) => extractEmbedded(Number(seatIndex)),
    },
    settings: core.settings,
  };
};

/* ------------------------------------------------------------- explain ---- */

export const makeExplainVerb = (host) => {
  const core = makeReadCore(host, {
    verbName: 'explain',
    wireVerb: 'analyze',
    declaration: (read) => ({
      declaredAnalyzeMetadataEncoding: read.metadataEncoding,
      declaredAnalyzeDialects: { requestedPPF1Origin: read.ppf1Origin },
    }),
    undeclaredTextFieldsOf: (answered) => answered.explanationInfo.infoUndeclaredTextFields,
    restingLine: voiceLines.explainResting,
    readLine: voiceLines.explainRead,
  });

  const textEncodingGroupMarkup = () => {
    const read = core.state();
    return encodingPickerMarkup(host.surface()?.surfaceEncodings ?? [], read.metadataEncoding, read.moreEncodingsOpen);
  };

  const structurePanelMarkup = (explanation) => {
    const read = core.state();
    const analysis = explanation.explanationAnalysis;
    const regions = analysisRegionsOf(analysis);
    read.reading.model ??= heatModel(regions, analysis.analysisSummary);
    return html`<div class="results">
      ${structureOverviewMarkup(regions, explanation.explanationInfo.infoLines)}
      ${read.reading.model && html`<div class="bar-shelf">${heatBarMarkup(read.reading.model)}</div>`}
      ${analysisAsidesMarkup(analysis)}
      ${embeddedContentMarkup(explanation.explanationInfo)}
    </div>`;
  };

  const optionsMarkup = () => {
    const read = core.state();
    return groupMarkup('options', html`
      ${dialectTogglesMarkup(core.applicableDialects(), read.ppf1Origin)}
      ${toggleMarkup({ id: 'every-record', setting: 'records', checked: read.everyRecord,
                       label: 'show every record', why: 'the full walk, not just the shape' })}`);
  };

  const stageMarkup = () => {
    const read = core.state();
    const sentence = html`<p class="sentence">explain
      ${seatSlotMarkup('patch', 'patch', read.patch, core.chipWord())}</p>`;
    if (!read.patch) return sentence;
    const answered = read.reading?.answered;
    if (!answered) return html`${sentence}${core.dialectGroupMarkup()}`;

    const explanationInfo = answered.explanationInfo;
    const regions = analysisRegionsOf(answered.explanationAnalysis);
    return html`
      ${sentence}
      ${infoReadoutMarkup(explanationInfo, core.chipWord() ?? formatLabelWord(explanationInfo.infoFormat.formatLabel))}
      ${structurePanelMarkup(answered)}
      ${core.encodingSpeaks() && textEncodingGroupMarkup()}
      ${optionsMarkup()}
      ${read.everyRecord && html`<div class="results">${walkMarkup(regions, read.walkRowsShown)}</div>`}`;
  };

  // The heat bar's hover caption updates in place — a hover is not a state change; wired once, against the stage.
  host.stage().addEventListener('mouseover', (event) => {
    const cell = event.target.closest('.heat-cell');
    const model = core.state().reading?.model;
    if (!cell || !model) return;
    const caption = host.stage().querySelector('[data-role="heat-caption"]');
    if (caption) caption.textContent = heatCaption(model, Number(cell.dataset.bucket));
  });

  return {
    stageMarkup,
    voiceMarkup: core.voiceMarkup,
    commandWords: core.commandWords,
    actMarkup: () => html``,
    admitDroppedFile: admitSorted(host, core),
    admitPickedFile: (_seat, file) => core.admitPatch(file),
    askAgain: () => { core.askIdentity(); core.askReading(); },
    actions: {
      'set-encoding': ({ token }) => core.rereadPatch((read) => { read.metadataEncoding = token; }),
      'walk-more': () => { core.state().walkRowsShown += 2000; host.render(); },
      'more-encodings': () => {
        core.state().moreEncodingsOpen = !core.state().moreEncodingsOpen;
        host.render();
      },
    },
    settings: {
      ...core.settings,
      records: (checked) => { core.state().everyRecord = checked; host.render(); },
    },
  };
};
