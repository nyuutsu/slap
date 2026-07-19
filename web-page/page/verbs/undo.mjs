// Everything the engine decides — can this patch go backwards, did that rom come out of it — arrives through the host's asks;
// this module owns only undo's shape and voice.

import { html } from './../dom.mjs';
import { groupMarkup, toggleMarkup, seatSlotMarkup, heldSeatMarkup, swapSeatsMarkup } from './../controls.mjs';
import { undoFactsCardMarkup } from './../facts-card.mjs';
import { voiceLines, plainVoice, workingVoice, revertedVoice, refusalVoice } from './../answer-surface.mjs';
import { verbWord, flagWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { dialectControls, dialectTogglesMarkup } from './../dialect-controls.mjs';
import { identifyDeclaration } from './../declarations.mjs';

const runLabel = 'Peel';

const atRest = () => ({
  patch: null, patchIdentity: null,
  patched: null, patchedFacts: null,
  verdict: null,
  verificationPolicy: 'EnforceVerification',
  ppf1Origin: 'PPF1OriginPC',
  running: null,
  outcome: null,
});

const revertedName = (patchedFile) => {
  const lastDot = patchedFile.name.lastIndexOf('.');
  return lastDot > 0
    ? `${patchedFile.name.slice(0, lastDot)}-reverted${patchedFile.name.slice(lastDot)}`
    : `${patchedFile.name}-reverted`;
};

const peelNoteMarkup = html`<div class="group"><p class="aside">Only three kinds of patch can
  be peeled. A <b>ups</b> patch is its own reverse, and a <b>ninja2</b> is too — one that shrinks
  the file carries the trimmed tail along. A <b>ppf3</b> can be, if whoever made it included undo
  data. Everything else is one-way — a patch says how to get there, not how to get back.</p></div>`;

export const makeUndoVerb = (host) => {
  let undo = atRest();

  const declaration = () => ({
    declaredUndoVerificationPolicy: undo.verificationPolicy,
    declaredUndoDialects: { requestedPPF1Origin: undo.ppf1Origin },
  });

  const undoAnswer = () => undo.patchIdentity?.answered?.spokenIdentityUndo;

  const patchPeels = () => {
    const answer = undoAnswer();
    return answer === 'PatchIsItsOwnReverse' || answer === 'PatchCarriesUndoData';
  };

  /* ------------------------------------------------------------- asks ---- */

  const askPatchedFacts = () => {
    if (!undo.patched) return;
    host.ask('describe-rom', { rom: undo.patched })
      ?.then(host.wheneverStillCurrent(({ answered }) => { undo.patchedFacts = answered; }))
      .catch(host.askFailed);
  };

  const askIdentity = () => {
    if (!undo.patch) return;
    host.ask('identify', { patch: undo.patch, declaration: identifyDeclaration(undo.ppf1Origin, 'utf-8') })
      ?.then(host.wheneverStillCurrent((answer) => { undo.patchIdentity = answer; askWeighing(); }))
      .catch(host.askFailed);
  };

  // The weighing feeds the act alone, so a patch that cannot peel is never weighed.
  const askWeighing = () => {
    if (!undo.patch || !undo.patched || !patchPeels()) return;
    host.ask('check-undo', { patch: undo.patch, patched: undo.patched, declaration: declaration() })
      ?.then(host.wheneverStillCurrent(({ answered }) => { undo.verdict = answered; }))
      .catch(host.askFailed);
  };

  const askUnanswered = () => {
    if (!undo.patchIdentity) askIdentity();
    if (!undo.patchedFacts) askPatchedFacts();
    if (!undo.verdict) askWeighing();
  };

  /* ------------------------------------------------------------ seats ---- */

  const abandonOutcome = () => {
    if (undo.outcome?.reverted) URL.revokeObjectURL(undo.outcome.reverted.downloadHref);
    undo.outcome = null;
  };

  const admitFile = (seat, file) => {
    if (undo.running) return;
    host.supersedeAsks();
    abandonOutcome();
    if (seat === 'patch') {
      undo.patch = file;
      undo.patchIdentity = null;
      // a stale toggle can't ride onto a patch it might not fit
      undo.ppf1Origin = 'PPF1OriginPC';
    } else {
      undo.patched = file;
      undo.patchedFacts = null;
    }
    undo.verdict = null;
    host.fellow.nod();
    askUnanswered();
    host.render();
  };

  /* --------------------------------------------------------- settings ---- */

  const restateQuietly = (change) => {
    change();
    host.render();
  };

  const rereadPatch = (change) => {
    host.supersedeAsks();
    change();
    undo.patchIdentity = null;
    undo.verdict = null;
    askUnanswered();
    host.render();
  };

  /* ---------------------------------------------------------- the act ---- */

  const runUndo = () => {
    if (!undo.patch || !undo.patched || undo.running) return;
    const job = host.startJob('undo', { patch: undo.patch, patched: undo.patched, declaration: declaration() });
    if (!job) return;
    undo.running = { cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      undo.running = null;
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = revertedName(undo.patched);
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        undo.outcome = { reverted: { spoken: answered, advisories, downloadName, downloadHref } };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        undo.outcome = { refused: { spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories } };
        host.fellow.droop();
      }
      host.render();
    }).catch((jobFailure) => {
      undo.running = null;
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        host.setNotice(voiceLines.cancelled);
      } else {
        undo.outcome = { failed: { sentence: jobFailure.message, advisories: [] } };
        host.fellow.droop();
      }
      host.render();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const chipWord = () => undo.patchIdentity?.answered?.spokenIdentityFormatName ?? null;

  const slotFor = (seat, roleWord, file, slotChipWord) =>
    undo.running ? heldSeatMarkup(file, slotChipWord) : seatSlotMarkup(seat, roleWord, file, slotChipWord);

  const sentenceMarkup = () => html`<p class="sentence">peel
    ${slotFor('patch', 'patch', undo.patch, chipWord())} from
    ${slotFor('patched', 'rom', undo.patched, null)}</p>`;

  const optionsMarkup = () => groupMarkup('options', html`
    ${toggleMarkup({ id: 'skip-verification', setting: 'verification',
                     checked: undo.verificationPolicy === 'SkipVerification',
                     label: 'skip verification', why: 'mismatches become warnings' })}
    ${dialectTogglesMarkup(undo.patchIdentity?.answered?.spokenIdentityDialects ?? [], undo.ppf1Origin)}`);

  const stageMarkup = () => {
    if (undo.outcome) return sentenceMarkup();
    const operandsSatisfied = undo.patch && undo.patched;
    // options serve the act, so none surface for a patch that cannot be peeled
    return html`
      ${sentenceMarkup()}
      ${operandsSatisfied && !undo.running && swapSeatsMarkup}
      ${!undo.patch && peelNoteMarkup}
      ${undoFactsCardMarkup(undo, patchPeels())}
      ${operandsSatisfied && patchPeels() && optionsMarkup()}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (undo.outcome?.reverted) return revertedVoice(undo.outcome.reverted);
    if (undo.outcome?.refused) return refusalVoice(undo.outcome.refused, 'undo');
    if (undo.outcome?.failed) return refusalVoice(undo.outcome.failed, 'undo');
    if (undo.running) return workingVoice();
    if (host.notice()) return plainVoice(host.notice());
    if (undo.patchIdentity?.refused)
      return html`<p class="refusal">${undo.patchIdentity.refused.spokenErrorSentence}</p>`;
    const answer = undoAnswer();
    if (answer === 'FormatHasNoUndo') return plainVoice(voiceLines.undoOneWay);
    if (answer === 'AuthorOmittedUndoData') return plainVoice(voiceLines.undoDataOmitted);
    if (!undo.patch && !undo.patched) return plainVoice(voiceLines.undoResting);
    if (!undo.patch) return plainVoice(voiceLines.undoRomOnly);
    if (!undo.patchIdentity) return plainVoice(voiceLines.sizingUp);
    if (!undo.patched)
      return plainVoice(answer === 'PatchIsItsOwnReverse' ? voiceLines.undoSelfInverse : voiceLines.undoCarriesData);
    if (undo.verificationPolicy === 'SkipVerification') return plainVoice(voiceLines.verificationOff);
    if (!undo.verdict) return plainVoice(voiceLines.sizingUp);
    if (undo.verdict.tag === 'VerdictMatches') return plainVoice(voiceLines.undoMatch);
    if (undo.verdict.tag === 'VerdictUncheckable') return plainVoice(voiceLines.undoUncheckable);
    return plainVoice(voiceLines.undoDiffers);
  };

  /* ------------------------------------------------------------ tutor ---- */

  const commandWords = () => {
    const ppf1Origin = dialectControls.PPF1OriginAxis;
    const words = [verbWord('slap'), verbWord('undo')];
    if (undo.verificationPolicy === 'SkipVerification') words.push(flagWord('--no-verify'));
    if (undo.ppf1Origin === ppf1Origin.chosenOrigin) words.push(flagWord(ppf1Origin.terminalFlag));
    words.push(namedOr(undo.patch, 'PATCH'), namedOr(undo.patched, 'PATCHED'));
    words.push(undo.patched ? fileWord(revertedName(undo.patched)) : placeholderWord('OUTPUT'));
    return words;
  };

  /* ---------------------------------------------------------- surface ---- */

  const refusalCertain = () => {
    if (undo.patchIdentity?.refused) return true;
    const answer = undoAnswer();
    if (answer === 'FormatHasNoUndo' || answer === 'AuthorOmittedUndoData') return true;
    if (undo.verificationPolicy === 'SkipVerification') return false;
    return undo.verdict?.tag === 'VerdictDiffers';
  };

  return {
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (undo.outcome || undo.running) return html``;
      const ready = host.hasSession() && undo.patch && undo.patched && !refusalCertain();
      return html`<button class="run" data-action="run" ${!ready && html`disabled`}>${runLabel}</button>`;
    },
    admitDroppedFile: (sorting, file) => admitFile(sorting === 'SortsAsPatch' ? 'patch' : 'patched', file),
    admitPickedFile: admitFile,
    askAgain: askUnanswered,
    actions: {
      run: runUndo,
      'cancel-run': () => undo.running?.cancel(),
      'swap-seats': () => {
        if (undo.running) return;
        host.supersedeAsks();
        abandonOutcome();
        [undo.patch, undo.patched] = [undo.patched, undo.patch];
        undo.patchIdentity = null;
        undo.patchedFacts = null;
        undo.verdict = null;
        undo.ppf1Origin = 'PPF1OriginPC';
        host.fellow.nod();
        askUnanswered();
        host.render();
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonOutcome();
        undo = atRest();
        host.fellow.settle();
        host.render();
      },
    },
    settings: {
      verification: (checked) => restateQuietly(() => {
        undo.verificationPolicy = checked ? 'SkipVerification' : 'EnforceVerification';
      }),
      dialect: (checked) => rereadPatch(() => {
        undo.ppf1Origin = checked ? 'PPF1OriginAmiga' : 'PPF1OriginPC';
      }),
    },
  };
};
