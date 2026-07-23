// Everything the engine decides — can this patch go backwards, did that rom come out of it — arrives through the host's asks;
// this module owns only undo's shape and voice.

import { html, nothing } from '../../vendor/lit-html/lit-html.js';
import { Verdict, UndoAnswer, Sorting, matcherOver } from './../engine-vocabulary.mjs';
import { groupMarkup, toggleMarkup, seatSlotMarkup, heldSeatMarkup, swapSeatsMarkup } from './../controls.mjs';
import { undoFactsCardMarkup } from './../facts-card.mjs';
import { voiceLines, plainVoice, workingVoice, revertedVoice, refusalVoice } from './../answer-surface.mjs';
import { verbWord, flagWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { dialectControls, dialectTogglesMarkup } from './../dialect-controls.mjs';
import { identifyDeclaration } from './../declarations.mjs';

const runLabel = 'Peel';

// The act as one value, apply's doctrine: AtRest | Running{cancel} | Reverted | Refused | Fell.
const atRest = () => ({
  patch: null, patchIdentity: null,
  patched: null, patchedFacts: null,
  verdict: null,
  verificationPolicy: 'EnforceVerification',
  ppf1Origin: 'PPF1OriginPC',
  act: { tag: 'AtRest' },
});

const revertedName = (patchedFile) => {
  const lastDot = patchedFile.name.lastIndexOf('.');
  return lastDot > 0
    ? `${patchedFile.name.slice(0, lastDot)}-reverted${patchedFile.name.slice(lastDot)}`
    : `${patchedFile.name}-reverted`;
};

const weighingVoiceLine = matcherOver(Verdict, {
  Matches:     () => voiceLines.undoMatch,
  Uncheckable: () => voiceLines.undoUncheckable,
  Differs:     () => voiceLines.undoDiffers,
});

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
    return answer === UndoAnswer.PatchIsItsOwnReverse || answer === UndoAnswer.PatchCarriesUndoData;
  };

  const impedimentSpoken = () => undo.patchIdentity?.answered?.spokenIdentityImpediment ?? null;

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
    if (!undo.patch || !undo.patched || !patchPeels() || impedimentSpoken()) return;
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

  const actRunning  = () => undo.act.tag === 'Running';
  const actAnswered = () => undo.act.tag !== 'AtRest' && !actRunning();

  const abandonAct = () => {
    if (undo.act.tag === 'Reverted') URL.revokeObjectURL(undo.act.downloadHref);
    undo.act = { tag: 'AtRest' };
  };

  const admitFile = (seat, file) => {
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
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

  // Both seats at once, for the two moves that are one move: swapping them, and a patch taking its own seat.
  const seatBothFiles = (patchFile, patchedFile) => {
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
    undo.patch = patchFile;
    undo.patched = patchedFile;
    undo.patchIdentity = null;
    undo.patchedFacts = null;
    undo.verdict = null;
    undo.ppf1Origin = 'PPF1OriginPC';
    askUnanswered();
    host.render();
  };

  // A picked patch takes the patch seat, by the rule apply's own picker states.
  const admitPickedFile = (seat, file) => {
    const displacedFromPatchSeat = undo.patch;
    const patchSeatReadable = !!undo.patchIdentity?.answered;
    admitFile(seat, file);
    if (seat !== 'patched' || patchSeatReadable) return;
    host.ask('classify', { file })
      ?.then(host.wheneverStillCurrent(({ answered }) => {
        if (answered !== Sorting.AsPatch || undo.patched !== file) return;
        seatBothFiles(file, displacedFromPatchSeat);
      }))
      .catch(host.askFailed);
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
    if (!undo.patch || !undo.patched || actRunning()) return;
    const job = host.startJob('undo', { patch: undo.patch, patched: undo.patched, declaration: declaration() });
    if (!job) return;
    undo.act = { tag: 'Running', cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = revertedName(undo.patched);
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        undo.act = { tag: 'Reverted', spoken: answered, advisories, downloadName, downloadHref };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        undo.act = { tag: 'Refused', spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories };
        host.fellow.droop();
      }
      host.render();
      host.carryFocusToAnswer();
    }).catch((jobFailure) => {
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        undo.act = { tag: 'AtRest' };
        host.setNotice(voiceLines.cancelled);
        host.render();
        return;
      }
      undo.act = { tag: 'Fell', sentence: jobFailure.message, advisories: [] };
      host.fellow.droop();
      host.render();
      host.carryFocusToAnswer();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const chipWord = () => undo.patchIdentity?.answered?.spokenIdentityFormatName ?? null;

  const slotFor = (seat, roleWord, file, slotChipWord) =>
    actRunning() ? heldSeatMarkup(file, slotChipWord) : seatSlotMarkup(seat, roleWord, file, slotChipWord);

  const sentenceMarkup = () => html`<p class="sentence">peel
    ${slotFor('patch', 'patch', undo.patch, chipWord())} from
    ${slotFor('patched', 'rom', undo.patched, null)}</p>`;

  const optionsMarkup = () => groupMarkup('options', html`
    ${toggleMarkup({ id: 'skip-verification', setting: 'verification',
                     checked: undo.verificationPolicy === 'SkipVerification',
                     label: 'skip verification', why: 'mismatches become warnings' })}
    ${dialectTogglesMarkup(undo.patchIdentity?.answered?.spokenIdentityDialects ?? [], undo.ppf1Origin)}`);

  const stageMarkup = () => {
    if (actAnswered()) return sentenceMarkup();
    const operandsSatisfied = undo.patch && undo.patched;
    // options serve the act, so none surface for a patch that cannot be peeled
    return html`
      ${sentenceMarkup()}
      ${operandsSatisfied && !actRunning() && undo.patchIdentity?.refused ? swapSeatsMarkup : nothing}
      ${!undo.patch ? peelNoteMarkup : nothing}
      ${undoFactsCardMarkup(undo, patchPeels() && !impedimentSpoken())}
      ${operandsSatisfied && patchPeels() && !impedimentSpoken() ? optionsMarkup() : nothing}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (undo.act.tag === 'Reverted') return revertedVoice(undo.act);
    if (undo.act.tag === 'Refused' || undo.act.tag === 'Fell') return refusalVoice(undo.act, 'undo');
    if (actRunning()) return workingVoice(voiceLines.peeling);
    if (host.notice()) return plainVoice(host.notice());
    if (undo.patchIdentity?.refused)
      return html`<p class="refusal">${undo.patchIdentity.refused.spokenErrorSentence}</p>`;
    const blocked = impedimentSpoken();
    if (blocked) return html`<p class="refusal">${blocked.spokenErrorSentence}</p>`;
    const answer = undoAnswer();
    if (answer === UndoAnswer.FormatHasNoUndo) return plainVoice(voiceLines.undoOneWay);
    if (answer === UndoAnswer.AuthorOmittedUndoData) return plainVoice(voiceLines.undoDataOmitted);
    if (!undo.patch && !undo.patched) return plainVoice(voiceLines.undoResting);
    if (!undo.patch) return plainVoice(voiceLines.undoRomOnly);
    if (!undo.patchIdentity) return plainVoice(voiceLines.sizingUp);
    if (!undo.patched)
      return plainVoice(answer === UndoAnswer.PatchIsItsOwnReverse ? voiceLines.undoSelfInverse : voiceLines.undoCarriesData);
    if (undo.verificationPolicy === 'SkipVerification') return plainVoice(voiceLines.verificationOff);
    if (!undo.verdict) return plainVoice(voiceLines.sizingUp);
    return plainVoice(weighingVoiceLine(undo.verdict));
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
    if (undo.patchIdentity?.refused || impedimentSpoken()) return true;
    const answer = undoAnswer();
    if (answer === UndoAnswer.FormatHasNoUndo || answer === UndoAnswer.AuthorOmittedUndoData) return true;
    if (undo.verificationPolicy === 'SkipVerification') return false;
    return undo.verdict?.tag === Verdict.Differs;
  };

  return {
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (undo.act.tag !== 'AtRest') return html``;
      const ready = host.hasSession() && undo.patch && undo.patched && !refusalCertain();
      return html`<button class="run" type="submit" form="stage" ?disabled=${!ready}>${runLabel}</button>`;
    },
    admitDroppedFile: (sorting, file) => admitFile(sorting === Sorting.AsPatch ? 'patch' : 'patched', file),
    admitPickedFile,
    askAgain: askUnanswered,
    actions: {
      run: runUndo,
      'cancel-run': () => { if (actRunning()) undo.act.cancel(); },
      'swap-seats': () => {
        seatBothFiles(undo.patched, undo.patch);
        host.fellow.nod();
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonAct();
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
