// Everything the engine decides — the verdict, the rescue, the unasked fix — arrives through the host's asks;
// this module owns only apply's shape and voice.

import { html } from './../dom.mjs';
import { groupMarkup, toggleMarkup, seatSlotMarkup, heldSeatMarkup, swapSeatsMarkup,
         headerControlMarkup, preseededConsoleRow } from './../controls.mjs';
import { applyFactsCardMarkup } from './../facts-card.mjs';
import { voiceLines, plainVoice, workingVoice, patchedVoice, refusalVoice } from './../answer-surface.mjs';
import { verbWord, flagWord, valueWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { dialectControls, dialectTogglesMarkup } from './../dialect-controls.mjs';
import { identifyDeclaration } from './../declarations.mjs';

const runLabel = 'Patch';

const atRest = () => ({
  patch: null, patchIdentity: null,
  rom: null, romFacts: null,
  sourceReport: null,
  framing: { tag: 'TakeInputAsIs', console: null },
  verificationPolicy: 'EnforceVerification',
  ppf1Origin: 'PPF1OriginPC',
  running: null,
  outcome: null,
});

const patchedName = (romFile) => {
  const lastDot = romFile.name.lastIndexOf('.');
  return lastDot > 0
    ? `${romFile.name.slice(0, lastDot)}-patched${romFile.name.slice(lastDot)}`
    : `${romFile.name}-patched`;
};

export const makeApplyVerb = (host) => {
  let apply = atRest();

  const declaration = () => ({
    declaredApplyFraming: apply.framing.tag === 'TakeInputAsIs'
      ? { tag: 'TakeInputAsIs' }
      : { tag: apply.framing.tag, contents: apply.framing.console.describedConsoleHeader },
    declaredApplyVerificationPolicy: apply.verificationPolicy,
    declaredApplyDialects: { requestedPPF1Origin: apply.ppf1Origin },
  });

  /* ------------------------------------------------------------- asks ---- */

  const askRomFacts = () => {
    if (!apply.rom) return;
    host.ask('describe-rom', { rom: apply.rom })
      ?.then(host.wheneverStillCurrent(({ answered }) => { apply.romFacts = answered; }))
      .catch(host.askFailed);
  };

  const impedimentSpoken = () => apply.patchIdentity?.answered?.spokenIdentityImpediment ?? null;

  const askIdentity = () => {
    if (!apply.patch) return;
    host.ask('identify', { patch: apply.patch, declaration: identifyDeclaration(apply.ppf1Origin, 'utf-8') })
      ?.then(host.wheneverStillCurrent((answer) => { apply.patchIdentity = answer; }))
      .catch(host.askFailed);
  };

  const askPreflight = () => {
    if (!apply.patch || !apply.rom || impedimentSpoken()) return;
    host.ask('check-apply', { patch: apply.patch, rom: apply.rom, declaration: declaration() })
      ?.then(host.wheneverStillCurrent(({ answered }) => { apply.sourceReport = answered; }))
      .catch(host.askFailed);
  };

  // Superseding drops even a sibling seat's in-flight answer, and an answer dropped without a re-ask never comes back.
  const askUnanswered = () => {
    if (!apply.patchIdentity) askIdentity();
    if (!apply.romFacts) askRomFacts();
    if (!apply.sourceReport) askPreflight();
  };

  /* ------------------------------------------------------------ seats ---- */

  const abandonOutcome = () => {
    if (apply.outcome?.patched) URL.revokeObjectURL(apply.outcome.patched.downloadHref);
    apply.outcome = null;
  };

  const admitFile = (seat, file) => {
    if (apply.running) return;
    host.supersedeAsks();
    abandonOutcome();
    if (seat === 'patch') {
      apply.patch = file;
      apply.patchIdentity = null;
      // a stale toggle can't ride onto a patch it might not fit
      apply.ppf1Origin = 'PPF1OriginPC';
    } else {
      apply.rom = file;
      apply.romFacts = null;
    }
    apply.sourceReport = null;
    host.fellow.nod();
    askUnanswered();
    host.render();
  };

  // Both seats at once, for the two moves that are one move: swapping them, and a patch taking its own seat.
  const seatBothFiles = (patchFile, romFile) => {
    if (apply.running) return;
    host.supersedeAsks();
    abandonOutcome();
    apply.patch = patchFile;
    apply.rom = romFile;
    apply.patchIdentity = null;
    apply.romFacts = null;
    apply.sourceReport = null;
    apply.ppf1Origin = 'PPF1OriginPC';
    askUnanswered();
    host.render();
  };

  // The picker learns what a drop already knows. A file the engine recognizes as a patch belongs in the patch seat wherever it was picked,
  // and the file it displaces belongs in the seat it was picked into.
  // Nothing else moves. A file picked as the patch and recognized as no patch stays there to be told so,
  // which is the answer worth having; and a patch seat already holding a readable patch is left alone,
  // two patches in hand being an arrangement only the person can mean. Undo seats its own pair by this same rule.
  const admitPickedFile = (seat, file) => {
    const displacedFromPatchSeat = apply.patch;
    const patchSeatReadable = !!apply.patchIdentity?.answered;
    admitFile(seat, file);
    if (seat !== 'rom' || patchSeatReadable) return;
    host.ask('classify', { file })
      ?.then(host.wheneverStillCurrent(({ answered }) => {
        if (answered !== 'SortsAsPatch' || apply.rom !== file) return;
        seatBothFiles(file, displacedFromPatchSeat);
      }))
      .catch(host.askFailed);
  };

  /* --------------------------------------------------------- settings ---- */
  /* The verification policy is not a comparison input — a held report stays true under either policy — so its toggle only redraws. */

  const restateQuietly = (change) => {
    change();
    host.render();
  };

  const reweighSource = (change) => {
    host.supersedeAsks();
    change();
    apply.sourceReport = null;
    askUnanswered();
    host.render();
  };

  const rereadPatch = (change) => {
    host.supersedeAsks();
    change();
    apply.patchIdentity = null;
    apply.sourceReport = null;
    askUnanswered();
    host.render();
  };

  /* ---------------------------------------------------------- the act ---- */

  const runApply = () => {
    if (!apply.patch || !apply.rom || apply.running) return;
    const job = host.startJob('apply', { patch: apply.patch, rom: apply.rom, declaration: declaration() });
    if (!job) return;
    apply.running = { cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      apply.running = null;
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = patchedName(apply.rom);
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        const inputReframed = apply.framing.tag !== 'TakeInputAsIs'
          || advisories.some((advisory) => advisory.spokenAdvisory.tag === 'InputReframedToMatchPatch');
        apply.outcome = { patched: {
          spoken: answered, advisories, downloadName, downloadHref, inputReframed,
          romCrc32: inputReframed ? null : (apply.romFacts?.romCRC32 ?? null),
        } };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        apply.outcome = { refused: { spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories } };
        host.fellow.droop();
      }
      host.render();
    }).catch((jobFailure) => {
      apply.running = null;
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        host.setNotice(voiceLines.cancelled);
      } else {
        apply.outcome = { failed: { sentence: jobFailure.message, advisories: [] } };
        host.fellow.droop();
      }
      host.render();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const chipWord = () => apply.patchIdentity?.answered?.spokenIdentityFormatName ?? null;

  const slotFor = (seat, roleWord, file, slotChipWord) =>
    apply.running ? heldSeatMarkup(file, slotChipWord) : seatSlotMarkup(seat, roleWord, file, slotChipWord);

  const sentenceMarkup = () => html`<p class="sentence">apply
    ${slotFor('patch', 'patch', apply.patch, chipWord())} to
    ${slotFor('rom', 'rom', apply.rom, null)}</p>`;

  const optionsMarkup = () => groupMarkup('options', html`
    ${toggleMarkup({ id: 'skip-verification', setting: 'verification',
                     checked: apply.verificationPolicy === 'SkipVerification',
                     label: 'skip verification', why: 'mismatches become warnings' })}
    ${dialectTogglesMarkup(apply.patchIdentity?.answered?.spokenIdentityDialects ?? [], apply.ppf1Origin)}`);

  const stageMarkup = () => {
    if (apply.outcome) return sentenceMarkup();

    const operandsSatisfied = apply.patch && apply.rom;
    const verdict = apply.sourceReport?.sourceVerdict;
    const headerControlSurfaces = operandsSatisfied && (
      apply.framing.tag !== 'TakeInputAsIs'
      || verdict?.tag === 'VerdictUncheckable'
      || (verdict?.tag === 'VerdictDiffers' && apply.sourceReport.sourceRescue.length > 1));

    return html`
      ${sentenceMarkup()}
      ${operandsSatisfied && !apply.running && apply.patchIdentity?.refused && swapSeatsMarkup}
      ${applyFactsCardMarkup(apply, host.surface()?.surfaceConsoleHeaders ?? [])}
      ${headerControlSurfaces && headerControlMarkup(apply.framing, host.surface().surfaceConsoleHeaders)}
      ${operandsSatisfied && !impedimentSpoken() && optionsMarkup()}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (apply.outcome?.patched) return patchedVoice(apply.outcome.patched);
    if (apply.outcome?.refused) return refusalVoice(apply.outcome.refused, 'apply');
    if (apply.outcome?.failed) return refusalVoice(apply.outcome.failed, 'apply');
    if (apply.running) return workingVoice(voiceLines.patching);
    if (host.notice()) return plainVoice(host.notice());
    if (apply.patchIdentity?.refused)
      return html`<p class="refusal">${apply.patchIdentity.refused.spokenErrorSentence}</p>`;
    const blocked = impedimentSpoken();
    if (blocked) return html`<p class="refusal">${blocked.spokenErrorSentence}</p>`;
    if (!apply.patch && !apply.rom) return plainVoice(voiceLines.resting);
    if (!apply.patch) return plainVoice(voiceLines.romOnly);
    if (!apply.rom) return plainVoice(voiceLines.patchOnly);
    if (apply.verificationPolicy === 'SkipVerification') return plainVoice(voiceLines.verificationOff);
    if (!apply.sourceReport) return plainVoice(voiceLines.sizingUp);
    const verdict = apply.sourceReport.sourceVerdict;
    if (verdict.tag === 'VerdictMatches') return plainVoice(voiceLines.match);
    if (verdict.tag === 'VerdictUncheckable') return plainVoice(voiceLines.uncheckable);
    const rescue = apply.sourceReport.sourceRescue;
    if (rescue.length === 1 && apply.framing.tag === 'TakeInputAsIs') return plainVoice(voiceLines.headeredButRescued);
    if (rescue.length > 1) return plainVoice(voiceLines.differsManyWays);
    return plainVoice(voiceLines.differsHopeless);
  };

  /* ------------------------------------------------------------ tutor ---- */

  const commandWords = () => {
    const ppf1Origin = dialectControls.PPF1OriginAxis;
    const words = [verbWord('slap'), verbWord('apply')];
    if (apply.verificationPolicy === 'SkipVerification') words.push(flagWord('--no-verify'));
    if (apply.framing.tag === 'RemoveHeader') words.push(flagWord('--remove-header'), valueWord(apply.framing.console.consoleToken));
    if (apply.framing.tag === 'AddHeader') words.push(flagWord('--add-header'), valueWord(apply.framing.console.consoleToken));
    if (apply.ppf1Origin === ppf1Origin.chosenOrigin) words.push(flagWord(ppf1Origin.terminalFlag));
    words.push(namedOr(apply.patch, 'PATCH'), namedOr(apply.rom, 'ROM'));
    words.push(apply.rom ? fileWord(patchedName(apply.rom)) : placeholderWord('OUTPUT'));
    return words;
  };

  /* ---------------------------------------------------------- surface ---- */

  // Dark only on a fact the page already holds; a question still in flight never darkens it.
  const refusalCertain = () => {
    if (apply.patchIdentity?.refused || impedimentSpoken()) return true;
    if (apply.verificationPolicy === 'SkipVerification') return false;
    if (apply.sourceReport?.sourceVerdict?.tag !== 'VerdictDiffers') return false;
    return !(apply.framing.tag === 'TakeInputAsIs' && apply.sourceReport.sourceRescue.length === 1);
  };

  return {
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (apply.outcome || apply.running) return html``;
      const ready = host.hasSession() && apply.patch && apply.rom && !refusalCertain();
      return html`<button class="run" data-action="run" ${!ready && html`disabled`}>${runLabel}</button>`;
    },
    admitDroppedFile: (sorting, file) => admitFile(sorting === 'SortsAsPatch' ? 'patch' : 'rom', file),
    admitPickedFile,
    askAgain: askUnanswered,
    actions: {
      'set-framing': ({ framing }) => reweighSource(() => {
        apply.framing = framing === 'TakeInputAsIs'
          ? { tag: 'TakeInputAsIs', console: null }
          : { tag: framing, console: apply.framing.console ?? preseededConsoleRow(host.surface().surfaceConsoleHeaders) };
      }),
      'set-console': ({ console: consoleToken }) => reweighSource(() => {
        apply.framing.console = host.surface().surfaceConsoleHeaders
          .find((row) => row.consoleToken === consoleToken);
      }),
      run: runApply,
      'cancel-run': () => apply.running?.cancel(),
      'swap-seats': () => {
        seatBothFiles(apply.rom, apply.patch);
        host.fellow.nod();
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonOutcome();
        apply = atRest();
        host.fellow.settle();
        host.render();
      },
    },
    settings: {
      verification: (checked) => restateQuietly(() => {
        apply.verificationPolicy = checked ? 'SkipVerification' : 'EnforceVerification';
      }),
      dialect: (checked) => rereadPatch(() => {
        apply.ppf1Origin = checked ? 'PPF1OriginAmiga' : 'PPF1OriginPC';
      }),
    },
  };
};
