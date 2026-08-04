// Everything the engine decides — the verdict, the rescue, the unasked fix — arrives through the host's asks;
// this module owns only apply's shape and voice.

import { html, nothing } from '../../vendor/lit-html/lit-html.js';
import { Verdict, Sorting, matcherOver } from './../engine-vocabulary.mjs';
import { groupMarkup, toggleMarkup, seatSlotMarkup, heldSeatMarkup, swapSeatsMarkup,
         headerControlMarkup, preseededConsoleRow } from './../controls.mjs';
import { applyFactsCardMarkup } from './../facts-card.mjs';
import { voiceLines, plainVoice, restingVoice, workingVoice, patchedVoice, refusalVoice } from './../answer-surface.mjs';
import { verbWord, flagWord, valueWord, fileWord, namedOr, placeholderWord } from './../command-tutor.mjs';
import { dialectControls, dialectTogglesMarkup } from './../dialect-controls.mjs';
import { identifyDeclaration } from './../declarations.mjs';

const runLabel = 'Patch';

// The act is one value, so "running and answered at once" has no spelling:
// AtRest | Running{cancel} | Patched{voice payload} | Refused{spokenError, sentence, advisories} | Fell{sentence, advisories}.
const atRest = () => ({
  patch: null, patchIdentity: null,
  rom: null, romFacts: null,
  sourceReport: null,
  framing: { tag: 'TakeInputAsIs', console: null },
  verificationPolicy: 'EnforceVerification',
  patchOrigin: 'OriginPC',
  act: { tag: 'AtRest' },
});

const patchedName = (romFile) => {
  const lastDot = romFile.name.lastIndexOf('.');
  return lastDot > 0
    ? `${romFile.name.slice(0, lastDot)}-patched${romFile.name.slice(lastDot)}`
    : `${romFile.name}-patched`;
};

// The weighing's word while everything is still in hand; Differs consults the rescue before despairing.
const weighingVoiceLine = matcherOver(Verdict, {
  Matches:     () => voiceLines.match,
  Uncheckable: () => voiceLines.uncheckable,
  Differs: (_mismatches, { sourceRescue, framingUntouched }) => {
    if (sourceRescue.length === 1 && framingUntouched) return voiceLines.headeredButRescued;
    if (sourceRescue.length > 1) return voiceLines.differsManyWays;
    return voiceLines.differsHopeless;
  },
});

export const makeApplyVerb = (host) => {
  let apply = atRest();

  const declaration = () => ({
    declaredApplyFraming: apply.framing.tag === 'TakeInputAsIs'
      ? { tag: 'TakeInputAsIs' }
      : { tag: apply.framing.tag, contents: apply.framing.console.describedConsoleHeader },
    declaredApplyVerificationPolicy: apply.verificationPolicy,
    declaredApplyDialects: { requestedPatchOrigin: apply.patchOrigin },
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
    host.ask('identify', { patch: apply.patch, declaration: identifyDeclaration(apply.patchOrigin, 'utf-8') })
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

  const actRunning  = () => apply.act.tag === 'Running';
  const actAnswered = () => apply.act.tag !== 'AtRest' && !actRunning();

  const abandonAct = () => {
    if (apply.act.tag === 'Patched') URL.revokeObjectURL(apply.act.downloadHref);
    apply.act = { tag: 'AtRest' };
  };

  const admitFile = (seat, file) => {
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
    if (seat === 'patch') {
      apply.patch = file;
      apply.patchIdentity = null;
      // a stale toggle can't ride onto a patch it might not fit
      apply.patchOrigin = 'OriginPC';
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
    if (actRunning()) return;
    host.supersedeAsks();
    abandonAct();
    apply.patch = patchFile;
    apply.rom = romFile;
    apply.patchIdentity = null;
    apply.romFacts = null;
    apply.sourceReport = null;
    apply.patchOrigin = 'OriginPC';
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
        if (answered !== Sorting.AsPatch || apply.rom !== file) return;
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

  // What the run still waits on, as the places it would point at. Resting on a waiting run outlines all of them
  // at once — the fellow's box among them, since the words for why are already in his mouth.
  const runReadiness = () => {
    if (!host.hasSession() || refusalCertain()) return { tag: 'Waiting', pointAt: ['voice'] };
    const awaited = [!apply.patch && 'seat-patch', !apply.rom && 'seat-rom'].filter(Boolean);
    return awaited.length === 0 ? { tag: 'Ready' } : { tag: 'Waiting', pointAt: ['voice', ...awaited] };
  };

  const runApply = () => {
    if (!apply.patch || !apply.rom || actRunning()) return;
    const job = host.startJob('apply', { patch: apply.patch, rom: apply.rom, declaration: declaration() });
    if (!job) return;
    apply.act = { tag: 'Running', cancel: job.cancel };
    host.fellow.beginFidgeting();
    host.render();

    job.answered.then(({ envelope, tail }) => {
      host.fellow.settle();
      const { answered, refused, advisories } = host.openEnvelope(envelope);
      if (answered) {
        const downloadName = patchedName(apply.rom);
        const downloadHref = URL.createObjectURL(new Blob([tail]));
        const inputReframed = apply.framing.tag !== 'TakeInputAsIs'
          || advisories.some((advisory) => advisory.spokenAdvisory.tag === 'InputReframedToMatchPatch');
        apply.act = {
          tag: 'Patched', spoken: answered, advisories, downloadName, downloadHref, inputReframed,
        };
        host.download(downloadHref, downloadName);
        host.fellow.smile();
      } else {
        apply.act = { tag: 'Refused', spokenError: refused.spokenError, sentence: refused.spokenErrorSentence, advisories };
        host.fellow.droop();
      }
      host.render();
      host.carryFocusToAnswer();
    }).catch((jobFailure) => {
      host.fellow.settle();
      if (host.wasCancelled(jobFailure)) {
        apply.act = { tag: 'AtRest' };
        host.setNotice(voiceLines.cancelled);
        host.render();
        return;
      }
      apply.act = { tag: 'Fell', sentence: jobFailure.message, advisories: [] };
      host.fellow.droop();
      host.render();
      host.carryFocusToAnswer();
    });
  };

  /* ------------------------------------------------------------ stage ---- */

  const chipWord = () => apply.patchIdentity?.answered?.spokenIdentityFormatName ?? null;

  const slotFor = (seat, roleWord, file, slotChipWord) =>
    actRunning() ? heldSeatMarkup(file, slotChipWord) : seatSlotMarkup(seat, roleWord, file, slotChipWord);

  const sentenceMarkup = () => html`<p class="sentence">apply
    ${slotFor('patch', 'patch', apply.patch, chipWord())} to
    ${slotFor('rom', 'rom', apply.rom, null)}</p>`;

  const optionsMarkup = () => groupMarkup('options', html`
    ${toggleMarkup({ id: 'skip-verification', setting: 'verification',
                     checked: apply.verificationPolicy === 'SkipVerification',
                     label: 'skip verification', why: 'mismatches become warnings' })}
    ${dialectTogglesMarkup(apply.patchIdentity?.answered?.spokenIdentityDialects ?? [], apply.patchOrigin)}`);

  const stageMarkup = () => {
    if (actAnswered()) return sentenceMarkup();

    const operandsSatisfied = apply.patch && apply.rom;
    const verdict = apply.sourceReport?.sourceVerdict;
    const headerControlSurfaces = operandsSatisfied && (
      apply.framing.tag !== 'TakeInputAsIs'
      || verdict?.tag === Verdict.Uncheckable
      || (verdict?.tag === Verdict.Differs
          && (apply.sourceReport.sourceRescue.length > 1
              || apply.verificationPolicy === 'SkipVerification')));

    return html`
      ${sentenceMarkup()}
      ${operandsSatisfied && !actRunning() && apply.patchIdentity?.refused ? swapSeatsMarkup : nothing}
      ${applyFactsCardMarkup(apply, host.surface().surfaceConsoleHeaders)}
      ${headerControlSurfaces ? headerControlMarkup(apply.framing, host.surface().surfaceConsoleHeaders) : nothing}
      ${operandsSatisfied && !impedimentSpoken() ? optionsMarkup() : nothing}`;
  };

  /* ------------------------------------------------------------ voice ---- */

  const voiceMarkup = () => {
    if (apply.act.tag === 'Patched') return patchedVoice(apply.act);
    if (apply.act.tag === 'Refused' || apply.act.tag === 'Fell') return refusalVoice(apply.act, 'apply');
    if (actRunning()) return workingVoice(voiceLines.patching);
    if (host.notice()) return plainVoice(host.notice());
    if (apply.patchIdentity?.refused)
      return html`<p class="refusal">${apply.patchIdentity.refused.spokenErrorSentence}</p>`;
    const blocked = impedimentSpoken();
    if (blocked) return html`<p class="refusal">${blocked.spokenErrorSentence}</p>`;
    if (!apply.patch && !apply.rom) return restingVoice(voiceLines.resting);
    if (!apply.patch) return plainVoice(voiceLines.romOnly);
    if (!apply.rom) return plainVoice(voiceLines.patchOnly);
    if (apply.verificationPolicy === 'SkipVerification') return plainVoice(voiceLines.verificationOff);
    if (!apply.sourceReport) return plainVoice(voiceLines.sizingUp);
    return plainVoice(weighingVoiceLine(apply.sourceReport.sourceVerdict, {
      sourceRescue: apply.sourceReport.sourceRescue,
      framingUntouched: apply.framing.tag === 'TakeInputAsIs',
    }));
  };

  /* ------------------------------------------------------------ tutor ---- */

  const commandWords = () => {
    const patchOriginControl = dialectControls.PatchOriginAxis;
    const words = [verbWord('slap'), verbWord('apply')];
    if (apply.verificationPolicy === 'SkipVerification') words.push(flagWord('--no-verify'));
    if (apply.framing.tag === 'RemoveHeader') words.push(flagWord('--remove-header'), valueWord(apply.framing.console.consoleToken));
    if (apply.framing.tag === 'AddHeader') words.push(flagWord('--add-header'), valueWord(apply.framing.console.consoleToken));
    if (apply.patchOrigin === patchOriginControl.chosenOrigin) words.push(flagWord(patchOriginControl.terminalFlag));
    words.push(namedOr(apply.patch, 'PATCH'), namedOr(apply.rom, 'ROM'));
    words.push(apply.rom ? fileWord(patchedName(apply.rom)) : placeholderWord('OUTPUT'));
    return words;
  };

  /* ---------------------------------------------------------- surface ---- */

  // Dark only on a fact the page already holds; a question still in flight never darkens it.
  const refusalCertain = () => {
    if (apply.patchIdentity?.refused || impedimentSpoken()) return true;
    if (apply.verificationPolicy === 'SkipVerification') return false;
    if (apply.sourceReport?.sourceVerdict?.tag !== Verdict.Differs) return false;
    return !(apply.framing.tag === 'TakeInputAsIs' && apply.sourceReport.sourceRescue.length === 1);
  };

  return {
    runReadiness,
    stageMarkup,
    voiceMarkup,
    commandWords,
    actMarkup: () => {
      if (apply.act.tag !== 'AtRest') return html``;
      const readiness = runReadiness();
      return html`<button class="run" type="submit" form="stage" aria-disabled="${readiness.tag === 'Waiting'}"
        data-points-at=${readiness.tag === 'Waiting' ? readiness.pointAt.join(' ') : nothing}>${runLabel}</button>`;
    },
    admitDroppedFile: (sorting, file) => admitFile(sorting === Sorting.AsPatch ? 'patch' : 'rom', file),
    admitPickedFile,
    askAgain: askUnanswered,
    actions: {
      run: runApply,
      'cancel-run': () => { if (actRunning()) apply.act.cancel(); },
      'swap-seats': () => {
        seatBothFiles(apply.rom, apply.patch);
        host.fellow.nod();
      },
      'start-over': () => {
        host.supersedeAsks();
        abandonAct();
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
        apply.patchOrigin = checked ? 'OriginAmiga' : 'OriginPC';
      }),
      framing: (framingTag) => reweighSource(() => {
        apply.framing = framingTag === 'TakeInputAsIs'
          ? { tag: 'TakeInputAsIs', console: null }
          : { tag: framingTag, console: apply.framing.console ?? preseededConsoleRow(host.surface().surfaceConsoleHeaders) };
      }),
      console: (consoleToken) => reweighSource(() => {
        apply.framing.console = host.surface().surfaceConsoleHeaders
          .find((row) => row.consoleToken === consoleToken);
      }),
    },
  };
};
