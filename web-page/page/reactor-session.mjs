// The page's one door to the engine.

import { compileReactor, startReactorJob, ReactorJobCancelled, ReactorNeverArrived } from '../reactor/reactor-client.mjs';

export { ReactorJobCancelled };

export const openReactorSession = async () => {
  const compiledReactor = await compileReactor('reactor/slap-web-reactor.wasm');
  const surfaceAnswer = await startReactorJob(compiledReactor, 'surface').answered;
  return {
    surface: surfaceAnswer.envelope.envelopeAnswer.Right,
    ask: (verb, seats) => startReactorJob(compiledReactor, verb, seats).answered,
    startJob: (verb, seats) => startReactorJob(compiledReactor, verb, seats),
  };
};

// The screenshot is the bug report: a terminal failure must show its distinguishing detail on screen,
// because the console never survives the trip from a user to us.
export const classifyBootFailure = (bootFailure) => {
  // the ReferenceError's prose is browser-specific; the absent global is the hard fact
  if (typeof WebAssembly === 'undefined') return { tag: 'WebAssemblySwitchedOff' };
  if (bootFailure instanceof ReactorNeverArrived) return { tag: 'ReactorNeverArrived', detail: bootFailure.message };
  return { tag: 'BootFell', detail: String(bootFailure) };
};

// An envelope's answer is aeson's Either: { Right: value } or { Left: spoken error }.
export const answerOf = (envelope) =>
  'Right' in envelope.envelopeAnswer
    ? { answered: envelope.envelopeAnswer.Right }
    : { refused: envelope.envelopeAnswer.Left };

export const advisoriesOf = (envelope) => envelope.envelopeAdvisories;
