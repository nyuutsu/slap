// The page's one door to the engine.

import { compileReactor, startReactorJob, ReactorJobCancelled } from '../reactor/reactor-client.mjs';

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

// An envelope's answer is aeson's Either: { Right: value } or { Left: spoken error }.
export const answerOf = (envelope) =>
  'Right' in envelope.envelopeAnswer
    ? { answered: envelope.envelopeAnswer.Right }
    : { refused: envelope.envelopeAnswer.Left };

export const advisoriesOf = (envelope) => envelope.envelopeAdvisories;
