// The page-side half of the browser crossing. Every job gets a fresh Worker and a fresh reactor instance:
// wasm memory never shrinks, so none survives a job, and cancelling is nothing more than terminating the Worker mid-flight.
// The module compiles once and crosses to each Worker as a handle, so a fresh instance never means a fresh compile.

// Per verb: the export it calls, its seats in the export's own order, and whether output bytes ride behind the envelope.
const reactorVerbs = {
  surface:         { reactorExport: 'slap_web_describe_surface', seatOrder: [],                                        answersWithTail: false },
  inspect:         { reactorExport: 'slap_web_inspect_patch',    seatOrder: ['patch'],                                 answersWithTail: false },
  analyze:         { reactorExport: 'slap_web_analyze_patch',    seatOrder: ['patch'],                                 answersWithTail: false },
  'check-apply':   { reactorExport: 'slap_web_check_apply',      seatOrder: ['patch', 'rom', 'declaration'],           answersWithTail: false },
  'check-undo':    { reactorExport: 'slap_web_check_undo',       seatOrder: ['patch', 'patched', 'declaration'],       answersWithTail: false },
  'check-create':  { reactorExport: 'slap_web_check_create',     seatOrder: ['original', 'modified', 'declaration'],   answersWithTail: false },
  'check-convert': { reactorExport: 'slap_web_check_convert',    seatOrder: ['patch', 'source', 'declaration'],        answersWithTail: false },
  apply:           { reactorExport: 'slap_web_apply_patch',      seatOrder: ['patch', 'rom', 'declaration'],           answersWithTail: true },
  undo:            { reactorExport: 'slap_web_undo_patch',       seatOrder: ['patch', 'patched', 'declaration'],       answersWithTail: true },
  create:          { reactorExport: 'slap_web_create_patch',     seatOrder: ['original', 'modified', 'declaration'],   answersWithTail: true },
  convert:         { reactorExport: 'slap_web_convert_patch',    seatOrder: ['patch', 'source', 'declaration'],        answersWithTail: true },
};

export class ReactorJobCancelled extends Error {}

export const compileReactor = (reactorUrl) => WebAssembly.compileStreaming(fetch(reactorUrl));

// Seats arrive named ({ patch, rom, declaration, … }): a File crosses as a handle, an absent seat crosses as null,
// and a plain object — a declaration — is JSON-encoded here.
// Returns { answered, cancel }; answered resolves to { envelope, tail } — the envelope parsed, the tail the act's output bytes,
// or null on the verbs that answer with none.
export const startReactorJob = (compiledReactor, verb, namedSeats = {}) => {
  const { reactorExport, seatOrder, answersWithTail } = reactorVerbs[verb];
  const worker = new Worker(new URL('./envelope-worker.mjs', import.meta.url), { type: 'module' });
  let cancel;
  const answered = new Promise((resolve, reject) => {
    cancel = () => {
      worker.terminate();
      reject(new ReactorJobCancelled(`the ${verb} job was cancelled`));
    };
    worker.onmessage = ({ data: answer }) => {
      worker.terminate();
      if (answer.failure !== undefined) reject(new Error(answer.failure));
      else resolve(splitPayload(answer.payload, answersWithTail));
    };
    worker.onerror = (errorEvent) => {
      worker.terminate();
      reject(new Error(errorEvent.message || `the ${verb} Worker failed`));
    };
  });
  const seats = seatOrder.map((seatName) => encodedSeat(namedSeats[seatName] ?? null));
  worker.postMessage({ module: compiledReactor, exportName: reactorExport, seats }, transferableBuffersOf(seats));
  return { answered, cancel };
};

const encodedSeat = (seat) => {
  if (seat === null || seat instanceof Blob || seat instanceof ArrayBuffer || ArrayBuffer.isView(seat)) return seat;
  return new TextEncoder().encode(JSON.stringify(seat));
};

const transferableBuffersOf = (seats) =>
  seats.flatMap((seat) => (seat instanceof ArrayBuffer ? [seat] : ArrayBuffer.isView(seat) ? [seat.buffer] : []));

const utf8 = new TextDecoder();

const splitPayload = (payload, answersWithTail) => {
  if (!answersWithTail) return { envelope: JSON.parse(utf8.decode(payload)), tail: null };
  const envelopeLength = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(0, true);
  return {
    envelope: JSON.parse(utf8.decode(payload.subarray(4, 4 + envelopeLength))),
    tail: payload.subarray(4 + envelopeLength),
  };
};
