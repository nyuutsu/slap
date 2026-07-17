// The Worker half of the browser crossing: one message runs one job, naming a reactor export and handing its seats,
// which cross in the export's own order under the buffer protocol Main.hs declares.
// A File seat arrives as a handle and is read here, so a rom-sized buffer never occupies the main thread.
// The verb table and the Worker's whole lifecycle — spawn, terminate-as-cancel, one job per instance — live in reactor-client.mjs.
import { WASI, WASIProcExit, OpenFile, File as WasiFile, ConsoleStdout } from '../vendor/browser_wasi_shim/dist/index.js';

// Deliberate twins of ReactorMemoryExhausted's rendered sentence (Slap.Status.Render.Error): no envelope can cross
// a refused seat allocation or a mid-act trap, so the worker speaks for both here; an edit to any of the three
// shouldn't drift from the others. The seat refusal is a known exhaustion (slap_web_alloc answers null for exactly
// that), so its sentence is the confident one; a trap only usually means memory, so its sentence hedges.
const seatMemorySentence =
  "these files don't fit in the browser's memory; the slap command line has no such ceiling";
const trapMemorySentence = (jobFailure) =>
  `slap stopped before finishing. The usual cause is files too large for the browser's available memory; ` +
  `the command-line version has no such limit. (${String(jobFailure)})`;

const diesWithoutAnswering = (jobFailure) =>
  jobFailure instanceof WASIProcExit || jobFailure instanceof WebAssembly.RuntimeError;

const seatBytes = async (seat) => {
  if (seat instanceof Blob) return new Uint8Array(await seat.arrayBuffer());
  if (seat instanceof ArrayBuffer) return new Uint8Array(seat);
  return seat;
};

self.onmessage = async ({ data: { module, exportName, seats } }) => {
  try {
    const wasi = new WASI([], [], [
      new OpenFile(new WasiFile([])),
      ConsoleStdout.lineBuffered((line) => console.log(line)),
      ConsoleStdout.lineBuffered((line) => console.error(line)),
    ], { debug: false });  // the shim reads an absent debug flag as on
    const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
    wasi.initialize(instance);
    instance.exports.hs_init(0, 0);

    const seatArguments = [];
    for (const seat of seats) {
      if (seat === null) {
        seatArguments.push(0, 0);
        continue;
      }
      const bytes = await seatBytes(seat);
      const pointer = instance.exports.slap_web_alloc(bytes.length) >>> 0;
      if (pointer === 0 && bytes.length > 0) {
        postMessage({ failure: seatMemorySentence });
        return;
      }
      new Uint8Array(instance.exports.memory.buffer, pointer, bytes.length).set(bytes);
      seatArguments.push(pointer, bytes.length);
    }

    const answerPointer = instance.exports[exportName](...seatArguments) >>> 0;
    const payloadLength = new DataView(instance.exports.memory.buffer).getUint32(answerPointer, true);
    const payload = new Uint8Array(instance.exports.memory.buffer, answerPointer + 4, payloadLength).slice();
    // Nothing calls slap_web_free: the instance and the Worker are discarded together.
    postMessage({ payload }, [payload.buffer]);
  } catch (jobFailure) {
    postMessage({ failure: diesWithoutAnswering(jobFailure) ? trapMemorySentence(jobFailure) : String(jobFailure) });
  }
};
