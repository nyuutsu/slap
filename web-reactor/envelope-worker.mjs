// The Worker half of the browser crossing: one message runs one job, naming a reactor export and handing its seats,
// which cross in the export's own order under the buffer protocol Main.hs declares.
// A File seat arrives as a handle and is read here, so a rom-sized buffer never occupies the main thread.
// The verb table and the Worker's whole lifecycle — spawn, terminate-as-cancel, one job per instance — live in reactor-client.mjs.
import { WASI, OpenFile, File as WasiFile, ConsoleStdout } from '../vendor/browser_wasi_shim/dist/index.js';

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
      new Uint8Array(instance.exports.memory.buffer, pointer, bytes.length).set(bytes);
      seatArguments.push(pointer, bytes.length);
    }

    const answerPointer = instance.exports[exportName](...seatArguments) >>> 0;
    const payloadLength = new DataView(instance.exports.memory.buffer).getUint32(answerPointer, true);
    const payload = new Uint8Array(instance.exports.memory.buffer, answerPointer + 4, payloadLength).slice();
    // Nothing calls slap_web_free: the instance and the Worker are discarded together.
    postMessage({ payload }, [payload.buffer]);
  } catch (jobFailure) {
    postMessage({ failure: String(jobFailure) });
  }
};
