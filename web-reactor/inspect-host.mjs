// Calls slap_web_inspect_patch over one patch file and writes the envelope bytes to stdout —
// the wasm half of the parity check, whose native half is the probe in Main.hs.
// The buffer protocol is Main.hs's too; the answer opens with a little-endian u32 payload length.
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const [reactorPath, patchPath] = process.argv.slice(2);
if (!reactorPath || !patchPath) {
  console.error('usage: node inspect-host.mjs <reactor.wasm> <patch>');
  process.exit(2);
}

const wasi = new WASI({ version: 'preview1' });
const reactorModule = await WebAssembly.compile(await readFile(reactorPath));
const instance = await WebAssembly.instantiate(reactorModule, wasi.getImportObject());
wasi.initialize(instance);
instance.exports.hs_init(0, 0);

const patchBytes = await readFile(patchPath);
const patchPointer = instance.exports.slap_web_alloc(patchBytes.length);
new Uint8Array(instance.exports.memory.buffer, patchPointer, patchBytes.length).set(patchBytes);
const envelopePointer = instance.exports.slap_web_inspect_patch(patchPointer, patchBytes.length);
instance.exports.slap_web_free(patchPointer);

const envelopeLength = new DataView(instance.exports.memory.buffer).getUint32(envelopePointer, true);
const envelopeBytes = Buffer.from(instance.exports.memory.buffer, envelopePointer + 4, envelopeLength);
process.stdout.write(Buffer.from(envelopeBytes));
instance.exports.slap_web_free(envelopePointer);
