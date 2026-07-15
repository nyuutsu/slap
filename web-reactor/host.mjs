// The instantiate / initialize / call sequence a browser (or Web Worker) runs, minus JSFFI: plain ccall
// exports only, so the check stays about the link rather than the glue. Reactor convention is wasi.initialize
// (runs _initialize) before hs_init (starts the GHC RTS); the export is callable only after both.
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const reactorPath = process.argv[2];
if (!reactorPath) {
  console.error('usage: node host.mjs <reactor.wasm>');
  process.exit(2);
}

const wasi = new WASI({ version: 'preview1' });
const reactorBytes = await readFile(reactorPath);
const reactorModule = await WebAssembly.compile(reactorBytes);
const instance = await WebAssembly.instantiate(reactorModule, wasi.getImportObject());
wasi.initialize(instance);
instance.exports.hs_init(0, 0);

const expectedCRC32 = 0xcbf43926;                          // CRC-32 of "123456789"
const returnedCRC32 = instance.exports.slap_web_link_check() >>> 0;
if (returnedCRC32 === expectedCRC32) {
  console.log('slap_web_link_check() = 0x' + returnedCRC32.toString(16) + ' — wasm link check PASSED');
} else {
  console.error('slap_web_link_check() = 0x' + returnedCRC32.toString(16)
              + ', want 0x' + expectedCRC32.toString(16) + ' — FAILED');
  process.exit(1);
}
