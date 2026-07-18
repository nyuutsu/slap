// Calls one envelope export and writes its bytes to stdout — the wasm half of the parity check,
// whose native half is the probe in Main.hs; both read the same argument shape, so the Makefile hands them one list.
// The buffer protocol is Main.hs's too; the answer opens with a little-endian u32 payload length.
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

// Per verb: the export it calls, and its argv paths rearranged into the export's own buffer order.
// A null entry crosses as (0, 0) — check-convert's seat for a source the declaration does not speak of.
const shapes = {
  surface:         { export: 'slap_web_describe_surface',      buffers: () => [] },
  classify:        { export: 'slap_web_classify_dropped_file', buffers: ([file]) => [file] },
  identify:        { export: 'slap_web_identify_patch',        buffers: ([patch, declaration]) => [patch, declaration] },
  'describe-rom':  { export: 'slap_web_describe_rom',          buffers: ([rom]) => [rom] },
  inspect:         { export: 'slap_web_inspect_patch',         buffers: ([patch, declaration]) => [patch, declaration] },
  analyze:         { export: 'slap_web_analyze_patch',         buffers: ([patch, declaration]) => [patch, declaration] },
  'check-apply':   { export: 'slap_web_check_apply',           buffers: ([patch, rom, declaration]) => [patch, rom, declaration] },
  'check-undo':    { export: 'slap_web_check_undo',            buffers: ([patch, patched, declaration]) => [patch, patched, declaration] },
  'check-create':  { export: 'slap_web_check_create',          buffers: ([original, modified, declaration]) => [original, modified, declaration] },
  'check-convert': { export: 'slap_web_check_convert',         buffers: ([patch, declaration, source]) => [patch, source ?? null, declaration] },
  apply:           { export: 'slap_web_apply_patch',           buffers: ([patch, rom, declaration]) => [patch, rom, declaration] },
  undo:            { export: 'slap_web_undo_patch',            buffers: ([patch, patched, declaration]) => [patch, patched, declaration] },
  create:          { export: 'slap_web_create_patch',          buffers: ([original, modified, declaration]) => [original, modified, declaration] },
  convert:         { export: 'slap_web_convert_patch',         buffers: ([patch, declaration, source]) => [patch, source ?? null, declaration] },
};

const [reactorPath, verb, ...verbArgs] = process.argv.slice(2);
const shape = shapes[verb];
if (!reactorPath || !shape) {
  console.error('usage: node envelope-host.mjs <reactor.wasm> <verb> <the verb\'s own arguments, as the probe takes them>');
  process.exit(2);
}

const wasi = new WASI({ version: 'preview1' });
const reactorModule = await WebAssembly.compile(await readFile(reactorPath));
const instance = await WebAssembly.instantiate(reactorModule, wasi.getImportObject());
wasi.initialize(instance);
instance.exports.hs_init(0, 0);

const buffers = [];
for (const path of shape.buffers(verbArgs)) {
  if (path == null) {
    buffers.push({ pointer: 0, length: 0, allocated: false });
    continue;
  }
  const bytes = await readFile(path);
  const pointer = instance.exports.slap_web_alloc(bytes.length) >>> 0;
  new Uint8Array(instance.exports.memory.buffer, pointer, bytes.length).set(bytes);
  buffers.push({ pointer, length: bytes.length, allocated: true });
}

const envelopePointer = instance.exports[shape.export](...buffers.flatMap(({ pointer, length }) => [pointer, length])) >>> 0;
for (const { pointer, allocated } of buffers) {
  if (allocated) instance.exports.slap_web_free(pointer);
}

const envelopeLength = new DataView(instance.exports.memory.buffer).getUint32(envelopePointer, true);
const envelopeBytes = Buffer.from(instance.exports.memory.buffer, envelopePointer + 4, envelopeLength);
process.stdout.write(Buffer.from(envelopeBytes));
instance.exports.slap_web_free(envelopePointer);
