// One cell of the web lane, run as its own process so the driver in bench-web.mjs can kill it at the patience budget:
// boot one side, time one verb on one pair, judge the output, print one json line.
//
//   node bench/web-lane-cell.mjs SIDE VERB TIER LANE-JSON

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WASI } from 'node:wasi';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const [side, verb, tierName, laneJson] = process.argv.slice(2);
const lane = JSON.parse(laneJson);

const baseBytes = readFileSync(`${repoRoot}${lane.basePath}`);
const modifiedBytes = readFileSync(`${repoRoot}bench/work/${tierName}/modified.bin`);
const modifiedDigest = createHash('sha256').update(modifiedBytes).digest('hex');
const sha256Of = (bytes) => createHash('sha256').update(bytes).digest('hex');

// The first invocation is measured and judged; a defective answer is the cell's whole story,
// and a slow one is its own measurement, since repetition would spend minutes refining a number whose scale is already plain.
// A quick faithful call earns the median of five more.
const timedRuns = 5;
const measureJudged = (call, judgeDefect) => {
  const firstBegin = performance.now();
  const firstAnswer = call();
  const firstMs = performance.now() - firstBegin;
  const defect = judgeDefect(firstAnswer);
  if (defect) return { tag: 'Balked', words: defect };
  if (firstMs > 5000) return { tag: 'Timed', ms: firstMs };
  const samples = [];
  for (let run = 0; run < timedRuns; run += 1) {
    const begin = performance.now();
    call();
    samples.push(performance.now() - begin);
  }
  return { tag: 'Timed', ms: [...samples].sort((a, b) => a - b)[Math.floor(samples.length / 2)] };
};

// a cell answers exactly once, and answering ends it — the apply branches never fall through to create
const answer = (outcome) => { console.log(JSON.stringify(outcome)); process.exit(0); };

/* ---------------------------------------------------------------- the web slap side ---- */

const bootWebSlap = async () => {
  const reactorModule = await WebAssembly.compile(readFileSync(`${repoRoot}dist-web/reactor/slap-web-reactor.wasm`));
  const wasi = new WASI({ version: 'preview1' });
  const reactor = await WebAssembly.instantiate(reactorModule, wasi.getImportObject());
  wasi.initialize(reactor);
  reactor.exports.hs_init(0, 0);
  // one envelope call: buffers in, (envelope, tail) out — the split reactor-client.mjs documents
  return (exportName, buffers) => {
    const placed = buffers.map((bytes) => {
      const pointer = reactor.exports.slap_web_alloc(bytes.length) >>> 0;
      new Uint8Array(reactor.exports.memory.buffer, pointer, bytes.length).set(bytes);
      return { pointer, length: bytes.length };
    });
    const answerPointer = reactor.exports[exportName](...placed.flatMap(({ pointer, length }) => [pointer, length])) >>> 0;
    placed.forEach(({ pointer }) => reactor.exports.slap_web_free(pointer));
    const answerLength = new DataView(reactor.exports.memory.buffer).getUint32(answerPointer, true);
    const wholeAnswer = new Uint8Array(reactor.exports.memory.buffer, answerPointer + 4, answerLength).slice();
    reactor.exports.slap_web_free(answerPointer);
    const envelopeLength = new DataView(wholeAnswer.buffer).getUint32(0, true);
    return {
      envelope: JSON.parse(new TextDecoder().decode(wholeAnswer.subarray(4, 4 + envelopeLength))),
      tail: wholeAnswer.subarray(4 + envelopeLength),
    };
  };
};

const runWebSlap = async () => {
  const callReactor = await bootWebSlap();
  const applyDeclaration = readFileSync(`${repoRoot}test/data/web/apply.json`);
  if (verb === 'apply') {
    const wildPatchBytes = readFileSync(`${repoRoot}bench/work/${tierName}/${lane.wildPatch}`);
    const applyOnce = () => callReactor('slap_web_apply_patch', [wildPatchBytes, baseBytes, applyDeclaration]);
    answer(measureJudged(applyOnce, (applied) =>
      !applied.envelope.envelopeAnswer?.Right || sha256Of(applied.tail) !== modifiedDigest
        ? 'output differs or refused' : null));
  }
  const createDeclaration = new TextEncoder().encode(JSON.stringify({
    declaredCreateTargetFormat: lane.webSlapFormat,
    declaredCreateOriginalName: 'base.bin',
    declaredCreateModifiedName: 'patched.bin',
    declaredCreateMetadata: { requestedFileIdDiz: { tag: 'InheritFileIdDiz' }, requestedEmbeddedBlob: { tag: 'InheritEmbeddedBlob' },
                              ...lane.webSlapMetadata },
    declaredCreateConstraints: { requestedSMCShape: 'AllowAnyTruncationShape' },
  }));
  const createOnce = () => callReactor('slap_web_create_patch', [baseBytes, modifiedBytes, createDeclaration]);
  let createdPatchLength = null;
  const outcome = measureJudged(createOnce, (created) => {
    if (created.envelope.envelopeAnswer?.Right === undefined) return 'refused';
    const roundTrip = callReactor('slap_web_apply_patch', [created.tail, baseBytes, applyDeclaration]);
    if (sha256Of(roundTrip.tail) !== modifiedDigest) return 'its patch does not rebuild the pair';
    createdPatchLength = created.tail.length;
    return null;
  });
  answer(outcome.tag === 'Timed' ? { ...outcome, patchBytes: createdPatchLength } : outcome);
};

/* -------------------------------------------------------------------- the rpjs side ---- */

const runRpjs = () => {
  const requireAsRpjs = createRequire(`${repoRoot}tools/rompatcher-js/index.js`);
  const RomPatcher = requireAsRpjs('./rom-patcher-js/RomPatcher');
  const BinFile = requireAsRpjs('./rom-patcher-js/modules/BinFile');
  // node hands file bytes as views over shared buffer pools, and BinFile trusts a view's whole underlying buffer,
  // so it is given a copy whose buffer is exactly the bytes and nothing else
  const binFileOf = (bytes, name) => {
    const exactBytes = new Uint8Array(bytes.length);
    exactBytes.set(bytes);
    const held = new BinFile(exactBytes);
    held.setName(name);
    return held;
  };
  const bytesOf = (binFile) => new Uint8Array(binFile._u8array ?? binFile.getBytes());

  try {
    if (verb === 'apply') {
      const wildPatchBytes = readFileSync(`${repoRoot}bench/work/${tierName}/${lane.wildPatch}`);
      const applyOnce = () => {
        const parsed = RomPatcher.parsePatchFile(binFileOf(wildPatchBytes, lane.wildPatch));
        return RomPatcher.applyPatch(binFileOf(baseBytes, 'base.bin'), parsed, {});
      };
      answer(measureJudged(applyOnce, (applied) =>
        sha256Of(bytesOf(applied)) !== modifiedDigest ? 'output differs from the pair' : null));
    }
    const createOnce = () =>
      RomPatcher.createPatch(binFileOf(baseBytes, 'base.bin'), binFileOf(modifiedBytes, 'patched.bin'), lane.rpjsToken);
    let createdPatchLength = null;
    const outcome = measureJudged(createOnce, (created) => {
      const exported = bytesOf(created.export());
      const parsedBack = RomPatcher.parsePatchFile(binFileOf(exported, `made.${lane.rpjsToken}`));
      const rebuilt = RomPatcher.applyPatch(binFileOf(baseBytes, 'base.bin'), parsedBack, {});
      if (sha256Of(bytesOf(rebuilt)) !== modifiedDigest) return 'its patch does not rebuild the pair';
      createdPatchLength = exported.length;
      return null;
    });
    answer(outcome.tag === 'Timed' ? { ...outcome, patchBytes: createdPatchLength } : outcome);
  } catch (failure) { answer({ tag: 'Balked', words: String(failure.message ?? failure) }); }
};

if (side === 'web-slap') await runWebSlap(); else runRpjs();
