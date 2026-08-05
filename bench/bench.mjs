// slap's benchmark rig. Each tier is a pair: a base file, and the modified file a real patch makes of it.
// Each format in a tier is bottled and applied by slap and by whichever reference tools can be driven from a shell, timed with hyperfine.
// A command whose output is unfaithful gets no timing: a wrong answer's speed is not a measurement.
//
//   node bench/bench.mjs            lists the tiers
//   node bench/bench.mjs 16MiB      runs one (results land in bench/results/)

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const slapBinary = process.env.SLAP_BINARY
  ?? `${repoRoot}dist-newstyle/build/x86_64-linux/ghc-9.12.2/slap-1.0.0/x/slap/opt/build/slap/slap`;
const cargoHyperfine = `${process.env.HOME}/.cargo/bin/hyperfine`;
const hyperfineBinary = existsSync(cargoHyperfine) ? cargoHyperfine : 'hyperfine';
const toolsRoot = `${repoRoot}tools/`;

/* ---------------------------------------------------------------- the contenders ---- */
/* An applier that patches in place gets a prepare step, which hyperfine runs outside the clock. */

const rivalCommands = {
  flips: {
    create: (dialectFlag) => (base, modified, patch) => `${toolsRoot}flips/flips -c ${dialectFlag} ${base} ${modified} ${patch}`,
    apply: (patch, base, output) => `${toolsRoot}flips/flips -a ${patch} ${base} ${output}`,
  },
  // sips prints a line per hunk on stderr, and draining that through the harness's synchronous pipe would be charged to sips as slowness,
  // so its stderr goes to /dev/null (hand-timed quiet: 87ms at 64MiB, 440ms at 520MiB)
  sips: { create: (base, modified, patch) => `${toolsRoot}sips/sips ${base} ${modified} ${patch} 2>/dev/null` },
  atmosphereIps: { apply: (patch, base, output) => `${toolsRoot}atmosphere-ips/atmosphere-ips-apply ${base} ${patch} ${output}` },
  goUps: {
    create: (base, modified, patch) => `${toolsRoot}go-ups/go-ups-bin diff --base ${base} --modified ${modified} --output ${patch}`,
    apply: (patch, base, output) => `${toolsRoot}go-ups/go-ups-bin apply --base ${base} --patch ${patch} --output ${output}`,
  },
  makeppf3: { create: (base, modified, patch) => `${toolsRoot}ppf/makeppf3 c ${base} ${modified} ${patch}` },
  applyppf3: {
    applyInPlace: (patch, base, workingCopy) => ({
      prepare: `cp ${base} ${workingCopy}`,
      command: `${toolsRoot}ppf/applyppf3 a ${workingCopy} ${patch}`,
      output: workingCopy,
    }),
  },
  ninjaPhp: {
    // a ninja1 patch names its rom's console
    create: (tier) => (base, modified, patch) =>
      `php -d short_open_tag=On ${toolsRoot}ninja1/ninja.php -b ${tier.ninjaRomType} ${base} ${modified} ${patch}`,
    applyInPlace: (patch, base, workingCopy) => ({
      prepare: `cp ${base} ${workingCopy}`,
      command: `php -d short_open_tag=On ${toolsRoot}ninja1/ninja.php -p ${patch} ${workingCopy}`,
      output: workingCopy,
    }),
  },
  ninja2Php: {
    // ninja2's console tokens are numbers, and there is no GBA among them, so that tier is created as raw.
    // The info file is the eight-line metadata form its CLI requires; blank lines satisfy it.
    create: (tier) => {
      const consoleNumber = { gbc: '5', gba: '0', n64: '4', raw: '0' }[tier.ninjaRomType];
      return (base, modified, patch) =>
        `php -d short_open_tag=On ${toolsRoot}ninja2/php/ninja2.php ${base} ${modified} ${patch} ${consoleNumber} ${repoRoot}bench/ninja2-info.txt`;
    },
    applyInPlace: (patch, base, workingCopy) => ({
      prepare: `cp ${base} ${workingCopy}`,
      command: `php -d short_open_tag=On ${toolsRoot}ninja2/php/ninja2.php ${patch} ${workingCopy}`,
      output: workingCopy,
    }),
  },
  javaxdelta: {
    create: (base, modified, patch) =>
      `java -cp ${toolsRoot}javaxdelta/javaxdelta-2.0.1.jar:${toolsRoot}javaxdelta/trove4j-2.0.4.jar com.nothome.delta.Delta ${base} ${modified} ${patch}`,
    apply: (patch, base, output) =>
      `java -cp ${toolsRoot}javaxdelta/javaxdelta-2.0.1.jar:${toolsRoot}javaxdelta/trove4j-2.0.4.jar com.nothome.delta.GDiffPatcher ${base} ${patch} ${output}`,
  },
  bsdiff: {
    create: (base, modified, patch) => `bsdiff ${base} ${modified} ${patch}`,
    apply: (patch, base, output) => `bspatch ${base} ${output} ${patch}`,
  },
  xdelta1: {
    create: (base, modified, patch) => `${toolsRoot}xdelta1/prefix/bin/xdelta delta ${base} ${modified} ${patch}`,
    apply: (patch, base, output) => `${toolsRoot}xdelta1/prefix/bin/xdelta patch ${patch} ${base} ${output}`,
  },
  xdelta3: {
    create: (base, modified, patch) => `xdelta3 -e -f -s ${base} ${modified} ${patch}`,
    apply: (patch, base, output) => `xdelta3 -d -f -s ${base} ${patch} ${output}`,
  },
};

// slap is implicit in every row
const contendersByFormat = {
  ips: { creators: { flips: rivalCommands.flips.create('--ips') }, appliers: { flips: rivalCommands.flips.apply, atmosphereIps: rivalCommands.atmosphereIps.apply } },
  ips32: { creators: { sips: rivalCommands.sips.create }, appliers: { atmosphereIps: rivalCommands.atmosphereIps.apply } },
  ebp: { creators: {}, appliers: {} },
  ups: { creators: { goUps: rivalCommands.goUps.create }, appliers: { flips: rivalCommands.flips.apply, goUps: rivalCommands.goUps.apply } },
  bps: { creators: { flips: rivalCommands.flips.create('--bps') }, appliers: { flips: rivalCommands.flips.apply } },
  // the PPF1 and PPF2 reference tools are DOS programs, and a DOSBox timing would measure the emulator's pacing rather than the tool,
  // so these two rows run slap alone
  ppf1: { creators: {}, appliers: {} },
  ppf2: { creators: {}, appliers: {} },
  // slap bottles undo data into PPF3 by default and makeppf3 leaves it out by default,
  // so a second slap row matches the reference's mode and the table holds both answers
  ppf3: { slapAlternates: { 'slap-no-undo': '--no-undo' },
          creators: { makeppf3: rivalCommands.makeppf3.create }, appliersInPlace: { applyppf3: rivalCommands.applyppf3.applyInPlace } },
  ppf4: { creators: {}, appliers: {} },
  'aps-n64': { creators: {}, appliers: {} },
  'aps-gba': { creators: {}, appliers: {} },
  dps: { creators: {}, appliers: {} },
  ninja1: { creatorsByTier: { ninjaPhp: rivalCommands.ninjaPhp.create }, appliersInPlace: { ninjaPhp: rivalCommands.ninjaPhp.applyInPlace } },
  ninja2: { creatorsByTier: { ninja2Php: rivalCommands.ninja2Php.create }, appliersInPlace: { ninja2Php: rivalCommands.ninja2Php.applyInPlace } },
  gdiff: { creators: { javaxdelta: rivalCommands.javaxdelta.create }, appliers: { javaxdelta: rivalCommands.javaxdelta.apply } },
  bsdiff: { creators: { bsdiff: rivalCommands.bsdiff.create }, appliers: { bsdiff: rivalCommands.bsdiff.apply } },
  xdelta1: { creators: { xdelta1: rivalCommands.xdelta1.create }, appliers: { xdelta1: rivalCommands.xdelta1.apply } },
  xdelta3: { creators: { xdelta3: rivalCommands.xdelta3.create }, appliers: { xdelta3: rivalCommands.xdelta3.apply } },
  'rfc-vcdiff': { creators: {}, appliers: { xdelta3: rivalCommands.xdelta3.apply } },
};

/* --------------------------------------------------------------------- the tiers ---- */

const patienceDefaults = { createPatienceSeconds: 30, applyPatienceSeconds: 15 };

export const tiers = {
  '4MiB': {
    base: 'test/data/dm4y/base.gbc',
    pairMakerPatch: 'dm4-yugi.bps',
    ninjaRomType: 'gbc',
    timedRuns: 5,
    formats: ['ips', 'ips32', 'ebp', 'ups', 'aps-gba', 'bps', 'ppf1', 'ppf2', 'ppf3',
              'ninja1', 'ninja2', 'dps', 'gdiff', 'bsdiff', 'xdelta1', 'xdelta3', 'rfc-vcdiff'],
  },
  '16MiB': {
    base: 'test/data/ffta/base.gba',
    pairMakerPatch: 'test/data/ffta/ffta-x.aps',
    ninjaRomType: 'gba',
    timedRuns: 5,
    formats: ['ips', 'ips32', 'ebp', 'ups', 'aps-gba', 'bps', 'ppf1', 'ppf2', 'ppf3',
              'ninja1', 'ninja2', 'dps', 'gdiff', 'bsdiff', 'xdelta1', 'xdelta3', 'rfc-vcdiff'],
  },
  '64MiB': {
    base: 'test/data/stadium2/base.z64',
    pairMakerPatch: 'test/data/stadium2/fair-heavy/patch.bps',
    ninjaRomType: 'n64',
    timedRuns: 3,
    formats: ['ips32', 'ups', 'aps-n64', 'bps', 'ppf1', 'ppf2', 'ppf3',
              'ninja1', 'ninja2', 'gdiff', 'bsdiff', 'xdelta1', 'xdelta3', 'rfc-vcdiff'],
  },
  '520MiB': {
    base: 'test/data/sotn/base-track1.bin',
    pairMakerPatch: 'test/data/sotn/eng-translation.ppf',
    ninjaRomType: 'raw',
    timedRuns: 2,
    createPatienceSeconds: 60,
    formats: ['ips32', 'ups', 'bps', 'ppf3', 'ninja2', 'gdiff', 'bsdiff', 'xdelta1', 'xdelta3', 'rfc-vcdiff'],
  },
};

/* ----------------------------------------------------------------------- helpers ---- */

// stderr stays wide: a tool that is still printing when the patience budget ends (ninja1 prints a line per record) must fail by that clock,
// not by filling a 1MiB stderr cap into a confusing error
const shellQuiet = (command, patienceSeconds) => execSync(command, {
  cwd: repoRoot, stdio: ['ignore', 'ignore', 'pipe'], maxBuffer: 256 * 1024 * 1024,
  timeout: patienceSeconds === undefined ? undefined : patienceSeconds * 1000, killSignal: 'SIGKILL',
});
const sha256Of = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

// The -i tolerates a candidate whose success is a nonzero exit — proveThenTime has already judged the output itself.
const medianSeconds = (command, { prepare, runs, reportPath }) => {
  const prepareFlag = prepare ? `--prepare '${prepare}'` : '';
  shellQuiet(`${hyperfineBinary} --warmup 1 --runs ${runs} ${prepareFlag} -i --export-json ${reportPath} '${command}'`);
  return JSON.parse(readFileSync(reportPath)).results[0].median;
};

const slapCreateCommand = (formatToken, extraFlags) => (base, modified, patch) =>
  `${slapBinary} create --format ${formatToken} ${extraFlags ? `${extraFlags} ` : ''}${base} ${modified} ${patch} -f`;
const slapApplyCommand = (patch, base, output) => `${slapBinary} apply ${patch} ${base} -o ${output} -f`;

// Runs a candidate once for its answer: a faithful answer earns a timing (Timed), anything else earns its words a row (Balked).
// The patience budget keeps one slow run from stalling the whole tier.
const proveThenTime = ({ command, prepare, output, expectedDigest, runs, reportPath, patienceSeconds }) => {
  rmSync(output, { force: true });   // a leftover from the previous candidate must not answer for this one
  // the candidate is exec'd so the patience SIGKILL lands on the tool itself:
  // killing only a wrapper shell would leave the tool running, contending with the next timing
  try {
    if (prepare) shellQuiet(prepare);
    shellQuiet(`exec ${command}`, patienceSeconds);
  }
  catch (commandFailure) {
    if (commandFailure.signal === 'SIGKILL') return { tag: 'Balked', words: `gave up after ${patienceSeconds}s` };
    // a nonzero exit can be a tool's way of saying yes (xdelta1 exits 1 for "the files differ"),
    // so a failure that still wrote its output falls through to be judged on the bytes
    const lastWords = commandFailure.stderr?.toString().trim().split('\n').at(-1) ?? String(commandFailure);
    if (!existsSync(output)) return { tag: 'Balked', words: lastWords };
  }
  if (!existsSync(output)) return { tag: 'Balked', words: 'produced nothing' };
  if (expectedDigest && sha256Of(output) !== expectedDigest) return { tag: 'Balked', words: 'output differs from the pair' };
  return { tag: 'Timed', seconds: medianSeconds(command, { prepare, runs, reportPath }) };
};

/* ---------------------------------------------------------------------- the run ----- */

const spellSeconds = (seconds) => seconds >= 1 ? `${seconds.toFixed(2)}s` : `${(seconds * 1000).toFixed(0)}ms`;
const spellBytes = (bytes) => bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)}MiB`
                            : bytes >= 1024 ? `${(bytes / 1024).toFixed(0)}KiB` : `${bytes}B`;
const spellOutcome = (outcome) => outcome.tag === 'Timed' ? spellSeconds(outcome.seconds) : `✗ ${outcome.words}`;

const creatorsFor = (formatToken, tier) => {
  const contenders = contendersByFormat[formatToken];
  return {
    slap: slapCreateCommand(formatToken),
    ...Object.fromEntries(Object.entries(contenders.slapAlternates ?? {})
      .map(([alternateName, extraFlags]) => [alternateName, slapCreateCommand(formatToken, extraFlags)])),
    ...contenders.creators,
    ...Object.fromEntries(Object.entries(contenders.creatorsByTier ?? {})
      .map(([creatorName, bindToTier]) => [creatorName, bindToTier(tier)])),
  };
};

const runTier = (tierName) => {
  const tier = { ...patienceDefaults, ...tiers[tierName] };
  const workRoot = `${repoRoot}bench/work/${tierName}/`;
  mkdirSync(workRoot, { recursive: true });
  mkdirSync(`${repoRoot}bench/results/`, { recursive: true });
  const reportPath = `${workRoot}hyperfine.json`;

  const base = `${repoRoot}${tier.base}`;
  const modified = `${workRoot}modified.bin`;
  if (!existsSync(modified)) {
    console.log(`making the ${tierName} pair: ${tier.pairMakerPatch} onto ${tier.base}`);
    shellQuiet(slapApplyCommand(`${repoRoot}${tier.pairMakerPatch}`, base, modified));
  }
  const modifiedDigest = sha256Of(modified);

  const rows = [];
  for (const formatToken of tier.formats) {
    console.log(`  ${formatToken}`);
    const contenders = contendersByFormat[formatToken];

    for (const [creatorName, buildCreateCommand] of Object.entries(creatorsFor(formatToken, tier))) {
      const patch = `${workRoot}${formatToken}.${creatorName}`;
      const creation = proveThenTime({
        command: buildCreateCommand(base, modified, patch),
        output: patch, runs: tier.timedRuns, reportPath, patienceSeconds: tier.createPatienceSeconds,
      });
      const row = { format: formatToken, creator: creatorName, creation, appliers: {} };
      rows.push(row);
      if (creation.tag !== 'Timed') continue;
      row.patchBytes = statSync(patch).size;

      const appliers = { slap: slapApplyCommand, ...contenders.appliers };
      for (const [applierName, buildApplyCommand] of Object.entries(appliers)) {
        const output = `${workRoot}applied.bin`;
        row.appliers[applierName] = proveThenTime({
          command: buildApplyCommand(patch, base, output),
          output, expectedDigest: modifiedDigest, runs: tier.timedRuns, reportPath, patienceSeconds: tier.applyPatienceSeconds,
        });
      }
      for (const [applierName, buildApplyInPlace] of Object.entries(contenders.appliersInPlace ?? {})) {
        const inPlace = buildApplyInPlace(patch, base, `${workRoot}in-place.bin`);
        row.appliers[applierName] = proveThenTime({
          ...inPlace, expectedDigest: modifiedDigest, runs: tier.timedRuns, reportPath, patienceSeconds: tier.applyPatienceSeconds,
        });
      }
    }
  }
  writeResults(tierName, tier, rows);
};

// One table per format, so each table carries only the appliers that format actually has.
const writeResults = (tierName, tier, rows) => {
  const formatTable = (formatRows) => {
    const applierNames = [...new Set(formatRows.flatMap((row) => Object.keys(row.appliers)))];
    const cellsOf = (row) => [
      row.creator, spellOutcome(row.creation),
      row.patchBytes === undefined ? '' : spellBytes(row.patchBytes),
      ...applierNames.map((applierName) =>
        row.appliers[applierName] === undefined ? '' : spellOutcome(row.appliers[applierName])),
    ];
    return [
      `| creator | create | patch | ${applierNames.map((name) => `apply: ${name}`).join(' | ')} |`,
      `|---|---|---|${applierNames.map(() => '---').join('|')}|`,
      ...formatRows.map((row) => `| ${cellsOf(row).join(' | ')} |`),
    ];
  };
  const formatTokens = [...new Set(rows.map((row) => row.format))];
  const lines = [
    `# ${tierName} — ${tier.base} + ${tier.pairMakerPatch}`,
    '',
    `Each creator bottles the same pair, then everyone who can applies each bottle.`,
    `Medians of ${tier.timedRuns} timed runs, warm cache. A ✗ names what happened instead of a number.`,
    ...formatTokens.flatMap((formatToken) => ['', `## ${formatToken}`,
      ...formatTable(rows.filter((row) => row.format === formatToken))]),
  ];
  writeFileSync(`${repoRoot}bench/results/${tierName}.md`, lines.join('\n') + '\n');
  writeFileSync(`${repoRoot}bench/results/${tierName}.json`, JSON.stringify(rows, null, 2) + '\n');
  console.log(`results: bench/results/${tierName}.md`);
};

// the summarizers import the tier table, and an import must never start a bench
const runningAsTheScript = process.argv[1] === fileURLToPath(import.meta.url);
if (runningAsTheScript) {
  const requestedTiers = process.argv.slice(2);
  if (requestedTiers.length === 0) {
    console.log(`tiers: ${Object.keys(tiers).join(', ')}\nusage: node bench/bench.mjs TIER [TIER...]`);
  } else {
    for (const tierName of requestedTiers) {
      if (!tiers[tierName]) throw new Error(`no tier named ${tierName} — have: ${Object.keys(tiers).join(', ')}`);
      runTier(tierName);
    }
  }
}
