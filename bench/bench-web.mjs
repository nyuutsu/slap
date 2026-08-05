// The web lane: web slap against RomPatcher.js on the pairs a browser plausibly meets.
// Every cell runs warm inside its own child process (web-lane-cell.mjs), booted once and timing only its calls;
// because the driver owns the process, a cell that cannot answer inside the patience budget is killed and says so, the same contract as the CLI rig.
//
//   node bench/bench-web.mjs        (results land in bench/results/web.md)

import { execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tiers } from './bench.mjs';
import { spellMs } from './page-skin.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const cellScript = `${repoRoot}bench/web-lane-cell.mjs`;
const patienceSeconds = 300;

// most formats meet the browser at 4MiB and 64MiB; ips and ebp cannot address 64MiB, so they take the fe6 pair instead
const defaultTierNames = ['4MiB', '64MiB'];
const webOnlyTierBases = { '8MiB': 'test/data/fe6/base.gba' };

// wildPatch is the CLI-made patch both sides are asked to apply.
// ppf matches rpjs's undoless mode; aps is APS-N64 (what rpjs's aps token writes),
// applying whichever aps patch the tier's CLI run left behind.
const lanes = [
  { name: 'ips', rpjsToken: 'ips', webSlapFormat: { tag: 'CreateDirect', contents: 'CreateIPS' }, wildPatch: 'ips.slap',
    tierNames: ['4MiB', '8MiB'] },
  { name: 'ups', rpjsToken: 'ups', webSlapFormat: { tag: 'CreateDifferential', contents: 'CreateUPS' }, wildPatch: 'ups.slap' },
  { name: 'bps', rpjsToken: 'bps', webSlapFormat: { tag: 'CreateDifferential', contents: 'CreateBPS' }, wildPatch: 'bps.slap' },
  { name: 'ppf', rpjsToken: 'ppf', webSlapFormat: { tag: 'CreateDirect', contents: 'CreatePPF3' },
    webSlapMetadata: { requestedUndoInclusion: 'OmitUndoData' }, wildPatch: 'ppf3.slap' },
  { name: 'ebp', rpjsToken: 'ebp', webSlapFormat: { tag: 'CreateDirect', contents: 'CreateEBP' }, wildPatch: 'ebp.slap',
    tierNames: ['4MiB', '8MiB'] },
  { name: 'aps', rpjsToken: 'aps', webSlapFormat: { tag: 'CreateDirect', contents: 'CreateAPSN64' },
    wildPatch: 'aps-gba.slap', wildPatchElsewhere: 'aps-n64.slap' },
  { name: 'rup', rpjsToken: 'rup', webSlapFormat: { tag: 'CreateDifferential', contents: 'CreateNINJA2' }, wildPatch: 'ninja2.slap' },
];

// The exec is what lets the SIGKILL land on node itself rather than an orphaned wrapper shell.
const runCell = (side, verb, tierName, lane) => {
  try {
    const spoken = execSync(`exec node ${cellScript} ${side} ${verb} ${tierName} '${JSON.stringify(lane)}'`, {
      cwd: repoRoot, stdio: ['ignore', 'pipe', 'pipe'],
      timeout: patienceSeconds * 1000, killSignal: 'SIGKILL',
    });
    return JSON.parse(spoken.toString());
  } catch (cellFailure) {
    if (cellFailure.signal === 'SIGKILL') return { tag: 'Balked', words: `gave up after ${patienceSeconds}s` };
    const lastWords = cellFailure.stderr?.toString().trim().split('\n').at(-1);
    return { tag: 'Balked', words: lastWords || 'the cell fell over' };
  }
};

// naming lanes on the command line reruns only those, their fresh rows replacing the ones on file
const requestedLaneNames = process.argv.slice(2);
const selectedLanes = requestedLaneNames.length === 0 ? lanes
  : lanes.filter((lane) => requestedLaneNames.includes(lane.name));
const keptRows = requestedLaneNames.length === 0 ? []
  : JSON.parse(readFileSync(`${repoRoot}bench/results/web.json`)).rows
      .filter((row) => !requestedLaneNames.includes(row.lane));

const rows = [];
for (const lane of selectedLanes) {
  for (const tierName of lane.tierNames ?? defaultTierNames) {
    console.log(`  ${tierName} ${lane.name}`);
    const wildPatch = [lane.wildPatch, lane.wildPatchElsewhere]
      .find((candidate) => candidate && existsSync(`${repoRoot}bench/work/${tierName}/${candidate}`));
    const laneHere = { ...lane, wildPatch, basePath: tiers[tierName]?.base ?? webOnlyTierBases[tierName] };
    rows.push({
      tier: tierName, lane: lane.name,
      webSlapApply: wildPatch ? runCell('web-slap', 'apply', tierName, laneHere) : null,
      rpjsApply: wildPatch ? runCell('rpjs', 'apply', tierName, laneHere) : null,
      webSlapCreate: runCell('web-slap', 'create', tierName, laneHere),
      rpjsCreate: runCell('rpjs', 'create', tierName, laneHere),
    });
  }
}

/* --------------------------------------------------------------------------- results ---- */

const spellOutcome = (outcome) => outcome === null ? '' : outcome.tag === 'Timed' ? spellMs(outcome.ms) : `✗ ${outcome.words}`;
const spellPatch = (outcome) => outcome?.tag === 'Timed' ? `${(outcome.patchBytes / 1024).toFixed(0)}KiB` : '';
const tierOrder = ['4MiB', '8MiB', '16MiB', '64MiB'];
const laneOrder = lanes.map((lane) => lane.name);
const allRows = [...keptRows, ...rows].sort((left, right) =>
  tierOrder.indexOf(left.tier) - tierOrder.indexOf(right.tier)
  || laneOrder.indexOf(left.lane) - laneOrder.indexOf(right.lane));

const lines = [
  `# web lane — web slap vs RomPatcher.js, warm, per-cell patience of ${patienceSeconds}s`,
  '',
  'Each cell is its own child process: booted once, calls timed warm, killed at the budget.',
  'Applies are of the same CLI-made slap patch; each create is judged by rebuilding the pair with its own patch.',
  '',
  '| tier | format | apply: web slap | apply: rpjs | create: web slap | create: rpjs | patch: web slap | patch: rpjs |',
  '|---|---|---|---|---|---|---|---|',
  ...allRows.map((row) => `| ${row.tier} | ${row.lane} | ${spellOutcome(row.webSlapApply)} | ${spellOutcome(row.rpjsApply)}`
    + ` | ${spellOutcome(row.webSlapCreate)} | ${spellOutcome(row.rpjsCreate)}`
    + ` | ${spellPatch(row.webSlapCreate)} | ${spellPatch(row.rpjsCreate)} |`),
];
writeFileSync(`${repoRoot}bench/results/web.md`, lines.join('\n') + '\n');
writeFileSync(`${repoRoot}bench/results/web.json`, JSON.stringify({ patienceSeconds, rows: allRows }, null, 2) + '\n');
console.log('results: bench/results/web.md');
