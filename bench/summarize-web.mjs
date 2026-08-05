// Builds bench/results/summary-web.html from web.json: web slap against RomPatcher.js, warm, across the browser-plausible pairs.
// Every number is read from the json at build time.
//
//   node bench/summarize-web.mjs

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { comparisonClass, escapeHtml, measurementStamp, pageAround, spellBytes, spellMs } from './page-skin.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const { patienceSeconds, rows } = JSON.parse(readFileSync(`${repoRoot}bench/results/web.json`));

const tierNames = ['4MiB', '8MiB', '16MiB', '64MiB'].filter((tierName) => rows.some((row) => row.tier === tierName));
const laneNames = [...new Set(rows.map((row) => row.lane))];
const rowOf = (tierName, laneName) => rows.find((row) => row.tier === tierName && row.lane === laneName);

const readingNotes = `
<div class="card">
  <h2>Reading notes</h2>
  <ul class="notes">
    <li>Each cell runs warm in its own child process — booted once, only the calls timed — and the
        driver kills any cell still working at ${patienceSeconds}s, which then says so in its cell.</li>
    <li>Settings are matched: ppf is created without undo data on both sides, and aps as APS-N64
        on both, that being what rpjs's aps token writes.</li>
    <li>rpjs's bps create searches (its delta mode) only for files of 4MiB and under — a 4194304-byte
        threshold in its source. Larger files take its linear pass: far quicker, and the patch grows
        accordingly, which is the whole 64MiB bps row.</li>
    <li>rup is NINJA2, and needed no matching — undo lives in the XOR itself, so both tools
        write the same shape.</li>
    <li>ips and ebp track each other because ebp is IPS with metadata; the encoders are shared on both sides.</li>
    <li>A dot means that pairing was not benched at that size — ips and ebp take the fe6 pair
        instead of the 64MiB one, which their format cannot address.</li>
    <li>The CLI lanes, with reference tools per format and tiers up to 520MiB, live in summary.html
        beside this page.</li>
  </ul>
</div>`;

/* --------------------------------------------------------------------- the tables ---- */

const sideCells = (webSlapOutcome, rpjsOutcome, valueOf, spell) => {
  if (webSlapOutcome === null && rpjsOutcome === null) return '<td class="absent">·</td><td class="absent">·</td>';
  const webSlapTimed = webSlapOutcome?.tag === 'Timed', rpjsTimed = rpjsOutcome?.tag === 'Timed';
  if (!webSlapTimed || !rpjsTimed) {
    // a lone survivor is ahead; two refusals are two facts side by side, tinted at neither
    const tintFor = (ownTimed, otherTimed) => ownTimed && !otherTimed ? 'ahead' : !ownTimed && otherTimed ? 'behind' : '';
    const spoken = (outcome, timed) => timed ? spell(valueOf(outcome)) : `✗ ${escapeHtml(outcome?.words ?? '')}`;
    return `<td class="number ${tintFor(webSlapTimed, rpjsTimed)}">${spoken(webSlapOutcome, webSlapTimed)}</td>`
         + `<td class="number ${tintFor(rpjsTimed, webSlapTimed)}">${spoken(rpjsOutcome, rpjsTimed)}</td>`;
  }
  const tint = comparisonClass(valueOf(webSlapOutcome), valueOf(rpjsOutcome));
  const oppositeOf = { ahead: 'behind', behind: 'ahead', '': '' };
  return `<td class="number ${tint}">${spell(valueOf(webSlapOutcome))}</td>`
       + `<td class="number ${oppositeOf[tint]}">${spell(valueOf(rpjsOutcome))}</td>`;
};

const comparisonTableOf = (cellsOf) => `<table>
  <thead><tr><th>format</th>${tierNames.map((tierName) =>
    `<th>web slap · ${tierName}</th><th>rpjs · ${tierName}</th>`).join('')}</tr></thead>
  <tbody>
${laneNames.map((laneName) => `<tr><td>${laneName}</td>${tierNames.map((tierName) => {
    const row = rowOf(tierName, laneName);
    return row ? cellsOf(row) : '<td class="absent">·</td><td class="absent">·</td>';
  }).join('')}</tr>`).join('\n')}
  </tbody>
</table>`;

const comparisonTables = `
<div class="card table-scroll">
  <h2>The measurements</h2>
  <p style="font-size:.92rem; margin-bottom:.6rem;">Green marks the side that is ahead, amber the side
     behind, plain a gap under ten percent — too close to call at this measurement's noise.</p>
  <h3>Applying the same slap-made patch</h3>
  ${comparisonTableOf((row) => sideCells(row.webSlapApply, row.rpjsApply, (outcome) => outcome.ms, spellMs))}
  <h3>Creating a patch from the pair</h3>
  ${comparisonTableOf((row) => sideCells(row.webSlapCreate, row.rpjsCreate, (outcome) => outcome.ms, spellMs))}
  <h3>The patch each create wrote — judged by rebuilding the pair</h3>
  ${comparisonTableOf((row) => sideCells(row.webSlapCreate, row.rpjsCreate, (outcome) => outcome.patchBytes, spellBytes))}
</div>`;

/* ----------------------------------------------------------------------- the page ---- */

const body = `
<header>
  <h1>slap bench — the web lane</h1>
  <p>Web slap against RomPatcher.js on browser-plausible pairs —
     a 4MiB handheld rom, a 64MiB N64 one, and for ips and ebp an 8MiB pair, their format being unable to address 64MiB.
     Both sides run warm, the way a visitor meets them: the page is long booted and the files are already in memory,
     so a timed call is only the patching work.</p>
  <p class="stamp">${measurementStamp()}</p>
</header>
${comparisonTables}
${readingNotes}`;

writeFileSync(`${repoRoot}bench/results/summary-web.html`, pageAround('slap bench — the web lane', body));
console.log('built bench/results/summary-web.html');
