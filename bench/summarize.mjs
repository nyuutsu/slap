// Builds bench/results/summary.html from the tier jsons: per-format grids across the tiers, reading notes, and the full tables.
// Every number on the page is read from the json at build time.
//
//   node bench/summarize.mjs

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tiers } from './bench.mjs';
import { comparisonClass, escapeHtml, measurementStamp, pageAround, spellBytes, spellSeconds } from './page-skin.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));

// result jsons written before the tagged outcome shape are still readable, so both vocabularies decode
const asOutcome = (recorded) => recorded.tag ? recorded
  : recorded.standing === 'ok' ? { tag: 'Timed', seconds: recorded.seconds }
  : { tag: 'Balked', words: recorded.standing };

const tierNames = Object.keys(tiers);
const rowsByTier = Object.fromEntries(tierNames.map((tierName) =>
  [tierName, JSON.parse(readFileSync(`${repoRoot}bench/results/${tierName}.json`))]));

// each format's reference creator, and the slap row that matches the reference's own mode
const referenceOf = { ips: 'flips', ips32: 'sips', ups: 'goUps', bps: 'flips', ppf3: 'makeppf3',
                      ninja1: 'ninjaPhp', ninja2: 'ninja2Php', gdiff: 'javaxdelta',
                      bsdiff: 'bsdiff', xdelta1: 'xdelta1', xdelta3: 'xdelta3' };
const slapRowNameOf = (formatToken) => formatToken === 'ppf3' ? 'slap-no-undo' : 'slap';
const rivaledFormats = Object.keys(referenceOf);

const rowsFor = (tierName, formatToken) => {
  const formatRows = rowsByTier[tierName].filter((row) => row.format === formatToken);
  return {
    slapRow: formatRows.find((row) => row.creator === slapRowNameOf(formatToken)),
    referenceRow: formatRows.find((row) => row.creator === referenceOf[formatToken]),
  };
};

const measuredCreate = (tierName, formatToken) => {
  const { slapRow, referenceRow } = rowsFor(tierName, formatToken);
  const slapCreation = slapRow && asOutcome(slapRow.creation);
  const referenceCreation = referenceRow && asOutcome(referenceRow.creation);
  return {
    slapSeconds: slapCreation?.tag === 'Timed' ? slapCreation.seconds : null,
    referenceSeconds: referenceCreation?.tag === 'Timed' ? referenceCreation.seconds : null,
    referenceWords: referenceCreation?.tag === 'Balked' ? referenceCreation.words : null,
    slapPatchBytes: slapRow?.patchBytes ?? null,
    referencePatchBytes: referenceRow?.patchBytes ?? null,
  };
};

const readingNotes = `
<div class="card">
  <h2>Reading notes</h2>
  <ul class="notes">
    <li>Every timed command's output was checked byte-for-byte against the pair first;
        an unfaithful answer gets its words in the cell instead of a number.</li>
    <li>ninja1's reference applier does not finish at any size, and its 64MiB creation does not rebuild the pair.</li>
    <li>In-place appliers (applyppf3, the ninjas) patch a copy made off the clock.</li>
    <li>javaxdelta's timings include JVM startup — a fixed cost that matters at 4MiB and not at 520MiB.</li>
    <li>PPF1 and PPF2's reference tools are DOS programs; timing them would time an emulator,
        so those formats appear only in the tier tables.</li>
    <li>ebp, ppf1, ppf2, aps-n64, aps-gba, and dps have no scriptable reference tool at all;
        their numbers stand alone in the tables below.</li>
    <li>ppf3 is compared in the reference's own mode (undo data omitted on both sides).</li>
  </ul>
</div>`;

/* ------------------------------------------------------------------- the grids ---- */

const pairCell = (slapWords, rivalWords, tint) =>
  `<td class="pair ${tint}"><span class="slap-value">${slapWords}</span><span class="rival-value">${rivalWords}</span></td>`;
const absentCell = '<td class="absent">·</td>';

const createCell = (tierName, formatToken) => {
  const measured = measuredCreate(tierName, formatToken);
  if (measured.slapSeconds === null || (!measured.referenceSeconds && !measured.referenceWords)) return absentCell;
  if (measured.referenceWords !== null)
    return pairCell(spellSeconds(measured.slapSeconds), escapeHtml(measured.referenceWords), 'ahead');
  return pairCell(spellSeconds(measured.slapSeconds), spellSeconds(measured.referenceSeconds),
                  comparisonClass(measured.slapSeconds, measured.referenceSeconds));
};

const sizeCell = (tierName, formatToken) => {
  const measured = measuredCreate(tierName, formatToken);
  if (!measured.slapPatchBytes || !measured.referencePatchBytes) return absentCell;
  return pairCell(spellBytes(measured.slapPatchBytes), spellBytes(measured.referencePatchBytes),
                  comparisonClass(measured.slapPatchBytes, measured.referencePatchBytes));
};

// slap's applier against the fastest rival applier, both applying slap's own patch
const applyCell = (tierName, formatToken) => {
  const { slapRow } = rowsFor(tierName, formatToken);
  if (!slapRow) return absentCell;
  const slapApply = slapRow.appliers.slap && asOutcome(slapRow.appliers.slap);
  const rivalApplies = Object.entries(slapRow.appliers)
    .filter(([applierName]) => applierName !== 'slap')
    .map(([applierName, outcome]) => [applierName, asOutcome(outcome)])
    .filter(([, outcome]) => outcome.tag === 'Timed');
  if (slapApply?.tag !== 'Timed' || rivalApplies.length === 0) return absentCell;
  const [rivalName, rivalApply] = rivalApplies.reduce((fastest, candidate) =>
    candidate[1].seconds < fastest[1].seconds ? candidate : fastest);
  return pairCell(spellSeconds(slapApply.seconds), `${rivalName} ${spellSeconds(rivalApply.seconds)}`,
                  comparisonClass(slapApply.seconds, rivalApply.seconds));
};

const comparisonGrid = (cellOf) => `<table>
<thead><tr><th>format · reference</th>${tierNames.map((tierName) => `<th>${tierName}</th>`).join('')}</tr></thead>
<tbody>${rivaledFormats.map((formatToken) =>
  `<tr><td>${formatToken} · ${referenceOf[formatToken]}</td>${tierNames.map((tierName) => cellOf(tierName, formatToken)).join('')}</tr>`
).join('\n')}</tbody></table>`;

const sizeTextureSection = `
<div class="card table-scroll">
  <h2>Across the sizes</h2>
  <p style="font-size:.94rem;">Each cell holds both measurements, slap's on top. Green means slap ahead,
     amber behind, plain a gap under ten percent — which these medians cannot tell from noise.
     A dot means that pairing was not benched at that size.</p>
  <h3>Create time</h3>
  ${comparisonGrid(createCell)}
  <h3>Patch size</h3>
  ${comparisonGrid(sizeCell)}
  <h3>Apply time, slap's patch, fastest rival applier</h3>
  ${comparisonGrid(applyCell)}
</div>`;

/* ------------------------------------------------------------- the full tables ---- */

const outcomeCell = (outcome) => outcome === undefined ? '<td></td>'
  : asOutcome(outcome).tag === 'Timed' ? `<td class="number">${spellSeconds(asOutcome(outcome).seconds)}</td>`
  : `<td class="balked">✗ ${escapeHtml(asOutcome(outcome).words)}</td>`;

const tierDetails = tierNames.map((tierName) => {
  const rows = rowsByTier[tierName];
  const formatTokens = [...new Set(rows.map((row) => row.format))];
  const formatSection = (formatToken) => {
    const formatRows = rows.filter((row) => row.format === formatToken);
    const applierNames = [...new Set(formatRows.flatMap((row) => Object.keys(row.appliers)))];
    const bodyRows = formatRows.map((row) => {
      const patchCell = row.patchBytes === undefined ? '<td></td>' : `<td class="number">${spellBytes(row.patchBytes)}</td>`;
      return `<tr><td>${row.creator}</td>${outcomeCell(row.creation)}${patchCell}`
        + applierNames.map((name) => outcomeCell(row.appliers[name])).join('') + '</tr>';
    }).join('\n');
    return `<h4>${formatToken}</h4>
<table><thead><tr><th>creator</th><th>create</th><th>patch</th>${applierNames.map((name) => `<th>apply: ${name}</th>`).join('')}</tr></thead>
<tbody>${bodyRows}</tbody></table>`;
  };
  return `<details><summary><strong>${tierName}</strong> — ${tiers[tierName].base} + ${tiers[tierName].pairMakerPatch}
  (medians of ${tiers[tierName].timedRuns})</summary>
${formatTokens.map(formatSection).join('\n')}
</details>`;
}).join('\n');

/* ------------------------------------------------------------------- the page ----- */

const body = `
<header>
  <h1>slap bench — the CLI lanes</h1>
  <p>Four before/after pairs, 4MiB to 520MiB. Every format slap writes is bottled and applied by slap
     and by each format's reference tool where one can be driven from a shell; every output is checked
     byte-for-byte against the pair before its time counts.</p>
  <p class="stamp">${measurementStamp()}</p>
</header>
${sizeTextureSection}
${readingNotes}
<section>
  <h2 style="margin-bottom:.6rem;">The full tables</h2>
  ${tierDetails}
</section>`;

writeFileSync(`${repoRoot}bench/results/summary.html`, pageAround('slap bench — the CLI lanes', body));
console.log('built bench/results/summary.html');
