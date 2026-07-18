// The read verbs' panels. info is a facts glance: PatchInfo's rows, laid out as the engine wrote them.
// explain is structure: the analysis drawn as a heatmap of the rebuilt file — where and how much changed, at a glance —
// with the record walk below for whoever wants to dig. Two renderers over one model; the terminal's dump is the other.

import { html } from './dom.mjs';
import { groupedCount, humanByteSize } from './readouts.mjs';

const hexOffset = (offset) => `0x${offset.toString(16).padStart(6, '0')}`;
const hexByte = (byte) => byte.toString(16).padStart(2, '0');
const base64Bytes = (encoded) => Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));

/* ---------------------------------------------------------------- info ---- */

const readoutRow = (label, value) => html`<div class="readout-row">
  <span class="readout-label">${label}</span><span class="readout-value">${value}</span></div>`;

// A FieldContent's positional parts, named once.
const embeddedFieldParts = (field) => {
  const [wireBase64, reading, substitutionCount] = field.contents;
  return { wireBase64, reading, substitutionCount };
};

// A reading that decoded cleanly counts in characters; one that had to substitute is really
// bytes, and says so — the terminal's own glance (sizeGlance, Slap.Display.EmbeddedContent).
const embeddedFieldGlance = (field) => {
  if (field.tag === 'FieldAbsent') return '(none)';
  if (field.tag === 'FieldEmpty') return '(empty)';
  const { wireBase64, reading, substitutionCount } = embeddedFieldParts(field);
  return substitutionCount === 0
    ? `${groupedCount([...reading.encodedTextContent].length)} characters`
    : `${groupedCount(base64Bytes(wireBase64).length)} bytes`;
};

const countUnitWord = (unit) => unit.toLowerCase();

// infoBytes and summaryBytes are the engine's Maybe: null for formats with no byte total to speak of.
const totalBytesRow = (infoBytes) =>
  infoBytes?.tag === 'TotalOutputBytes' ? readoutRow('output', `${groupedCount(infoBytes.contents)} bytes`)
  : infoBytes?.tag === 'TotalPayloadBytes' ? readoutRow('payload', `${groupedCount(infoBytes.contents)} bytes`)
  : null;

const rangePhrase = (range) =>
  `${hexOffset(range.rangeStart)} – ${hexOffset(range.rangeStart + range.rangeLength - 1)}`;

export const infoReadoutMarkup = (info, formatName) => html`
  <div class="results"><div class="readout">
    ${readoutRow('format', formatName + (info.infoFormat.formatExtra ?? ''))}
    ${info.infoLines.map((line) => readoutRow(line.infoLineLabel, line.infoLineValue))}
    ${info.infoEmbedded.map((embed) => readoutRow(embed.embeddedLabel, embeddedFieldGlance(embed.embeddedField)))}
    ${readoutRow(countUnitWord(info.infoUnit), groupedCount(info.infoTally))}
    ${totalBytesRow(info.infoBytes)}
    ${info.infoRange && readoutRow('range', rangePhrase(info.infoRange))}
  </div></div>`;

export const embeddedContentsOf = (info) =>
  info.infoEmbedded.flatMap((embed, seatIndex) =>
    embed.embeddedField.tag === 'FieldContent'
      ? [{ seatIndex, label: embed.embeddedLabel, ...embeddedFieldParts(embed.embeddedField) }]
      : []);

/* ------------------------------------------------------------- explain ---- */

const payloadCategory = (payload) =>
  payload.tag === 'PayloadWrite' ? 'write'
  : payload.tag === 'PayloadFill' ? 'fill'
  : payload.tag === 'PayloadXOR' ? 'xor'
  : payload.tag === 'PayloadMeta' ? 'meta'
  : payload.contents === 'FromSource' ? 'copy-source'
  : payload.contents === 'FromTarget' ? 'copy-target'
  : 'copy-patch';

const categoryWords = {
  'copy-source': 'kept from the source', 'copy-target': 'copied from earlier output',
  'copy-patch': 'copied from the patch', write: 'new bytes', fill: 'a fill',
  xor: 'an XOR delta', meta: 'metadata',
};

// A region leaves the file as it was only when it copies the source from the very offset it lands on.
// Everything else — writes, fills, XORs, moved copies — changes what's there.
const leavesBytesAsTheyWere = (region) =>
  region.regionPayload.tag === 'PayloadCopy' && region.regionPayload.contents === 'FromSource'
  && region.regionAnnotation.annotationDetails.some(
       (detail) => detail.tag === 'DetailSource' && detail.contents === region.regionOffset);

// The heatmap's model: the file divided into equal buckets, each holding how many of its bytes the patch changes.
// Bucketing is a display choice, not a fact: 54,000 alternating regions would be unreadable drawn one by one,
// and "where and how much" is the question.
export const heatModel = (regions, summary) => {
  const regionEnd = (region) => region.regionOffset + region.regionSize;
  const domain = summary?.tag === 'Summary' && summary.contents.summaryBytes?.tag === 'TotalOutputBytes'
    ? summary.contents.summaryBytes.contents
    : regions.reduce((furthest, region) => Math.max(furthest, regionEnd(region)), 0);
  if (domain <= 0) return null;

  const bucketCount = Math.min(240, domain);
  const bucketSpan = domain / bucketCount;
  const changed = new Float64Array(bucketCount);
  for (const region of regions) {
    if (region.regionSize === 0 || leavesBytesAsTheyWere(region)) continue;
    const firstBucket = Math.floor(region.regionOffset / bucketSpan);
    const lastBucket = Math.min(bucketCount - 1, Math.floor((regionEnd(region) - 1) / bucketSpan));
    for (let bucket = firstBucket; bucket <= lastBucket; bucket += 1) {
      const overlapStart = Math.max(region.regionOffset, bucket * bucketSpan);
      const overlapEnd = Math.min(regionEnd(region), (bucket + 1) * bucketSpan);
      changed[bucket] += Math.max(0, overlapEnd - overlapStart);
    }
  }
  return { domain, bucketCount, bucketSpan, changed };
};

// Calm sand for untouched stretches; any change at all reads warm, and more reads hotter.
const heatColor = (changedFraction) => {
  if (changedFraction <= 0) return '#EDE4D6';
  const eased = 0.3 + 0.7 * Math.sqrt(Math.min(1, changedFraction));
  const blend = (calm, hot) => Math.round(calm + (hot - calm) * eased);
  return `rgb(${blend(246, 242)}, ${blend(201, 107)}, ${blend(162, 67)})`;
};

export const heatBarMarkup = (model) => html`
  <p class="map-label">how much of the file changes, start to end →</p>
  <div class="heat-map">${[...model.changed].map((changedBytes, bucket) => {
    const span = Math.min(model.bucketSpan, model.domain - bucket * model.bucketSpan);
    return html`<div class="heat-cell" data-bucket="${bucket}"
      style="background:${heatColor(changedBytes / span)}"></div>`;
  })}</div>
  <p class="map-caption" data-role="heat-caption">hover the bar to inspect a stretch</p>
  <div class="heat-legend"><span>untouched</span><span class="heat-scale"></span><span>rewritten</span></div>`;

export const heatCaption = (model, bucket) => {
  const start = Math.floor(bucket * model.bucketSpan);
  const end = Math.min(model.domain, Math.floor((bucket + 1) * model.bucketSpan)) - 1;
  const span = end - start + 1;
  const changedBytes = Math.round(model.changed[bucket]);
  return `${hexOffset(start)} – ${hexOffset(end)} · ${groupedCount(changedBytes)} of ${groupedCount(span)} bytes changed`;
};

/* ------------------------------------------------- the embedded content ---- */

// explain opens what info only glances at: the content itself, decoded under the chosen encoding.
export const embeddedContentMarkup = (info) => info.infoEmbedded
  .filter((embed) => embed.embeddedField.tag === 'FieldContent')
  .map((embed) => html`
    <div class="blob">
      <div class="blob-header">${embed.embeddedLabel} · ${embeddedFieldGlance(embed.embeddedField)}</div>
      <pre>${embeddedFieldParts(embed.embeddedField).reading.encodedTextContent}</pre>
    </div>`);

/* ------------------------------------------------ the structure overview ---- */
/* The overview the terminal's explain derives from these same regions:
   how much the patch touches and how, where it reaches, how the record sizes run. */

const payloadKindNoun = (payload) =>
  payload.tag === 'PayloadWrite' ? 'writes'
  : payload.tag === 'PayloadFill' ? 'fills'
  : payload.tag === 'PayloadCopy' ? 'copies'
  : payload.tag === 'PayloadXOR' ? 'XOR'
  : 'structural';

// The sizes exist only as rendered rows, so the fold reads them back — the terminal's own trick.
const parseSizeLine = (infoLines, label) => {
  const line = infoLines.find((candidate) => candidate.infoLineLabel === label);
  if (!line) return null;
  const digits = line.infoLineValue.match(/^[\d,]+/)?.[0].replaceAll(',', '');
  return digits ? Number(digits) : null;
};

export const structureOverviewMarkup = (regions, infoLines) => {
  if (regions.length === 0) return html`<div class="readout">${readoutRow('range', '(empty patch)')}</div>`;

  const totalModified = regions.reduce((sum, region) => sum + region.regionSize, 0);
  const kindCounts = new Map();
  for (const region of regions) {
    const noun = payloadKindNoun(region.regionPayload);
    kindCounts.set(noun, (kindCounts.get(noun) ?? 0) + 1);
  }
  const breakdown = ['writes', 'fills', 'copies', 'XOR', 'structural']
    .filter((noun) => kindCounts.has(noun))
    .map((noun) => `${groupedCount(kindCounts.get(noun))} ${noun}`).join(', ');

  const firstOffset = regions.reduce((least, region) => Math.min(least, region.regionOffset), Infinity);
  const lastByte = regions.reduce((furthest, region) => Math.max(furthest, region.regionOffset + region.regionSize), 0) - 1;

  const sourceSize = parseSizeLine(infoLines, 'source size');
  const targetSize = parseSizeLine(infoLines, 'target size') ?? parseSizeLine(infoLines, 'new size');
  const sizeChange = sourceSize !== null && targetSize !== null ? targetSize - sourceSize : null;

  const sizes = regions.map((region) => region.regionSize).sort((left, right) => left - right);
  const smallest = sizes[0], largest = sizes[sizes.length - 1];
  const medianSize = sizes[Math.floor(sizes.length / 2)];
  const meanSize = Math.floor(totalModified / sizes.length);
  const sizesGlance = smallest === largest
    ? `${groupedCount(smallest)} B`
    : `${groupedCount(smallest)} – ${groupedCount(largest)} B (median ${groupedCount(medianSize)}, mean ${groupedCount(meanSize)})`;

  return html`<div class="readout">
    ${readoutRow('modified', `${groupedCount(totalModified)} bytes (${breakdown})`)}
    ${readoutRow('range', `${hexOffset(firstOffset)} – ${hexOffset(lastByte)}`)}
    ${sizeChange !== null && readoutRow('size change', `${sizeChange >= 0 ? '+' : ''}${groupedCount(sizeChange)} bytes`)}
    ${readoutRow('record sizes', sizesGlance)}
  </div>`;
};

/* ----------------------------------------------------------- the walk ---- */

// The page's phrasing of each annotation detail — the same facts the terminal's renderer speaks, worn a little differently.
const detailPhrases = {
  DetailRLE: () => '(RLE)',
  DetailUndo: () => '(undo data)',
  DetailDelta: (delta) => `(delta ${delta >= 0 ? '+' : ''}${groupedCount(delta)})`,
  DetailSkip: (skipped) => `(skip ${groupedCount(skipped)})`,
  DetailAdd: (added) => `(add ${groupedCount(added)})`,
  DetailCopy: (copied) => `(copy ${groupedCount(copied)})`,
  DetailSeek: (moved) => `(seek ${moved >= 0 ? '+' : ''}${groupedCount(moved)})`,
  DetailSource: (sourceOffset) => `(source ${hexOffset(sourceOffset)})`,
  DetailSourceIndex: (sourceIndex) => `from source ${sourceIndex}`,
  DetailCRC16: ([sourceCrc, targetCrc]) =>
    `(src CRC16 ${sourceCrc.toString(16).padStart(4, '0')}, tgt CRC16 ${targetCrc.toString(16).padStart(4, '0')})`,
  DetailCursorUnderflow: ([cursorKind, underflow]) =>
    `⚠ ${cursorKind} cursor underflow: ${underflow} (patch invalid here)`,
};

const annotationPhrase = (annotation) =>
  annotation.annotationDetails
    .map((detail) => (detailPhrases[detail.tag] ?? (() => ''))(detail.contents))
    .filter((phrase) => phrase !== '')
    .join('  ');

const payloadGlimpse = (payload) => {
  if (payload.tag === 'PayloadWrite' || payload.tag === 'PayloadXOR') {
    const bytes = base64Bytes(payload.contents);
    const shown = [...bytes.slice(0, 16)].map(hexByte).join(' ');
    return html`<div class="walk-hex">${shown}${bytes.length > 16 ? ' …' : ''}</div>`;
  }
  if (payload.tag === 'PayloadFill') {
    const [fillByte, repeatCount] = payload.contents;
    return html`<div class="walk-hex">${hexByte(fillByte)} × ${groupedCount(repeatCount)}</div>`;
  }
  return null;
};

const walkRow = (region) => html`
  <div class="walk-row">
    <span class="walk-op"><span class="dot ${payloadCategory(region.regionPayload)}"></span>${region.regionLabel.trim()}</span>
    <span class="walk-offset">${hexOffset(region.regionOffset)}</span>
    <span class="walk-size">${humanByteSize(region.regionSize)}</span>
    <span class="walk-detail">${annotationPhrase(region.regionAnnotation)}</span>
  </div>
  ${payloadGlimpse(region.regionPayload)}`;

export const walkLegendMarkup = (regions) => {
  const present = [...new Set(regions.map((region) => payloadCategory(region.regionPayload)))];
  return html`<div class="legend">${present.map((category) => html`
    <span class="legend-entry"><span class="dot ${category}"></span>${categoryWords[category]}</span>`)}</div>`;
};

export const walkMarkup = (regions, rowsShown) => html`
  ${walkLegendMarkup(regions)}
  <div class="walk">${regions.slice(0, rowsShown).map(walkRow)}</div>
  ${regions.length > rowsShown && html`<div class="walk-more">
    <button class="quiet-button" data-action="walk-more">show 2,000 more</button>
    <span class="aside">— ${groupedCount(regions.length - rowsShown)} further records below</span>
  </div>`}`;

/* ------------------------------------------------------------ assembly ---- */

export const analysisRegionsOf = (analysis) =>
  analysis.analysisSections.flatMap((section) => section.tag === 'SectionRegions' ? section.contents : []);

export const analysisAsidesMarkup = (analysis) => analysis.analysisSections.map((section) =>
  section.tag === 'SectionText' ? html`<p class="aside">${section.contents}</p>`
  : section.tag === 'SectionLabeled' ? html`<div class="readout">
      <p class="readout-heading">${section.contents[0]}</p>
      ${section.contents[1].map((line) => readoutRow(line.infoLineLabel, line.infoLineValue))}</div>`
  : null);
