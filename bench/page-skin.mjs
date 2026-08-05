// The one skin both summary pages wear: slap-adjacent tokens on a paper ground, cards, tables, and the three-way comparison tint.
// Words always carry the comparison; the tint only echoes it.

import { hostname } from 'node:os';

// Two timings within a tenth of each other are a tie at this rig's noise floor, so the cell stays plain.
export const comparisonClass = (slapValue, rivalValue) => {
  const rivalOverSlap = rivalValue / slapValue;
  return rivalOverSlap >= 1.10 ? 'ahead' : rivalOverSlap <= 1 / 1.10 ? 'behind' : '';
};

export const spellSeconds = (seconds) => seconds >= 1 ? `${seconds.toFixed(2)}s` : `${(seconds * 1000).toFixed(0)}ms`;
export const spellMs = (milliseconds) => milliseconds >= 1000 ? `${(milliseconds / 1000).toFixed(1)}s` : `${milliseconds.toFixed(0)}ms`;
export const spellBytes = (bytes) => bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)}MiB`
                                   : bytes >= 1024 ? `${(bytes / 1024).toFixed(0)}KiB` : `${bytes}B`;
export const escapeHtml = (text) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export const measurementStamp = () => `measured ${new Date().toISOString().slice(0, 10)} on ${hostname()}, warm cache`;

const styleSheet = `
  :root {
    --paper: #FBFBF9; --panel: #FFFFFF; --hairline: #C9CFCA; --ink: #1A211C;
    --ok-ink: #2C4A21; --ok-line: #A8D5A0; --ok-room: #D8ECD3;
    --caution-ink: #6B4715; --caution-line: #EFC98F; --caution-room: #F6E3C4;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--paper); color: var(--ink); font-family: system-ui, sans-serif;
         font-size: 17px; line-height: 1.55; padding: 2.5rem 1.25rem 4rem; }
  main { max-width: 62rem; margin: 0 auto; display: grid; gap: 1.4rem; }
  h1 { font-size: 1.9rem; font-weight: 800; }
  h2 { font-size: 1.25rem; font-weight: 800; margin-bottom: .4rem; }
  h3 { font-size: 1.02rem; font-weight: 700; margin: 1rem 0 .3rem; }
  h4 { font-size: 1rem; font-weight: 700; margin: 1rem 0 .3rem; }
  p  { max-width: 72ch; }
  .stamp { font-size: .88rem; }
  .card { background: var(--panel); border: 1px solid var(--hairline); border-radius: 12px; padding: 1.1rem 1.3rem; }
  table { border-collapse: collapse; width: 100%; background: var(--panel); font-size: .92rem; }
  th, td { border: 1px solid var(--hairline); padding: .32rem .6rem; text-align: left; vertical-align: top; }
  th { font-weight: 700; background: #F1F3F0; }
  td.number { font-family: ui-monospace, monospace; font-variant-numeric: tabular-nums; white-space: nowrap; }
  td.ahead  { background: var(--ok-room); }
  td.behind { background: var(--caution-room); }
  td.balked { color: var(--caution-ink); background: var(--caution-room); font-size: .88rem; }
  td.absent { color: var(--hairline); text-align: center; }
  .pair .slap-value { display: block; font-family: ui-monospace, monospace; font-variant-numeric: tabular-nums; }
  .pair .rival-value { display: block; font-family: ui-monospace, monospace; font-variant-numeric: tabular-nums;
                       font-size: .82rem; opacity: .85; }
  .table-scroll { overflow-x: auto; }
  details { background: var(--panel); border: 1px solid var(--hairline); border-radius: 12px; padding: .8rem 1.3rem; }
  summary { cursor: pointer; font-size: 1.02rem; }
  details table { font-size: .88rem; }
  .notes { font-size: .92rem; }
  .notes li { margin-bottom: .35rem; }
  ul { padding-left: 1.2rem; max-width: 72ch; }
`;

export const pageAround = (title, bodyMarkup) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${styleSheet}</style></head><body><main>
${bodyMarkup}
</main></body></html>
`;
