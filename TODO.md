# slap TODO

## Features

- [x] **`convert` command** — Convert between patch formats
  - Direct conversion (no ROM needed) for offset+data formats that share the same representation: IPS ↔ IPS32
  - Re-delta conversion (`slap convert patch.bps --to ups --with base.rom`) for formats that use different delta algorithms (BPS, UPS, bsdiff, VCDIFF, xdelta1)
  - Clear error message when user tries naked conversion on a format that requires the base ROM — explain *why* it's impossible

- [x] **Man page** — `slap.1`

## New Formats

- [x] BDF (Binary Delta Format) — shares `BSDIFF40` magic with bsdiff; same binary format, no separate module needed. Detected and applied as BSDiff
- [x] PMSR (Paper Mario Star Rod) — simple offset+data format. Parse, apply, create, info, explain
- [ ] Git binary diff (`git diff --binary` output)
- [ ] Unified diff / GNU patch format
- [ ] HDiffPatch — https://github.com/sisong/HDiffPatch
- [ ] librsync / rdiff
- [ ] JojoDiff — https://jojodiff.sourceforge.net/
- [ ] Courgette (Chrome update delta format)
- [ ] Zucchini (Courgette successor)
- [ ] Fossil delta
- [ ] detools

## Test Data Gaps

- [x] IPS32 patch — created with sips (leoetlino), verified with slap
- [x] GDIFF patch — created with javaxdelta, verified round-trip
- [x] APS GBA patch — FFTA ROM + FFTA_X patch provided, CRC32s verified
- [x] PPF4 round-trip verification — Suikoden 1 disc image provided (USA + Rev 1)
- [x] BDF test data — Tetris ROM + Rosy Retrospection patch provided, CRC32s verified
- [ ] APS N64 type=1 (N64-specific) — need Everdrive auto-APS patch + matching .z64 ROM (see homework.md)
