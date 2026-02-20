# slap TODO

## Features

- [x] **`convert` command** — Convert between patch formats
  - Overlay→overlay direct conversion (no ROM needed) for all overlay formats (IPS, IPS32, EBP, PPF1/2/3, APS-N64, NINJA1, PMSR)
  - Re-delta conversion (`slap convert patch.bps --to ups --with base.rom`) for formats that use different delta algorithms (BPS, UPS, bsdiff, VCDIFF, xdelta1)
  - Clear error message when user tries naked conversion on a format that requires the base ROM — explain *why* it's impossible

- [x] **Man page** — `slap.1`

## New Formats

- [x] BDF (Binary Delta Format) — shares `BSDIFF40` magic with bsdiff; same binary format, no separate module needed. Detected and applied as BSDiff
- [x] PMSR (Paper Mario Star Rod) — simple offset+data format. Parse, apply, create, info, explain. Yay0-compressed .mod files transparently decompressed
- [ ] Git binary diff (`git diff --binary` output)
- [ ] Unified diff / GNU patch format
- [ ] HDiffPatch — https://github.com/sisong/HDiffPatch
- [ ] librsync / rdiff — low priority, questionable scope (VCS/sync tool)
- [ ] JojoDiff — https://jojodiff.sourceforge.net/ — low priority, questionable scope
- [ ] detools — low priority, questionable scope (embedded/OTA update tool)

## Test Data Gaps

- [x] IPS32 patch — created with sips (leoetlino), verified with slap
- [x] GDIFF patch — created with javaxdelta, verified round-trip
- [x] APS GBA patch — FFTA ROM + FFTA_X patch provided, CRC32s verified
- [x] PPF4 round-trip verification — Suikoden 1 disc image provided (USA + Rev 1)
- [x] BDF test data — Tetris ROM + Rosy Retrospection patch provided, CRC32s verified
- [x] APS N64 type=1 (N64-specific) — Banjo-Tooie Dextrose (1786 recs) + Paper Mario deblur (31 recs)
- [x] PPF4 test suite — Suikoden 1 disc image + Pyriel bribe.ppf (19 records, first real-world PPF4 validation)
- [x] IPS stress test — FE6 english translation (7639 records, 572 KB, offsets to 0x1000000)
- [ ] xdelta3 real-world test — large VCDIFF patch (e.g., Pokemon Unbound)
- [x] PMSR real-world test — Yay0-compressed .mod files from Star Rod parse successfully (14521 and 6256 records)
