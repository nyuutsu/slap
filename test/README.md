# Testing

I should describe testing here. I will do this later.

## Lineage

The test suite has four classifications:

* Real: a real-world patch from some actual project
* Converted: a "real" patch repackaged into a different patch format
* Synthetic: the patch target was fabricated (e.g. via PRNG XOR).
* Broken: a known-broken patch, skipped by the runner. Unused at time of writing.

We now have some patches that I feel do not cleanly fit into any of the above categories. The distinguishing property they have, is that the following procedure was used to create them:

1. Prepare an input rom and output rom somehow[^somehow]

2. Use slap to create a patch

3. Use some well-regarded tool to make a patch in the same format with same input

4. Use slap to apply each patch; record hashes

5. Use the external tool to apply each patch; record hashes

6. If all hashes agree then we can be fairly confident that the patch is *probably correct*

This is sort of a different axis of "how confident are we about this patch?" vs what lineage is tracking.

## Suite format

*Paths are relative to the slap repo root.*

Test scenarios are in `test/suites/*.suite`. Each names an input rom, the expected SHA1 of the output rom, and one or more patches that should produce the output. The test runner discovers suite files automatically and skips any whose input rom is missing.

An example of the `.suite` format is provided. The `.suite` format documentation is in `test/suites/README.MD` 

*This patch is actually mine! It's a working copy of the "[DM4 Translation](https://nyuu.page/projects/dm4-translation/)" project.*

```
base:   test/data/dm4y/base.gbc
sha1:   10f5981bca3660127d308778b60a343e2e44dec7
desc:   dm4y translation (4 MB GBC, 14 formats)

BPS      | test/data/dm4y/patch.bps       | real      | dm4-hacking translation project
IPS      | test/data/dm4y/patch.ips       | converted | Flips
IPS32    | test/data/dm4y/patch.ips32     | converted | sips
UPS      | test/data/dm4y/patch.ups       | converted | Go ups
PPF3     | test/data/dm4y/patch.ppf       | converted | MakePPF3
PPF1     | test/data/dm4y/patch.ppf1.ppf  | converted | RomPatcher.js
PPF2     | test/data/dm4y/patch.ppf2.ppf  | converted | RomPatcher.js
EBP      | test/data/dm4y/patch.ebp       | converted | RomPatcher.js
APS-N64  | test/data/dm4y/patch.aps       | converted | RomPatcher.js
NINJA2   | test/data/dm4y/patch.rup       | converted | RomPatcher.js
VCDIFF   | test/data/dm4y/patch.vcdiff    | converted | xdelta3 -S none
bsdiff   | test/data/dm4y/patch.bsdiff    | converted | bsdiff
xdelta1  | test/data/dm4y/patch.xdelta1   | converted | xdelta 1.1.4
GDIFF    | test/data/dm4y/patch.gdiff     | converted | javaxdelta
```

The fourth column names the tool or project that produced the patch.

VCDIFF suite coverage is paused while the format is being reimplemented; its rows return when the rewrite lands.

# Footnotes

[^somehow]: dm4y's output state is a development build of my dm4 translation hack. Stadium 2's output state (which probably is not bootable; I haven't checked) is just the base game with some swaps, copies, transforms, etc done in a mostly clustered way.