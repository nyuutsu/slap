# slap 👋

## In a nutshell 🌰

`slap` is a [rom](https://en.wikipedia.org/wiki/ROM_image) [patching](https://en.wikipedia.org/wiki/Patch_(computing)#Binary_patching) (🩹) tool. It knows how to work with a lot of patch formats. It probably knows (🎓) more than you'll actually need. Most people just need to apply patches; `slap` does this, and also creates them, converts between formats[^CONVERTS], and lets you look inside them.

On conversion: if a conversion would lose data, it tells you what's being left behind. If it can't do what you're asking, it says so and in most cases explains what is missing and how to provide it so as to make the operation succeed.

`slap` understands[^UNDERSTANDS]: `IPS`, `IPS32`, `EBP`, `BPS`, `UPS`, `PPF1`, `PPF2`, `PPF3`, `PPF4`[^PPF4], `VCDIFF` (qua RFC 3284), `xdelta3`[^XDELTA3]), `BSDiff`, `GDIFF`, `xdelta1`[^XDELTA1], `APS-N64`[^APS], `APS-GBA`[^APS], `RUP`/`ninja2`[^RUP], `NINJA1`[^RUP], `PMSR`, `PCHTXT`, and `DPS`.

If your patch is tucked inside a `zip`, `rar`, or `7z` archive (📦), `slap` will attempt to find and retrieve it.

## Shape 🧅

`slap`, like an onion[^ONION], has layers. At its core is a library that describes formats, and, provides an common normalized representation of "a patch". The CLI wraps this library and tries to be useful to humans and scripts and frontends. Eventually I'll make a GUI, which will probably wrap the CLI. Three layers.

Looking inside the core of that onion: each format is described declaratively. (i.e.) what fields it carries, what it requires, and what it can provide. Conversion compatability between formats *falls out* of these descriptions. If you like hearing about internals, `ARCHITECTURE.md` has *much* to say on the shape of the program.

`Slap.BPS` and `Slap.UPS` are the two format modules that I'm most pleased with. `Slap.IPS` is being tidied up so as to be similarly pretty. The rest of the formats are still waiting their turn for that kind of care.

## Applying 🍄

This is the most common thing you'd do with it. Give it a patch and a rom and it does the thing.

```console
slap apply patch.bps rom.gba
slap apply patch.bps rom.gba -o patched.gba
slap apply patch.bps rom.gba --in-place
```

The output of the first example will be in the same directory as the input rom, and named `rom [patch].gba`.

Application can be modified in these ways:

`--output` or `-o`: Name the output file. This can be a filename (in which case the output will be in the cwd) or a fully qualified path (in which case the output goes to the exact location it is given).

`--in-place` or `-i`: Make a backup copy of the input rom: `rom.gba.bak`. Then, modify the input rom directly.[^INPLACE]

`--no-backup`: Don't make the backup copy. This modifies `--in-place`.

`--no-verify`: If the patch contains identity checksums, allow these checksums to fail. More specifically: input, output, and adler32 checksums now emit warnings instead of errors; all other checksums are not even computed. This is for if you think you *know better* than "the process". This will probably result in a nonfunctioning output, but, it might, in principle, allow you to cheaply combine two patches that modify entirely separate regions of the rom.

`--force` or `-f`: Let `slap` overwrite a file that already exists.

`--verbose` or `-V`: Have `slap` narrate each record it modifies as it applies the patch. `-v` and `-V` might trade places. When this notice is removed, the mapping is probably final.

`--dry-run`: Please ignore this flag for now as it doesn't do anything meaningful yet.[^DRYRUN] Print the record count, where the output *would* go, and, if applicable whether the input's CRC matches the one named in the patch.

`--raw`: Tell `slap` the patch-argument *is* a patch and *isn't* an archive, and so does *not* need to be rummaged through like one. This is probably never going to matter, but it is *totally* possible to make polymorphic archive-patch-combos.

### p.s. 📬

re: `slap apply patch.bps rom.gba`: The grammar is something like "hey `slap`: `apply` this `patch` to that `rom`", so, the patch argument comes before the rom one.  If this feels wrong, let me know and maybe I'll swap them. I can be reached: [here](nyuu@nyuu.page).

## Creating 🏗️

Bottling the difference between an original file and a modified version.

```console
slap create original.gba modified.gba patch.bps
slap create --format ips original.gba modified.gba patch.ips
```

Without `--format`, slap makes a `BPS` patch.

`--format`: Specify the patch format to be any of: `bps`, `ips`, `ips32`, `ebp`, `ups`, `ppf3`, `pmsr`, `ninja1`, `dps`, `rup`, `aps-n64`, `aps-gba`, `gdiff`, `pchtxt`.

`--raw`: This suppresses archive detection and unwrapping. This is the cousin of `slap apply`'s `--raw`. Its purpose is "My rom (concerningly!!!) starts with the zip magic bytes. Treat it like the rom it is anyway." You probably do not need this. You could, and shouldn't, use this to produce diffs of zip files.

### Metadata 📚

Some formats have room for text fields. I *think* the right way to explain this is to list the flags at the top level and for each list the formats that store it.

`--description` or `-d`: `EBP`, `PPF3`, `DPS`, `APS-N64`, `RUP`, `PCHTXT`

`--title`: `EBP`, `RUP`

`--author`: `EBP`, `DPS`, `RUP`

`--version`: `DPS`, `RUP`

`--genre`: `RUP`
 
`--language`: `RUP`
 
`--date`: `RUP`

The format is YYYYMMDD

`--website`: `RUP`

`--patch-encoding`: `RUP`:

The supported values are `utf8` and `system`. If left unspecified, `slap` goes with `utf8`. `system` means "'use' the locale/codepage of "the computer"[^CODEPAGE].

### PPF3

`--undo` or `-u`: Tuck a copy of the original bytes into the patch at each offset, so the patch can be reversed later. Said reversal can be done with `slap undo`.

`--validate` or `-v`: Store a 1024-byte sample from the intended output file. `-v` and `-V` might trade places. When this notice is removed, the mapping is probably final.

`--image-type`: Remember what kind of media is being patched, as this determins *where* in the file the 1024-byte comes from. The image types are `bin` and `gi`. You probably have a `bin`.

You could express non-playstation patches in this format. If you do, it is sort of pointless to bother with setting `--validate`, since doing so is either implicitly or explicitly answering `--image-type`, and the format only allows that `gi` or `bin`, and either of these answers is a declaration of "this is the kind of playstation media representation I am".

### NINJA1 and RUP/NINJA2

`--rom-type`: Tag the patch, with the platform its rom is from, and thus what preprocessing options to expose. There are 18 kinds of rom: `raw`, `nes`, `snes`, `n64`, `gb`, `gbc`, `gba`, `ngp`, `ngpc`, `sms`, `gg`, `mega`, `pce`, `ws`, `wsc`, `lynx`, `jag`, `gp32`. `raw` means "no preprocessing", so, if unspecified, `slap` tags the patch as `raw`.

The other 17 modes specify normalization procedures. For example, if `gb`, then the patcher is to strip *GB Smart Card headers* before patching. 

Right now the implementation is *wrong*: it treats all values as though they are `raw`. This will be fixed. It is low priority as nobody is using roms that care about any of these normalizations, and this has been the way of things for like 20 years. Also, I don't know of any patches that actually use a non-`raw` mode, so this is a bit hard to get good test data for. So this issue might be academic. But academic correctness is what we're here for, so it will be made right.

### BPS

This is *sick as hell*, *based*, *cool*, and other superlatives.

`--metadata`: Nestle an arbitrary file ("often" XML) into the patch as a metadata payload.

### DPS

`--unstable`: Store in the metadata the annotation that "this patch is unstable".

## Converting ⚗️

Take your patch on a journey from one format to another.

```
slap convert patch.bps --to ips32
slap convert patch.rup --to bps --with original.gba
```

Every format describes what fields it carries, what it requires, and what it can accept. Conversion compares these descriptions and acts based on the gaps, or lack thereof, between the formats.

`--to` or `-t`: Required: what to convert to.

We attempt to be exactly as strict as the formats involved require us to be. If it says a field is mandatory, then it is so. If it says it is optional, that is so instead.

If the conversion is impossible for structural reasons (e.g. `IPS` has a maximum file size and it's fairly low), `slap` will refuse and explain why. If the conversion *could* be possible but the patch on its own isn't enough, then, it will say what is missing and how to furnish it.

In short:

`--with`: Show `slap` where the input rom is, thus making the vast majority of conversions work.[^CONVERTS]

`--with` and and the metadata flags used for `slap create` are your tools for making this work.

If you are simultaneously using `--with` and using metadata flags, the metadata flags win.

If the conversion is *lossy*, as is the case in most conversions to `IPS`, this is fine. `slap` will tell you what fields survive, what ones don't, and (as said above) what's missing, if anything.

## Peeking 🔍

Look at what's inside a patch without applying it.

```console
slap info patch.ppf
slap explain patch.ips
slap explain patch.bps --records --with original.gba
```

`info`: Show what the patch is carrying in a high-level sense. It shows the format, metadata, record count, and checksums. If the patch is a `BPS` and has embedded metadata, then `--extract-metadata` writes that data to a file.

`explain`: Show the shape of the patch. Where are the modifications clustered, how big are the records, etc? This has a cute sparkline.

`--records`: `explain` now unfolds every record. This gets quite close to "dump a transcription of 'what the patch does', into the terminal". It will be very long and you will not want to read it. This is entirely for scripts and robots to filter through.

`--with`: Accepts the source rom, allowing differential formats to resolve delta operations and show resulting bytes, rather than just instructions.

`--raw`: Skip archive unwrapping. As with other instances of `--raw`, this is a hedge against the (unlikely) risk that the detection gets confused and tries to insist on treating a non-archive, as though it were one. Like always, this flag is safe to tack onto any "normal" operation. So if you are writing a script that involves calling slap and you are not intentionally attempting to do or permit archive manipulation: you probably should append `--raw` to every command that accepts it.

## Undoing ↩️

Where supported by the patch format, put things back the way they were.

```console
slap undo patch.ppf3 patched.gba
slap undo patch.ups patched.gba
```
 
This works with `PPF3`--if-made-with`--undo`-enabled, and `UPS`. `PPF3` stores the original bytes at each offset. `slap undo` write those bytes back. Applying a `UPS` patch to an already-patched file cleanly returns the original file for cool XOR reasons, so in that case we just apply the patch and so retrieve the original file.
 
`--output` or `-o`: Write the de-patched file to somewhere else.
 
`--verbose` or `-V`: Have `slap` narrate each record it modifies as it applies the patch. `-v` and `-V` might trade places. When this notice is removed, the mapping is probably final.
 
`--raw`: Ensure file is treated as a bare rom and not as an archive.

## Building 🔨

Thank you for trying it out!

```
make
make test
```

# footnotes (👣)

[^CONVERTS]: Conversion is *pretty close to being* a special case, or "sugar" for "use the apply mode to apply `example.patch` to `input.rom`, yielding `output.rom`, then use create mode, `input.rom`, and `output.rom` to create a patch in the new format". It probably is not directly useful to most users but was extremely helpful as a whetstone for the program's design. Also it isn't *quite* the same, in that if there is a metadata field that's in both the input and output formats, it is safely transplanted into the new patch, and so doesn't need to be specified via a flag.

[^UNDERSTANDS]: By "understands" I mean it "can apply". The following formats are not yet able to be created or converted-to: `PPF1`, `PPF2`, `PPF4`, `VCDIFF`, `xdelta3`, `BSDIFF`, `xdelta1`.

[^PPF4]: [Pyriel](https://www.romhacking.net/community/1288/) distributes their patches in files that have the extension `.ppf`, but is entirely distinct from the standard PPF1, PPF2, or PPF3. Said patches have the magic `PPF4`, so we're calling the format `ppf4`. Apologies to Mr./Ms./Mx. Pyriel if you prefer it be called something else.

[^XDELTA3]: `xdelta3` is a tool that trades in the format `VCDIFF`. Ish. The [O.G. RFC 3284 VCDIFF specification](https://datatracker.ietf.org/doc/html/rfc3284) is its own thing. `xdelta3`'s format adds extensions to it. In practice, if you are dealing with a patch billed as with the extension `.vcdiff`, `.xd3`, or `xdelta`: under the hood it is the VCDIFF-with-`xdelta3`-extensions format.

[^XDELTA1]: Entirely unrelated to `xdelta3` or `VCDIFF`. Your patch *probably* is not `xdelta1`.

[^APS]: The formats I'm calling "`APS-N64`" and "`APS-GBA`" are entirely unrelated, and only coincidentally share a name. In common practice people usually say "APS" without qualifiers, and do so to refer to the "GBA" format. The N64 one is comparatively obscure.

[^RUP]: There are two formats: `ninja1` and `ninja2`. Both might use the extension `rup`. Your patch *probably* is not `ninja1`. I will probably change `rup`'s in-program name to `ninja2`.

[^ONION]: Fun fact: in the USA, onions come with a *restrictive license*: it  is [illegal to trade onion futures](https://en.wikipedia.org/wiki/Onion_Futures_Act). In contrast, you're allowed to do almost anything with, or, to `slap`.

[^INPLACE]: Right now all patching is done in-memory on a whole-file representation of the input, *and* we don't support creation of or conversion-to certain complex differential formats such as VCDIFF. When *both* of these change, this will *overdeterminedly* require defining what it *means* to `slap apply --in-place --no-backup patch.vcdiff ...`. The naïve implementation doesn't make any sense and would trash the input file. I *think* we have to, for copy-from-source formats such as VCDIFF, say that backup is *probably* mandatory. The applier would have to *read* the backup and use that as its roadmap as it *edits* the in-place input file. `--in-place --no-backup` has to either not be allowed, or has to sort of cheat by meaning "create a backup, apply the patch, delete the backup at the end". This is like-three layers of edge-case deep. The standard use case is like. `slap apply patch.bps input.rom`, which requires *none* of these considerations.

[^DRYRUN]: This feature is functionally a stub right now. When fleshed out it will instead "do everything apply does *except* writing the output file to disc at the end". Probably you are not going to use this but it might be helpful when wiring up the GUI.

[^CODEPAGE]: So, if you make your patch on (a computer that's) using [`Shift JIS`](https://en.wikipedia.org/wiki/Shift_JIS), it encodes as `Shift JIS`. If you then try to interpret it (on a computer that's) using [`Windows-1252`](https://en.wikipedia.org/wiki/Windows-1252), you'll get garbage. I don't (yet) know whether many or any real patches have this set to `system`. If they do, and you get garbage when trying to read the metadata, one thing you *could* try is to use an environment variable to run `slap` as though you're in a different locale. Probably
