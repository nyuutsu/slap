# slap 👋

To be honest this program isn't ready for prime-time just yet. There is some stuff that ain't right. The log of such things is: in my head. I will remove this message when I feel like it is ready for use. Until then: beware!

For common tasks ("I want to make / create a patch in a normal format, using non-adversarial inputs": it ought to work fine. But: xdelta3 secondary compression is not present yet, which is a critical blocker to general usability. And, there are other issues that, frankly, you as a user are not going to encounter, but I would feel embarassed showcasing the program before these)

## In a nutshell 🌰

`slap` is a [rom](https://en.wikipedia.org/wiki/ROM_image) [patching](https://en.wikipedia.org/wiki/Patch_(computing)#Binary_patching) (🩹) tool. It knows how to work with a lot of patch formats. It probably knows (🎓) more than you'll actually need. Most people just need to apply patches; `slap` does this, and also creates them, converts between formats[^CONVERTS], and lets you look inside them.

On conversion: if a conversion would lose data, it tells you what's being left behind. If it can't do what you're asking, it says so. In most cases it also explains what is missing, and how to include it and have the operation succeed.

`slap` understands[^UNDERSTANDS]: `IPS`, `IPS32`, `EBP`, `BPS`, `UPS`, `PPF1`, `PPF2`, `PPF3`, `PPF4`[^PPF4], `VCDIFF` (qua RFC 3284), `xdelta3`[^XDELTA3], `BSDiff`, `GDIFF`, `xdelta1`[^XDELTA1], `APS-N64`[^APS], `APS-GBA`[^APS], `NINJA2`[^NINJA], `NINJA1`[^NINJA], `PMSR`, and `DPS`.

If your patch is tucked inside a `zip`, `rar`, or `7z` archive (📦), `slap` will attempt to find and retrieve it.

## Shape 🧅

`slap`, like an onion[^ONION], has layers. At its core is a library that describes formats, and, provides a common normalized representation of "a patch". The CLI wraps this library and tries to be useful to humans and scripts and frontends. Eventually I'll make a GUI, which will probably wrap the CLI. Three layers.

Looking inside the core of that onion: each format is described declaratively. (i.e. what fields it carries), what it requires, and what it can provide. Conversion compatibility between formats *falls out* of these descriptions. If you like hearing about internals, `ARCHITECTURE.md` has *much* to say on the shape of the program.

`app/Main.hs`, `Slap.BPS`, `Slap.IPS`, and `Slap.UPS` are the components I'm most pleased with; I think they're quite pretty. The rest of the formats are still waiting their turn for that kind of care.

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

`--in-place` or `-i`: Make a backup copy of the input rom: `rom.gba.bak`. Then, modify the input rom directly.

`--no-backup`: Don't make the backup copy. This modifies `--in-place`.

`--no-verify`: If the patch contains identity checksums or validation criteria, and these don't match the rom you're trying to apply to, proceed anyway with a warning.

This is for if you know better than `slap` 🧠📈.

`--force` or `-f`: Let `slap` overwrite a file that already exists.

`--verbose` or `-v`: Have `slap` narrate each record it modifies as it applies the patch.

`--dry-run`: *Don't* apply the patch. Do the following:

1. Check whether the patch can be parsed

2. Determine and print the would-be output path

3. *If* the patch has a source checksum, check that sum and print

`--raw`: Handle a polymorphic input-patch: tell `slap` the patch-argument *is* a patch and *isn't* an archive, and so does *not* need to be rummaged through like one.

### Dialects 🌍

Declare something about how to interpret the patch. This is about information needed to read the patch, but that isn't declared by the patch.

`--is-amiga-patch`: Correctly *interpret* a `PPF1` patch made on an Amiga computer.

Why: leave no patch behind! 😤‼️ There is an Amiga-based `PPF1` tool. A patch made by this tool would be stored as [big-endian](https://en.wikipedia.org/wiki/Endianness). `slap` defaults to little-endian; this flag toggles endianness.

This also works with `info`, `explain`, and `convert`. Regarding `convert`: our *outputs* are always little-endian.

### p.s. 📬

re: `slap apply patch.bps rom.gba`: The grammar is something like "hey `slap`: `apply` this `patch` to that `rom`", so, the patch argument comes before the rom one.  If this feels wrong, let me know and maybe I'll swap them. I can be reached: [here](mailto:nyuu@nyuu.page).

## Creating 🏗️

Bottling the difference between an original file and a modified version.

```console
slap create original.gba modified.gba patch.bps
slap create --format ips original.gba modified.gba patch.ips
```

Without `--format`, slap makes a `BPS` patch.

`--format`: Specify the patch format to be any of: `bps`, `ips`, `ips32`, `ebp`, `ups`, `ppf1`, `ppf2`, `ppf3`, `pmsr`, `ninja1`, `ninja2`, `xdelta1`, `dps`, `aps-n64`, `aps-gba`, `gdiff`.

`--raw`: This suppresses archive detection and unwrapping. This is the cousin of `slap apply`'s `--raw`. Its purpose is "My rom (concerningly!!!) starts with the zip magic bytes. Treat it like the rom it is anyway." You probably do not need this. You could, and shouldn't, use this to produce diffs of zip files.

### Metadata 📚

Some formats have room for text fields. I *think* the right way to explain this is to list the flags at the top level and for each list the formats that store it.

`--description`: `EBP`, `PPF1`, `PPF2`, `PPF3`, `APS-N64`, `NINJA2`

`--title`: `EBP`, `DPS`, `NINJA2`

`--author`: `EBP`, `DPS`, `NINJA2`

`--patch-version`: `DPS`, `NINJA2`

`--genre`: `NINJA2`
 
`--language`: `NINJA2`
 
`--date`: `NINJA2`

The format is YYYYMMDD

`--website`: `NINJA2`

`--ninja2-text-mode`: `NINJA2`:

The supported values are `utf8` and `undeclared`. If left unspecified, `slap` goes with `utf8`. `undeclared` means "'use' the locale/codepage of "the computer"[^CODEPAGE]. You likely want this to be `utf8`.

#### PPF3

`--no-undo`: *Don't* tuck a copy of the original bytes into the patch at each offset. *If you do not use this flag*, the patch can be reversed later. Said reversal can be done with `slap undo`.

`--omit-verification`: *Don't* store a 1024-byte sample from the intended output file.

`--image-type`: Remember what kind of media is being patched, as this determines *where* in the file the 1024-byte sample comes from. The image types are `bin` and `gi`. You probably have a `bin`.

#### NINJA1 and NINJA2

`--rom-type`: Tag the patch, with the platform its rom is from, and thus what preprocessing options to expose. There are 19 kinds of rom: `raw`, `nes`, `fds`, `snes`, `n64`, `gb`, `gbc`, `gba`, `ngp`, `ngpc`, `sms`, `gg`, `mega`, `pce`, `ws`, `wsc`, `lynx`, `jag`, `gp32`. `raw` means "no preprocessing", so, if unspecified, `slap` tags the patch as `raw`.

`NINJA1` and `NINJA2` enumerate different subsets of the above.

The non-`raw` modes are meant to correspond to *normalization procedures*. For example, if `gb`, then the patcher is to strip *GB Smart Card headers* before patching. Most values do not have defined behaviors.

Of the subset that *do*: *we* don't implement the behaviors yet. This is considered pretty low priority since modern roms are in the normalized forms *anyway*.

#### BPS

This is *sick as hell*, *based*, *cool*, and other superlatives.

`--metadata`: Nestle an arbitrary file ("often" XML) into the patch as a metadata payload.

#### DPS

`--unstable`: Store in the metadata the annotation that "this patch is unstable".

#### xdelta1

`--omit-verification`: *Don't* store checksums of the input and output files.

`--no-compress`: *Don't* (internally) gzip-compress the patch. The default is to compress

### Constraints 🤐

#### IPS

`--require-smc-shaped-target-size`: *Don't* allow `IPS` patch creation *if*:

1. The patch would contain a truncation[^TRUNCATION] marker

2. The size declared by that truncation marker *doesn't* satisfy this shape: `(size & 0xFFF) == 0x200`

[SNESTool](https://www.romhacking.net/utilities/18/) is an early IPS patching tool. It refuses to apply patches that have a truncation marker, whose size doesn't pass the above test. If your patch is going to be applied by someone using this tool, then:

1. `slap` will refuse to create a patch that SNESTool would reject for this reason

2. Tell me your story. Why do you need this feature? I can be reached [here](mailto:nyuu@nyuu.page)

## Converting ⚗️

Take your patch on a journey from one format to another.

```
slap convert patch.bps --to ips32
slap convert patch.rup --to bps --with original.gba
```

Every format describes what fields it carries, what it requires, and what it can accept. Conversion compares these descriptions and acts based on the gaps, or lack thereof, between the formats. Metadata is preserved, when this is possible.

`--to` or `-t`: Required: what to convert to.

We attempt to be exactly as strict as the formats involved require us to be. If it says a field is mandatory, then it is so. If it says it is optional, that is so instead.

If the conversion is impossible for structural reasons (e.g. `IPS` has a maximum file size and it's fairly low), `slap` will refuse and explain why. If the conversion *could* be possible but the patch on its own isn't enough, then, it will say what is missing and how to furnish it.

`--with`: Show `slap` where the input rom is, thus making the vast majority of conversions work.[^CONVERTS] 

`--with` and the metadata flags described in the section on `slap create` are your tools for making this work.


If you are simultaneously using `--with` and using metadata flags, the metadata flags win.

If the conversion is *lossy*, as is the case in most conversions to `IPS`, this is fine. `slap` will tell you what fields survive, what ones don't, and anything notable (or trivial, in some cases) it finds.

### BPS

`--drop-metadata`: *Don't* preserve the metadata blob[^UNBLOB].

### PPF3

`--omit-verification`: *Don't* store a 1024-byte sample from the intended output file.

### xdelta1

`--omit-verification`: *Don't* store checksums of the input and output files.

## Peeking 🔍

Look at what's inside a patch without applying it.

```console
slap info patch.ppf
slap explain patch.ips
slap explain patch.bps --records --with original.gba
```

`info`: Show what the patch is carrying in a high-level sense. It shows the format, metadata, record count, and checksums. If the patch is a `BPS` and has embedded metadata, then `--extract-metadata` writes that data to a file.

`explain`: Show the shape of the patch. Where are the modifications clustered, how big are the records, etc? This has a cute sparkline.

`--records`: `explain` now unfolds every record. This gets quite close to "dump a transcription of 'what the patch does', into the terminal". It will be very long and isn't suitable for casual skimming.

`--with`: Accepts the source rom, allowing differential formats to resolve delta operations and show resulting bytes, rather than just instructions.

`--raw`: Skip archive unwrapping. As with other instances of `--raw`, this is a hedge against the (unlikely) risk that the detection gets confused and tries to insist on treating a non-archive, as though it were one. Like always, this flag is safe to tack onto any "normal" operation. So if you are writing a script that involves calling slap and you are not intentionally attempting to do or permit archive manipulation: you probably should append `--raw` to every command that accepts it.

## Undoing ↩️

Where supported by the patch format, put things back the way they were.

```console
slap undo patch.ppf3 patched.gba
slap undo patch.ups patched.gba
```

Undo works with all `UPS` patches. Applying a `UPS` patch to an already-patched file cleanly returns the original file for cool XOR reasons, so `undo` and `apply` would both work. Regardless of which is chosen, we can apply the patch and so retrieve the original file.

Undo also works with some `PPF3` patches. When creating a `PPF3`, you can include undo information. If present, `slap` can use it. `slap` includes this information when making a `PPF3` patch unless asked not to. Asking not to is done by using `--no-undo`.

`undo` understands the same flags as does `apply`:

* `--output` or `-o`

* `--in-place` or `-i`

* `--no-backup`

* `--no-verify`

* `--force` or `-f`

* `--verbose` or `-v`

* `--dry-run`

* `--raw`.

## Building 🔨

Thank you for trying it out!

```
make
make test
```

slap uses the GHC2024 language edition, so it needs **GHC 9.10, 9.12, or 9.14** — anything older won't compile. ghcup's *recommended* GHC is currently older than that, so choose one of these explicitly, along with a cabal recent enough to drive it (cabal 3.16+ for GHC 9.14).

# footnotes (👣)

[^UNBLOB]: BPS has an unusual property: it supports metadata-as-in-arbitrary-data. The spec *suggests* a structure/format (XML; I don't recall the subflavor but it is largely immaterial), but makes it explicit that "anything goes". "Converting" from `BPS` to `BPS` is allowed (if a bit "why are you doing this?"). It is rare (and I'm being generous by calling it "rare", rather than "unheard of") for patches to have anything in the metadata blob area. If you want to re-encode a patch and drop the blob in one go, this flag could help.

[^TRUNCATION]: IPS has a "truncation marker" feature. This is a location in the patch where you can specify a size-value, and this is meant to indicate "drop all data in the file after this point". So, "shrink the file", hence the name. It isn't obvious to me what it would "mean" to set this value to something *larger* than the size of the input file. Like, if you do this *and* the patch is writing data past the end of the file, then this means "expand the file". But if it *just* says "file is larger" and doesn't put anything in some or all of that new space, what should happen? One tool (I *think* it is [rompatcher.js](https://github.com/marcrobledo/RomPatcher.js/)?) says "if that happens, the declared size is correct. Zero-fill the file until it reaches the size the truncation marker says to use". So, truncation marker can unilaterally grow the file. At the moment we're doing the same. I'm not really sure about this call on an aesthetic level and might do something else.

[^CONVERTS]: Conversion is *pretty close to being* a special case, or "sugar" for "use the apply mode to apply `example.patch` to `input.rom`, yielding `output.rom`, then use create mode, `input.rom`, and `output.rom` to create a patch in the new format". It probably is not directly useful to most users but was extremely helpful as a whetstone for the program's design. Also it isn't *quite* the same, in that if there is a metadata field that's in both the input and output formats, it is safely transplanted into the new patch, and so doesn't need to be specified via a flag.

[^UNDERSTANDS]: By "understands" I mean it "can apply". The following formats are not yet able to be created or converted-to: `VCDIFF`, `xdelta3`, `BSDIFF`.

[^PPF4]: [Pyriel](https://www.romhacking.net/community/1288/) distributes their patches in files that have the extension `.ppf`. The [magic](https://en.wikipedia.org/wiki/List_of_file_signatures) says it is of type: `PPF4`. The main thing is that it supports having the output be larger than the input.

[^XDELTA3]: `xdelta3` is a tool that trades in the format `VCDIFF`. Ish. The [O.G. RFC 3284 VCDIFF specification](https://datatracker.ietf.org/doc/html/rfc3284) is its own thing. `xdelta3`'s format adds extensions to it. In practice, if you are dealing with a patch billed as with the extension `.vcdiff`, `.xd3`, or `xdelta`: under the hood it is the VCDIFF-with-`xdelta3`-extensions format.

[^XDELTA1]: Entirely unrelated to `xdelta3` or `VCDIFF`. Your patch *probably* is not `xdelta1`. The versions we support are those with magics `%XDZ003%` or `%XDZ004%`. If you're trying to apply a pre-`%XDZ003%` patch, complain about my omission: [here](mailto:nyuu@nyuu.pate). I will *probably* implement the older versions upon request.

[^APS]: The formats I'm calling "`APS-N64`" and "`APS-GBA`" are entirely unrelated, and only coincidentally share a name. In common practice people usually say "APS" without qualifiers, and do so to refer to the "GBA" format. The N64 one is comparatively obscure.

[^NINJA]: There are two formats: `ninja1` and `ninja2`. Both use the file extension `.rup`. Your patch *probably* is not `ninja1`.

[^ONION]: Fun fact: in the USA, onions come with a *restrictive license*: it  is [illegal to trade onion futures](https://en.wikipedia.org/wiki/Onion_Futures_Act). In contrast, you're allowed to do almost anything with, or, to `slap`.

[^CODEPAGE]: So, if you make your patch on (a computer that's) using [`Shift JIS`](https://en.wikipedia.org/wiki/Shift_JIS), it encodes as `Shift JIS`. If you then try to interpret it (on a computer that's) using [`Windows-1252`](https://en.wikipedia.org/wiki/Windows-1252), you'll get garbage. I don't (yet) know whether many or any real patches have this set to `undeclared`. If they do, and you get garbage when trying to read the metadata, one thing you *could* try is to use an environment variable to run `slap` as though you're in a different locale.