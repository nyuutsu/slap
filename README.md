# slap 👋

## In a nutshell 🌰

`slap` is a [rom](https://en.wikipedia.org/wiki/ROM_image) [patching](https://en.wikipedia.org/wiki/Patch_(computing)#Binary_patching) (🩹) tool that is pathologically concerned with specification-accuracy[^ACCURACY] qua "literally everything that is spec-permitted is handled gracefully". This orientation is *wildly excessive* for the task of just applying patches to roms. But it doesn't hurt and was fun to think about.

Most people just need to apply patches; `slap` does this, and also creates them, converts between formats[^CONVERTS], and lets you look inside them.

On conversion: if a conversion would lose data, it tells you what's being left behind. If it can't do what you're asking, it says so. In most cases it also explains what is missing, and how to include it and have the operation succeed.

`slap` understands[^UNDERSTANDS]: `IPS`, `IPS32`, `EBP`, `BPS`, `UPS`, `PPF1`, `PPF2`, `PPF3`, `PPF4`[^PPF4], `VCDIFF` (qua RFC 3284), `xdelta3`[^XDELTA3], `BSDiff`, `GDIFF`, `xdelta1`[^XDELTA1], `APS-N64`[^APS], `APS-GBA`[^APS], `NINJA2`[^NINJA], `NINJA1`[^NINJA], `PMSR`, and `DPS`.

If your patch is tucked inside a `zip`, `rar`, or `7z` archive (📦), `slap` will attempt to find and retrieve it.

Here is basically everything you are likely to care about:

```
slap apply patch.bps rom.gba
slap create original.gba modified.gba patch.bps
slap create --format ips original.gba modified.gba patch.ips
slap info patch.ppf
slap explain patch.ips
```

Here are some longer or more esoteric things that can be done:

```
slap explain patch.bps --records --with original.gba
slap convert patch.ips --to bps --with original.gba
slap convert patch.ips --to ebp --description "foo" --title "bar" --author "baz"
slap convert patch.rup --metadata-encoding shift-jis --to ebp
slap convert patch.ppf1 --to ppf3 --is-amiga-patch -o patch.ppf3
slap create --format ninja2 --description "请输入描述" --title "my cool patch" --author "nyuu" --patch-version "69.420" --genre "😎" --language "unsure" --ninja2-text-mode "utf8" original.gba modified.gba
```

The rest of this document is very long since there are a lot of niche options.

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

The supported values are `utf8` and `undeclared`. If left unspecified, `slap` goes with `utf8`. `undeclared` means "codepage of patch creator" (the patch does not write down which one that is, however). You likely want this to be `utf8`.

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

`slap` is written in Haskell and Rust; the latter is there mostly for heavy byte-crunching stuff. You will need a toolchain for each. Once those are present and working, building is straightforward:

```sh
make
```

At which point you could go find it in `dist-newstyle/`. Or use `cabal run slap --` to run it from the project root, e.g.: `cabal run slap -- info path/to/patch.ebp`. Or, and I like this one more: `make install`.

Thank you for trying it out!

### Digression: how to get the aforementioned toolchains

For each language,

1. install a version-manager tool

2. use the tool to install a suitable version of the compiler

Then, in Haskell's case, download the package list.

In Haskell's case, the version-manager tool I know to work is [GHCup](https://www.haskell.org/ghcup/). This manages the (versions of) the compiler (ghc) and the build tool (cabal). `slap` is using GHC2024, so what's needed is GHC 9.10, 9.12, or 9.14, alongside a version of cabal compatible with the version of GHC.

```
ghcup install ghc 9.12.2 && ghcup set ghc 9.12.2
ghcup install cabal 3.16.1.0 && ghcup set cabal 3.16.1.0
cabal update
```

In Rust's case, the version-manager is [rustup](https://rustup.rs); installing it gives you `cargo` and `rustc`. These two things are all you need. If you want to be thorough, though:

```
rustup default stable
```

*then* you can run `make`.

## Running the tests 🧪

`make test` runs the test suite. I would advise against doing this! If you want to do this anyway:

1. get the test patches

2. get the corresponding test roms

3. run the tests

To get the patches:

```
git submodule update --init
```

This populates `test/data/` with subfolders containing patches.

To know what roms to get: see `test/data/README.md`

The per-test durations logged to `test-results/` are unreliable when the tests are run in parallel. So, if curious how long a specific test took, run `make test-onecore`.

The *vast* majority of this time is due to how the bps creation implementation uses a super greedy algo that has to do a lot of work before it decides it has found the best way to pack everything.

# that which didn't fit into a footnote

Four examples:

1. IPS arguably allows for nonsequential records, partially overlapping records, and RLE segments of length 0. We oblige by not choking-on or misapplying in any of these cases. There are quite a lot of things that are at once *definitely not **not**-allowed* and "ought" to be handled gracefully, but also in practice are most likely a sign that either this is an adversarial input (why?) or that the patch is malformed. In all such cases we found, we try to handle them gracefully, and to also flag to the user that the thing they just applied is weird and why.

2. The reference PPF1 software has a PC version and an Amiga version. The former is little endian; the latter is big endian. The patches made on PC cannot be applied on Amiga (nor vice versa), and, the patch doesn't tell you which flavor it is. It is fractally unlikely that you're actually trying to apply an Amiga-made PPF1 patch, but, you should be *allowed to do it*. So, we offer `--is-amiga-patch` as a "correct for big endianness" option: `slap apply patch.ppf rom.psx --is-amiga-patch`

3. BPS explicitly allows *literally anything* to go in its metadata area. In practice it is most likely that there is no metadata. If there were data, it'd most likely be text. So `slap explain` does make an attempt to read the area and display the printable contents *if* it is text. But, if it was some arbitrary binary blob, you should be allowed to retrieve it. So, we offer `--extract-metadata` as an option: `slap info patch.bps --extract-metadata file.bin`

4. Several formats do not say what encoding the metadata uses. In one case, a format has a toggle, where the two possible states are "UTF-8" or "system codepage" -- as in, the text encoding used by the OS of whoever made the patch. The patch doesn't know which encoding that was. In these unstated-encoding cases, occasionally the data isn't just ASCII, and also isn't just UTF-8.

This matters: not *whatsoever* to anyone applying a patch. The user applies and is out in 30 seconds. If the patch has text in the fields, they don't care and will not know. But they should be able to ask, and the answer isn't useful if it comes out as mojibake.

So: since it is *not quite correct* to go "if it is in an inconvenient format, it doesn't exist": we provide fifty alternate encodings that can be used for this decoding. The list of encodings can be viewed through `slap --encodings` and one can be used like so: `slap info patch.rup --metadata-encoding gb18030`

# footnotes (👣)

[^ACCURACY]: see [§ that which didn't fit into a footnote](#that-which-didnt-fit-into-a-footnote)

[^UNBLOB]: BPS has an unusual property: it supports metadata-as-in-arbitrary-data. The spec *suggests* a structure/format (XML; I don't recall the subflavor but it is largely immaterial), but makes it explicit that "anything goes". "Converting" from `BPS` to `BPS` is allowed (if a bit "why are you doing this?"). It is rare (and I'm being generous by calling it "rare", rather than "unheard of") for patches to have anything in the metadata blob area. If you want to re-encode a patch and drop the blob in one go, this flag could help.

[^TRUNCATION]: An IPS patch can have in it a "truncation marker". This is a location in the patch where you can specify a size-value, and this is meant to indicate "drop all data in the file after this point". So, "shrink the file", hence the name.

[^CONVERTS]: Conversion is *pretty close to being* a special case, or "sugar" for "use the apply mode to apply `example.patch` to `input.rom`, yielding `output.rom`, then use create mode, `input.rom`, and `output.rom` to create a patch in the new format". It probably is not directly useful to most users but was extremely helpful as a whetstone for the program's design. Also it isn't *quite* the same, in that if there is a metadata field that's in both the input and output formats, it is safely transplanted into the new patch, and so doesn't need to be specified via a flag.

[^UNDERSTANDS]: By "understands" I mean it "can apply". The following formats are not yet able to be created or converted-to: `VCDIFF`, `xdelta3`, `BSDIFF`.

[^PPF4]: [Pyriel](https://www.romhacking.net/community/1288/) distributes their patches in files that have the extension `.ppf`. The [magic](https://en.wikipedia.org/wiki/List_of_file_signatures) says it is of type: `PPF4`. The main thing is that it supports having the output be larger than the input.

[^XDELTA3]: `xdelta3` is a tool that trades in the format `VCDIFF`. Ish. The [O.G. RFC 3284 VCDIFF specification](https://datatracker.ietf.org/doc/html/rfc3284) is its own thing. `xdelta3`'s format adds extensions to it. In practice, if you are dealing with a patch billed as with the extension `.vcdiff`, `.xd3`, or `xdelta`: under the hood it is the VCDIFF-with-`xdelta3`-extensions format.

[^XDELTA1]: Entirely unrelated to `xdelta3` or `VCDIFF`. Your patch *probably* is not `xdelta1`. The versions we support are those with magics `%XDZ003%` or `%XDZ004%`. If you're trying to apply a pre-`%XDZ003%` patch, complain about my omission: [here](mailto:nyuu@nyuu.pate). I will *probably* implement the older versions upon request.

[^APS]: The formats I'm calling "`APS-N64`" and "`APS-GBA`" are entirely unrelated, and only coincidentally share an acronym.

[^NINJA]: There are two formats: `ninja1` and `ninja2`. Both use the file extension `.rup`. Your patch *probably* is not `ninja1`.

[^ONION]: Fun fact: in the USA, onions come with a *restrictive license*: it  is [illegal to trade onion futures](https://en.wikipedia.org/wiki/Onion_Futures_Act). In contrast, you're allowed to do almost anything with, or, to `slap`.