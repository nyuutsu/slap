# slap 👋

slap is a [rom](https://en.wikipedia.org/wiki/ROM_image) [patching](https://en.wikipedia.org/wiki/Patch_(computing)#Binary_patching) (🩹) tool.

See the [project page](https://nyuu.page/projects/slap/) for details.

There is a web application; it lives [here](https://slap.nyuu.page)[^WEB].

## In a nutshell 🌰

slap attempts to handle everything the format specs permit. This posture is *wildly excessive*[^EXCESSIVE] for the task of just applying patches to roms. But it doesn't hurt and was fun to think about.

Most people just need to apply patches; slap does this, and also creates them, converts between formats[^CONVERTS], and lets you look inside them.

On conversion: if a conversion would lose data, it tells you what's being left behind. If it can't do what you're asking, it says so. In most cases it also explains what is missing, and how to include it and have the operation succeed.

slap understands: `APS-GBA`, `APS-N64`[^APS], `BPS`, `BSDiff`, `DPS`, `EBP`, `GDIFF`, `IPS`, `IPS32`, `NINJA1`, `NINJA2`[^NINJA], `PMSR`, `PPF1`, `PPF2`, `PPF3`, `PPF4`[^PPF4], `UPS`, `VCDIFF` (qua RFC 3284)[^VCDIFF], `xdelta1`[^XDELTA1], and `xdelta3`[^XDELTA3].

If your patch is tucked inside a `zip`, `rar`, or `7z` archive (📦), slap will attempt[^RAR] to find and retrieve it.

Here is a representative sample of everything you are likely to care about doing:

```
slap apply patch.bps rom.gba
slap create original.gba modified.gba patch.bps
slap create --format ips original.gba modified.gba patch.ips
slap info patch.ppf
slap explain patch.ips
```

(screenshot of explain can go here. maybe also of explain's dump records mode, of info, of an interesting info message?)

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

## Applying 🍄

This is the most common thing you'd do with it. Give it a patch and a rom and it does the thing.

```console
slap apply patch.bps rom.gba
slap apply patch.bps rom.gba patched.gba
slap apply patch.bps rom.gba -o patched.gba
slap apply patch.bps rom.gba --in-place
```

The output of the first example will be in the same directory as the input rom, and named `rom [patch].gba`.

Application can be modified in these ways:

`--output` or `-o`: Name the output file. This can be a filename (in which case the output will be in the cwd) or a fully qualified path (in which case the output goes to the exact location it is given). The output can also be declared positionally, so, this flag is "nice, but unnecessary".

`--in-place` or `-i`: Make a backup copy of the input rom: `rom.gba.bak`. Then, modify the input rom directly.

`--no-backup`: Don't make the backup copy. This modifies `--in-place`.

`--no-verify`: If the patch contains identity checksums or validation criteria, and these don't match the rom you're trying to apply to, proceed anyway with a warning.

`--force` or `-f`: Let slap overwrite a file that already exists.

`--verbose` or `-v`: Have slap narrate each record it modifies as it applies the patch.

`--add-header `: Before applying, put a temporary header's worth of bytes in front of the in-memory copy of the rom. The flavors of header it knows about: `nes`, `fds`, `gb`, `snes`, `pce`, `lynx`, `a78`, and `nes-ffe`. The last one is for Front Fareast's uniquely-sized header.

`--remove-header`: Before applying, remove a header's worth of bytes from the front of the in-memory copy of the rom. The flavors of header it knows about: `nes`, `fds`, `gb`, `snes`, `pce`, `lynx`, `a78`, and `nes-ffe`. The last one is for Front Fareast's uniquely-sized header.

`--raw`: Handle a polymorphic input-patch: tell slap the patch-argument *is* a patch and *isn't* an archive, and so does *not* need to be rummaged through like one.

## Creating 🏗️

Bottling the difference between an original file and a modified version.

```console
slap create original.gba modified.gba patch.bps
slap create --format ips original.gba modified.gba patch.ips
```

Without `--format`, slap makes a `BPS` patch.

`--format`: Specify the patch format to be any of: `aps-gba`, `aps-n64`, `bps`, `bsdiff`, `dps`, `ebp`, `gdiff`, `ips`, `ips32`, `ninja1`, `ninja2`, `pmsr`, `ppf1`, `ppf2`, `ppf3`, `ppf4`, `rfc-vcdiff`, `ups`, `xdelta1`, `xdelta3`.

`--raw`: This suppresses archive detection and unwrapping. This is the cousin of `slap apply`'s `--raw`. Its purpose is "My rom (concerningly!!!) starts with the zip magic bytes. Treat it like the rom it is anyway." You probably do not need this. You could, but shouldn't, use this to produce diffs of zip files.

### Metadata 📚

Some formats have room for creator-defined information. Usually this a text field. Sometimes it is an option flag. Rarely, it is something more bold, like a slot explicitly reserved for arbitrary data.

The list of metadata flags is below. The ones that need explaining are elaborated on in the subsections that follow.

`APS-N64`: `--description`

`BPS`: `--metadata`

`DPS`: `--title`, `--author`, `--patch-version`, `--unstable`

`EBP`: `--title`, `--author`, `--description`

`NINJA1`: `--rom-type`

`NINJA2`: `--title`, `--author`, `--patch-version`, `--description`, `--genre`, `--language`, `--date`, `--website`, `--rom-type`, `--ninja2-text-mode`

`PPF1`: `--description`

`PPF2`: `--description`, `--diz`

`PPF3`: `--description`, `--diz`, `--image-type`, `--no-undo`, `--omit-verification`

`rfc-vcdiff`: `--window-size`

`xdelta1`: `--from-name`, `--to-name`, `--no-compress`, `--omit-verification`

`xdelta3`: `--metadata`, `--compress-with`, `--window-size`, `--no-compress`, `--omit-verification`

#### BPS

`--metadata`: Nestle an arbitrary file into the patch as a metadata payload.

#### DPS

`--unstable`: Store in the metadata the annotation that "this patch is unstable".

#### NINJA1

`--rom-type`: Tag the patch, with the platform its rom is from, and thus what preprocessing options to expose. There are 18 kinds of rom: `gb`, `gba`, `gbc`, `gg`, `gp32`, `jag`, `lynx`, `mega`, `n64`, `nes`, `ngp`, `ngpc`, `pce`, `raw`, `sms`, `snes`, `ws`, `wsc`. `raw` means "no preprocessing", so, if unspecified, slap tags the patch as `raw`.

The non-`raw` modes are meant to correspond to *normalization procedures[^NORMALIZE]*: deinterleaving, header removal or editing, etc. Most values do not have defined behaviors. No-op if the input rom is already in the normalized form, which it probably is.

#### NINJA2

`--rom-type`: Tag the patch, with the platform its rom is from, and thus what preprocessing options to expose. There are 11 kinds of rom: `fds`, `gb`, `gg`, `lynx`, `mega`, `n64`, `nes`, `pce`, `raw`, `sms`, `snes`. `raw` means "no preprocessing", so, if unspecified, slap tags the patch as `raw`.

The non-`raw` modes are meant to correspond to *normalization procedures*: deinterleaving, header removal or editing, etc. Most values do not have defined behaviors. No-op if the input rom is already in the normalized form, which it probably is.

`--date`: The format is YYYYMMDD

`--ninja2-text-mode`: The supported values are `utf8` and `undeclared`. If left unspecified, slap goes with `utf8`. `undeclared` means "codepage of patch creator" (the patch does not write down which one that is, however). You likely want this to be `utf8`.

#### PPF2

`--diz`: Include a DIZ description file.

#### PPF3

`--diz`: include a DIZ description file.

`--no-undo`: *Don't* tuck a copy of the original bytes into the patch at each offset. *If you do not use this flag*, the patch can be reversed later. Said reversal can be done with `slap undo`.

`--omit-verification`: *Don't* store a 1024-byte sample from the intended output file.

`--image-type`: Remember what kind of media is being patched, as this determines *where* in the file the 1024-byte sample comes from. The image types are `bin` and `gi`. You probably have a `bin`.

#### RFC VCDIFF

`--window-size`: The default is "100% of the edited portion of the file; it's all one big window[^WINDOWSIZE]". Some examples of valid arguments are `65536` `512k` and `8m`. `k` means KiB; `m` mean MiB. Using this flag and thus changing the window size, will probably make your patch larger.

#### xdelta1

`--from-name`, `--to-name`: These are no-op fields that are only *required* for compatibility reasons. Put filenames in each. Other tools may use the `to-name` as the default filename for their output.

`--omit-verification`: *Don't* store checksums of the input and output files.

`--no-compress`: *Don't* (internally) gzip-compress the patch.

#### xdelta3

`--metadata`: Nestle an arbitrary file into the patch as a metadata payload.

`--compress-with`: The supported values are `lzma` (the default) and `djw`.

`--no-compress`: *Don't* (internally) compress the patch.

`--omit-verification`: *Don't* store checksums of the output.

`--window-size`: The default is `8m`. Some examples of valid arguments are `65536` `512k` and `8m`. `k` means KiB; `m` mean MiB. Using this flag and thus changing the window size, could make your patch larger. Setting it above `16m` will cause the patch to be incompatible with some other patchers.

### Constraints 🤐

#### IPS

`--require-smc-shaped-target-size`: *Don't* allow `IPS` patch creation *if*:

1. The patch would contain a truncation[^TRUNCATION] marker

2. The size declared by that truncation marker *doesn't* satisfy this shape: `(size & 0xFFF) == 0x200`

[SNESTool](https://www.romhacking.net/utilities/18/) is an early IPS patching tool. It refuses to apply patches that have a truncation marker, whose size doesn't pass the above test. If your patch is going to be applied by someone using this SNESTool, then:

1. Use this flag; slap will refuse to create a patch that SNESTool would reject-for-this-reason

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

If the conversion is impossible for structural reasons (e.g. `IPS` has a maximum file size and it's fairly low), slap will refuse and explain why. If the conversion *could* be possible but the patch on its own isn't enough, then, it will say what is missing and how to furnish it.

`--with`: Show slap where the input rom is, thus making the vast majority of conversions work. 

It and the metadata flags described in the section on `slap create` are your tools for making this work. If you are simultaneously using `--with` and using metadata flags, the metadata flags win.

If the conversion is *lossy*, as is the case in most conversions to `IPS`, this is fine. slap will tell you what fields survive, what ones don't, and anything notable (or trivial, in some cases) it finds.

### BPS

`--drop-metadata`: *Don't* preserve the metadata blob[^UNBLOB].

### PPF2

`--drop-diz`: *Don't* preserve the embedded DIZ.

### PPF3

`--drop-diz`: *Don't* preserve the embedded DIZ.

`--omit-verification`: *Don't* store a 1024-byte sample from the intended output file.

### xdelta1

`--omit-verification`: *Don't* store checksums of the input and output files.

## Peeking 🔍

Look at what's inside a patch without applying it. There are two flavors; the latter has some options.

```console
slap info patch.ppf
slap explain patch.ips
slap explain patch.bps --records --with original.gba
```

`info`: Show what the patch is carrying in a high-level sense. It shows the format, metadata, record count, and checksums.

`explain`: Show the shape of the patch. Where are the modifications clustered, how big are the records, etc? This has a cute sparkline.

### Info

`--extract-metadata`: If the patch is `BPS` or `xdelta3` and has embedded metadata, write it to a file.

`--extract-diz`: If the patch is `PPF2` or `PPF3` and has an embedded DIZ, write it to a file.

### Explain

`--records`: `explain` now unfolds every record. This gets quite close to "dump a transcription of 'what the patch does', into the terminal". It will be very long and isn't suitable for casual skimming.

`--with`: Accepts the source rom, allowing differential formats to resolve delta operations and show resulting bytes, rather than just instructions.

`--raw`: Skip archive unwrapping. As with other instances of `--raw`, this is a hedge against the (unlikely) risk that the detection gets confused and tries to insist on treating a non-archive, as though it were one. Like always, this flag is safe to tack onto any "normal" operation. So if you are writing a script that involves calling slap and you are not intentionally attempting to do or permit archive manipulation: you probably should append `--raw` to every command that accepts it.

## Undoing ↩️

Where supported by the patch format, put things back the way they were. `undo` understands the same flags as does `apply`.

```console
slap undo patch.ppf3 patched.gba
slap undo patch.ups patched.gba
```

## Interpreting Patches 🤔

### Text Encoding 💬

Several formats do not say what encoding the metadata should be in. On the off chance that you're trying to read (and, converting-from is a kind of reading) metadata and the text is coming out wrong: the issue may be downstream of how by default we attempt to decode as UTF-8.

It might be possible to retrieve whatever the text is by decoding it as not-UTF-8. We offer two levers for this:

`slap --encodings`: list the supported encodings

`--metadata-encoding`: use the specified encoding

The latter is used like so:

```
slap info patch.rup --metadata-encoding gb18030`
slap convert patch.rup --metadata-encoding shift-jis --to ebp
```

`explain` *attempts* to interpret and display the contents of opaque "anything can go here" fields, as text; `--metadata-encoding` works there as well.

### Dialects 🌍

Declare something about how to interpret the patch. This is about information needed to read the patch, but that isn't declared by the patch.

`--is-amiga-patch`: Correctly *interpret* a `PPF1` patch made on an Amiga computer.

This also works with `info`, `explain`, and `convert`. Regarding `convert`: our *outputs* are always little-endian.

## Building 🔨

slap is written in Haskell and Rust; the latter is there mostly for heavy byte-crunching stuff. To build it you will need tooling for each of these. You will need to clone one submodule:

```
git submodule update --init rusty-slap/vendor/lzma-rust2
```

Once those prerequisites are in place, building is straightforward:

```sh
make
```

At which point you could go find your newly-compiled program in `dist-newstyle/`. Or use `cabal run slap --` to run it from the project root, e.g. `cabal run slap -- info path/to/patch.ebp`. Or, and I like this approach more: `make install`; this allows using it without qualifiers, e.g. `slap info path/to/patch.rfc-vcdiff`.

Thank you for trying it out!

### Digression: how to get the aforementioned toolchains

For each language,

1. install a version-manager tool

2. use the tool to install a suitable version of the compiler

Then, in Haskell's case, download the package list.

In Haskell's case, the version-manager tool I know to work is [GHCup](https://www.haskell.org/ghcup/). This manages the (versions of) the compiler (ghc) and the build tool (cabal). slap is using GHC2024, so what's needed is GHC 9.10, 9.12, or 9.14, alongside a version of cabal compatible with the version of GHC.

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

`make test` runs the test suite. Large segments of it are about patching copyrighted material I will not be providing. If you want to run the tests:

1. get the test patches

2. get the corresponding test roms

3. run the tests

To get the patches:

```
git submodule update --init test/data
```

This populates `test/data/` with subfolders containing patches.

To know what roms to get: see `test/data/README.md`.

The per-test durations are logged to `test-results/`.

# footnotes (👣)

[^WEB]: Web-based slap doesn't have the flags `--force`, `--in-place`, and `--no-backup`. It also doesn't have the same archive-unwrapping skills.

[^EXCESSIVE]: The project page linked above talks about this.

[^UNBLOB]: `BPS` has an unusual property: it supports metadata-as-in-arbitrary-data. The spec *suggests* putting XML there but is firm that it is valid for *anything* to go here. `xdelta3` has an analogous field. If converting between these formats, or converting one of these formats *to itself*, *and* you want to drop the blob, this will help.

[^TRUNCATION]: An `IPS` patch can have a "truncation marker" at its end. This is a location in the patch where you can specify a size-value, and this is meant to indicate "drop all data in the file after this point". So, "shrink the file", hence the name.

[^WINDOWSIZE]: Internally, a VCDIFF patch is made out of some number of "windows". A window is a segment of a file. A streaming patching tool could work with fewer resources via working on one window at a time, rather than loading everything into memory all at once.

[^CONVERTS]: Conversion is *pretty close to being* [sugar](https://en.wikipedia.org/wiki/Syntactic_sugar) for "use the apply mode to apply `example.patch` to `input.rom`, yielding `output.rom`, then use create mode, `input.rom`, and `output.rom` to create a patch in the new format". It probably is not directly useful to most users but was extremely helpful as a whetstone for the program's design. Also it isn't *quite* the same, in that if there is a metadata field that's in both the input and output formats, it is safely transplanted into the new patch, and so doesn't need to be re-specified.

[^PPF4]: [Pyriel](https://www.romhacking.net/community/1288/) distributes their patches in files that have the extension `.ppf`. The [magic](https://en.wikipedia.org/wiki/List_of_file_signatures) says it is of type: `PPF4`. It allows growing the output file.

[^VCDIFF]: Okay, okay, so: this is actually novel. I *think* slap is the first[^GOOGLE] tool to *emit* patches that use either, let alone both, of these features: custom code tables, and, using `vcd_target`. The latter only becomes applicable if you go out of your way to request multiple windows in the patch. What these *do* is a bit beyond the scope of this readme, but, the post linked at the top of the file *should* explain this, along with a lot of other things.

[^GOOGLE]: Google had (archived, as of April of 2026) an implementation of VCDIFF, which could *apply* patches that use these features. But, it doesn't *emit* patches containing them. Also, they added some extensions.

[^XDELTA3]: `xdelta3` is a variation on the [O.G. RFC 3284 VCDIFF specification](https://datatracker.ietf.org/doc/html/rfc3284). It adds some things (adler32 checksums, three specific secondary compressor options, and the `appheader` field), and removes some things (custom code tables, `vcd_target`). If you have a patch and it has the extension `.vcdiff`: it is probably an `xdelta3` patch.

[^NORMALIZE]: If the input is already *in* this normalized form then this tag is no-op.

[^XDELTA1]: The versions we support are those with magics `%XDZ003%` or `%XDZ004%`. If you're trying to apply a pre-`%XDZ003%` patch, complain about my omission: [here](mailto:nyuu@nyuu.page). I will *probably* implement the older versions upon request. But, please include the patch you're trying to apply; I don't have any and suspect there *aren't* any.

[^APS]: The formats I'm calling "`APS-N64`" and "`APS-GBA`" are unrelated, and only coincidentally share an acronym.

[^NINJA]: There are two formats: `ninja1` and `ninja2`. Both might use the file extension `.rup`.

[^RAR]: The `RAR` format is proprietary; I don't know of a practical way to include a `RAR` decompressor.