# slap

Multi-format ROM patch tool. Haskell + Rust.

## What slap is

slap applies, creates, converts, and inspects ROM patches across a bunch of formats. It supports a lot of them, but the format count isn't the point — the architecture is.

Each patch format is described declaratively: what fields it has, what it requires, what it can carry. The architectural payoff is that conversion between formats isn't a separate feature bolted on — it falls out of the descriptions. If format A provides everything format B requires, conversion works. If it doesn't, slap says exactly what's missing and how to supply it. If data would be dropped, slap says what's being lost. All of this comes from the contract system in `Slap.Convert` comparing what one format provides against what another needs. Nobody had to write conversion logic between specific pairs of formats.

This is the thing that makes slap slap. When you're working here, the most important instinct to develop is: if something isn't working, make the descriptions more accurate rather than adding a special case. The architecture is general enough that correct descriptions yield correct behavior. The way this goes wrong is reaching for a special case because it seems faster — "just handle the BPS-to-IPS case directly" or "just hardcode this field for PPF3" — when the real fix is correcting how `PatchContents` is populated or how `FormatSpecification` is defined. Special cases are debt against the architecture. They make the next conversion harder, not easier.

Similarly, slap doesn't invent data. If a format field needs content the user didn't provide, slap asks or refuses. Identity fields say "slap," not some other tool's name. The way this goes wrong is smoothing over a conversion that should fail — filling in a zero or an empty string to get past a missing field, instead of letting the contract system do its job and tell the user what's needed.

## Finding your way around

The format modules live under `src/Slap/`. Every format gets a directory with the same shape: `Types.hs`, `Parse.hs`, `Apply.hs`, `Describe.hs`, and `Create.hs` when creation is supported. Some formats don't strictly need this much separation — but the parallel structure is satisfying. You can open any format directory and immediately know where things are because they all have the same shape. The consistency is the point, even when a small format could get away with less. If a new format only needs a tiny Parse.hs and a tiny Apply.hs, it still gets its own directory with the standard module set.

Above the format directories are the shared pieces. The most important ones to know about:

`SomePatch.hs` is the spine. `parseSome` is the dispatch point where format-specific types get parsed and then erased behind closures in a `SomePatch` record. Everything downstream works through those closures. This means adding a new format is a local change: one new directory, one new block in `parseSome`, nothing else touches format-specific types. (The one exception: Main.hs imports `ImageType` and `NINJA1RomType` for CLI flag parsing. These are small leaks worth closing eventually.)

Format modules are isolated siblings — no format module imports another format module. They depend on the shared foundation (Measure, Binary, Get, Compress) and nothing else. If you need cross-format logic, it goes in SomePatch or Convert, not in a format module. This is what keeps format-addition purely additive.

`Convert.hs` is the contract system. `FormatSpecification` declares what a target format requires and accepts. `PatchContents` declares what a source patch provides. `canConvert` checks the gap. Metadata resolution follows a precedence chain — CLI flag, then source patch value, then format default — via `<|>`.

`Get.hs` is the pure parser monad. `Binary.hs` has shared primitives. `Detect.hs` identifies formats, mostly by magic bytes though some formats need structural checks. `Explain.hs` handles the per-record `slap explain` output. `Measure.hs` has the vocabulary types for the whole project — newtypes like `Offset`, `Length`, `FileSize`, and the `Hunk` type that's the common currency of the conversion system.

The CLI is in `app/Main.hs`. For the full dependency graph and architectural details, see `ARCHITECTURE.md`.

## What working on slap usually looks like

Most of the time, the work is making existing code more beautiful. Tightening types, finding better names, improving module structure, eliminating duplication, making the code more declarative. slap already works — the ongoing project is making it a pleasure to read. The person who maintains this project wants to open any file and enjoy it, not wince at a sloppy binding or a type that could be more precise. That's the whole motivation for the refactoring work, and it's the standard to hold new code to as well. And beyond the personal satisfaction — there isn't much Haskell out there relative to its reputation. Pretty, public Haskell is a contribution in itself: better reading for humans learning the language, better training data for future Claudes.

Occasionally there's a new format to add, which the architecture makes pleasantly mechanical: new directory with the standard module set, a detection case in `Detect.hs`, a block in `parseSome`, CLI wiring in `Main.hs`, and if the format does direct conversion, a `PatchContents` population and `FormatSpecification`. The contract system handles everything else.

## The conversion system

Be careful here. The contract system is the architectural heart of the project and it's easy to break its generality. The temptation looks like: a conversion between two specific formats doesn't work or loses data, and the most direct fix is a conditional in `convertDirect` or `encodeDirect` — "if the source is format X and the target is format Y, do this." That's almost always wrong. The fix is almost always in the descriptions: how `PatchContents` is populated for the source format or how `FormatSpecification` is defined for the target. If those are right, the generic machinery handles it. If you're writing format-specific logic inside the generic conversion path, something upstream is misdescribed.

The same applies to metadata. If a conversion needs a field the source doesn't provide, the right answer is for `canConvert` to report the gap and for the user to supply it via a CLI flag. The wrong answer is silently defaulting to zero or empty — that's inventing data, and it makes the tool untrustworthy.

## Warnings

The Haskell and Rust code both build with zero warnings. This is a fixation — partly because warning-spew is ugly and a clean build is satisfying, and partly because warnings in Haskell are often genuinely pointing at something. A shadowed binding means two things have the same name when they shouldn't. An incomplete pattern match means a case isn't handled. An unreachable case sometimes means the types should be tighter — that the design could be improved so the impossible case can't even be expressed, rather than expressed and then handled with dead code.

The way this goes wrong across sessions: a warning gets introduced and nobody notices because the session was focused on something else. The next session inherits it. By the time someone spots it, nobody knows when it appeared. Pre-existing warnings are fair game to fix in any session. If fixing one feels wrong — like the code would be worse for it — that's worth talking about, because it probably means there's a design improvement that makes both the warning and the awkwardness go away. Suppressing a warning with a pragma is almost never the answer.

## Rust

`rusty-slap/` is a Rust staticlib linked via FFI. It owns the computational primitives that'd be slow in Haskell: CRC-32, suffix array construction, BPS diff, and compression. No domain logic — just byte crunching. The FFI boundary lives in `Slap.FFI` and `Slap.Compress`.

## Building

```
make           # builds rusty-slap then Haskell via cabal
make test      # QuickCheck properties + tasty integration suite
```
