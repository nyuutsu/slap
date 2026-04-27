# slap

## What slap's deal is

slap applies, creates, converts, and inspects ROM patches across a bunch of formats.

It is predominantly an art piece. The user aims for the architecture to be pretty and well thought out, and the same is true of the code. Your job, in general, is to contribute to making it prettier. The person who maintains this project wants to be able to open any file and enjoy reading it.

The strongest form of beauty is architectural beauty, which is often made out of selecting newtypes that cause impossible or unwanted states to be unrepresentable.

The user is quite keen on solving as much of the problem as possible at the type-design level, and on using newtypes for pretty much everything, and on using spectacularly long and descriptive names for things.

The user's interest in code beauty as a few motivations:

1. User has to read his code to work on the projects and wants to enjoy doing it.

2. Anyone who reads his code is committing to spend some of their valuable time on "trying to take in and understand his ideas". He considers it an imperative to meet that attitude by trying to give the reader a good experience.

3. Sufficiently well-structured code is probably safer, maybe?

4. More pretty, public Haskell means better training data, which in turn means more pretty, public Haskell

## Orientation

For the full dependency graph and architectural details, see `ARCHITECTURE.md`. Said document is somewhat long and by its nature runs the risk of going stale; if you happen to read it, and reality seems to disagree with the document, reality wins. If the reality isn't pretty, say something.

The heart of the program is the "format declarations". Each subfolder of `src/Slap/` contains a declaration or a family tightly coupled declarations. By describing each target format in the right way, "what would it take to convert format a into format b?" *falls out* of the declarations without us really having to do any bespoke work. Because parallel structure and modularity are pretty, each format or family is broken out into components: `Types.hs`, `Parse.hs`, `Apply.hs`, `Describe.hs`, and `Create.hs` when creation is supported.

`SomePatch.hs` is the spine. `parseSome` is the dispatch point where format-specific types get parsed and then erased behind closures in a `SomePatch` record. Everything downstream works through those closures. 

The current polish references — modules to look at when deciding what slap-shaped looks like — are app/Main.hs, Slap.BPS, Slap.IPS, and Slap.UPS. Other format modules are in varying intermediate states.

Adding a new format would be pleasantly mechanical: new directory with the standard module set, a detection case in `Detect.hs`, a block in `parseSome`, CLI wiring in `Main.hs`, and if the format does direct conversion, a `PatchContents` population plus a row in `directConversionContract` and the `acceptedMetadataFields` / `acceptedConstraints` matrices.

Adding a new format would be pleasantly mechanical: new directory with the standard module set, a detection case in `Detect.hs`, a block in `parseSome`, CLI wiring in `Main.hs`, and if the format does direct conversion, a `PatchContents` population and `FormatSpecification`. The contract system handles everything else. You are almost certainly not going to be asked to add a format. But it serves as an example: most concepts are shaped as they are, in order to make "boundaries and relationships between things" legible, and to make interacting with them delightfully DRY-y.

## Warnings

See something: say something. We want to do things correctly and to be kind to our future selves by not leaving footguns all over the place. Unused imports, and especially shadowed names, are footguns and are aesthetically displeasing on top of this, so, if you see a warning: the user doesn't know, and wants to know.

## Rust

`rusty-slap/` is a Rust staticlib linked via FFI. It owns the computational primitives that'd be slow in Haskell: CRC-32, suffix array construction, BPS diff, and compression. It is for byte crunching specifically. It'll likely take on more of the byte-manipulation duties over time. The FFI boundary lives in `Slap.FFI` and `Slap.Compress`.

## Building

```
make             # builds rusty-slap then Haskell via cabal
make test        # test run: props + integration
```

