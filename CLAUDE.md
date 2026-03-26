# slap — Project Instructions

Multi-format ROM patch tool. Haskell + Rust.

Applies, creates, converts, and inspects ROM patches — IPS, BPS,
UPS, PPF, RUP, and more. Haskell for format logic, Rust for
performance-critical internals (checksums, suffix arrays,
compression) via FFI.

## Design principles

- **Honesty above convenience.** Every byte slap writes must be
  traceable to inputs, user choices, or values true by construction.
  No silently invented data. See the Honesty section for the full
  rule.
- **Respect settled patterns.** The closure-based existential
  (`SomePatch`), `Either String` errors, the conversion contract
  system — these are design decisions. Don't propose alternatives
  without explicitly flagging the departure.
- **Types encode constraints.** If a field can only be two things,
  its type is a sum type, not a raw byte. The compiler enforces
  what convention can't.
- **Haskell > Rust > C.** Pure domain logic in Haskell. Performance-
  critical internals in Rust via FFI. No C dependencies.

## Build and test

```
make           # builds rusty-slap (Rust staticlib) then Haskell via cabal
make test      # props (QuickCheck) + integration (tasty)
```

Direct cabal (when Rust hasn't changed):
```
cabal build --extra-lib-dirs=$(pwd)/rusty-slap/target/release
cabal test  --extra-lib-dirs=$(pwd)/rusty-slap/target/release
```

Filter: `cabal test integration --test-options='-p "$0~/apply/"' --extra-lib-dirs=...`

GHC 9.12.2, GHC2024, `-Wall -O2`, zero warnings (Haskell + Rust + clippy).

## Haskell style

GHC2024 language edition. `-Wall -O2`, zero warnings. Fix the code,
don't disable the warning. Strict fields on data types by default.
No orphan instances.

**Be idiomatic.** Use the right combinator when it fits (`unfoldr`,
`foldl'`, `mapAccumL`, `fromMaybe`, `mapMaybe`, `guard`). Don't
write manual recursion to avoid learning a combinator, but don't
force one in when direct recursion reads better.

**Descriptive names.** `patchOffset` not `off`, `sourceBytes` not
`bs`, `remaining` not `rem`. Spell it out. Domain abbreviations
that ARE the standard term stay abbreviated: CRC, EOF, BPS, IPS,
PPF. When in doubt, spell it out.

**No shadowing, no prime-naming.** Don't reuse a binding name in
an inner scope. Don't use `x'` or `xs''` — if two things need
names, find two real names.

**Pattern matching** over if-chains. Guards over nested cases.
`where` over deeply nested `let`.

**Sugar is good when it's free.** Operator sections, `<$>`, `<*>`,
`LambdaCase` — use them when they make code read better without
hiding meaning.

**Composability.** Small functions that combine well. When a pattern
emerges, make a clean abstraction — three duplicated blocks are
worse than one clear function.

**New code follows the same rules.** Every naming convention here
applies equally to new code, refactors, and helpers introduced
during changes. If a rename pass cleaned something up, the same
patterns shouldn't come back in through new helpers or variables.
This includes test code.

**Qualified imports** for containers (`Map`, `Set`, `Text`,
`ByteString`, `LazyByteString`).

**Proposals should be elegant** — but we discuss fit with the
project's direction before committing.

**Upgrade existing code** when touching it. Better names, better
combinators, clearer structure.

Derive what's natural for the type. Closed enumerations should
have `Enum, Bounded`.

`fromIntegral` is unavoidable in binary format code. Explicit type
conversions at byte boundaries are clearer than type class
abstractions.

## Comments

Comments explain *why*, not *what*. If a comment restates the code next
to it, delete the comment. `-- increment counter` is noise. `-- bit 0
encodes sign, bits 1+ encode magnitude` is signal.

Format spec references are welcome — a comment explaining which RFC
section or which bytes in a header correspond to what saves the next
reader a trip to the spec. Wire format details are not obvious from code.

No `-- TODO` comments in committed code. Either do it or track it
outside the source.

## Working together

The user is learning Haskell alongside building. Teaching is part
of the work — not separate from it.

- Explain new concepts before using them — combinators, type
  signatures, patterns. Say what they mean and why they work.
  Lecture freely.
- Teach the user to write Haskell, not just watch it appear.
  Explain what to write and why, then have them write it.
- Go slow on structural changes and new abstractions. Discuss
  before committing. No bulk code drops.
- When upgrading code to better patterns, show before and after,
  explain what improved.
- If something isn't clear, stop and explain. Understanding
  matters more than progress.
- Commit messages describe what changed and why, in imperative mood
  ("Add X" rather than "Added X"). Keep subject lines under 72
  characters and put detail in the body when it's needed. Avoid
  em dashes in commit messages.

## Error handling

`Either String` for parse/apply errors. Every error path ends in
`hPutStrLn stderr` and `exitFailure` — an error ADT adds type safety
that no consumer benefits from.

Error message convention:
- Format prefix: `"FORMAT: description"` (e.g., `"BPS: input too short"`)
- Magic checks: `"not a FORMAT file (bad magic)"`
- Show actual values when rejecting (`"version byte: 7"` not just
  `"bad version"`)

## Performance

Use `unsafeCreate` from `Data.ByteString.Internal` for building output
buffers in apply functions. For copying from a ByteString into a raw
pointer, use `copyBSRange` (which wraps memcpy) — not byte-by-byte
`mapM_`/`pokeByteOff` loops. The one exception is BPS TargetCopy, where
the source and destination regions overlap and byte-by-byte is
semantically required.

## Honesty

Every byte slap writes must come from one of three sources:
1. The inputs (source file, target file, parsed patch).
2. An explicit user choice (CLI flag).
3. A value that is true by construction — format magic bytes, version
   markers, EOF sentinels, and tool identity (e.g. `"patcher":"slap"`).

If a format field requires content metadata and we don't have it: ask
the user or refuse the operation. Never silently invent data.

This means:
- No hardcoded content metadata. If `createFoo` needs an author
  field, it takes a parameter. If the user didn't pass `--author`,
  the field is empty or the operation is rejected — not filled with
  a default.
- Constrained fields use sum types, not raw bytes. If a field can
  only be Append or Truncate, its type is `data OverflowMode =
  OverflowAppend | OverflowTruncate`, not `Word8`. The compiler
  enforces that nobody fabricates a value.
- Conversion preserves what it can and warns about what it drops.
  The contract system in `Patch.Convert` rejects conversions when
  required metadata is missing. `conversionNotes` reports fields
  that don't survive the conversion. Nothing is silently lost.
- Permissiveness is a feature, not a defect — but it must be
  explicit. If a user supplies a missing field via a flag and that
  gets a conversion over the line, good. If the program quietly
  fills in a zero and pretends, bad.

Every committed test patch is either `real` (real-world), `converted`
(real patch re-diffed in a new format by an external tool), or
`synthetic` (fabricated target, diffed by an external tool). slap
never creates its own test inputs (except NINJA1, pending replacement).

## Rust code style (rusty-slap)

Write idiomatic Rust, not C-in-Rust-syntax. The same principle as
Haskell: prefer the shorter, cleaner way to express something.

- **Iterator adapters over manual loops.** `.map().collect()` over
  `for x in xs { v.push(f(x)) }`. `.scan()` for prefix sums.
  `.take_while()`, `.zip()`, `.enumerate()` over index arithmetic.
  Don't force an adapter chain when a `for` loop reads better, but
  default to iterators and only fall back to loops when the adapter
  chain becomes unreadable.
- **Pattern matching.** `if let`, `match`, destructuring. Never
  `x.is_some()` followed by `x.unwrap()`.
- **`#[inline]` on small hot functions** called in tight loops
  (lcp, varint encode, extend helpers). The compiler usually inlines
  these anyway, but the annotation documents intent.
- **`#[must_use]` on pure functions** that return computed values.
- **Minimal `unsafe`.** Confine `unsafe` to the FFI boundary
  (pointer-to-slice conversion). Algorithmic code must be safe Rust.
  If you reach for `unsafe` inside an algorithm, justify it with a
  benchmark showing the safe version is measurably slower.
- **Newtypes and enums** when they prevent misuse. If a function
  takes both an offset and a length as `usize`, consider whether
  newtypes would catch transposition bugs. Same threshold as Haskell:
  use them when the cost of a bug exceeds the syntactic cost.
- **No `unwrap()` / `expect()` in library code.** Return `Result` or
  `Option`. The FFI boundary converts errors to return codes.
- **Descriptive names** — same convention as the Haskell side.
  Spell it out.
- **`clippy` clean.** `cargo clippy --release` with no warnings.
  Fix the code, don't `#[allow]` the lint.

Release profile: `lto = "fat"`, `codegen-units = 1`,
`panic = "abort"`, `target-cpu=native` via RUSTFLAGS.

## Where to find things

- `src/Patch/` — one module per format (parse, apply, info, explain)
- `src/Patch/SomePatch.hs` — `parseSome` dispatch, `SomePatch` type
- `src/Patch/Convert.hs` — conversion contracts and encoding
- `src/Patch/FFI.hs` — Rust FFI: CRC32, Adler32, BPS diff
- `src/Patch/Compress.hs` — Rust FFI: zlib, gzip, bzip2
- `rusty-slap/` — Rust staticlib (SA-IS, BPS diff, checksums, compression)
- `app/Main.hs` — CLI parsing and command handlers
- `test/` — Props.hs (QuickCheck), Integration/ (tasty integration)
- `Makefile` — orchestrates Rust build then Haskell build
- `NEXT.md` — planned work
