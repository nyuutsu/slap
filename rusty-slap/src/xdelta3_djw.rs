//! DJW secondary compression and decompression: xdelta3's own static
//! multi-table Huffman coder (catalog id 1), defined nowhere but its
//! source — `xdelta3-djw.h`, whose header credits the techniques at
//! work: bzip2's multi-table strategy (Seward), RFC 1951's code-length
//! coding (Gailly/Adler/Deutsch), Hirschberg–LeLewer prefix decoding,
//! and Wheeler's 1-2 run coding. That source is the specification;
//! the decode half owes output matching xdelta3's byte for byte, and
//! the encode half owes streams that decode — its table and grouping
//! choices are its own.
//!
//! Unlike LZMA, DJW is fresh per section: xd3's per-section driver
//! (`xd3_decode_secondary`) holds every section to its own consume-all
//! and exact-output checks, the DJW stream state is literally
//! `struct _djw_stream { int unused; }`, and `xd3_decode_huff`
//! initializes a fresh bit reader on every call. Each section is
//! self-contained — its own table headers, its own bit stream, decoded
//! to exactly its declared size — so this module encodes or decodes
//! one section per call and carries nothing between calls.
//!
//! The wire, as the decoder walks it: a group count (and a sector
//! size, when there is more than one group); a code-length-code table,
//! itself prefix-coded; each group's 256 symbol code lengths, decoded
//! through that table under move-to-front and 1-2 run coding; a
//! canonical prefix decoder built per group; a selector sequence
//! assigning each sector to a group (multi-group only, same MTF/run
//! coding); then sectors of prefix-coded bytes until the output
//! budget fills.
//!
//! The expected output length arrives as an argument: it is the decode
//! loop's terminus — "produce exactly N bytes" — not a framing fact.
//! What goes back is bytes and facts: the decoded output, plus how
//! many input bytes the reader consumed. Whether those facts honor the
//! framing the section was carried under is the caller's judgment, on
//! the other side of the seam.

// ── Wire constants (names track xdelta3-djw.h's defines) ─────────────

/// The byte alphabet every group table codes. (`ALPHABET_SIZE`)
const ALPHABET_SIZE: usize = 256;

/// Maximum bit length of an alphabet code. (`DJW_MAX_CODELEN`)
const MAX_CODE_LENGTH: usize = 20;

/// The code-length-code alphabet: the two run codes, then one symbol
/// per move-to-front index over the 20 possible code lengths.
/// (`DJW_TOTAL_CODES`)
const CODE_LENGTH_CODE_ALPHABET_SIZE: usize = MAX_CODE_LENGTH + 2;

/// How many code-length-code lengths are always present on the wire;
/// a 4-bit count says how many more follow. (`DJW_EXTRA_12OFFSET`,
/// `DJW_EXTRA_CODE_BITS`)
const ALWAYS_CODED_CODE_LENGTH_CODES: usize = 7;
const EXTRA_CODE_COUNT_BITS: usize = 4;

/// Each code-length-code length is a 4-bit field, so its ceiling of
/// 15 (`DJW_MAX_CLCLEN`) is enforced by the field width itself.
const CODE_LENGTH_CODE_LENGTH_BITS: usize = 4;

/// The group count is coded as a 3-bit value minus one, capping the
/// tables at 8. (`DJW_GROUP_BITS`, `DJW_MAX_GROUPS`)
const GROUP_COUNT_BITS: usize = 3;

/// The sector size is coded as a 5-bit value, offset by one and
/// scaled by 5 — so 5..=160 bytes per sector. (`DJW_SECTORSZ_BITS`,
/// `DJW_SECTORSZ_MULT`)
const SECTOR_SIZE_BITS: usize = 5;
const SECTOR_SIZE_MULTIPLIER: usize = 5;

/// Each group-selector code length is a 3-bit field, ceiling 7.
/// (`DJW_GBCLEN_BITS`, `DJW_MAX_GBCLEN`)
const SELECTOR_CODE_LENGTH_BITS: usize = 3;

/// The ceilings those field widths impose, named for the encoder's
/// table design: the largest group count the 3-bit field can carry
/// (`DJW_MAX_GROUPS`), and the deepest code the 4-bit and 3-bit
/// length fields can spell (`DJW_MAX_CLCLEN`, `DJW_MAX_GBCLEN`).
/// The decoder needs no names for them — the widths bound what it
/// can read.
const MAX_GROUP_COUNT: usize = 1 << GROUP_COUNT_BITS;
const MAX_CODE_LENGTH_CODE_LENGTH: usize = (1 << CODE_LENGTH_CODE_LENGTH_BITS) - 1;
const MAX_SELECTOR_CODE_LENGTH: usize = (1 << SELECTOR_CODE_LENGTH_BITS) - 1;

/// The two run codes of Wheeler's 1-2 coding, always the first two
/// symbols of a run-coded alphabet. (`RUN_0`, `RUN_1`)
const RUN_CODE_1: usize = 1;

/// The initial move-to-front order for code-length decoding: zero
/// first, then the five lengths nearly every table uses, then the
/// fifteen ordered by how rarely xd3's measurements saw them — the
/// exact `djw_init_clen_mtf_1_2` ordering, which the encoder and
/// decoder must share for the MTF indices to mean the same lengths.
const INITIAL_CODE_LENGTH_RECENCY_ORDER: [u8; MAX_CODE_LENGTH + 1] = [
    0, 4, 5, 6, 7, 8, 9, 10, 3, 11, 2, 12, 13, 1, 14, 15, 16, 17, 18, 19, 20,
];

// ── Faults ───────────────────────────────────────────────────────────

/// The ways a DJW section can refuse to decode. Every arm is a
/// surfaced verdict — including the paths xd3 guards with assertions
/// (`XD3_ASSERT (gp < groups)`) or trusts to its table arithmetic; a
/// crafted section reaches a named refusal here, never undefined
/// behavior.
#[derive(Debug, PartialEq, Eq)]
pub enum DjwFault {
    /// The caller asked for zero output bytes. xd3 rejects this
    /// before reading a single bit ("invalid input"), and so do we —
    /// a section that produces nothing has no reason to exist.
    OutputBudgetIsZero,
    /// The declared output exceeds what the section's bits could code:
    /// every output byte costs at least one bit under its group table,
    /// so a section can never produce more bytes than it holds bits.
    /// Checked before any size-derived bookkeeping — the sector count
    /// and selector sequence scale with the declaration, and a
    /// declaration the input's own bytes never justify must not
    /// command that work.
    DeclaredOutputExceedsBitCapacity { declared: usize, bit_capacity: usize },
    /// The bit stream ended before the section's declared output was
    /// produced. (xd3: "secondary decoder end of input")
    InputExhausted,
    /// A prefix code ran past the deepest length of the table decoding
    /// it, or landed outside the table's assigned codes — the bits do
    /// not name a symbol. (xd3: "secondary decoder invalid code")
    CodeOutsideTable,
    /// A repeat run carried past the end of the sequence it was
    /// filling. (xd3: "secondary decoder invalid repeat code")
    RepeatRunOvershootsSequence,
    /// A sector selector named a group the section never declared.
    /// Believed structurally unreachable — the selector queue only
    /// ever holds declared group numbers — but xd3 spends an assertion
    /// on it, so we spend a verdict.
    SelectorNamesMissingGroup { selector: u8, group_count: usize },
}

impl std::fmt::Display for DjwFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DjwFault::OutputBudgetIsZero => {
                write!(formatter, "a DJW section cannot decode to zero bytes")
            }
            DjwFault::DeclaredOutputExceedsBitCapacity { declared, bit_capacity } => {
                write!(
                    formatter,
                    "the section declares {declared} output bytes but holds only {bit_capacity} bits, and each output byte costs at least one bit"
                )
            }
            DjwFault::InputExhausted => {
                write!(formatter, "the bit stream ended before the declared output was produced")
            }
            DjwFault::CodeOutsideTable => {
                write!(formatter, "a prefix code fell outside the table decoding it")
            }
            DjwFault::RepeatRunOvershootsSequence => {
                write!(formatter, "a repeat run carried past the end of its coded sequence")
            }
            DjwFault::SelectorNamesMissingGroup { selector, group_count } => {
                write!(
                    formatter,
                    "a sector selector named group {selector} but the section declares only {group_count}"
                )
            }
        }
    }
}

// ── Bit reading ──────────────────────────────────────────────────────

/// The bit stream convention shared by every DJW field
/// (`xd3_decode_bits` / `bit_state`): bytes are consumed in order;
/// within a byte, bits are consumed from the least significant up;
/// multi-bit values and prefix codes assemble those bits most
/// significant first. Consumption is counted in whole bytes — a byte
/// is consumed the moment its first bit is read, which is also how
/// xd3's input pointer moves.
struct BitReader<'section> {
    section_bytes: &'section [u8],
    consumed_byte_count: usize,
    current_byte: u8,
    /// The next bit's mask, `0x01..=0x80`; `0x100` means the current
    /// byte is spent and the next read fetches. (`BIT_STATE_DECODE_INIT`
    /// starts spent.)
    current_mask: u16,
}

const BYTE_SPENT: u16 = 0x100;

impl<'section> BitReader<'section> {
    fn over(section_bytes: &'section [u8]) -> Self {
        BitReader {
            section_bytes,
            consumed_byte_count: 0,
            current_byte: 0,
            current_mask: BYTE_SPENT,
        }
    }

    fn read_bit(&mut self) -> Result<bool, DjwFault> {
        if self.current_mask == BYTE_SPENT {
            self.current_byte = *self
                .section_bytes
                .get(self.consumed_byte_count)
                .ok_or(DjwFault::InputExhausted)?;
            self.consumed_byte_count += 1;
            self.current_mask = 1;
        }
        let bit = self.current_byte & (self.current_mask as u8) != 0;
        self.current_mask <<= 1;
        Ok(bit)
    }

    /// Read a fixed-width value, most significant bit first.
    fn read_value(&mut self, bit_count: usize) -> Result<usize, DjwFault> {
        (0..bit_count).try_fold(0, |value, _| Ok((value << 1) | self.read_bit()? as usize))
    }

    fn consumed_byte_count(&self) -> usize {
        self.consumed_byte_count
    }
}

// ── Canonical prefix decoding ────────────────────────────────────────

/// A canonical prefix decoder in the Hirschberg–LeLewer base/limit
/// form (`djw_build_decoder`): per code length, the first code value
/// assigned (`base`), the last (`limit`), and the symbols laid out in
/// code order. Decoding reads bits into a growing code and stops at
/// the first length whose limit admits it.
///
/// Construction is total over any code-length set, exactly as xd3's
/// is: a set that assigns no codes builds a decoder whose every
/// decode refuses ('CodeOutsideTable'), rather than refusing at build
/// — a group that is never selected may legally carry such a table.
struct CanonicalPrefixDecoder {
    /// The coded symbols, shortest code first, ties in symbol order.
    symbols_in_code_order: Vec<u8>,
    /// Indexed by code length; meaningful from `shortest_code_length`
    /// to `longest_code_length`.
    first_code_at_length: Vec<usize>,
    last_code_at_length: Vec<usize>,
    shortest_code_length: usize,
    /// Zero when the table assigns no codes at all.
    longest_code_length: usize,
}

impl CanonicalPrefixDecoder {
    /// Build from one code length per alphabet symbol (zero = symbol
    /// not coded). Every caller's lengths are field-width bounded
    /// (4-bit, 3-bit) or drawn from the MTF queue's 0..=20 contents,
    /// so they always fit the counting array.
    fn from_code_lengths(code_lengths: &[u8]) -> CanonicalPrefixDecoder {
        let mut count_at_length = [0usize; MAX_CODE_LENGTH + 1];
        for &length in code_lengths {
            count_at_length[length as usize] += 1;
        }

        let longest_code_length = (1..=MAX_CODE_LENGTH)
            .rev()
            .find(|&length| count_at_length[length] != 0)
            .unwrap_or(0);
        if longest_code_length == 0 {
            return CanonicalPrefixDecoder {
                symbols_in_code_order: Vec::new(),
                first_code_at_length: Vec::new(),
                last_code_at_length: Vec::new(),
                shortest_code_length: 0,
                longest_code_length: 0,
            };
        }
        let shortest_code_length = (1..=MAX_CODE_LENGTH)
            .find(|&length| count_at_length[length] != 0)
            .expect("a longest length exists, so a shortest does");

        // first_symbol_at_length is xd3's tmp_base: where each
        // length's symbols begin in code order. first_code_at_length
        // can never underflow — inductively, each length's last code
        // sits at least one past its symbol count, so the doubled
        // code space always covers the symbols placed so far.
        let mut first_symbol_at_length = vec![0usize; longest_code_length + 1];
        let mut first_code_at_length = vec![0usize; longest_code_length + 1];
        let mut last_code_at_length = vec![0usize; longest_code_length + 1];
        last_code_at_length[shortest_code_length] = count_at_length[shortest_code_length] - 1;
        for length in (shortest_code_length + 1)..=longest_code_length {
            let code_space_floor = (last_code_at_length[length - 1] + 1) << 1;
            first_symbol_at_length[length] =
                first_symbol_at_length[length - 1] + count_at_length[length - 1];
            last_code_at_length[length] = code_space_floor + count_at_length[length] - 1;
            first_code_at_length[length] = code_space_floor - first_symbol_at_length[length];
        }

        let coded_symbol_count = first_symbol_at_length[longest_code_length]
            + count_at_length[longest_code_length];
        let mut symbols_in_code_order = vec![0u8; coded_symbol_count];
        let mut next_slot_at_length = first_symbol_at_length;
        for (symbol, &length) in code_lengths.iter().enumerate() {
            if length != 0 {
                symbols_in_code_order[next_slot_at_length[length as usize]] = symbol as u8;
                next_slot_at_length[length as usize] += 1;
            }
        }

        CanonicalPrefixDecoder {
            symbols_in_code_order,
            first_code_at_length,
            last_code_at_length,
            shortest_code_length,
            longest_code_length,
        }
    }

    /// Decode one symbol (`djw_decode_symbol`): grow the code a bit at
    /// a time until a length admits it, then look it up in the symbol
    /// order. The lengths the table assigns bound the walk — a code
    /// still unadmitted at the deepest one is outside the table, and
    /// falling out of the loop is that verdict, not a guard inside it.
    fn decode_symbol(&self, reader: &mut BitReader) -> Result<usize, DjwFault> {
        let mut code = 0usize;
        for length in 1..=self.longest_code_length {
            code = (code << 1) | reader.read_bit()? as usize;
            if length >= self.shortest_code_length && code <= self.last_code_at_length[length] {
                return self.symbol_assigned_to(length, code);
            }
        }
        Err(DjwFault::CodeOutsideTable)
    }

    /// The symbol an admitted code of the given length names. Both
    /// exits xd3 reaches by table arithmetic are checked reads here —
    /// a code below its length's first code, or an offset past the
    /// coded symbols, is 'CodeOutsideTable', never a stray index.
    fn symbol_assigned_to(&self, length: usize, code: usize) -> Result<usize, DjwFault> {
        let code_order_offset = code
            .checked_sub(self.first_code_at_length[length])
            .ok_or(DjwFault::CodeOutsideTable)?;
        self.symbols_in_code_order
            .get(code_order_offset)
            .copied()
            .map(usize::from)
            .ok_or(DjwFault::CodeOutsideTable)
    }
}

// ── Move-to-front + 1-2 run decoding ─────────────────────────────────

/// A move-to-front queue over the values a run-coded sequence emits:
/// code lengths for the group tables, group numbers for the selector
/// sequence. Decoded symbols above the run codes are recency indices
/// into this queue.
struct MoveToFrontQueue {
    recency_order: Vec<u8>,
}

impl MoveToFrontQueue {
    fn of_code_lengths() -> MoveToFrontQueue {
        MoveToFrontQueue { recency_order: INITIAL_CODE_LENGTH_RECENCY_ORDER.to_vec() }
    }

    /// The selector queue: group numbers in order, one entry per
    /// selector-alphabet symbol. The last entry sits beyond every
    /// reachable recency index (indices run to the alphabet's top
    /// symbol minus one), which is exactly why a selector can never
    /// name a group the section didn't declare.
    fn of_group_numbers(selector_alphabet_size: usize) -> MoveToFrontQueue {
        MoveToFrontQueue {
            recency_order: (0..selector_alphabet_size as u8).collect(),
        }
    }

    fn front(&self) -> u8 {
        self.recency_order[0]
    }

    /// Pull the value at a recency index to the front and return it
    /// (`djw_update_mtf`). The index is in range for every reachable
    /// decode — the alphabet sizes and queue lengths are built in
    /// lockstep — and an out-of-range one is a table-construction bug
    /// this decoder would rather surface than silently mask, so the
    /// checked read maps onto the same refusal as a code outside its
    /// table.
    fn pull_to_front(&mut self, recency_index: usize) -> Result<u8, DjwFault> {
        if recency_index >= self.recency_order.len() {
            return Err(DjwFault::CodeOutsideTable);
        }
        self.recency_order[..=recency_index].rotate_right(1);
        Ok(self.recency_order[0])
    }
}

/// What a run-coded decode owes its next slots. The three states are
/// mutually exclusive — xd3 keeps them as two zero-sentinel counters,
/// but their exclusion is structural, so here it is a sum. A decode
/// step consumes the state and answers with the next one.
enum PendingWork {
    /// Nothing owed: the next slot wants a fresh symbol off the wire.
    DecodeNextSymbol,
    /// A run in progress: the queue's front value, this many more times.
    EmitRepeats { remaining: usize },
    /// A decoded recency index whose pull-to-front hasn't landed yet —
    /// real intermediate state, because skipped zeros can be emitted
    /// between the decode and the pull.
    PullToFront { recency_index: usize },
}

/// Decode a move-to-front, 1-2 run-coded value sequence
/// (`djw_decode_1_2`): symbols 0 and 1 accumulate a binary run of the
/// queue's front value, higher symbols pull a recency index to the
/// front and emit it. The priority per slot — zero-skip first, then
/// whatever 'PendingWork' is owed — is the source's exactly.
///
/// `zero_skip_stride` is the group-table special case: a symbol whose
/// previous group coded length zero is skipped as zero here too,
/// never spending a wire symbol (the encoder's zero set is identical
/// across groups, so the first group's zeros tell the rest). Zero
/// disables the rule; the selector sequence runs with it disabled.
fn decode_run_coded_values(
    reader: &mut BitReader,
    decoder: &CanonicalPrefixDecoder,
    queue: &mut MoveToFrontQueue,
    element_count: usize,
    zero_skip_stride: usize,
) -> Result<Vec<u8>, DjwFault> {
    // Pre-reserve only up to the largest group-table sequence (eight
    // groups of 256 lengths): a selector sequence's element count is
    // wire-derived and a hostile one must not command an allocation.
    let mut values: Vec<u8> = Vec::with_capacity(element_count.min(ALPHABET_SIZE * 8));
    let mut pending = PendingWork::DecodeNextSymbol;
    let mut next_run_digit_position = 0u32;

    while values.len() < element_count {
        if zero_skip_stride != 0
            && values.len() >= zero_skip_stride
            && values[values.len() - zero_skip_stride] == 0
        {
            values.push(0);
            continue;
        }
        pending = match pending {
            PendingWork::EmitRepeats { remaining } => {
                values.push(queue.front());
                match remaining - 1 {
                    0         => PendingWork::DecodeNextSymbol,
                    still_due => PendingWork::EmitRepeats { remaining: still_due },
                }
            }
            PendingWork::PullToFront { recency_index } => {
                values.push(queue.pull_to_front(recency_index)?);
                PendingWork::DecodeNextSymbol
            }
            PendingWork::DecodeNextSymbol => {
                let symbol = decoder.decode_symbol(reader)?;
                if symbol <= RUN_CODE_1 {
                    // Each run code contributes its digit at the next
                    // binary position. The wire grammar puts no
                    // ceiling on consecutive run codes, so a count
                    // past the machine word is input the format
                    // admits and this decoder must answer. The answer
                    // is already decided: a contribution the word
                    // cannot hold — the shift past its width, or the
                    // digit's bits shifted out — is necessarily
                    // larger than any sequence being filled, so it is
                    // the overrun verdict the moment it appears.
                    let run_contribution = (symbol + 1)
                        .checked_shl(next_run_digit_position)
                        .filter(|&contribution| contribution != 0)
                        .ok_or(DjwFault::RepeatRunOvershootsSequence)?;
                    next_run_digit_position += 1;
                    PendingWork::EmitRepeats { remaining: run_contribution }
                } else {
                    next_run_digit_position = 0;
                    PendingWork::PullToFront { recency_index: symbol - 1 }
                }
            }
        };
    }

    match pending {
        // A run still owing values past the sequence's end is the
        // wire's error. An unlanded pull is dropped without complaint,
        // as the source drops it.
        PendingWork::EmitRepeats { .. } => Err(DjwFault::RepeatRunOvershootsSequence),
        PendingWork::DecodeNextSymbol | PendingWork::PullToFront { .. } => Ok(values),
    }
}

// ── The section decode ───────────────────────────────────────────────

/// What one section's decode produced: the decoded bytes, and how
/// many input bytes the reader consumed before the output filled. A
/// shortfall against the section's length means trailing bytes the
/// decode never needed — a framing fact for the caller to judge.
#[derive(Debug)]
pub struct DjwDecodeOutcome {
    pub decoded_bytes: Vec<u8>,
    pub consumed_input_length: usize,
}

/// Decode one DJW-compressed section to exactly
/// `expected_output_length` bytes. On failure the returned message
/// names the cause, for the caller to wrap as it sees fit.
pub fn djw_decompress(
    section_bytes: &[u8],
    expected_output_length: usize,
) -> Result<DjwDecodeOutcome, String> {
    decode_section(section_bytes, expected_output_length).map_err(|fault| fault.to_string())
}

fn decode_section(
    section_bytes: &[u8],
    expected_output_length: usize,
) -> Result<DjwDecodeOutcome, DjwFault> {
    if expected_output_length == 0 {
        return Err(DjwFault::OutputBudgetIsZero);
    }
    let bit_capacity = section_bytes.len().saturating_mul(8);
    if expected_output_length > bit_capacity {
        return Err(DjwFault::DeclaredOutputExceedsBitCapacity {
            declared: expected_output_length,
            bit_capacity,
        });
    }

    let mut reader = BitReader::over(section_bytes);

    let group_count = reader.read_value(GROUP_COUNT_BITS)? + 1;
    let sector_size = if group_count > 1 {
        (reader.read_value(SECTOR_SIZE_BITS)? + 1) * SECTOR_SIZE_MULTIPLIER
    } else {
        // A single group needs no sectoring; the whole output is one
        // sector under the one table.
        expected_output_length
    };
    let sector_count = 1 + (expected_output_length - 1) / sector_size;

    // The code-length code: how the group tables' own lengths are
    // prefix-coded (djw_decode_clclen). The wire carries the first
    // seven lengths always and a 4-bit count of extras; the field
    // widths bound every value.
    let coded_length_count =
        reader.read_value(EXTRA_CODE_COUNT_BITS)? + ALWAYS_CODED_CODE_LENGTH_CODES;
    let mut code_length_code_lengths = [0u8; CODE_LENGTH_CODE_ALPHABET_SIZE];
    for length_slot in code_length_code_lengths.iter_mut().take(coded_length_count) {
        *length_slot = reader.read_value(CODE_LENGTH_CODE_LENGTH_BITS)? as u8;
    }
    let code_length_decoder =
        CanonicalPrefixDecoder::from_code_lengths(&code_length_code_lengths);

    // Every group's 256 code lengths, as one run-coded sequence with
    // the zero-skip rule keyed to the previous group (djw_decode_prefix).
    let mut code_length_queue = MoveToFrontQueue::of_code_lengths();
    let group_code_lengths = decode_run_coded_values(
        &mut reader,
        &code_length_decoder,
        &mut code_length_queue,
        ALPHABET_SIZE * group_count,
        ALPHABET_SIZE,
    )?;
    let group_decoders: Vec<CanonicalPrefixDecoder> = group_code_lengths
        .chunks_exact(ALPHABET_SIZE)
        .map(CanonicalPrefixDecoder::from_code_lengths)
        .collect();

    // The selector sequence: which group decodes each sector
    // (multi-group only; one group decodes everything otherwise).
    let sector_selectors: Option<Vec<u8>> = if group_count > 1 {
        Some(decode_sector_selectors(&mut reader, group_count, sector_count)?)
    } else {
        None
    };

    // The sector walk: every output byte is one prefix code under its
    // sector's group table. Grown rather than pre-reserved so a tiny
    // hostile section declaring an enormous output exhausts its bits
    // long before it exhausts memory.
    let mut decoded_bytes: Vec<u8> = Vec::new();
    for sector_index in 0..sector_count {
        let sector_decoder = match &sector_selectors {
            None => &group_decoders[0],
            Some(selectors) => {
                let selector = selectors[sector_index];
                group_decoders.get(selector as usize).ok_or(
                    DjwFault::SelectorNamesMissingGroup { selector, group_count },
                )?
            }
        };
        let sector_output_length =
            sector_size.min(expected_output_length - decoded_bytes.len());
        for _ in 0..sector_output_length {
            decoded_bytes.push(sector_decoder.decode_symbol(&mut reader)? as u8);
        }
    }

    Ok(DjwDecodeOutcome {
        decoded_bytes,
        consumed_input_length: reader.consumed_byte_count(),
    })
}

/// Decode the selector sequence: one 3-bit code length per
/// selector-alphabet symbol (the group numbers plus the run codes'
/// extra slot), a canonical decoder over them, then the sectors' group
/// numbers under MTF and run coding.
fn decode_sector_selectors(
    reader: &mut BitReader,
    group_count: usize,
    sector_count: usize,
) -> Result<Vec<u8>, DjwFault> {
    let selector_alphabet_size = group_count + 1;
    let mut selector_code_lengths = vec![0u8; selector_alphabet_size];
    for length_slot in selector_code_lengths.iter_mut() {
        *length_slot = reader.read_value(SELECTOR_CODE_LENGTH_BITS)? as u8;
    }
    let selector_decoder = CanonicalPrefixDecoder::from_code_lengths(&selector_code_lengths);
    let mut selector_queue = MoveToFrontQueue::of_group_numbers(selector_alphabet_size);
    decode_run_coded_values(reader, &selector_decoder, &mut selector_queue, sector_count, 0)
}

// ── Bit writing ──────────────────────────────────────────────────────

/// The write-side mirror of `BitReader` (`xd3_encode_bits`): bits land
/// LSB-first within each byte, multi-bit values and prefix codes most
/// significant bit first. `finish` pushes the final partial byte, its
/// unused high bits zero — the decoder never reads them, its output
/// budget filling first.
struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    current_mask: u8,
}

impl BitWriter {
    fn new() -> BitWriter {
        BitWriter { bytes: Vec::new(), current_byte: 0, current_mask: 0x01 }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= self.current_mask;
        }
        if self.current_mask == 0x80 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.current_mask = 0x01;
        } else {
            self.current_mask <<= 1;
        }
    }

    /// Write a fixed-width value, most significant bit first.
    fn write_value(&mut self, bit_count: usize, value: usize) {
        for position in (0..bit_count).rev() {
            self.write_bit(value >> position & 1 != 0);
        }
    }

    /// Write one symbol's canonical code, most significant bit first —
    /// the order `decode_symbol` grows its code in.
    fn write_prefix_code(&mut self, code: PrefixCode) {
        for position in (0..code.bit_length).rev() {
            self.write_bit(code.bits >> position & 1 != 0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.current_mask != 0x01 {
            self.bytes.push(self.current_byte);
        }
        self.bytes
    }
}

// ── Canonical code assignment (the encode half) ──────────────────────

/// One symbol's canonical prefix code: the code value in the low
/// `bit_length` bits of `bits`.
#[derive(Copy, Clone)]
struct PrefixCode {
    bits: u32,
    bit_length: u8,
}

/// Assign canonical codes from one code length per symbol (zero =
/// symbol not coded): the inverse of
/// `CanonicalPrefixDecoder::from_code_lengths`, advancing the same
/// doubled code-space floor per length with symbols ascending within
/// one, so every assigned code decodes to the symbol it was assigned
/// to. Slot `s` of the result is `None` where `code_lengths[s]` is
/// zero.
fn assign_canonical_codes(code_lengths: &[u8]) -> Vec<Option<PrefixCode>> {
    let mut count_at_length = [0u32; MAX_CODE_LENGTH + 1];
    for &length in code_lengths {
        count_at_length[length as usize] += 1;
    }
    count_at_length[0] = 0;

    let mut next_code_at_length = [0u32; MAX_CODE_LENGTH + 1];
    let mut code_space_floor = 0u32;
    for length in 1..=MAX_CODE_LENGTH {
        code_space_floor = (code_space_floor + count_at_length[length - 1]) << 1;
        next_code_at_length[length] = code_space_floor;
    }

    code_lengths
        .iter()
        .map(|&length| {
            if length == 0 {
                return None;
            }
            let assigned = next_code_at_length[length as usize];
            next_code_at_length[length as usize] += 1;
            Some(PrefixCode { bits: assigned, bit_length: length })
        })
        .collect()
}

// ── Length-limited code lengths (package-merge) ──────────────────────

/// Optimal code lengths under a maximum length, by package-merge:
/// starting from the leaves sorted by weight, each of the remaining
/// `length_limit - 1` rounds pairs the previous round's items into
/// packages and merges the leaves back in; the cheapest `2n - 2` items
/// of the last round are the solution, and a symbol's code length is
/// how many of them its leaf appears in. Zero-frequency symbols get no
/// code; a single coded symbol gets the one-bit code directly, the
/// `2n - 2 = 0` case the round structure cannot express.
fn length_limited_code_lengths(frequencies: &[u64], length_limit: usize) -> Vec<u8> {
    let mut lengths = vec![0u8; frequencies.len()];
    let mut leaves: Vec<Package> = frequencies
        .iter()
        .enumerate()
        .filter(|&(_, &frequency)| frequency > 0)
        .map(|(symbol, &frequency)| Package { weight: frequency, leaves: vec![symbol as u16] })
        .collect();
    match leaves.len() {
        0 => return lengths,
        1 => {
            lengths[leaves[0].leaves[0] as usize] = 1;
            return lengths;
        }
        coded_symbol_count => debug_assert!(
            coded_symbol_count <= 1 << length_limit,
            "{coded_symbol_count} symbols cannot fit codes of at most {length_limit} bits"
        ),
    }
    leaves.sort_by_key(|package| package.weight);

    let mut round = leaves.clone();
    for _ in 1..length_limit {
        let paired = round
            .chunks_exact(2)
            .map(|pair| Package {
                weight: pair[0].weight + pair[1].weight,
                leaves: [pair[0].leaves.as_slice(), pair[1].leaves.as_slice()].concat(),
            })
            .collect::<Vec<Package>>();
        round = merge_by_weight(leaves.clone(), paired);
    }

    for package in round.iter().take(2 * leaves.len() - 2) {
        for &leaf in &package.leaves {
            lengths[leaf as usize] += 1;
        }
    }
    lengths
}

/// A package-merge item: its weight, and the leaf symbols inside it,
/// multiplicity and all.
#[derive(Clone)]
struct Package {
    weight: u64,
    leaves: Vec<u16>,
}

/// Merge two weight-sorted package lists, keeping the sort.
fn merge_by_weight(left: Vec<Package>, right: Vec<Package>) -> Vec<Package> {
    let mut merged = Vec::with_capacity(left.len() + right.len());
    let mut left_items = left.into_iter().peekable();
    let mut right_items = right.into_iter().peekable();
    loop {
        let left_is_lighter = match (left_items.peek(), right_items.peek()) {
            (Some(from_left), Some(from_right)) => from_left.weight <= from_right.weight,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return merged,
        };
        let next = if left_is_lighter { left_items.next() } else { right_items.next() };
        merged.push(next.expect("the peeked side has an item"));
    }
}

// ── Move-to-front + 1-2 run encoding ─────────────────────────────────

impl MoveToFrontQueue {
    /// Where a value currently sits in the recency order: the index
    /// the decoder will pull. The tiny queue makes the scan the whole
    /// cost.
    fn recency_index_of(&self, value: u8) -> usize {
        self.recency_order
            .iter()
            .position(|&held| held == value)
            .expect("every encodable value is in its queue")
    }
}

/// Run-code one value sequence into wire symbols: a maximal run of the
/// queue's front value becomes its 1-2 digits (least significant
/// first, RUN_0 carrying 1 and RUN_1 carrying 2 at each binary
/// position), any other value the pull of its recency index. The
/// inverse of `decode_run_coded_values`, with the zero-skip already
/// applied by the caller: these are wire slots only.
fn run_code_values(values: &[u8], queue: &mut MoveToFrontQueue) -> Vec<u8> {
    let mut wire_symbols = Vec::new();
    let mut position = 0;
    while position < values.len() {
        if values[position] == queue.front() {
            let run_start = position;
            while position < values.len() && values[position] == queue.front() {
                position += 1;
            }
            let mut remaining = position - run_start;
            while remaining > 0 {
                // remaining = digit + 2·rest with digit in {1, 2}:
                // bijective base 2, the unique digit string
                // `decode_run_coded_values` resums.
                let digit = 2 - (remaining & 1);
                wire_symbols.push((digit - 1) as u8);
                remaining = (remaining - digit) / 2;
            }
        } else {
            let recency_index = queue.recency_index_of(values[position]);
            wire_symbols.push((recency_index + 1) as u8);
            queue
                .pull_to_front(recency_index)
                .expect("the scanned index is within the queue");
            position += 1;
        }
    }
    wire_symbols
}

/// Tally one run-coded sequence's wire symbols, the frequencies its
/// prefix table is designed from.
fn wire_symbol_frequencies(wire_symbols: &[u8], alphabet_size: usize) -> Vec<u64> {
    let mut frequencies = vec![0u64; alphabet_size];
    for &symbol in wire_symbols {
        frequencies[symbol as usize] += 1;
    }
    frequencies
}

/// Emit one run-coded sequence under its assigned codes.
fn write_wire_symbols(
    writer: &mut BitWriter,
    codes: &[Option<PrefixCode>],
    wire_symbols: &[u8],
) {
    for &symbol in wire_symbols {
        let code = codes[symbol as usize].expect("every emitted wire symbol was given a code");
        writer.write_prefix_code(code);
    }
}

// ── The section encode ───────────────────────────────────────────────

/// slap's sector size. Any multiple of 5 in [5, 160] is legal wire;
/// 20 balances the per-sector selector cost against how locally the
/// tables can specialize. xd3 keys its choice on section kind and
/// size; ours is one number until measurement says otherwise.
const SECTOR_SIZE: usize = 20;

/// Below this many sectors the table overhead outweighs anything the
/// clustering could specialize, so the multi-table candidate is not
/// built at all.
const FEWEST_SECTORS_WORTH_CLUSTERING: usize = 32;

/// One candidate group per this many sectors — half the clustering
/// gate, so the smallest clustered section starts at the two-group
/// floor.
const SECTORS_PER_CANDIDATE_GROUP: usize = FEWEST_SECTORS_WORTH_CLUSTERING / 2;

/// The refinement's round cap, xd3's own (`DJW_MAX_ITER`); the loop
/// usually settles earlier, the moment an assignment repeats.
const MAX_CLUSTERING_ROUNDS: usize = 6;

/// One emission plan: each group's 256 code lengths (zero = symbol
/// absent) and which group codes each sector. Every group carries the
/// same zero set — the code-length transmission's skip rule makes
/// that a wire obligation, not a preference ('write_group_code_lengths').
struct EmissionPlan {
    sector_size: usize,
    sector_groups: Vec<u8>,
    group_code_lengths: Vec<Vec<u8>>,
}

/// Compress one section into a DJW bit stream. Total, and the inverse
/// of `djw_decompress`: any non-empty input yields a stream that
/// decodes back byte-identically, consuming the whole stream. Two
/// candidates are built — one table for the whole section, and where
/// the section is big enough, sectors clustered over several — and the
/// smaller emission wins. The caller holds the winner against the
/// plain bytes; an empty input comes back as an empty stream, though
/// no caller compresses one.
pub fn djw_compress(plain_section: &[u8]) -> Vec<u8> {
    if plain_section.is_empty() {
        return Vec::new();
    }
    let single_table_emission = emit_plan(plain_section, &single_table_plan(plain_section));
    match clustered_plan(plain_section) {
        None => single_table_emission,
        Some(plan) => {
            let clustered_emission = emit_plan(plain_section, &plan);
            if clustered_emission.len() < single_table_emission.len() {
                clustered_emission
            } else {
                single_table_emission
            }
        }
    }
}

fn byte_frequencies(bytes: &[u8]) -> Vec<u64> {
    let mut frequencies = vec![0u64; ALPHABET_SIZE];
    for &byte in bytes {
        frequencies[byte as usize] += 1;
    }
    frequencies
}

/// Code lengths for one wire table: package-merge under the table's
/// length limit, with xd3's lone-symbol convention mirrored — a table
/// that would code exactly one symbol gets a phantom second at
/// frequency 1 (symbol 0, or the top symbol when 0 is the real one),
/// so no wire table ever holds a lone code (`djw_build_prefix` does
/// the same faking).
fn code_lengths_for_table(frequencies: &[u64], length_limit: usize) -> Vec<u8> {
    let coded_symbol_count = frequencies.iter().filter(|&&frequency| frequency > 0).count();
    if coded_symbol_count != 1 {
        return length_limited_code_lengths(frequencies, length_limit);
    }
    let mut faked_frequencies = frequencies.to_vec();
    let phantom_symbol = if frequencies[0] > 0 { frequencies.len() - 1 } else { 0 };
    faked_frequencies[phantom_symbol] = 1;
    length_limited_code_lengths(&faked_frequencies, length_limit)
}

/// The one-table plan: the whole output is a single sector under a
/// table designed from the section's own byte frequencies.
fn single_table_plan(plain_section: &[u8]) -> EmissionPlan {
    EmissionPlan {
        sector_size: plain_section.len(),
        sector_groups: vec![0],
        group_code_lengths: vec![code_lengths_for_table(
            &byte_frequencies(plain_section),
            MAX_CODE_LENGTH,
        )],
    }
}

/// The multi-table plan: sectors clustered onto up to eight tables by
/// iterative refinement. Groups seed on equal runs of consecutive
/// sectors; each round reassigns every sector to the group whose
/// table codes it cheapest and redesigns each group's table from its
/// sectors, until the assignment repeats or the round cap. Groups no
/// sector chose are dropped and the rest renumbered. `None` when the
/// section has too few sectors to specialize over, or when the
/// refinement settles on one group anyway — the single-table plan
/// already is that emission.
fn clustered_plan(plain_section: &[u8]) -> Option<EmissionPlan> {
    let sectors: Vec<&[u8]> = plain_section.chunks(SECTOR_SIZE).collect();
    if sectors.len() < FEWEST_SECTORS_WORTH_CLUSTERING {
        return None;
    }
    let group_count = (sectors.len() / SECTORS_PER_CANDIDATE_GROUP).clamp(2, MAX_GROUP_COUNT);
    let global_frequencies = byte_frequencies(plain_section);

    let mut sector_groups: Vec<u8> = (0..sectors.len())
        .map(|sector_index| (sector_index * group_count / sectors.len()) as u8)
        .collect();
    let mut group_tables =
        design_group_tables(&sectors, &sector_groups, group_count, &global_frequencies);
    for _ in 0..MAX_CLUSTERING_ROUNDS {
        let reassigned: Vec<u8> = sectors
            .iter()
            .map(|sector| cheapest_group(sector, &group_tables))
            .collect();
        if reassigned == sector_groups {
            break;
        }
        sector_groups = reassigned;
        group_tables =
            design_group_tables(&sectors, &sector_groups, group_count, &global_frequencies);
    }

    // Drop the groups no sector chose, renumbering the survivors in
    // their original order: group numbers stay dense, which is all the
    // wire asks of them.
    let mut renumbering: Vec<Option<u8>> = vec![None; group_count];
    let mut surviving_tables: Vec<Vec<u8>> = Vec::new();
    for group in 0..group_count {
        if sector_groups.iter().any(|&chosen| chosen as usize == group) {
            renumbering[group] = Some(surviving_tables.len() as u8);
            surviving_tables.push(group_tables[group].clone());
        }
    }
    if surviving_tables.len() < 2 {
        return None;
    }
    for chosen in sector_groups.iter_mut() {
        *chosen = renumbering[*chosen as usize].expect("a chosen group survives the drop");
    }
    Some(EmissionPlan {
        sector_size: SECTOR_SIZE,
        sector_groups,
        group_code_lengths: surviving_tables,
    })
}

/// Design each group's table from the sectors currently assigned to it.
/// A symbol the group's own sectors never use, but the section does,
/// rides at frequency one — xd3's own concession (`evolve_freq`) —
/// keeping the zero set identical across groups, the wire obligation
/// `EmissionPlan` records.
fn design_group_tables(
    sectors: &[&[u8]],
    sector_groups: &[u8],
    group_count: usize,
    global_frequencies: &[u64],
) -> Vec<Vec<u8>> {
    let mut per_group_frequencies = vec![vec![0u64; ALPHABET_SIZE]; group_count];
    for (sector, &group) in sectors.iter().zip(sector_groups) {
        for &byte in *sector {
            per_group_frequencies[group as usize][byte as usize] += 1;
        }
    }
    per_group_frequencies
        .iter_mut()
        .map(|frequencies| {
            for (symbol, frequency) in frequencies.iter_mut().enumerate() {
                if *frequency == 0 && global_frequencies[symbol] > 0 {
                    *frequency = 1;
                }
            }
            code_lengths_for_table(frequencies, MAX_CODE_LENGTH)
        })
        .collect()
}

/// The group whose current table codes a sector in the fewest bits,
/// ties to the lower group number.
fn cheapest_group(sector: &[u8], group_tables: &[Vec<u8>]) -> u8 {
    let cost_under = |table: &Vec<u8>| -> u64 {
        sector.iter().map(|&byte| table[byte as usize] as u64).sum()
    };
    group_tables
        .iter()
        .enumerate()
        .min_by_key(|&(group, table)| (cost_under(table), group))
        .map(|(group, _table)| group as u8)
        .expect("a plan holds at least one group")
}

/// Serialize one plan to the wire, in the decoder's reading order: the
/// group count; the sector size and, later, the selector sequence when
/// there is more than one group; the groups' code-length transmission;
/// then every sector's bytes as prefix codes under its group's table.
fn emit_plan(plain_section: &[u8], plan: &EmissionPlan) -> Vec<u8> {
    let group_count = plan.group_code_lengths.len();
    let mut writer = BitWriter::new();

    writer.write_value(GROUP_COUNT_BITS, group_count - 1);
    if group_count > 1 {
        writer.write_value(SECTOR_SIZE_BITS, plan.sector_size / SECTOR_SIZE_MULTIPLIER - 1);
    }
    write_group_code_lengths(&mut writer, &plan.group_code_lengths);
    if group_count > 1 {
        write_sector_selectors(&mut writer, group_count, &plan.sector_groups);
    }

    let group_codes: Vec<Vec<Option<PrefixCode>>> = plan
        .group_code_lengths
        .iter()
        .map(|code_lengths| assign_canonical_codes(code_lengths))
        .collect();
    for (sector, &group) in plain_section.chunks(plan.sector_size).zip(&plan.sector_groups) {
        let codes = &group_codes[group as usize];
        for &byte in sector {
            writer.write_prefix_code(
                codes[byte as usize].expect("every section byte is coded in every group"),
            );
        }
    }
    writer.finish()
}

/// The groups' code lengths as one run-coded sequence — group 0 whole,
/// each later group only at the symbols the previous group coded, the
/// decoder reconstructing the skipped zeros by its own rule — behind
/// the 22-symbol code-length code, itself transmitted as a
/// trailing-zero-trimmed row of 4-bit lengths after a 4-bit count of
/// how many past the always-transmitted seven follow.
fn write_group_code_lengths(writer: &mut BitWriter, group_code_lengths: &[Vec<u8>]) {
    let mut wire_values: Vec<u8> = Vec::new();
    for (group_index, code_lengths) in group_code_lengths.iter().enumerate() {
        for (symbol, &length) in code_lengths.iter().enumerate() {
            let skipped = group_index > 0 && group_code_lengths[group_index - 1][symbol] == 0;
            if !skipped {
                wire_values.push(length);
            }
        }
    }
    let mut queue = MoveToFrontQueue::of_code_lengths();
    let wire_symbols = run_code_values(&wire_values, &mut queue);
    let frequencies = wire_symbol_frequencies(&wire_symbols, CODE_LENGTH_CODE_ALPHABET_SIZE);
    let code_length_code_lengths =
        code_lengths_for_table(&frequencies, MAX_CODE_LENGTH_CODE_LENGTH);

    let mut transmitted_count = CODE_LENGTH_CODE_ALPHABET_SIZE;
    while transmitted_count > ALWAYS_CODED_CODE_LENGTH_CODES
        && code_length_code_lengths[transmitted_count - 1] == 0
    {
        transmitted_count -= 1;
    }
    writer.write_value(
        EXTRA_CODE_COUNT_BITS,
        transmitted_count - ALWAYS_CODED_CODE_LENGTH_CODES,
    );
    for &length in &code_length_code_lengths[..transmitted_count] {
        writer.write_value(CODE_LENGTH_CODE_LENGTH_BITS, length as usize);
    }
    write_wire_symbols(
        writer,
        &assign_canonical_codes(&code_length_code_lengths),
        &wire_symbols,
    );
}

/// The per-sector group numbers, run-coded like the tables but over
/// the identity queue, behind a raw untrimmed row of 3-bit code
/// lengths — one per selector-alphabet symbol.
fn write_sector_selectors(writer: &mut BitWriter, group_count: usize, sector_groups: &[u8]) {
    let selector_alphabet_size = group_count + 1;
    let mut queue = MoveToFrontQueue::of_group_numbers(selector_alphabet_size);
    let wire_symbols = run_code_values(sector_groups, &mut queue);
    let frequencies = wire_symbol_frequencies(&wire_symbols, selector_alphabet_size);
    let selector_code_lengths =
        code_lengths_for_table(&frequencies, MAX_SELECTOR_CODE_LENGTH);
    for &length in &selector_code_lengths {
        writer.write_value(SELECTOR_CODE_LENGTH_BITS, length as usize);
    }
    write_wire_symbols(
        writer,
        &assign_canonical_codes(&selector_code_lengths),
        &wire_symbols,
    );
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Both fixture pairs are unmodified xdelta3 output, produced by
    // the in-tree source (tools/xdelta, built standalone) via the
    // -S djw / -S none twin trick xdelta3_lzma.rs documents: the DJW patch's
    // data section with its dec_size varint stripped, paired with the
    // same window's plain data section from the -S none twin. The
    // twin's plain section is the expected decode, checked by the
    // round-trip tests below.
    //
    // The first is a single-group section (the CLI default: -S djw
    // pins one table). The second was encoded with -S djw9, the
    // secondary level whose group suggestion table engages — two
    // groups, a sector size, a selector sequence, and compressed
    // instruction/address kinds alongside.

    const XD3_SINGLE_GROUP_SECTION: [u8; 328] = [
        0x60, 0x14, 0x62, 0x00, 0x00, 0x90, 0x83, 0x0F, 0x28, 0x93, 0xA4, 0xDA,
        0x8C, 0x9C, 0x03, 0xA0, 0xA1, 0xC4, 0xBF, 0x2C, 0x84, 0x55, 0xDC, 0xAC,
        0x50, 0x33, 0xFA, 0x6F, 0x98, 0xB8, 0xC6, 0xE9, 0xAB, 0xB0, 0xBF, 0x6D,
        0x78, 0x86, 0x43, 0x1D, 0xB7, 0xA1, 0x59, 0x6F, 0xAA, 0x58, 0xBF, 0xC3,
        0x30, 0xFA, 0x39, 0xD7, 0x70, 0xB0, 0x63, 0x8E, 0xA3, 0x19, 0xD0, 0xBB,
        0x69, 0x33, 0xF0, 0xEC, 0x5A, 0x67, 0xD5, 0x7C, 0x71, 0x70, 0x77, 0x4C,
        0x12, 0x54, 0xF4, 0xEF, 0x2B, 0xAF, 0x69, 0x17, 0xE9, 0xE3, 0x2D, 0xA0,
        0x1F, 0x40, 0xC7, 0xD1, 0xBB, 0xF0, 0xAB, 0x34, 0x59, 0xE5, 0x55, 0xB5,
        0xFE, 0xCB, 0x4A, 0xC8, 0xFD, 0x5B, 0xE4, 0x45, 0x5A, 0xFF, 0x06, 0x13,
        0x09, 0x1B, 0x26, 0xCC, 0x66, 0xAC, 0x56, 0x68, 0xB5, 0x5B, 0x57, 0xCA,
        0x8C, 0x6F, 0x69, 0xA8, 0x2F, 0xA1, 0x0D, 0x7E, 0x11, 0xF2, 0x48, 0x2B,
        0xC6, 0x57, 0x61, 0x23, 0x6C, 0xDE, 0x7E, 0x3E, 0x55, 0x7E, 0x9F, 0x37,
        0xEE, 0xC8, 0x0E, 0xAB, 0x99, 0xD4, 0xDF, 0x03, 0xCF, 0xDC, 0x26, 0xB7,
        0x0A, 0x88, 0x62, 0xA7, 0x72, 0xA7, 0xC0, 0x1D, 0x5B, 0xE3, 0x85, 0x36,
        0xFC, 0xFA, 0xF7, 0xDA, 0xCA, 0xC7, 0x22, 0xCD, 0xA7, 0x91, 0xE4, 0x38,
        0xDC, 0x3B, 0x14, 0x9F, 0x5C, 0xAF, 0x87, 0x5E, 0xB7, 0xCC, 0xB4, 0xBE,
        0xD0, 0x07, 0xAB, 0x2D, 0xAE, 0xEC, 0x8A, 0x64, 0x9C, 0x7F, 0x18, 0xD8,
        0x5F, 0x9A, 0xF9, 0x61, 0xBF, 0xF7, 0x1B, 0x94, 0xAC, 0xE3, 0x5A, 0x94,
        0x0B, 0xF6, 0xF7, 0xAF, 0xD9, 0xFA, 0x39, 0xF2, 0xB7, 0xB3, 0xC7, 0x07,
        0x9E, 0xA4, 0xE7, 0x47, 0xE6, 0x2D, 0xFE, 0xBC, 0x39, 0xD6, 0x6D, 0xFD,
        0x8E, 0x1C, 0x05, 0xCB, 0xFC, 0xF3, 0xC5, 0x80, 0x4B, 0x96, 0x9C, 0x83,
        0x8F, 0x8B, 0xB4, 0xF4, 0xE4, 0x3C, 0xE8, 0xE6, 0x81, 0x3D, 0x8E, 0xFA,
        0x3A, 0xA8, 0x9A, 0x55, 0x1D, 0x46, 0x2F, 0x5A, 0xD2, 0xC2, 0x3E, 0xE2,
        0xA4, 0x90, 0xC5, 0x29, 0xFB, 0xA7, 0x57, 0xF7, 0xE6, 0x0E, 0x6F, 0xB9,
        0x25, 0xD3, 0xD2, 0x27, 0x52, 0xD5, 0xC7, 0x06, 0x2B, 0x23, 0xB5, 0xEE,
        0xAD, 0x6E, 0x28, 0xF8, 0xE7, 0x4E, 0xA9, 0x27, 0xFF, 0xCC, 0x71, 0x86,
        0x45, 0xE0, 0xC3, 0xB2, 0xAB, 0xFF, 0x32, 0x74, 0xAE, 0xEC, 0xB9, 0xCC,
        0x19, 0x69, 0x6D, 0x01,
    ];
    const XD3_SINGLE_GROUP_PLAIN: [u8; 670] = [
        0x20, 0x20, 0x6F, 0x72, 0x61, 0x6F, 0x6F, 0x61, 0x75, 0x74, 0x69, 0x6C,
        0x20, 0x68, 0x64, 0x6C, 0x68, 0x74, 0x72, 0x73, 0x6F, 0x20, 0x6C, 0x72,
        0x72, 0x6F, 0x75, 0x75, 0x6E, 0x20, 0x64, 0x6F, 0x61, 0x73, 0x64, 0x61,
        0x72, 0x6E, 0x74, 0x6C, 0x68, 0x64, 0x75, 0x74, 0x73, 0x6E, 0x20, 0x65,
        0x69, 0x68, 0x65, 0x20, 0x6F, 0x6E, 0x68, 0x74, 0x73, 0x68, 0x6F, 0x72,
        0x73, 0x65, 0x6E, 0x61, 0x6F, 0x6C, 0x61, 0x6C, 0x75, 0x73, 0x72, 0x61,
        0x68, 0x64, 0x61, 0x65, 0x74, 0x65, 0x61, 0x73, 0x64, 0x20, 0x74, 0x20,
        0x64, 0x74, 0x61, 0x69, 0x72, 0x65, 0x20, 0x6E, 0x61, 0x68, 0x20, 0x6F,
        0x75, 0x65, 0x64, 0x6F, 0x73, 0x69, 0x68, 0x20, 0x75, 0x61, 0x6E, 0x6C,
        0x73, 0x65, 0x61, 0x6C, 0x6C, 0x72, 0x75, 0x6C, 0x61, 0x72, 0x20, 0x74,
        0x74, 0x74, 0x61, 0x69, 0x61, 0x61, 0x20, 0x61, 0x6F, 0x68, 0x6E, 0x75,
        0x73, 0x75, 0x6F, 0x69, 0x74, 0x6E, 0x61, 0x64, 0x74, 0x68, 0x69, 0x65,
        0x72, 0x65, 0x6E, 0x6F, 0x20, 0x20, 0x6E, 0x75, 0x20, 0x20, 0x20, 0x6E,
        0x68, 0x74, 0x61, 0x65, 0x6E, 0x6C, 0x20, 0x75, 0x73, 0x6F, 0x69, 0x64,
        0x6F, 0x64, 0x6C, 0x69, 0x74, 0x6C, 0x6C, 0x6E, 0x6F, 0x75, 0x75, 0x6C,
        0x64, 0x6C, 0x6F, 0x20, 0x69, 0x73, 0x75, 0x74, 0x73, 0x20, 0x69, 0x74,
        0x68, 0x69, 0x64, 0x6E, 0x75, 0x73, 0x68, 0x61, 0x69, 0x20, 0x69, 0x20,
        0x64, 0x72, 0x61, 0x69, 0x20, 0x64, 0x64, 0x72, 0x72, 0x64, 0x6C, 0x73,
        0x6F, 0x20, 0x6E, 0x6F, 0x6E, 0x65, 0x64, 0x6E, 0x6C, 0x69, 0x6F, 0x64,
        0x64, 0x61, 0x75, 0x64, 0x69, 0x64, 0x20, 0x6C, 0x75, 0x6C, 0x6F, 0x20,
        0x6E, 0x64, 0x20, 0x65, 0x74, 0x68, 0x68, 0x6F, 0x65, 0x68, 0x69, 0x64,
        0x6C, 0x61, 0x68, 0x75, 0x6C, 0x6C, 0x20, 0x73, 0x68, 0x68, 0x64, 0x72,
        0x75, 0x64, 0x75, 0x72, 0x75, 0x69, 0x6F, 0x6C, 0x65, 0x74, 0x75, 0x69,
        0x74, 0x72, 0x65, 0x65, 0x20, 0x69, 0x6E, 0x68, 0x64, 0x6C, 0x72, 0x72,
        0x69, 0x6F, 0x75, 0x74, 0x75, 0x20, 0x20, 0x75, 0x61, 0x69, 0x73, 0x6E,
        0x61, 0x61, 0x73, 0x6C, 0x6C, 0x20, 0x20, 0x68, 0x6C, 0x61, 0x6E, 0x69,
        0x6F, 0x69, 0x73, 0x72, 0x6C, 0x20, 0x61, 0x73, 0x72, 0x64, 0x73, 0x64,
        0x61, 0x74, 0x68, 0x6F, 0x73, 0x68, 0x65, 0x74, 0x6E, 0x75, 0x73, 0x74,
        0x6E, 0x64, 0x6C, 0x65, 0x72, 0x64, 0x68, 0x69, 0x64, 0x65, 0x72, 0x6E,
        0x20, 0x69, 0x61, 0x61, 0x72, 0x65, 0x20, 0x65, 0x65, 0x6E, 0x68, 0x6F,
        0x68, 0x75, 0x69, 0x61, 0x73, 0x65, 0x6C, 0x75, 0x20, 0x6F, 0x75, 0x6F,
        0x74, 0x73, 0x61, 0x69, 0x69, 0x64, 0x6E, 0x74, 0x68, 0x6F, 0x75, 0x68,
        0x61, 0x6C, 0x6E, 0x64, 0x68, 0x74, 0x6C, 0x64, 0x74, 0x6C, 0x61, 0x61,
        0x61, 0x68, 0x74, 0x65, 0x75, 0x68, 0x64, 0x20, 0x61, 0x6E, 0x75, 0x6C,
        0x6F, 0x72, 0x72, 0x75, 0x72, 0x61, 0x6E, 0x75, 0x65, 0x6E, 0x75, 0x64,
        0x20, 0x6F, 0x69, 0x61, 0x6C, 0x74, 0x61, 0x73, 0x64, 0x68, 0x6C, 0x65,
        0x6F, 0x20, 0x64, 0x75, 0x74, 0x75, 0x75, 0x6F, 0x72, 0x73, 0x6C, 0x75,
        0x72, 0x74, 0x61, 0x61, 0x75, 0x73, 0x6E, 0x69, 0x6E, 0x72, 0x65, 0x72,
        0x20, 0x65, 0x69, 0x61, 0x61, 0x65, 0x69, 0x75, 0x68, 0x69, 0x69, 0x74,
        0x73, 0x20, 0x75, 0x74, 0x65, 0x6E, 0x61, 0x72, 0x64, 0x6E, 0x6E, 0x64,
        0x6E, 0x75, 0x65, 0x20, 0x69, 0x72, 0x6F, 0x68, 0x61, 0x6C, 0x64, 0x65,
        0x75, 0x69, 0x75, 0x6F, 0x61, 0x68, 0x20, 0x65, 0x6F, 0x6F, 0x64, 0x69,
        0x61, 0x72, 0x74, 0x20, 0x65, 0x72, 0x65, 0x6F, 0x61, 0x61, 0x64, 0x69,
        0x65, 0x69, 0x61, 0x72, 0x75, 0x20, 0x61, 0x65, 0x64, 0x65, 0x68, 0x20,
        0x73, 0x74, 0x61, 0x72, 0x6F, 0x6E, 0x74, 0x6E, 0x68, 0x61, 0x6F, 0x6C,
        0x72, 0x73, 0x6F, 0x6C, 0x74, 0x20, 0x72, 0x6F, 0x75, 0x6F, 0x61, 0x64,
        0x69, 0x61, 0x64, 0x68, 0x64, 0x75, 0x68, 0x68, 0x74, 0x6F, 0x6F, 0x68,
        0x6F, 0x64, 0x68, 0x74, 0x6F, 0x69, 0x6E, 0x75, 0x72, 0x6E, 0x73, 0x6F,
        0x74, 0x75, 0x64, 0x65, 0x65, 0x20, 0x65, 0x6E, 0x6F, 0x65, 0x64, 0x69,
        0x61, 0x69, 0x64, 0x69, 0x65, 0x72, 0x68, 0x69, 0x6F, 0x6C, 0x6E, 0x74,
        0x61, 0x6E, 0x20, 0x61, 0x6C, 0x69, 0x68, 0x69, 0x6F, 0x73, 0x65, 0x65,
        0x6E, 0x6F, 0x6E, 0x6E, 0x20, 0x6F, 0x68, 0x61, 0x75, 0x74, 0x65, 0x65,
        0x61, 0x6F, 0x6F, 0x6E, 0x72, 0x69, 0x75, 0x74, 0x64, 0x65, 0x20, 0x74,
        0x64, 0x20, 0x73, 0x20, 0x68, 0x20, 0x75, 0x68, 0x64, 0x69, 0x6E, 0x6C,
        0x6E, 0x75, 0x74, 0x69, 0x68, 0x6F, 0x74, 0x65, 0x6F, 0x69, 0x6E, 0x72,
        0x74, 0x69, 0x69, 0x72, 0x72, 0x6F, 0x6F, 0x73, 0x64, 0x73,
    ];
    const XD3_MULTI_GROUP_SECTION: [u8; 958] = [
        0x84, 0x4A, 0x44, 0xAC, 0x06, 0x0A, 0x06, 0x2A, 0xC0, 0x1F, 0x00, 0x8C,
        0x6D, 0x71, 0x72, 0x11, 0x9D, 0x35, 0xE5, 0x86, 0x00, 0x37, 0x50, 0x4A,
        0x17, 0xCE, 0x1B, 0x55, 0xD4, 0xF7, 0x2A, 0x4A, 0xA4, 0x4C, 0x98, 0x4F,
        0x25, 0x4E, 0x24, 0x64, 0xAC, 0xA6, 0xAC, 0x7E, 0x19, 0x12, 0xA7, 0x55,
        0x30, 0xBA, 0x49, 0xC9, 0x16, 0x31, 0xAC, 0x21, 0x34, 0x44, 0x49, 0xCF,
        0xF3, 0xF8, 0x34, 0x7A, 0x51, 0x35, 0x61, 0x4F, 0x3E, 0x3F, 0xA6, 0xCB,
        0x38, 0x0B, 0x8B, 0x6A, 0xAA, 0x5A, 0x84, 0x90, 0x12, 0x2D, 0x8C, 0x55,
        0x6F, 0xB8, 0xD6, 0x94, 0x62, 0xCF, 0x57, 0xA3, 0x85, 0x8D, 0xE0, 0x2D,
        0xBD, 0x43, 0xF6, 0x55, 0x61, 0xB4, 0xDA, 0x39, 0xAE, 0xB4, 0x33, 0x82,
        0x39, 0x54, 0x14, 0x76, 0xEB, 0xBA, 0x9E, 0x7C, 0xA5, 0x27, 0x5E, 0xA9,
        0xD1, 0x9A, 0x87, 0xAA, 0xDA, 0x57, 0x80, 0xB7, 0xDE, 0xA0, 0x74, 0x0C,
        0x84, 0x62, 0xE0, 0xA9, 0xD4, 0x6D, 0xDD, 0x8E, 0x68, 0xA6, 0x9D, 0x41,
        0x0F, 0x0A, 0xAC, 0xCD, 0xE1, 0xCC, 0x0C, 0xBA, 0x2E, 0x6A, 0xBA, 0x6F,
        0x8D, 0x47, 0xBF, 0x50, 0xE1, 0x4D, 0x70, 0xC9, 0x07, 0x92, 0xC6, 0x3C,
        0xD5, 0x15, 0xDF, 0x31, 0x5F, 0x88, 0xEA, 0x1A, 0xD7, 0x76, 0xA5, 0xAD,
        0x12, 0x56, 0xB2, 0x04, 0x14, 0x01, 0x8C, 0xA2, 0xFC, 0x52, 0x26, 0x17,
        0xD0, 0x63, 0x45, 0x5F, 0x45, 0x26, 0xD3, 0x31, 0x9B, 0xA9, 0x98, 0xB4,
        0x2E, 0x58, 0xD0, 0xB8, 0xB4, 0x58, 0x17, 0x1E, 0x6F, 0xC6, 0x63, 0xD8,
        0x26, 0xF3, 0xC5, 0xDD, 0x09, 0xC3, 0x14, 0x7B, 0x5C, 0x73, 0x62, 0x68,
        0x22, 0x18, 0x7C, 0x8B, 0x23, 0xEF, 0xAE, 0xF5, 0xF4, 0x8A, 0x98, 0x95,
        0xE2, 0x4A, 0xC0, 0xD4, 0xBE, 0xAD, 0x7A, 0x41, 0x36, 0xA7, 0x66, 0x6A,
        0xAE, 0x1F, 0x84, 0xC1, 0x83, 0xB4, 0x64, 0x5B, 0x51, 0xE7, 0x7C, 0x70,
        0x42, 0x69, 0xED, 0x70, 0xFC, 0x40, 0x89, 0x84, 0xF8, 0xEE, 0x98, 0x35,
        0x60, 0xD8, 0x29, 0x9D, 0x3D, 0xDE, 0xB7, 0xB0, 0x86, 0x21, 0xBA, 0x08,
        0xF5, 0x13, 0xEC, 0x65, 0xE6, 0xEB, 0xE7, 0xAC, 0xCD, 0xBD, 0x80, 0x08,
        0x97, 0x1B, 0xC3, 0x29, 0xDE, 0xC8, 0x7E, 0x57, 0x15, 0xD7, 0x49, 0x1D,
        0xFC, 0x1E, 0xDC, 0x8A, 0xAE, 0x78, 0x2F, 0xE9, 0xA1, 0xF3, 0xF1, 0x58,
        0xAA, 0x72, 0x73, 0xCF, 0x45, 0x2B, 0xAA, 0x1D, 0x54, 0x76, 0x1F, 0x4E,
        0x62, 0x1B, 0x1D, 0x33, 0xAE, 0x7C, 0x43, 0xB7, 0x54, 0x5C, 0x44, 0xC1,
        0x9A, 0xF0, 0x32, 0x0B, 0x85, 0x8C, 0x77, 0x75, 0xF2, 0x38, 0xB0, 0x8D,
        0xA0, 0x21, 0x6C, 0xD5, 0xA9, 0x3B, 0xC6, 0xD8, 0x2A, 0x6A, 0xE5, 0x77,
        0x42, 0x4C, 0x5E, 0x7B, 0x72, 0x26, 0xC8, 0x29, 0x8D, 0x5F, 0x47, 0xB7,
        0xC2, 0x65, 0x86, 0x14, 0x56, 0x16, 0xF0, 0xAA, 0xF8, 0xDE, 0x85, 0x2B,
        0x7B, 0xE4, 0x98, 0x43, 0x89, 0x2C, 0x98, 0x32, 0xEA, 0xA0, 0x6B, 0x96,
        0x66, 0xE7, 0x95, 0x30, 0x56, 0xA2, 0xEA, 0x24, 0x3F, 0xC8, 0xDD, 0x1C,
        0xE1, 0x9C, 0x76, 0x57, 0xD2, 0xA1, 0x51, 0xBD, 0xEA, 0x91, 0x5A, 0x6D,
        0x02, 0xF4, 0xF4, 0xE4, 0x3B, 0x2F, 0x00, 0x0D, 0xA5, 0x29, 0x62, 0x5B,
        0xB8, 0x6C, 0xD4, 0x2B, 0xE7, 0x54, 0x22, 0xB6, 0xCE, 0xBD, 0x78, 0xE9,
        0x99, 0x39, 0x3F, 0x8E, 0x9C, 0x2A, 0x96, 0x32, 0x31, 0xDC, 0xE8, 0xF5,
        0x68, 0x14, 0x46, 0x0F, 0x9E, 0xBA, 0x24, 0x25, 0xBD, 0x66, 0xED, 0x9A,
        0x3C, 0xBD, 0x9B, 0x7A, 0xCB, 0x58, 0x5D, 0x11, 0x79, 0x2A, 0x46, 0x94,
        0x12, 0xEE, 0x78, 0x52, 0x57, 0x0C, 0x73, 0x87, 0x6A, 0x0E, 0x6A, 0x54,
        0xDA, 0x4A, 0x21, 0x5D, 0x13, 0x7C, 0x33, 0xD5, 0xD2, 0x6B, 0xD5, 0x31,
        0xA3, 0x97, 0xF9, 0xA8, 0x2C, 0x1F, 0xBA, 0x66, 0x56, 0xAE, 0x9B, 0xE1,
        0x49, 0x55, 0xCF, 0xEB, 0x17, 0xAC, 0xE5, 0x56, 0x95, 0x55, 0x53, 0xD4,
        0x00, 0x15, 0x06, 0x47, 0x1C, 0x8B, 0x4E, 0x3B, 0x0E, 0x38, 0x03, 0x55,
        0x9C, 0x78, 0x6A, 0x3C, 0x28, 0x55, 0xEE, 0x3B, 0x89, 0x99, 0x02, 0x90,
        0x28, 0xE9, 0x46, 0x2A, 0x03, 0x9C, 0x17, 0x20, 0xA2, 0x3D, 0xCE, 0xEC,
        0x16, 0x6F, 0x90, 0xE4, 0x1C, 0x42, 0x42, 0x72, 0xEF, 0xA2, 0x85, 0xD2,
        0xE8, 0xDE, 0x7B, 0xA9, 0x5C, 0xD6, 0x5C, 0x50, 0x98, 0xA0, 0xD9, 0x6F,
        0xB5, 0xAD, 0x97, 0x5D, 0xBA, 0x81, 0x50, 0x51, 0xCB, 0x31, 0x18, 0x61,
        0xFA, 0x00, 0x8B, 0xF6, 0xED, 0x4D, 0x93, 0x18, 0xF7, 0x61, 0x57, 0xAE,
        0x18, 0x6B, 0xE2, 0x21, 0x57, 0xAF, 0x8D, 0x87, 0x89, 0x57, 0xC9, 0x0A,
        0x60, 0x11, 0x78, 0x57, 0xAE, 0xAD, 0x4D, 0x57, 0x8A, 0x9B, 0xA3, 0x41,
        0x87, 0x9A, 0x4F, 0xBD, 0xA5, 0x77, 0xA0, 0x0B, 0xE8, 0x53, 0xB6, 0x29,
        0x47, 0x1F, 0xA5, 0x2A, 0x51, 0xA1, 0x4A, 0xBF, 0x06, 0x2E, 0x8D, 0x9B,
        0xE0, 0xC0, 0x91, 0x25, 0x27, 0xF6, 0xCD, 0x3A, 0x54, 0x94, 0x5D, 0xB1,
        0x4F, 0x59, 0x51, 0xCD, 0xD7, 0x50, 0xAC, 0x0A, 0x31, 0xDE, 0x59, 0x60,
        0xC2, 0x5C, 0x0C, 0xA9, 0xF4, 0xBE, 0x17, 0xA3, 0xDA, 0x87, 0xDC, 0x41,
        0x2B, 0x7B, 0xCB, 0x5C, 0x01, 0xAB, 0x6E, 0xDD, 0xC5, 0xA9, 0xCF, 0x43,
        0x55, 0x08, 0xE7, 0xB3, 0x7C, 0x37, 0x04, 0xBB, 0x80, 0x37, 0x50, 0x3E,
        0x81, 0x23, 0x36, 0x35, 0x95, 0x01, 0xC8, 0x49, 0xC5, 0x34, 0xF4, 0x5C,
        0x3C, 0xE4, 0x26, 0x29, 0xBE, 0x2C, 0xD2, 0x9D, 0x89, 0x99, 0x7E, 0x9C,
        0x57, 0x6D, 0x79, 0xB2, 0x80, 0xDB, 0x26, 0x10, 0xEB, 0x95, 0x58, 0xB6,
        0x04, 0xB5, 0xCC, 0x73, 0x8A, 0x76, 0xF5, 0x69, 0xB8, 0xC5, 0x59, 0x90,
        0x37, 0x01, 0xB2, 0xE8, 0x7D, 0xF6, 0x5B, 0xBA, 0xAD, 0xCE, 0x90, 0x19,
        0xB3, 0x33, 0x81, 0x9A, 0x71, 0xEB, 0xAC, 0xAA, 0x9D, 0x39, 0x44, 0x46,
        0xBD, 0xBE, 0x29, 0xA8, 0xF3, 0xE1, 0xC4, 0x2E, 0x04, 0xCA, 0x11, 0xDE,
        0xED, 0x49, 0x08, 0x55, 0xEF, 0x89, 0x8F, 0xA8, 0xE8, 0x5A, 0xC8, 0xB6,
        0x03, 0xD3, 0xCC, 0xCC, 0x59, 0x66, 0x63, 0x15, 0x1E, 0x13, 0xAE, 0x9D,
        0xA9, 0xF3, 0x3A, 0x7E, 0xE7, 0x65, 0x56, 0x1A, 0x4B, 0xDD, 0xEC, 0xD6,
        0x59, 0x60, 0x0A, 0x41, 0x86, 0x24, 0x6C, 0xC1, 0xB2, 0xD1, 0x36, 0xC8,
        0x1A, 0xD2, 0x31, 0xD3, 0xD2, 0x26, 0x8E, 0xB5, 0xBA, 0x2C, 0xD4, 0xD9,
        0x6A, 0xB2, 0x34, 0x4D, 0xDA, 0xA1, 0x62, 0x6B, 0x36, 0x68, 0x61, 0x61,
        0x15, 0x8C, 0x84, 0xC4, 0x32, 0x0D, 0x3A, 0x09, 0x65, 0x26, 0x5B, 0xD0,
        0x05, 0xC2, 0x26, 0x5D, 0xDC, 0x62, 0x91, 0x4A, 0x3B, 0x93, 0xCC, 0x62,
        0x92, 0x86, 0xB6, 0x1D, 0x09, 0xBA, 0xB8, 0x24, 0x90, 0x58, 0x96, 0x50,
        0x07, 0x81, 0x91, 0x6D, 0xB4, 0x68, 0x2B, 0x03, 0x5D, 0x58, 0x2B, 0x62,
        0xC7, 0xE8, 0x0C, 0xB1, 0xDD, 0x44, 0xD7, 0xE1, 0x48, 0x56, 0xED, 0xE8,
        0x22, 0xD1, 0xAE, 0x29, 0x0D, 0x4B, 0x56, 0x29, 0x12, 0x01,
    ];
    const XD3_MULTI_GROUP_PLAIN: [u8; 2144] = [
        0x74, 0x63, 0x68, 0x72, 0x65, 0x72, 0x63, 0x6F, 0x61, 0x62, 0x20, 0x72,
        0x74, 0x20, 0x70, 0x72, 0x6F, 0x65, 0x74, 0x72, 0x6C, 0x68, 0x62, 0x61,
        0x72, 0x72, 0x63, 0x6F, 0x6C, 0x72, 0x65, 0x20, 0x74, 0x20, 0x6C, 0x6C,
        0x63, 0x63, 0x72, 0x72, 0x74, 0x74, 0x72, 0x63, 0x20, 0x6F, 0x63, 0x65,
        0x6F, 0x63, 0x20, 0x72, 0x6F, 0x63, 0x20, 0x65, 0x72, 0x72, 0x68, 0x74,
        0x6F, 0x68, 0x63, 0x68, 0x72, 0x6F, 0x72, 0x68, 0x61, 0x65, 0x65, 0x6F,
        0x61, 0x74, 0x74, 0x6F, 0x62, 0x68, 0x74, 0x68, 0x63, 0x62, 0x74, 0x65,
        0x74, 0x20, 0x73, 0x74, 0x72, 0x20, 0x70, 0x20, 0x65, 0x6C, 0x63, 0x72,
        0x65, 0x6C, 0x72, 0x63, 0x20, 0x72, 0x20, 0x62, 0x72, 0x72, 0x63, 0x74,
        0x72, 0x20, 0x6F, 0x74, 0x72, 0x65, 0x68, 0x6F, 0x63, 0x70, 0x74, 0x72,
        0x6F, 0x65, 0x72, 0x61, 0x70, 0x73, 0x74, 0x73, 0x65, 0x6F, 0x72, 0x70,
        0x20, 0x74, 0x74, 0x20, 0x61, 0x63, 0x73, 0x70, 0x63, 0x74, 0x70, 0x6F,
        0x63, 0x63, 0x6C, 0x73, 0x65, 0x65, 0x20, 0x6F, 0x72, 0x70, 0x72, 0x70,
        0x6F, 0x73, 0x63, 0x70, 0x72, 0x72, 0x70, 0x6F, 0x6F, 0x72, 0x20, 0x74,
        0x63, 0x6F, 0x63, 0x72, 0x61, 0x65, 0x20, 0x70, 0x70, 0x65, 0x73, 0x6C,
        0x65, 0x68, 0x72, 0x74, 0x73, 0x65, 0x72, 0x68, 0x72, 0x63, 0x73, 0x65,
        0x72, 0x6C, 0x20, 0x6C, 0x72, 0x6F, 0x68, 0x20, 0x65, 0x65, 0x65, 0x70,
        0x68, 0x65, 0x20, 0x20, 0x74, 0x70, 0x65, 0x68, 0x6F, 0x20, 0x65, 0x72,
        0x73, 0x63, 0x61, 0x20, 0x61, 0x72, 0x61, 0x6F, 0x20, 0x74, 0x6F, 0x65,
        0x62, 0x72, 0x73, 0x70, 0x65, 0x73, 0x70, 0x6F, 0x72, 0x63, 0x74, 0x63,
        0x62, 0x74, 0x74, 0x62, 0x61, 0x63, 0x74, 0x6F, 0x20, 0x65, 0x20, 0x63,
        0x65, 0x70, 0x62, 0x6F, 0x63, 0x6F, 0x6F, 0x6F, 0x6F, 0x20, 0x6C, 0x65,
        0x73, 0x61, 0x65, 0x6F, 0x6C, 0x6C, 0x73, 0x70, 0x74, 0x20, 0x68, 0x63,
        0x74, 0x68, 0x61, 0x72, 0x65, 0x20, 0x68, 0x6F, 0x61, 0x63, 0x70, 0x63,
        0x63, 0x68, 0x20, 0x63, 0x63, 0x63, 0x74, 0x20, 0x6F, 0x68, 0x72, 0x65,
        0x73, 0x65, 0x63, 0x68, 0x73, 0x63, 0x62, 0x68, 0x61, 0x72, 0x63, 0x72,
        0x6C, 0x65, 0x6F, 0x74, 0x65, 0x70, 0x6C, 0x65, 0x62, 0x74, 0x74, 0x72,
        0x65, 0x72, 0x20, 0x70, 0x72, 0x72, 0x74, 0x72, 0x72, 0x20, 0x20, 0x65,
        0x63, 0x20, 0x20, 0x20, 0x6F, 0x72, 0x61, 0x65, 0x74, 0x68, 0x62, 0x72,
        0x74, 0x63, 0x63, 0x70, 0x20, 0x20, 0x72, 0x68, 0x63, 0x65, 0x61, 0x6C,
        0x73, 0x65, 0x61, 0x62, 0x62, 0x63, 0x62, 0x74, 0x61, 0x6F, 0x70, 0x62,
        0x62, 0x72, 0x61, 0x6F, 0x62, 0x74, 0x72, 0x73, 0x61, 0x63, 0x65, 0x20,
        0x72, 0x6F, 0x74, 0x65, 0x72, 0x70, 0x20, 0x70, 0x74, 0x65, 0x20, 0x68,
        0x63, 0x73, 0x6F, 0x6F, 0x74, 0x6F, 0x74, 0x20, 0x74, 0x74, 0x74, 0x63,
        0x63, 0x62, 0x68, 0x61, 0x73, 0x73, 0x73, 0x72, 0x20, 0x6F, 0x63, 0x62,
        0x72, 0x63, 0x6C, 0x6F, 0x74, 0x65, 0x6F, 0x73, 0x72, 0x63, 0x61, 0x72,
        0x6F, 0x61, 0x61, 0x63, 0x61, 0x63, 0x68, 0x70, 0x20, 0x73, 0x63, 0x63,
        0x73, 0x73, 0x73, 0x6C, 0x72, 0x68, 0x72, 0x68, 0x65, 0x63, 0x20, 0x6F,
        0x70, 0x72, 0x72, 0x61, 0x73, 0x65, 0x72, 0x20, 0x20, 0x6F, 0x65, 0x70,
        0x68, 0x70, 0x65, 0x65, 0x68, 0x61, 0x63, 0x63, 0x6C, 0x63, 0x6F, 0x65,
        0x6F, 0x6F, 0x65, 0x6F, 0x73, 0x6C, 0x68, 0x20, 0x72, 0x20, 0x6F, 0x20,
        0x68, 0x20, 0x72, 0x72, 0x70, 0x63, 0x63, 0x6C, 0x74, 0x72, 0x61, 0x65,
        0x73, 0x74, 0x62, 0x68, 0x20, 0x74, 0x62, 0x20, 0x72, 0x62, 0x74, 0x72,
        0x70, 0x6F, 0x63, 0x6F, 0x74, 0x68, 0x20, 0x63, 0x72, 0x72, 0x63, 0x63,
        0x20, 0x72, 0x63, 0x68, 0x73, 0x73, 0x63, 0x62, 0x65, 0x6F, 0x20, 0x63,
        0x61, 0x74, 0x74, 0x62, 0x72, 0x72, 0x73, 0x74, 0x74, 0x6F, 0x74, 0x70,
        0x68, 0x70, 0x20, 0x74, 0x72, 0x6F, 0x63, 0x61, 0x72, 0x63, 0x74, 0x65,
        0x63, 0x20, 0x72, 0x6C, 0x68, 0x72, 0x20, 0x74, 0x74, 0x70, 0x63, 0x62,
        0x62, 0x68, 0x6C, 0x68, 0x74, 0x62, 0x65, 0x70, 0x62, 0x70, 0x73, 0x61,
        0x20, 0x72, 0x63, 0x20, 0x74, 0x65, 0x74, 0x6C, 0x20, 0x6F, 0x63, 0x6F,
        0x65, 0x63, 0x73, 0x6F, 0x72, 0x74, 0x74, 0x68, 0x73, 0x65, 0x65, 0x61,
        0x73, 0x6C, 0x62, 0x63, 0x72, 0x73, 0x20, 0x74, 0x68, 0x68, 0x20, 0x74,
        0x6C, 0x72, 0x61, 0x6C, 0x65, 0x61, 0x68, 0x68, 0x62, 0x63, 0x74, 0x6F,
        0x63, 0x74, 0x62, 0x68, 0x63, 0x73, 0x63, 0x65, 0x72, 0x65, 0x65, 0x74,
        0x6C, 0x63, 0x70, 0x73, 0x74, 0x65, 0x63, 0x74, 0x72, 0x61, 0x65, 0x6C,
        0x74, 0x61, 0x63, 0x72, 0x62, 0x6C, 0x6C, 0x73, 0x20, 0x73, 0x72, 0x72,
        0x63, 0x6C, 0x74, 0x20, 0x6C, 0x61, 0x6F, 0x6F, 0x74, 0x65, 0x62, 0x68,
        0x6F, 0x63, 0x74, 0x6C, 0x72, 0x72, 0x65, 0x63, 0x70, 0x20, 0x61, 0x65,
        0x20, 0x74, 0x72, 0x6F, 0x61, 0x74, 0x70, 0x63, 0x62, 0x65, 0x20, 0x65,
        0x20, 0x62, 0x61, 0x68, 0x73, 0x65, 0x73, 0x72, 0x74, 0x6F, 0x74, 0x61,
        0x20, 0x70, 0x6C, 0x20, 0x61, 0x63, 0x74, 0x20, 0x72, 0x20, 0x70, 0x65,
        0x65, 0x73, 0x72, 0x6C, 0x6C, 0x61, 0x6F, 0x74, 0x20, 0x70, 0x65, 0x65,
        0x63, 0x72, 0x70, 0x72, 0x74, 0x68, 0x73, 0x72, 0x20, 0x61, 0x6F, 0x62,
        0x73, 0x6C, 0x74, 0x6F, 0x62, 0x6F, 0x6F, 0x61, 0x63, 0x63, 0x6F, 0x65,
        0x72, 0x6F, 0x74, 0x68, 0x6C, 0x61, 0x6C, 0x6C, 0x72, 0x61, 0x74, 0x65,
        0x74, 0x63, 0x61, 0x72, 0x72, 0x61, 0x74, 0x72, 0x62, 0x65, 0x20, 0x20,
        0x68, 0x65, 0x65, 0x63, 0x68, 0x68, 0x73, 0x61, 0x74, 0x65, 0x62, 0x6C,
        0x6F, 0x72, 0x74, 0x61, 0x6F, 0x73, 0x20, 0x65, 0x72, 0x63, 0x63, 0x65,
        0x20, 0x74, 0x63, 0x72, 0x74, 0x20, 0x65, 0x73, 0x20, 0x72, 0x73, 0x6C,
        0x63, 0x65, 0x72, 0x6F, 0x70, 0x6F, 0x68, 0x65, 0x72, 0x20, 0x6F, 0x74,
        0x72, 0x62, 0x20, 0x65, 0x65, 0x73, 0x72, 0x72, 0x74, 0x68, 0x20, 0x72,
        0x74, 0x6C, 0x6C, 0x63, 0x6F, 0x72, 0x20, 0x73, 0x74, 0x62, 0x74, 0x74,
        0x6C, 0x65, 0x62, 0x63, 0x74, 0x61, 0x72, 0x6F, 0x72, 0x65, 0x68, 0x65,
        0x6C, 0x6F, 0x72, 0x72, 0x6C, 0x72, 0x6C, 0x74, 0x63, 0x20, 0x20, 0x63,
        0x74, 0x6F, 0x6C, 0x6F, 0x62, 0x68, 0x73, 0x74, 0x70, 0x20, 0x20, 0x20,
        0x72, 0x6F, 0x63, 0x72, 0x72, 0x6F, 0x65, 0x63, 0x20, 0x70, 0x6C, 0x72,
        0x20, 0x73, 0x62, 0x6C, 0x20, 0x65, 0x68, 0x65, 0x74, 0x62, 0x6F, 0x65,
        0x62, 0x20, 0x61, 0x70, 0x65, 0x73, 0x74, 0x6C, 0x70, 0x20, 0x68, 0x62,
        0x74, 0x6F, 0x6F, 0x6F, 0x73, 0x74, 0x68, 0x63, 0x6F, 0x72, 0x74, 0x62,
        0x72, 0x65, 0x63, 0x65, 0x72, 0x62, 0x62, 0x20, 0x6F, 0x63, 0x70, 0x61,
        0x6C, 0x70, 0x74, 0x6F, 0x72, 0x6F, 0x72, 0x61, 0x74, 0x20, 0x6C, 0x6F,
        0x20, 0x68, 0x72, 0x6C, 0x65, 0x72, 0x72, 0x72, 0x62, 0x63, 0x74, 0x70,
        0x74, 0x63, 0x65, 0x70, 0x70, 0x74, 0x63, 0x63, 0x73, 0x72, 0x68, 0x73,
        0x6F, 0x65, 0x68, 0x70, 0x63, 0x61, 0x70, 0x72, 0x73, 0x65, 0x63, 0x20,
        0x62, 0x73, 0x72, 0x65, 0x63, 0x61, 0x61, 0x65, 0x72, 0x62, 0x20, 0x74,
        0x6C, 0x61, 0x68, 0x72, 0x72, 0x6C, 0x65, 0x61, 0x6F, 0x63, 0x62, 0x70,
        0x6F, 0x63, 0x72, 0x6C, 0x63, 0x6F, 0x20, 0x65, 0x6F, 0x72, 0x65, 0x72,
        0x70, 0x65, 0x62, 0x72, 0x20, 0x62, 0x74, 0x65, 0x6F, 0x61, 0x63, 0x68,
        0x6F, 0x6F, 0x65, 0x6C, 0x72, 0x72, 0x68, 0x6C, 0x72, 0x65, 0x73, 0x63,
        0x62, 0x61, 0x6C, 0x70, 0x63, 0x62, 0x68, 0x63, 0x72, 0x62, 0x65, 0x74,
        0x73, 0x20, 0x6C, 0x65, 0x6F, 0x6F, 0x70, 0x72, 0x74, 0x65, 0x73, 0x6F,
        0x6F, 0x63, 0x73, 0x72, 0x72, 0x65, 0x65, 0x68, 0x74, 0x70, 0x74, 0x68,
        0x61, 0x63, 0x65, 0x70, 0x63, 0x70, 0x65, 0x65, 0x65, 0x74, 0x72, 0x65,
        0x6F, 0x65, 0x63, 0x72, 0x6F, 0x20, 0x20, 0x65, 0x61, 0x74, 0x20, 0x63,
        0x6F, 0x72, 0x63, 0x6F, 0x74, 0x72, 0x63, 0x74, 0x62, 0x74, 0x74, 0x61,
        0x73, 0x20, 0x20, 0x73, 0x74, 0x20, 0x20, 0x65, 0x65, 0x63, 0x6F, 0x61,
        0x68, 0x72, 0x6C, 0x20, 0x68, 0x20, 0x72, 0x62, 0x72, 0x65, 0x74, 0x6C,
        0x73, 0x73, 0x72, 0x72, 0x63, 0x62, 0x62, 0x72, 0x20, 0x20, 0x20, 0x62,
        0x20, 0x65, 0x72, 0x72, 0x73, 0x6F, 0x72, 0x72, 0x65, 0x74, 0x20, 0x20,
        0x63, 0x6F, 0x68, 0x61, 0x20, 0x63, 0x20, 0x61, 0x6C, 0x74, 0x6F, 0x74,
        0x62, 0x62, 0x6C, 0x6C, 0x72, 0x63, 0x73, 0x6F, 0x20, 0x62, 0x63, 0x63,
        0x6F, 0x73, 0x20, 0x61, 0x72, 0x72, 0x20, 0x62, 0x63, 0x70, 0x73, 0x73,
        0x61, 0x6C, 0x72, 0x20, 0x65, 0x72, 0x6F, 0x72, 0x73, 0x68, 0x68, 0x68,
        0x62, 0x72, 0x62, 0x70, 0x63, 0x65, 0x6F, 0x73, 0x61, 0x63, 0x72, 0x20,
        0x6F, 0x61, 0x63, 0x74, 0x63, 0x6C, 0x68, 0x70, 0x72, 0x70, 0x6C, 0x72,
        0x68, 0x62, 0x6C, 0x65, 0x72, 0x73, 0x6F, 0x20, 0x72, 0x20, 0x65, 0x61,
        0x65, 0x70, 0x63, 0x6F, 0x74, 0x20, 0x63, 0x61, 0x61, 0x74, 0x63, 0x74,
        0x73, 0x20, 0x20, 0x74, 0x72, 0x63, 0x74, 0x74, 0x73, 0x70, 0x73, 0x6F,
        0x6C, 0x63, 0x63, 0x20, 0x6F, 0x74, 0x6C, 0x73, 0x20, 0x70, 0x70, 0x72,
        0x74, 0x65, 0x61, 0x6F, 0x74, 0x72, 0x6F, 0x61, 0x68, 0x20, 0x62, 0x70,
        0x72, 0x68, 0x6C, 0x74, 0x20, 0x68, 0x20, 0x6F, 0x61, 0x68, 0x65, 0x62,
        0x63, 0x65, 0x61, 0x20, 0x20, 0x70, 0x20, 0x61, 0x20, 0x68, 0x73, 0x65,
        0x74, 0x65, 0x70, 0x65, 0x70, 0x62, 0x74, 0x65, 0x62, 0x72, 0x63, 0x70,
        0x62, 0x6F, 0x72, 0x6F, 0x20, 0x6C, 0x61, 0x72, 0x6C, 0x63, 0x68, 0x72,
        0x6C, 0x70, 0x65, 0x72, 0x68, 0x73, 0x20, 0x63, 0x74, 0x65, 0x20, 0x20,
        0x6C, 0x73, 0x72, 0x62, 0x6C, 0x74, 0x63, 0x72, 0x74, 0x61, 0x6C, 0x73,
        0x63, 0x72, 0x72, 0x65, 0x65, 0x72, 0x63, 0x72, 0x61, 0x72, 0x65, 0x62,
        0x74, 0x68, 0x6C, 0x20, 0x20, 0x73, 0x62, 0x74, 0x20, 0x73, 0x6F, 0x61,
        0x63, 0x6F, 0x20, 0x74, 0x61, 0x62, 0x65, 0x72, 0x74, 0x62, 0x20, 0x70,
        0x68, 0x6F, 0x70, 0x74, 0x61, 0x72, 0x65, 0x63, 0x72, 0x74, 0x74, 0x65,
        0x61, 0x70, 0x68, 0x72, 0x62, 0x65, 0x61, 0x65, 0x6C, 0x63, 0x68, 0x6C,
        0x20, 0x72, 0x61, 0x70, 0x72, 0x65, 0x20, 0x61, 0x6F, 0x74, 0x70, 0x6F,
        0x70, 0x20, 0x20, 0x6F, 0x61, 0x74, 0x63, 0x70, 0x20, 0x6F, 0x63, 0x63,
        0x72, 0x62, 0x74, 0x70, 0x68, 0x68, 0x61, 0x6F, 0x72, 0x65, 0x70, 0x68,
        0x20, 0x62, 0x70, 0x6F, 0x20, 0x6C, 0x72, 0x62, 0x6C, 0x70, 0x65, 0x74,
        0x63, 0x70, 0x72, 0x20, 0x20, 0x70, 0x72, 0x6C, 0x6C, 0x72, 0x73, 0x73,
        0x61, 0x73, 0x72, 0x6C, 0x73, 0x74, 0x6F, 0x63, 0x72, 0x65, 0x61, 0x72,
        0x20, 0x73, 0x74, 0x73, 0x74, 0x72, 0x74, 0x73, 0x73, 0x6F, 0x63, 0x20,
        0x63, 0x6C, 0x65, 0x20, 0x20, 0x68, 0x6F, 0x20, 0x72, 0x62, 0x68, 0x72,
        0x20, 0x63, 0x6F, 0x72, 0x63, 0x6C, 0x63, 0x72, 0x6F, 0x65, 0x62, 0x61,
        0x20, 0x20, 0x72, 0x74, 0x62, 0x63, 0x72, 0x61, 0x6F, 0x6C, 0x20, 0x72,
        0x68, 0x74, 0x65, 0x63, 0x73, 0x20, 0x62, 0x70, 0x62, 0x63, 0x63, 0x72,
        0x63, 0x68, 0x62, 0x65, 0x63, 0x63, 0x74, 0x6C, 0x62, 0x62, 0x20, 0x6F,
        0x6F, 0x6C, 0x68, 0x63, 0x6F, 0x68, 0x65, 0x6C, 0x74, 0x72, 0x74, 0x6F,
        0x62, 0x65, 0x20, 0x20, 0x73, 0x70, 0x6C, 0x63, 0x20, 0x20, 0x61, 0x70,
        0x74, 0x70, 0x72, 0x72, 0x63, 0x65, 0x74, 0x74, 0x72, 0x72, 0x20, 0x72,
        0x6C, 0x72, 0x74, 0x63, 0x73, 0x74, 0x62, 0x72, 0x63, 0x74, 0x74, 0x65,
        0x6C, 0x73, 0x72, 0x6F, 0x63, 0x70, 0x65, 0x63, 0x6F, 0x70, 0x20, 0x63,
        0x63, 0x73, 0x6F, 0x61, 0x20, 0x63, 0x63, 0x65, 0x63, 0x74, 0x70, 0x68,
        0x74, 0x74, 0x68, 0x70, 0x63, 0x74, 0x6C, 0x74, 0x72, 0x6C, 0x62, 0x61,
        0x72, 0x74, 0x63, 0x61, 0x6F, 0x70, 0x6F, 0x6F, 0x61, 0x20, 0x65, 0x6F,
        0x6F, 0x74, 0x6C, 0x72, 0x73, 0x74, 0x72, 0x65, 0x65, 0x70, 0x6F, 0x6F,
        0x73, 0x20, 0x61, 0x62, 0x61, 0x65, 0x68, 0x6C, 0x73, 0x6F, 0x65, 0x20,
        0x72, 0x6C, 0x62, 0x68, 0x20, 0x73, 0x72, 0x63, 0x6C, 0x65, 0x20, 0x61,
        0x20, 0x65, 0x74, 0x61, 0x61, 0x74, 0x70, 0x70, 0x6C, 0x6F, 0x62, 0x20,
        0x72, 0x20, 0x65, 0x65, 0x68, 0x68, 0x72, 0x63, 0x68, 0x63, 0x20, 0x65,
        0x61, 0x6C, 0x65, 0x70, 0x20, 0x72, 0x74, 0x74, 0x74, 0x74, 0x61, 0x20,
        0x6F, 0x6C, 0x63, 0x62, 0x62, 0x62, 0x6F, 0x70, 0x63, 0x62, 0x6C, 0x20,
        0x70, 0x72, 0x61, 0x74, 0x6F, 0x74, 0x63, 0x20, 0x74, 0x65, 0x70, 0x6F,
        0x6F, 0x65, 0x68, 0x6F, 0x62, 0x72, 0x68, 0x6F, 0xF8, 0x80, 0xFF, 0xF0,
        0xC3, 0xF0, 0x80, 0xF8, 0xF0, 0xC3, 0xF0, 0xF8, 0xFF, 0xFF, 0xF8, 0xF0,
        0xFF, 0xFF, 0xF0, 0xFF, 0xF8, 0xF0, 0xC3, 0xC3, 0xC3, 0xFF, 0xF8, 0xF8,
        0xC3, 0xC3, 0x80, 0xC3, 0xF8, 0xC3, 0xFF, 0xC3, 0xF8, 0xC3, 0x80, 0x80,
        0xC3, 0xFF, 0xFF, 0x80, 0xC3, 0xF8, 0xF0, 0xC3, 0xFF, 0xFF, 0xC3, 0xF0,
        0xF0, 0xF0, 0x80, 0xC3, 0xF8, 0xC3, 0xFF, 0xF0, 0x80, 0xC3, 0x80, 0xF0,
        0xFF, 0xC3, 0xFF, 0xF8, 0x80, 0xF0, 0xF0, 0xC3, 0xF0, 0xF0, 0x80, 0x80,
        0xF8, 0xFF, 0xC3, 0xFF, 0xF0, 0xF0, 0xF8, 0xF8, 0xFF, 0x80, 0xFF, 0x80,
        0xC3, 0xF0, 0xF8, 0xFF, 0xF8, 0xF0, 0xF0, 0xF8, 0xF8, 0x80, 0x80, 0xFF,
        0x80, 0xF0, 0x80, 0xF0, 0x80, 0x80, 0xF0, 0xF0, 0xFF, 0xC3, 0xF8, 0xF8,
        0xF8, 0xC3, 0xF8, 0xF0, 0xF0, 0xF8, 0x80, 0xFF, 0xFF, 0xC3, 0xC3, 0xF0,
        0xF0, 0xC3, 0xC3, 0xFF, 0x80, 0xC3, 0xFF, 0xF0, 0xF8, 0xC3, 0xC3, 0xF8,
        0x80, 0xF8, 0xC3, 0x80, 0xC3, 0x80, 0x80, 0xF8, 0xF0, 0xC3, 0xFF, 0xF8,
        0xF8, 0x80, 0xC3, 0xF8, 0xF8, 0xFF, 0xF8, 0xC3, 0x80, 0xC3, 0xF0, 0xC3,
        0xFF, 0xF8, 0x80, 0x80, 0xFF, 0xFF, 0x80, 0xC3, 0xF8, 0xF8, 0xFF, 0x80,
        0xC3, 0xC3, 0x80, 0xC3, 0xFF, 0xFF, 0xF8, 0xC3, 0xF0, 0xFF, 0x80, 0xF8,
        0xFF, 0xFF, 0x80, 0xF8, 0xF0, 0xC3, 0xF8, 0xC3, 0xF0, 0xF8, 0xC3, 0xF0,
        0xF0, 0xFF, 0xF8, 0x80, 0x80, 0x80, 0xFF, 0xF8, 0xF0, 0xC3, 0xF8, 0x80,
        0x80, 0x80, 0xF0, 0x80, 0xC3, 0xF0, 0xF0, 0xF0, 0xF0, 0xFF, 0xC3, 0x80,
        0x80, 0xC3, 0xF8, 0xF8, 0xFF, 0x80, 0xF8, 0xFF, 0x80, 0x80, 0x80, 0xC3,
        0xC3, 0x80, 0x80, 0xF8, 0xF0, 0xC3, 0xFF, 0x80, 0x80, 0xC3, 0xF0, 0xF8,
        0xFF, 0xC3, 0xC3, 0x80, 0xC3, 0xC3, 0xFF, 0xC3, 0x80, 0xFF, 0xFF, 0xFF,
        0xC3, 0xF0, 0xF0, 0xC3, 0xF8, 0xF8, 0xF0, 0xF0, 0xF8, 0xC3, 0xFF, 0xC3,
        0xC3, 0xF8, 0xF8, 0xFF, 0x80, 0xC3, 0xFF, 0xF0, 0xF0, 0xF8, 0xC3, 0xF8,
        0xC3, 0xF8, 0xF0, 0xFF, 0xC3, 0xFF, 0xC3, 0xF0, 0xFF, 0xF8, 0x80, 0xC3,
        0x80, 0xF8, 0xF0, 0xF0, 0xFF, 0xFF, 0xF8, 0xC3, 0xF8, 0xF8, 0xFF, 0xF0,
        0xFF, 0xC3, 0xF8, 0xFF, 0xC3, 0x80, 0x80, 0xFF, 0xF0, 0xF8, 0xF8, 0xF0,
        0xFF, 0xC3, 0xF0, 0xFF, 0x80, 0xF8, 0xC3, 0x80, 0xF8, 0xF8, 0xF0, 0xFF,
        0xF0, 0x80, 0xF0, 0xC3, 0xF0, 0x80, 0xC3, 0xFF, 0x80, 0x80, 0xFF, 0xF0,
        0xF8, 0xC3, 0xF0, 0xC3, 0xF8, 0xC3, 0x80, 0xF8,
    ];

    #[test]
    fn single_group_section_round_trips() {
        let outcome = djw_decompress(&XD3_SINGLE_GROUP_SECTION, XD3_SINGLE_GROUP_PLAIN.len())
            .expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_SINGLE_GROUP_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_SINGLE_GROUP_SECTION.len());
    }

    #[test]
    fn multi_group_section_round_trips() {
        let outcome = djw_decompress(&XD3_MULTI_GROUP_SECTION, XD3_MULTI_GROUP_PLAIN.len())
            .expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_MULTI_GROUP_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_MULTI_GROUP_SECTION.len());
    }

    #[test]
    fn truncated_stream_exhausts_input() {
        let truncated = &XD3_MULTI_GROUP_SECTION[..XD3_MULTI_GROUP_SECTION.len() / 2];
        let fault = decode_section(truncated, XD3_MULTI_GROUP_PLAIN.len()).unwrap_err();
        assert_eq!(fault, DjwFault::InputExhausted);
    }

    #[test]
    fn empty_input_cannot_back_any_output() {
        let fault = decode_section(&[], 10).unwrap_err();
        assert_eq!(
            fault,
            DjwFault::DeclaredOutputExceedsBitCapacity { declared: 10, bit_capacity: 0 }
        );
    }

    #[test]
    fn zero_output_budget_is_refused() {
        let fault = decode_section(&XD3_SINGLE_GROUP_SECTION, 0).unwrap_err();
        assert_eq!(fault, DjwFault::OutputBudgetIsZero);
    }

    /// A tiny section declaring an enormous output is refused before
    /// the sector bookkeeping that scales with the declaration, not
    /// after it.
    #[test]
    fn declared_output_past_bit_capacity_is_refused() {
        let bit_capacity = XD3_SINGLE_GROUP_SECTION.len() * 8;
        let fault =
            decode_section(&XD3_SINGLE_GROUP_SECTION, bit_capacity + 1).unwrap_err();
        assert_eq!(
            fault,
            DjwFault::DeclaredOutputExceedsBitCapacity { declared: bit_capacity + 1, bit_capacity }
        );
    }

    /// A code-length-code table that assigns no codes at all: the
    /// decoder builds it anyway (as xd3's does), and the first
    /// symbol wanted from it refuses.
    #[test]
    fn table_with_no_codes_refuses_first_symbol() {
        let mut writer = BitWriter::new();
        writer.write_value(GROUP_COUNT_BITS, 0); // one group
        writer.write_value(EXTRA_CODE_COUNT_BITS, 0); // seven lengths follow
        for _ in 0..ALWAYS_CODED_CODE_LENGTH_CODES {
            writer.write_value(CODE_LENGTH_CODE_LENGTH_BITS, 0); // all zero
        }
        let section = writer.finish();
        let fault = decode_section(&section, 16).unwrap_err();
        assert_eq!(fault, DjwFault::CodeOutsideTable);
    }

    /// A repeat run that carries past the 256-length code-length
    /// sequence: one pulled value, then run codes whose binary
    /// accumulation overshoots the elements that remain.
    #[test]
    fn repeat_run_past_sequence_end_is_refused() {
        let mut writer = BitWriter::new();
        writer.write_value(GROUP_COUNT_BITS, 0); // one group
        writer.write_value(EXTRA_CODE_COUNT_BITS, 0); // seven lengths follow
        // Code-length-code lengths: RUN_0 gets a 1-bit code, RUN_1
        // and the first recency index get 2-bit codes — canonically
        // RUN_0 = 0, RUN_1 = 10, recency-1 = 11.
        for length in [1usize, 2, 2, 0, 0, 0, 0] {
            writer.write_value(CODE_LENGTH_CODE_LENGTH_BITS, length);
        }
        // One pulled value (recency-1), then RUN_1 and seven RUN_0s:
        // contributions 2, 2, 4, 8, 16, 32, 64, 128 fill past 256
        // with a repeat left over.
        writer.write_value(2, 0b11);
        writer.write_value(2, 0b10);
        for _ in 0..7 {
            writer.write_bit(false);
        }
        let section = writer.finish();
        let fault = decode_section(&section, 16).unwrap_err();
        assert_eq!(fault, DjwFault::RepeatRunOvershootsSequence);
    }

    // DjwFault::SelectorNamesMissingGroup has no test here: the selector
    // queue holds exactly the declared group numbers and the recency
    // indices stay within them. The verdict exists as the typed landing
    // for xd3's assertion (XD3_ASSERT (gp < groups)), should the
    // structural argument ever be wrong.

    // ── Encoder round-trips ──────────────────────────────────────────

    /// SplitMix64, matching the house pseudo-random helper in the
    /// sibling modules.
    fn pseudo_random_bytes(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut mixed = state;
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d049bb133111eb);
                mixed ^= mixed >> 31;
                mixed as u8
            })
            .collect()
    }

    /// The encoder's whole contract at once: the stream decodes back
    /// to the input, and the decode consumes every stream byte — the
    /// consume-all framing check both slap and xd3 hold sections to.
    fn assert_round_trips(plain: &[u8]) {
        let stream = djw_compress(plain);
        let outcome = djw_decompress(&stream, plain.len()).expect("the emitted stream decodes");
        assert_eq!(outcome.decoded_bytes, plain, "decode differs from the encoded input");
        assert_eq!(
            outcome.consumed_input_length,
            stream.len(),
            "the decode must consume the whole stream"
        );
    }

    #[test]
    fn encoded_fixture_material_round_trips_and_shrinks() {
        for plain in [XD3_SINGLE_GROUP_PLAIN.as_slice(), XD3_MULTI_GROUP_PLAIN.as_slice()] {
            assert_round_trips(plain);
            assert!(
                djw_compress(plain).len() < plain.len(),
                "compressible material must shrink"
            );
        }
    }

    /// Uniform input exercises the lone-symbol phantom in both its
    /// arms: a nonzero byte puts the phantom at symbol 0, byte zero
    /// puts it at symbol 255.
    #[test]
    fn uniform_input_round_trips_through_the_phantom_code() {
        assert_round_trips(&[0x41; 1000]);
        assert_round_trips(&[0x00; 37]);
        assert!(djw_compress(&[0x41; 1000]).len() < 250, "one bit per byte plus tables");
    }

    #[test]
    fn tiny_inputs_round_trip() {
        assert_round_trips(&[0x7F]);
        for length in 1..=12 {
            assert_round_trips(&pseudo_random_bytes(0xd1ce + length as u64, length));
        }
    }

    #[test]
    fn full_alphabet_round_trips() {
        let plain: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        assert_round_trips(&plain);
    }

    #[test]
    fn random_low_alphabet_inputs_round_trip() {
        let cases: &[(u64, usize, u8)] =
            &[(0x01, 50, 3), (0x02, 700, 5), (0x03, 4096, 2), (0x04, 20000, 16)];
        for &(seed, length, alphabet) in cases {
            let plain: Vec<u8> = pseudo_random_bytes(seed, length)
                .into_iter()
                .map(|byte| byte % alphabet)
                .collect();
            assert_round_trips(&plain);
        }
    }

    /// A section stitched from two statistically different kinds of
    /// stretch, alternating — the shape the clustering exists for. The
    /// multi-table plan must round-trip on its own, not only when the
    /// size gate happens to choose it.
    #[test]
    fn clustered_emission_round_trips() {
        let mut plain = Vec::new();
        for stretch in 0..64u64 {
            let bytes = pseudo_random_bytes(stretch, 160).into_iter();
            if stretch % 2 == 0 {
                plain.extend(bytes.map(|byte| byte % 4));
            } else {
                plain.extend(bytes.map(|byte| 0xF0 | (byte % 8)));
            }
        }
        let plan = clustered_plan(&plain).expect("heterogeneous stretches cluster");
        assert!(plan.group_code_lengths.len() > 1, "the refinement must keep several tables");
        let stream = emit_plan(&plain, &plan);
        let outcome =
            djw_decompress(&stream, plain.len()).expect("the multi-table stream decodes");
        assert_eq!(outcome.decoded_bytes, plain);
        assert_eq!(outcome.consumed_input_length, stream.len());
        assert_round_trips(&plain);
    }
}
