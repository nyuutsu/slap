//! FGK secondary decompression: xdelta3's adaptive-Huffman coder
//! (catalog id 16), the catalog's last entry and, by its own source's
//! account, "for demonstration purposes only" — `xdelta3-fgk.h`, an
//! implementation of the FGK algorithm (Faller–Gallager–Knuth dynamic
//! Huffman coding, Knuth, *Journal of Algorithms* 6). That source is
//! the specification; the only hard requirement here is that decoded
//! output match xdelta3's byte for byte.
//!
//! Unlike DJW's static per-section tables, FGK carries no tables on the
//! wire at all. Decoder and encoder both start from a tree where every
//! byte is unseen and rebuild it in lockstep: decode a symbol by
//! walking the bit-path down the tree, run the identical update that
//! raises that symbol's weight and re-sorts the tree, then decode the
//! next symbol against the changed tree. The tree is not a structure
//! built once and read — it is a running fold, one step per output
//! byte, and correctness is entirely about reproducing xd3's update
//! order exactly.
//!
//! Tree-continuous across a kind, unlike DJW's fresh-per-section
//! tables: xd3 allocates and inits a kind's secondary stream once
//! (`xd3_get_secondary` inits only when the stream pointer is still
//! null) and carries it across every section of that kind, so a
//! section's first byte decodes against the tree the earlier sections
//! left behind, not an empty one. What does reset per section is the
//! bit reader and the output bound — xd3 byte-flushes each section and
//! decodes it to its own declared size. So this module decodes a kind's
//! sections as a sequence over one tree, restarting the reader at each
//! section's byte boundary. The gathering of a kind's sections lives on
//! the Haskell side, the way LZMA's does: both compressors process a
//! kind's sections as one continuous thing — a bitstream for LZMA, a
//! tree for FGK.
//!
//! The one mechanism that is noise in the C and wants to be structure
//! here is the zero-weight escape. An unseen byte has no path yet, so
//! all unseen bytes share a single zero-weight leaf — arriving there
//! means "read more bits to learn which unseen byte." The count of
//! still-unseen bytes is held as `2^exp + rem`, and the escape reads
//! `exp` or `exp + 1` bits — the ordinary trick for indexing a range
//! that is not a power of two — then walks that many steps down the
//! unseen list. That dance codes the first occurrence of every byte;
//! it has its own named shape here ('AdaptiveTree::nth_unseen' and the
//! escape branch of 'decode_one_symbol') rather than the bit-twiddling
//! xd3 spends on it.
//!
//! Where xd3 threads its tree through an arena of `fgk_node`s wired by
//! sibling/child/parent pointers and a block free-list, this holds the
//! tree as a `Vec<Node>` indexed by 'NodeId' and maintains the
//! sibling-weight order by index swaps. xd3's block bookkeeping exists
//! only to find a node's block leader — the rightmost node of equal
//! weight — in O(1); 'AdaptiveTree::block_front' finds it by walking
//! the weight-ordered sibling list instead, which lets the whole
//! block free-list (and the `fgk_promote` that maintains it) fall
//! away. The update then reads as the moves it is: reveal the symbol,
//! slide it to the front of its weight block, raise its weight, climb.

// ── Wire / algorithm constants ───────────────────────────────────────

/// The byte alphabet the coder ranges over. (`ALPHABET_SIZE`)
const ALPHABET_SIZE: usize = 256;

/// Total tree nodes: `ALPHABET_SIZE` leaves plus the `ALPHABET_SIZE - 1`
/// internal nodes a full binary tree over them needs.
/// (`(2 * alphabet_size) - 1`)
const TOTAL_NODES: usize = 2 * ALPHABET_SIZE - 1;

// ── Faults ───────────────────────────────────────────────────────────

/// The ways an FGK section can refuse to decode. Every arm is a
/// surfaced verdict — including the paths xd3 guards with an assertion
/// or trusts to its caller's "check integrity anyway." A crafted or
/// corrupt section reaches a named refusal here, never undefined
/// behavior.
#[derive(Debug, PartialEq, Eq)]
pub enum FgkFault {
    /// The caller asked for zero output bytes. The real path never
    /// does — a compressed section's framing declares a positive size
    /// before this is called — but a section that produces nothing has
    /// no reason to exist, so it is refused before a bit is read, as
    /// the DJW sibling refuses it.
    OutputBudgetIsZero,
    /// The bit stream ended before the section's declared output was
    /// produced. (xd3: "secondary decoder end of input")
    InputExhausted,
    /// The zero-weight escape resolved to an index past the end of the
    /// unseen-symbol list. xd3's `fgk_nth_zero` walks off the list and
    /// returns whatever it stopped on, documenting that "the caller
    /// should check integrity anyway"; this is that check. `requested`
    /// is the index the escape bits named, `unseen` the number of
    /// symbols that remained to name. Reachable on a crafted stream
    /// once the unseen count is not a power of two (so the escape field
    /// is one bit wider than the count strictly needs).
    ZeroIndexPastUnseenList { requested: usize, unseen: usize },
    /// A node's weight overflowed the 32-bit counter xd3 keeps it in
    /// (`fgk_weight`, whose source carries a literal "TODO: Need to
    /// test for overflow"). The root's weight is the count of symbols
    /// decoded so far, so reaching this needs an output past
    /// 2^32 bytes — bounded out of any real section by the declared
    /// size and by 'InputExhausted' arriving first. Surfaced rather
    /// than wrapped; no crafted case builds it.
    WeightCounterOverflow,
    /// A tree link that the shared invariant guarantees was found
    /// absent: a navigation step into a child an internal node must
    /// have, a block leader with no higher-weight successor, an unseen
    /// list with no head while a symbol is being revealed. None is
    /// reachable from a well-formed stream — internal nodes always
    /// carry both children, the root is the unique highest-weight node,
    /// the unseen list is non-empty whenever a zero-weight symbol is
    /// decoded — so this is the typed landing for xd3's assertions,
    /// surfaced should the structural argument ever be wrong. No
    /// crafted case builds it.
    TreeStructureCorrupt,
}

impl std::fmt::Display for FgkFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FgkFault::OutputBudgetIsZero => {
                write!(formatter, "an FGK section cannot decode to zero bytes")
            }
            FgkFault::InputExhausted => {
                write!(formatter, "the bit stream ended before the declared output was produced")
            }
            FgkFault::ZeroIndexPastUnseenList { requested, unseen } => write!(
                formatter,
                "a first-occurrence escape named unseen symbol {requested} but only {unseen} remain"
            ),
            FgkFault::WeightCounterOverflow => {
                write!(formatter, "a node's weight overflowed its 32-bit counter")
            }
            FgkFault::TreeStructureCorrupt => {
                write!(formatter, "the adaptive tree reached a structurally impossible state")
            }
        }
    }
}

// ── Bit reading ──────────────────────────────────────────────────────

/// The bit stream convention every FGK code is read under
/// (`xd3_decode_fgk`'s `cur_mask` loop): bytes are consumed in order;
/// within a byte, bits are consumed from the least significant up. The
/// escape field and the tree walk both assemble their bits most
/// significant first, but that is the reader's caller's doing — this
/// only hands out one bit at a time. Consumption is counted in whole
/// bytes: a byte is consumed the moment its first bit is read, which is
/// where xd3's input pointer moves too. A separate honest copy of the
/// DJW reader rather than a shared one — FGK needs only `read_bit`, and
/// the coupling would buy nothing.
struct BitReader<'section> {
    section_bytes: &'section [u8],
    consumed_byte_count: usize,
    current_byte: u8,
    /// The next bit's mask, `0x01..=0x80`; `0x100` means the current
    /// byte is spent and the next read fetches a fresh one.
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

    fn read_bit(&mut self) -> Result<bool, FgkFault> {
        if self.current_mask == BYTE_SPENT {
            self.current_byte = *self
                .section_bytes
                .get(self.consumed_byte_count)
                .ok_or(FgkFault::InputExhausted)?;
            self.consumed_byte_count += 1;
            self.current_mask = 1;
        }
        let bit = self.current_byte & (self.current_mask as u8) != 0;
        self.current_mask <<= 1;
        Ok(bit)
    }

    /// Discard any unread bits of the current byte so the next read
    /// fetches a fresh one — the per-section reset xd3 performs between
    /// a kind's sections (each section's bits are byte-flushed by the
    /// encoder). A no-op when already at a byte boundary.
    fn align_to_next_byte(&mut self) {
        self.current_mask = BYTE_SPENT;
    }

    fn consumed_byte_count(&self) -> usize {
        self.consumed_byte_count
    }
}

// ── The adaptive tree ────────────────────────────────────────────────

/// A position in the tree's node arena. The first `ALPHABET_SIZE`
/// indices are the symbol leaves (a leaf for byte `b` lives at
/// `NodeId(b)`), the rest are internal nodes handed out as symbols are
/// first seen. A newtype so a raw arena index can never stand in for a
/// symbol value or a byte count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct NodeId(usize);

/// One tree node. The two child links and the parent describe the
/// Huffman tree; `left`/`right` are the node's neighbours in the
/// weight-ordered sibling sequence (`left` toward lower weight, `right`
/// toward higher). A leaf carries no children. While a symbol is still
/// unseen its leaf is off the tree and on the unseen list, which is
/// threaded through the otherwise-idle `left_child`/`right_child`
/// fields of those leaves — the same reuse xd3 makes, so the fields
/// mean "tree child" for a coded leaf and "unseen-list neighbour" for
/// an unseen one.
#[derive(Clone, Copy, Default)]
struct Node {
    weight: u32,
    parent: Option<NodeId>,
    left_child: Option<NodeId>,
    right_child: Option<NodeId>,
    left: Option<NodeId>,
    right: Option<NodeId>,
}

/// The decoder's whole state for one section: the node arena and the
/// running accounting that the escape field reads. Mirrors xd3's
/// `fgk_stream` minus the block free-list.
struct AdaptiveTree {
    nodes: Vec<Node>,
    root: NodeId,
    /// Where the current symbol's tree walk has reached. Reset to the
    /// root after every decoded symbol.
    decode_ptr: NodeId,
    /// The next free internal-node slot, handed out by 'reveal_symbol'.
    free_node: usize,
    /// The head of the unseen-symbol list, or `None` once every symbol
    /// has been seen.
    remaining_zeros: Option<NodeId>,
    /// The unseen count and its `2^exp + rem` factoring, kept in step
    /// the way `fgk_factor_remaining` keeps them: the escape field is
    /// `exp` bits wide when `rem` is zero, `exp + 1` otherwise.
    zero_freq_count: usize,
    zero_freq_exp: usize,
    zero_freq_rem: usize,
}

impl AdaptiveTree {
    /// A fresh coder over the 256-byte alphabet, as `fgk_init` leaves
    /// it: the root is the unseen list's head (so the very first symbol
    /// is coded entirely by the escape), every leaf has weight zero,
    /// and the unseen list runs through the leaves in symbol order. The
    /// two `factor_remaining` calls reproduce xd3's init arithmetic,
    /// which seeds `zero_freq_count` at `alphabet_size + 2` and walks it
    /// down to `alphabet_size` while setting the exp/rem factoring.
    fn new() -> Self {
        let mut tree = AdaptiveTree {
            nodes: vec![Node::default(); TOTAL_NODES],
            root: NodeId(0),
            decode_ptr: NodeId(0),
            free_node: ALPHABET_SIZE,
            remaining_zeros: Some(NodeId(0)),
            zero_freq_count: ALPHABET_SIZE + 2,
            zero_freq_exp: 0,
            zero_freq_rem: 0,
        };
        tree.factor_remaining();
        tree.factor_remaining();
        for symbol in 0..ALPHABET_SIZE {
            let leaf = &mut tree.nodes[symbol];
            leaf.right_child = (symbol + 1 < ALPHABET_SIZE).then(|| NodeId(symbol + 1));
            leaf.left_child = (symbol >= 1).then(|| NodeId(symbol - 1));
        }
        tree
    }

    fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.0]
    }

    fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id.0]
    }

    /// Re-factor the unseen count after one symbol leaves the list:
    /// drop the count by one and set `exp`/`rem` so that
    /// `count == 2^exp + rem` with `exp` as large as it can be
    /// (`fgk_factor_remaining`).
    fn factor_remaining(&mut self) {
        self.zero_freq_count -= 1;
        let mut shrinking = self.zero_freq_count;
        self.zero_freq_exp = 0;
        while shrinking > 1 {
            self.zero_freq_exp += 1;
            shrinking >>= 1;
        }
        self.zero_freq_rem = self.zero_freq_count - (1 << self.zero_freq_exp);
    }

    /// Decode one symbol: walk the tree bit by bit, resolving the
    /// zero-weight escape when the walk lands on the unseen leaf, then
    /// run the update that keeps decoder and encoder in step. Returns
    /// the decoded byte; the tree is advanced and `decode_ptr` reset
    /// for the next call.
    fn decode_one_symbol(&mut self, reader: &mut BitReader) -> Result<u8, FgkFault> {
        // The escape bits accumulate here; at most `exp + 1` of them
        // (nine over the 256-byte alphabet) before they resolve.
        let mut escape_bits: Vec<bool> = Vec::new();
        loop {
            let bit = reader.read_bit()?;
            if self.node(self.decode_ptr).weight == 0 {
                // On the unseen leaf: this bit is part of the escape
                // field naming which unseen symbol is meant.
                escape_bits.push(bit);
                let bits_required = if self.zero_freq_rem == 0 {
                    self.zero_freq_exp
                } else {
                    self.zero_freq_exp + 1
                };
                if escape_bits.len() >= bits_required {
                    let symbol = self.nth_unseen(unseen_index_from(&escape_bits))?;
                    return self.settle_symbol(symbol);
                }
            } else {
                // On an interior node: the bit chooses a child.
                let descend_into = if bit {
                    self.node(self.decode_ptr).right_child
                } else {
                    self.node(self.decode_ptr).left_child
                };
                self.decode_ptr = descend_into.ok_or(FgkFault::TreeStructureCorrupt)?;
                if self.node(self.decode_ptr).left_child.is_none() {
                    // A leaf. A weighted one is the decoded symbol; the
                    // unseen leaf is the decoded symbol only when it is
                    // the last unseen one (no escape bits left to read),
                    // and otherwise begins the escape on the next bit.
                    if self.node(self.decode_ptr).weight != 0 {
                        let symbol = self.decode_ptr.0;
                        return self.settle_symbol(symbol);
                    }
                    if self.zero_freq_count == 1 {
                        let symbol = self.nth_unseen(0)?;
                        return self.settle_symbol(symbol);
                    }
                }
            }
        }
    }

    /// A decoded symbol's common tail: run the lockstep update and reset
    /// the walk to the root for the next symbol.
    fn settle_symbol(&mut self, symbol: usize) -> Result<u8, FgkFault> {
        self.update_after(symbol)?;
        self.decode_ptr = self.root;
        Ok(symbol as u8)
    }

    /// The symbol `steps` places down the unseen list from its head
    /// (`fgk_nth_zero`). xd3 walks off the end silently and trusts the
    /// caller to notice; this names the overrun instead.
    fn nth_unseen(&self, steps: usize) -> Result<usize, FgkFault> {
        let mut cursor = self.remaining_zeros.ok_or(FgkFault::TreeStructureCorrupt)?;
        for _ in 0..steps {
            cursor = self.node(cursor).right_child.ok_or(FgkFault::ZeroIndexPastUnseenList {
                requested: steps,
                unseen: self.zero_freq_count,
            })?;
        }
        Ok(cursor.0)
    }

    /// Update the tree after `symbol` was decoded — the running fold
    /// that keeps decoder and encoder in lockstep (`fgk_update_tree`).
    /// Reveal the symbol if this is its first sighting, then climb from
    /// it to the root, at each level sliding the node to the front of
    /// its weight block before raising its weight by one.
    fn update_after(&mut self, symbol: usize) -> Result<(), FgkFault> {
        let mut climbing = if self.node(NodeId(symbol)).weight == 0 {
            self.reveal_symbol(symbol)?
        } else {
            NodeId(symbol)
        };
        while climbing != self.root {
            self.slide_to_block_front(climbing)?;
            self.raise_weight(climbing)?;
            climbing = self.node(climbing).parent.ok_or(FgkFault::TreeStructureCorrupt)?;
        }
        self.raise_weight(self.root)
    }

    /// Raise one node's weight by one, refusing the 32-bit overflow xd3
    /// leaves as a TODO.
    fn raise_weight(&mut self, id: NodeId) -> Result<(), FgkFault> {
        let raised = self.node(id).weight.checked_add(1).ok_or(FgkFault::WeightCounterOverflow)?;
        self.node_mut(id).weight = raised;
        Ok(())
    }

    /// The leader of a node's weight block: the rightmost node of equal
    /// weight in the sibling sequence. xd3 maintains this in O(1)
    /// through its block free-list; the sibling sequence is weight-
    /// ordered with equal weights contiguous, so walking right while the
    /// weight holds finds the same node and lets the free-list go.
    fn block_front(&self, node: NodeId) -> NodeId {
        let block_weight = self.node(node).weight;
        let mut leader = node;
        while let Some(higher) = self.node(leader).right {
            if self.node(higher).weight != block_weight {
                break;
            }
            leader = higher;
        }
        leader
    }

    /// Slide a node to the front of its weight block (`fgk_move_right`):
    /// swap it with its block leader in both the sibling sequence and
    /// the tree, so that the weight raise about to follow keeps the
    /// sequence ordered. A no-op for a zero-weight node, for the leader
    /// itself, or when the leader is the node's own parent — the three
    /// guards xd3 spends before touching a pointer.
    fn slide_to_block_front(&mut self, forward: NodeId) -> Result<(), FgkFault> {
        if self.node(forward).weight == 0 {
            return Ok(());
        }
        let back = self.block_front(forward);
        if forward == back || self.node(forward).parent == Some(back) {
            return Ok(());
        }

        // The leader has a higher-weight successor in any well-formed
        // tree — it is not the root (the root is the unique top of the
        // sequence, and a forward node whose leader were the root would
        // have tripped the parent guard). Its absence is corruption.
        let back_successor = self.node(back).right.ok_or(FgkFault::TreeStructureCorrupt)?;

        // Re-link the sibling sequence so `forward` takes `back`'s slot
        // and `back` takes `forward`'s. The adjacency special-cases
        // (the two nodes neighbouring each other) are xd3's, kept.
        self.node_mut(back_successor).left = Some(forward);
        if let Some(forward_left) = self.node(forward).left {
            self.node_mut(forward_left).right = Some(back);
        }

        let forward_right = self.node(forward).right;
        self.node_mut(forward).right = Some(back_successor);
        if forward_right == Some(back) {
            self.node_mut(back).right = Some(forward);
        } else {
            if let Some(between) = forward_right {
                self.node_mut(between).left = Some(back);
            }
            self.node_mut(back).right = forward_right;
        }

        let back_left = self.node(back).left;
        let forward_left = self.node(forward).left;
        self.node_mut(back).left = forward_left;
        if back_left == Some(forward) {
            self.node_mut(forward).left = Some(back);
        } else {
            if let Some(between) = back_left {
                self.node_mut(between).right = Some(forward);
            }
            self.node_mut(forward).left = back_left;
        }

        // Exchange the two nodes' places in the tree: swap their
        // parents, then point each parent's child slot at the node that
        // now sits there. Both child-slot sides are read before either
        // is written, so a shared parent swaps its two children cleanly.
        let parent_forward = self.node(forward).parent;
        let parent_back = self.node(back).parent;
        let forward_was_right = parent_forward.map(|p| self.node(p).right_child == Some(forward));
        let back_was_right = parent_back.map(|p| self.node(p).right_child == Some(back));
        self.node_mut(forward).parent = parent_back;
        self.node_mut(back).parent = parent_forward;
        if let Some(parent) = parent_forward {
            self.set_child(parent, forward_was_right.unwrap(), back);
        }
        if let Some(parent) = parent_back {
            self.set_child(parent, back_was_right.unwrap(), forward);
        }
        Ok(())
    }

    /// Point a parent's right or left child slot at a node.
    fn set_child(&mut self, parent: NodeId, to_right: bool, child: NodeId) {
        if to_right {
            self.node_mut(parent).right_child = Some(child);
        } else {
            self.node_mut(parent).left_child = Some(child);
        }
    }

    /// Bring a symbol into the tree on its first sighting
    /// (`fgk_increase_zero_weight`): split the unseen leaf into a new
    /// internal node whose right child is this newly-seen symbol and
    /// whose left child is the rest of the unseen list. Returns the
    /// node now carrying the symbol, from which 'update_after' climbs.
    /// The lone-remaining-symbol case needs no split — the unseen leaf
    /// simply becomes that symbol's leaf.
    fn reveal_symbol(&mut self, symbol: usize) -> Result<NodeId, FgkFault> {
        let revealed = NodeId(symbol);
        if self.zero_freq_count == 1 {
            self.node_mut(revealed).right_child = None;
            self.remaining_zeros = None;
            return Ok(revealed);
        }

        let old_head = self.remaining_zeros.ok_or(FgkFault::TreeStructureCorrupt)?;
        let new_internal = NodeId(self.free_node);
        self.free_node += 1;

        let head_parent = self.node(old_head).parent;
        let head_right = self.node(old_head).right;
        {
            let internal = self.node_mut(new_internal);
            internal.parent = head_parent;
            internal.right = head_right;
            internal.weight = 0;
            internal.right_child = Some(revealed);
            internal.left = Some(revealed);
        }

        if self.remaining_zeros == Some(self.root) {
            // The first symbol ever coded: the new internal node is the
            // whole tree's new root.
            self.root = new_internal;
        } else {
            if let Some(successor) = head_right {
                self.node_mut(successor).left = Some(new_internal);
            }
            let head_parent = head_parent.ok_or(FgkFault::TreeStructureCorrupt)?;
            let parent_holds_head_right = self.node(head_parent).right_child == Some(old_head);
            self.set_child(head_parent, parent_holds_head_right, new_internal);
        }

        // Drop the symbol from the unseen list; the list's head advances
        // and the count re-factors. The new head becomes the internal
        // node's left child — the unseen leaf in its new tree slot.
        self.eliminate_unseen(revealed);
        let new_head = self.remaining_zeros.ok_or(FgkFault::TreeStructureCorrupt)?;
        self.node_mut(new_internal).left_child = Some(new_head);
        {
            let symbol_leaf = self.node_mut(revealed);
            symbol_leaf.right = Some(new_internal);
            symbol_leaf.left = Some(new_head);
            symbol_leaf.parent = Some(new_internal);
            symbol_leaf.left_child = None;
            symbol_leaf.right_child = None;
        }
        {
            let head_leaf = self.node_mut(new_head);
            head_leaf.parent = Some(new_internal);
            head_leaf.right = Some(revealed);
        }
        Ok(revealed)
    }

    /// Splice a symbol out of the unseen list (`fgk_eliminate_zero`).
    /// The list is threaded through the leaves' `left_child`/
    /// `right_child` links; the head's removal advances
    /// `remaining_zeros`, an interior removal re-links its neighbours.
    /// Re-factors the unseen count as the symbol leaves.
    fn eliminate_unseen(&mut self, node: NodeId) {
        if self.zero_freq_count == 1 {
            return;
        }
        self.factor_remaining();
        let predecessor = self.node(node).left_child;
        let successor = self.node(node).right_child;
        match (predecessor, successor) {
            // The head: advance to the next unseen symbol, which becomes
            // the new head with no predecessor.
            (None, _) => {
                self.remaining_zeros = successor;
                if let Some(new_head) = successor {
                    self.node_mut(new_head).left_child = None;
                }
            }
            // The tail: its predecessor becomes the new tail.
            (Some(predecessor), None) => {
                self.node_mut(predecessor).right_child = None;
            }
            // Interior: stitch predecessor and successor together.
            (Some(predecessor), Some(successor)) => {
                self.node_mut(successor).left_child = Some(predecessor);
                self.node_mut(predecessor).right_child = Some(successor);
            }
        }
    }
}

/// Assemble the unseen-list index from accumulated escape bits, most
/// significant first — the order `fgk_decode_data` reconstructs them
/// in. An empty field (the lone-remaining-symbol path, which reads no
/// escape bits) names index zero.
fn unseen_index_from(escape_bits: &[bool]) -> usize {
    escape_bits.iter().fold(0, |index, &bit| (index << 1) | bit as usize)
}

// ── The section decode ───────────────────────────────────────────────

/// What one kind's decode produced: the decoded bytes of every section
/// of the kind, concatenated in order, and how many input bytes the
/// reader consumed across all of them. A shortfall against the gathered
/// stream's length means trailing bytes the decode never needed — a
/// framing fact for the caller to judge.
#[derive(Debug)]
pub struct FgkKindOutcome {
    pub decoded_bytes: Vec<u8>,
    pub consumed_input_length: usize,
}

/// Decode a kind's gathered FGK sections through one shared tree.
/// `gathered` is the sections' stream bytes concatenated in window
/// order; `section_output_lengths` is each section's declared size, in
/// the same order. Every section decodes to exactly its declared size
/// against the tree the earlier sections matured, and the reader
/// realigns to a byte boundary between sections. On failure the
/// returned message names the cause, for the caller to wrap as it sees
/// fit.
pub fn fgk_decompress_sections(
    gathered: &[u8],
    section_output_lengths: &[usize],
) -> Result<FgkKindOutcome, String> {
    decode_kind(gathered, section_output_lengths).map_err(|fault| fault.to_string())
}

fn decode_kind(
    gathered: &[u8],
    section_output_lengths: &[usize],
) -> Result<FgkKindOutcome, FgkFault> {
    let mut reader = BitReader::over(gathered);
    let mut tree = AdaptiveTree::new();

    // Grown rather than pre-reserved so a tiny hostile section declaring
    // an enormous output exhausts its bits long before it exhausts
    // memory, the same guard the DJW sector walk keeps.
    let mut decoded_bytes: Vec<u8> = Vec::new();
    for &section_output_length in section_output_lengths {
        if section_output_length == 0 {
            return Err(FgkFault::OutputBudgetIsZero);
        }
        let section_end = decoded_bytes.len() + section_output_length;
        while decoded_bytes.len() < section_end {
            decoded_bytes.push(tree.decode_one_symbol(&mut reader)?);
        }
        reader.align_to_next_byte();
    }

    Ok(FgkKindOutcome {
        decoded_bytes,
        consumed_input_length: reader.consumed_byte_count(),
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Write bits in the encoder's convention (`xd3_encode_bit`): bits
    /// land LSB-first within each byte. Used only to hand-build the
    /// crafted hostile streams below; the round-trip fixtures are
    /// unmodified xdelta3 output.
    struct BitWriter {
        bytes: Vec<u8>,
        current_byte: u8,
        current_mask: u8,
    }

    impl BitWriter {
        fn new() -> Self {
            BitWriter { bytes: Vec::new(), current_byte: 0, current_mask: 1 }
        }
        fn write_bit(&mut self, bit: bool) {
            if bit {
                self.current_byte |= self.current_mask;
            }
            if self.current_mask == 0x80 {
                self.bytes.push(self.current_byte);
                self.current_byte = 0;
                self.current_mask = 1;
            } else {
                self.current_mask <<= 1;
            }
        }
        /// Write `bit_count` bits of `value`, most significant first —
        /// the order the escape field and the tree walk read.
        fn write_value(&mut self, bit_count: usize, value: usize) {
            for position in (0..bit_count).rev() {
                self.write_bit(value >> position & 1 != 0);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.current_mask != 1 {
                self.bytes.push(self.current_byte);
            }
            self.bytes
        }
    }

    // The two round-trip fixtures are unmodified xdelta3 output, lifted
    // by the -S fgk / -S none twin trick the DJW and LZMA modules use:
    // the -S fgk patch's compressed section with its decompressed-size
    // varint stripped (that prefix is the framing the Haskell seam peels
    // before calling here), paired with the same window's plain section
    // from the -S none twin — the instruction streams are identical
    // across the two settings, so the twin's section is exactly what the
    // FGK stream decodes to. The patches they were cut from were
    // generated in a scratch directory and discarded; only these arrays
    // are durable.
    //
    // The first is short and first-occurrence-heavy: a small section
    // whose bytes are mostly distinct, so nearly every symbol is coded
    // through the zero-weight escape and the tree is still sparse. The
    // second is long enough that the adaptive tree matures and repeated
    // bytes decode by short paths.

    const XD3_FGK_SHORT_STREAM: [u8; 77] = [
        0x2E, 0x2C, 0x30, 0x0D, 0x01, 0xEC, 0xC6, 0x21, 0xCC, 0xC4, 0x08, 0xCC,
        0x70, 0x0C, 0x8B, 0x55, 0xB0, 0x30, 0xD6, 0xC2, 0x7C, 0xC4, 0x48, 0x81,
        0xE5, 0x0E, 0xE3, 0x68, 0x4C, 0x12, 0x93, 0xC0, 0x64, 0xEF, 0x98, 0xA4,
        0x80, 0x61, 0xC0, 0xC5, 0xE8, 0x7D, 0x18, 0x03, 0x46, 0x9F, 0x18, 0xCC,
        0xC2, 0xA0, 0x43, 0xFB, 0x1F, 0xCB, 0xE6, 0xB6, 0xDA, 0xCD, 0x22, 0xD9,
        0xBE, 0x8E, 0xC3, 0x6E, 0x96, 0xFE, 0xE6, 0xDD, 0xD1, 0xED, 0xDE, 0xAE,
        0xBD, 0x35, 0x6C, 0xBB, 0x0A,
    ];
    const XD3_FGK_SHORT_PLAIN: [u8; 83] = [
        0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72,
        0x6F, 0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
        0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x61, 0x20, 0x6C, 0x61, 0x7A,
        0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x20, 0x70, 0x61, 0x63, 0x6B, 0x20,
        0x6D, 0x79, 0x20, 0x62, 0x6F, 0x78, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20,
        0x66, 0x69, 0x76, 0x65, 0x20, 0x64, 0x6F, 0x7A, 0x65, 0x6E, 0x20, 0x6C,
        0x69, 0x71, 0x75, 0x6F, 0x72, 0x20, 0x6A, 0x75, 0x67, 0x73, 0x2E,
    ];
    const XD3_FGK_LONG_STREAM: [u8; 285] = [
        0x04, 0xEC, 0x70, 0x8C, 0x60, 0x8F, 0x71, 0xD8, 0x39, 0x66, 0x19, 0x82,
        0x41, 0xEF, 0x7F, 0x7D, 0xCF, 0x8D, 0x75, 0x61, 0xB1, 0x5C, 0xA7, 0x27,
        0x82, 0x2D, 0x25, 0x1D, 0x5D, 0x2B, 0x08, 0xB8, 0x99, 0xB6, 0x3E, 0xD6,
        0x1A, 0x02, 0xED, 0x19, 0xF3, 0x1D, 0x36, 0xA1, 0x8B, 0xFB, 0xF9, 0x37,
        0x6F, 0xA9, 0x37, 0x1E, 0xEC, 0xB1, 0x46, 0xE1, 0x7C, 0x64, 0xBD, 0x31,
        0xB2, 0x6B, 0x7B, 0x6E, 0xFD, 0x76, 0x66, 0x24, 0x9B, 0x78, 0xCC, 0xCA,
        0x7C, 0x0C, 0x0C, 0xD1, 0x50, 0xFE, 0x34, 0xF1, 0xD3, 0xCE, 0x40, 0x78,
        0x9D, 0xDC, 0xFD, 0xD7, 0xC4, 0x3F, 0xFE, 0x53, 0xC7, 0x59, 0x3D, 0x37,
        0xD4, 0x91, 0xE7, 0xC3, 0xB1, 0xC7, 0xE9, 0xCA, 0x01, 0xB3, 0xAE, 0xB3,
        0xDC, 0x47, 0x5E, 0x6F, 0x27, 0xEF, 0xE4, 0xA5, 0x5F, 0x64, 0x72, 0x51,
        0x63, 0x85, 0x3D, 0x9C, 0x7F, 0xD2, 0x42, 0xAF, 0x4F, 0xDB, 0xF7, 0xBE,
        0x3A, 0x62, 0x77, 0x63, 0x6D, 0x91, 0x98, 0x5D, 0xC1, 0xBA, 0xED, 0x48,
        0xCD, 0xBB, 0x9B, 0xCA, 0xB2, 0xA1, 0x13, 0xFC, 0x59, 0xAE, 0x90, 0x58,
        0x74, 0xD4, 0xF9, 0x94, 0x7E, 0x23, 0xE4, 0xFD, 0xF1, 0xBD, 0xC5, 0x98,
        0xDB, 0xE7, 0xF8, 0xEB, 0x87, 0xEB, 0xBF, 0xE9, 0xFF, 0x85, 0x3F, 0x12,
        0xAE, 0xA8, 0xDA, 0xCB, 0xBE, 0x1E, 0x9F, 0x66, 0x9C, 0x8D, 0x2F, 0xF9,
        0x1A, 0x9B, 0x1B, 0x1F, 0xEC, 0x65, 0x2B, 0xB0, 0x25, 0x79, 0x6D, 0xF0,
        0x79, 0xFF, 0x3B, 0x75, 0x1D, 0xF7, 0xBB, 0x45, 0x4F, 0xA7, 0x1C, 0x07,
        0x36, 0xDC, 0xB6, 0x3F, 0xAF, 0x64, 0xCB, 0xBE, 0xFC, 0x7B, 0xAB, 0x41,
        0x90, 0x92, 0x0A, 0xEE, 0xAD, 0xB0, 0x51, 0x89, 0x4C, 0xFD, 0x2E, 0x51,
        0xE2, 0x08, 0xEA, 0x14, 0x39, 0x41, 0x0B, 0x81, 0x1F, 0x75, 0x79, 0xFC,
        0x63, 0xB1, 0xC8, 0xFD, 0xA4, 0x84, 0xBC, 0x7F, 0x07, 0x1F, 0xC1, 0x86,
        0x6D, 0x14, 0x09, 0x3B, 0x90, 0xF1, 0x48, 0xA4, 0xB9, 0xC1, 0xEA, 0x3D,
        0xAF, 0xDE, 0xAC, 0xBB, 0x75, 0xFD, 0xE6, 0x2A, 0x2B,
    ];
    const XD3_FGK_LONG_PLAIN: [u8; 564] = [
        0x20, 0x6F, 0x73, 0x42, 0x20, 0x20, 0x65, 0x72, 0x20, 0x69, 0x73, 0x43,
        0x61, 0x20, 0x20, 0x43, 0x73, 0x6F, 0x20, 0x72, 0x69, 0x20, 0x74, 0x6E,
        0x20, 0x43, 0x6E, 0x73, 0x65, 0x20, 0x44, 0x69, 0x61, 0x74, 0x74, 0x20,
        0x6E, 0x43, 0x74, 0x6E, 0x41, 0x73, 0x20, 0x44, 0x6F, 0x41, 0x6F, 0x6F,
        0x41, 0x61, 0x45, 0x42, 0x6E, 0x20, 0x61, 0x43, 0x45, 0x74, 0x6F, 0x72,
        0x20, 0x72, 0x65, 0x20, 0x41, 0x43, 0x43, 0x42, 0x6F, 0x73, 0x44, 0x73,
        0x45, 0x20, 0x20, 0x73, 0x45, 0x43, 0x45, 0x65, 0x69, 0x74, 0x42, 0x20,
        0x61, 0x69, 0x43, 0x61, 0x45, 0x61, 0x73, 0x20, 0x6E, 0x44, 0x69, 0x20,
        0x44, 0x61, 0x20, 0x41, 0x41, 0x74, 0x73, 0x42, 0x69, 0x20, 0x61, 0x72,
        0x20, 0x69, 0x69, 0x41, 0x45, 0x65, 0x6F, 0x6F, 0x74, 0x74, 0x42, 0x20,
        0x43, 0x20, 0x45, 0x44, 0x45, 0x69, 0x44, 0x6F, 0x41, 0x73, 0x20, 0x6F,
        0x20, 0x45, 0x73, 0x69, 0x65, 0x65, 0x61, 0x20, 0x6E, 0x20, 0x73, 0x65,
        0x42, 0x20, 0x42, 0x69, 0x73, 0x73, 0x42, 0x61, 0x20, 0x42, 0x73, 0x42,
        0x41, 0x6E, 0x73, 0x61, 0x45, 0x72, 0x42, 0x42, 0x61, 0x44, 0x43, 0x73,
        0x69, 0x43, 0x45, 0x72, 0x6E, 0x44, 0x61, 0x41, 0x20, 0x6F, 0x20, 0x44,
        0x20, 0x73, 0x45, 0x42, 0x20, 0x20, 0x44, 0x41, 0x69, 0x45, 0x72, 0x45,
        0x44, 0x44, 0x42, 0x73, 0x43, 0x61, 0x74, 0x45, 0x42, 0x44, 0x65, 0x42,
        0x44, 0x65, 0x65, 0x20, 0x20, 0x74, 0x74, 0x45, 0x69, 0x42, 0x20, 0x65,
        0x74, 0x20, 0x72, 0x20, 0x20, 0x6E, 0x45, 0x20, 0x72, 0x73, 0x72, 0x20,
        0x61, 0x41, 0x20, 0x61, 0x42, 0x74, 0x45, 0x61, 0x6F, 0x73, 0x61, 0x42,
        0x73, 0x65, 0x43, 0x20, 0x41, 0x6F, 0x72, 0x42, 0x74, 0x42, 0x6F, 0x42,
        0x20, 0x41, 0x74, 0x45, 0x72, 0x74, 0x44, 0x20, 0x6E, 0x73, 0x61, 0x6F,
        0x20, 0x65, 0x74, 0x45, 0x6E, 0x42, 0x42, 0x44, 0x41, 0x72, 0x65, 0x73,
        0x6F, 0x65, 0x45, 0x6F, 0x72, 0x20, 0x45, 0x73, 0x43, 0x74, 0x44, 0x72,
        0x44, 0x42, 0x73, 0x61, 0x6F, 0x74, 0x20, 0x43, 0x20, 0x6E, 0x6E, 0x20,
        0x42, 0x6F, 0x44, 0x41, 0x20, 0x61, 0x20, 0x45, 0x65, 0x42, 0x20, 0x72,
        0x44, 0x45, 0x72, 0x72, 0x65, 0x20, 0x45, 0x20, 0x20, 0x72, 0x6E, 0x72,
        0x42, 0x20, 0x6F, 0x43, 0x69, 0x42, 0x45, 0x61, 0x20, 0x20, 0x6E, 0x20,
        0x20, 0x69, 0x45, 0x69, 0x6F, 0x74, 0x69, 0x20, 0x65, 0x65, 0x65, 0x6E,
        0x20, 0x45, 0x41, 0x74, 0x44, 0x6E, 0x20, 0x61, 0x20, 0x73, 0x72, 0x20,
        0x45, 0x44, 0x43, 0x6E, 0x74, 0x41, 0x65, 0x20, 0x45, 0x74, 0x42, 0x6F,
        0x43, 0x20, 0x20, 0x65, 0x41, 0x20, 0x42, 0x74, 0x6F, 0x20, 0x72, 0x45,
        0x20, 0x6F, 0x20, 0x41, 0x72, 0x73, 0x20, 0x65, 0x73, 0x69, 0x43, 0x6E,
        0x73, 0x6F, 0x42, 0x6F, 0x72, 0x42, 0x43, 0x6F, 0x6F, 0x69, 0x43, 0x42,
        0x43, 0x73, 0x74, 0x65, 0x20, 0x61, 0x20, 0x20, 0x20, 0x45, 0x65, 0x61,
        0x44, 0x45, 0x6F, 0x41, 0x20, 0x6E, 0x69, 0x65, 0x6F, 0x69, 0x45, 0x6E,
        0x20, 0x6E, 0x42, 0x41, 0x65, 0x6F, 0x20, 0x20, 0x69, 0x20, 0x43, 0x65,
        0x43, 0x65, 0x61, 0x20, 0x42, 0x41, 0x65, 0x74, 0x43, 0x73, 0x69, 0x44,
        0x74, 0x74, 0x74, 0x69, 0x6E, 0x43, 0x44, 0x61, 0x65, 0x72, 0x43, 0x20,
        0x72, 0x20, 0x44, 0x43, 0x20, 0x65, 0x20, 0x74, 0x73, 0x43, 0x20, 0x65,
        0x69, 0x20, 0x43, 0x20, 0x61, 0x42, 0x20, 0x6F, 0x42, 0x74, 0x42, 0x20,
        0x6E, 0x42, 0x20, 0x45, 0x20, 0x72, 0x43, 0x74, 0x45, 0x6E, 0x20, 0x74,
        0x69, 0x43, 0x44, 0x41, 0x6E, 0x45, 0x73, 0x20, 0x61, 0x73, 0x44, 0x20,
        0x44, 0x73, 0x20, 0x45, 0x65, 0x20, 0x69, 0x20, 0x72, 0x43, 0x44, 0x42,
        0x20, 0x20, 0x72, 0x73, 0x44, 0x6F, 0x43, 0x20, 0x69, 0x65, 0x20, 0x42,
        0x73, 0x20, 0x61, 0x43, 0x41, 0x42, 0x44, 0x43, 0x43, 0x45, 0x74, 0x65,
        0x42, 0x42, 0x45, 0x44, 0x72, 0x6E, 0x61, 0x44, 0x72, 0x69, 0x45, 0x69,
    ];

    // Two consecutive data sections of one patch's data kind — window 0
    // and window 1 — gathered in order, the way the Haskell seam hands a
    // kind's compressed sections across. They share one tree: window 1's
    // first byte decodes against the tree window 0 matured, and decoding
    // window 1 from a fresh tree (the bug this guards) diverges on its
    // very first symbol. Lifted by the same -S fgk / -S none twin trick,
    // from a multi-window patch generated in a scratch directory and
    // discarded.
    const XD3_FGK_MULTI_GATHERED: [u8; 281] = [
        0x82, 0x44, 0x10, 0xD4, 0x46, 0x74, 0x0E, 0xC1, 0x10, 0xFA, 0x0F, 0x82,
        0x44, 0x10, 0x83, 0x94, 0xBD, 0x2D, 0xE3, 0xD6, 0x63, 0xDD, 0xDD, 0x27,
        0x50, 0x30, 0x4B, 0x32, 0x91, 0xC5, 0xE7, 0xAC, 0x2F, 0x5F, 0x20, 0xAD,
        0xF5, 0x7B, 0x6F, 0xDD, 0xD9, 0xA6, 0xF7, 0xAB, 0x38, 0xB9, 0x48, 0xF9,
        0x25, 0x0E, 0x6B, 0x1B, 0x65, 0x0B, 0xDB, 0x1E, 0x2D, 0x0C, 0xA2, 0xE6,
        0x97, 0x4A, 0x23, 0xCC, 0x19, 0x5A, 0x88, 0xE3, 0x54, 0x1F, 0x23, 0xE1,
        0xA9, 0x84, 0xBA, 0x1E, 0x1C, 0x62, 0x30, 0xA7, 0xF1, 0xD4, 0x1F, 0x57,
        0x5E, 0x46, 0x2B, 0x0E, 0xC5, 0xED, 0xD8, 0x93, 0x32, 0x7E, 0x67, 0x8E,
        0x56, 0x1B, 0xEA, 0x4A, 0xE7, 0xAE, 0xAD, 0x6A, 0x11, 0xB1, 0xD8, 0xC6,
        0xD5, 0xE9, 0x09, 0xDF, 0x2B, 0x6C, 0xDC, 0x7C, 0xE3, 0x68, 0x3D, 0x59,
        0x50, 0xE8, 0x44, 0x18, 0x4E, 0xEB, 0xAA, 0x93, 0x24, 0xCE, 0xC7, 0x8D,
        0x23, 0x62, 0x88, 0x9F, 0xC2, 0xC6, 0xF3, 0xA2, 0x79, 0xE6, 0xE5, 0x7B,
        0x77, 0x01, 0xF8, 0xCF, 0x38, 0x56, 0xA9, 0x91, 0xC6, 0xCF, 0xB6, 0xF5,
        0xA5, 0x4E, 0x9B, 0x20, 0x9A, 0x49, 0x7D, 0x11, 0x8B, 0xC7, 0xCF, 0x58,
        0x65, 0xCF, 0x91, 0xEA, 0xB2, 0x77, 0x33, 0x85, 0x62, 0x26, 0x2A, 0xB2,
        0x3C, 0x5C, 0x1A, 0xF5, 0x69, 0xE7, 0x84, 0xC6, 0xDB, 0x4B, 0x4E, 0x6D,
        0xDA, 0x29, 0x2E, 0xA4, 0xD5, 0xFC, 0x73, 0xBD, 0xD6, 0xB6, 0xFA, 0xD2,
        0x72, 0xE9, 0x7F, 0x22, 0x23, 0x2A, 0xE2, 0xE7, 0xFF, 0x1D, 0xB1, 0x67,
        0xA8, 0xA2, 0x14, 0x51, 0x1F, 0x6B, 0xC9, 0xC7, 0x23, 0x62, 0x2D, 0x7C,
        0x24, 0x34, 0x22, 0x77, 0x16, 0x6F, 0x0E, 0x23, 0x2C, 0x16, 0x53, 0x8C,
        0x8B, 0xDF, 0x76, 0x61, 0xF5, 0xE9, 0x6E, 0x13, 0x62, 0x17, 0xAF, 0xAA,
        0x50, 0x21, 0x32, 0xFD, 0x30, 0x09, 0x36, 0xF4, 0xAF, 0xB4, 0x18, 0x8D,
        0x4E, 0x51, 0x1B, 0x9E, 0x7C, 0x4B, 0xD5, 0x2B, 0x25, 0xD6, 0x48, 0x9C,
        0xD1, 0x99, 0x31, 0xB7, 0x01,
    ];
    /// The two sections' decoded outputs concatenated; the sections
    /// produce 349 then 343 bytes.
    const XD3_FGK_MULTI_PLAIN: [u8; 692] = [
        0x41, 0x45, 0x42, 0x41, 0x42, 0x45, 0x48, 0x42, 0x48, 0x42, 0x43, 0x46,
        0x42, 0x45, 0x45, 0x44, 0x47, 0x44, 0x41, 0x46, 0x48, 0x47, 0x48, 0x46,
        0x48, 0x45, 0x47, 0x43, 0x45, 0x42, 0x44, 0x48, 0x45, 0x48, 0x44, 0x41,
        0x46, 0x47, 0x45, 0x45, 0x44, 0x46, 0x45, 0x45, 0x41, 0x46, 0x46, 0x46,
        0x42, 0x47, 0x44, 0x47, 0x45, 0x47, 0x47, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x41, 0x48, 0x42, 0x46, 0x44, 0x42, 0x46, 0x44, 0x45, 0x45, 0x43, 0x44,
        0x41, 0x43, 0x46, 0x41, 0x46, 0x47, 0x41, 0x44, 0x42, 0x44, 0x43, 0x44,
        0x44, 0x47, 0x46, 0x43, 0x41, 0x46, 0x41, 0x47, 0x41, 0x47, 0x47, 0x43,
        0x43, 0x48, 0x42, 0x41, 0x45, 0x44, 0x48, 0x43, 0x46, 0x43, 0x44, 0x41,
        0x41, 0x47, 0x43, 0x42, 0x47, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x44,
        0x48, 0x41, 0x42, 0x48, 0x41, 0x43, 0x43, 0x42, 0x41, 0x47, 0x41, 0x46,
        0x43, 0x42, 0x45, 0x46, 0x45, 0x42, 0x48, 0x44, 0x41, 0x43, 0x44, 0x43,
        0x47, 0x42, 0x48, 0x48, 0x44, 0x43, 0x44, 0x42, 0x45, 0x42, 0x44, 0x48,
        0x42, 0x47, 0x47, 0x48, 0x44, 0x43, 0x46, 0x45, 0x45, 0x43, 0x46, 0x44,
        0x47, 0x44, 0x41, 0x48, 0x45, 0x48, 0x48, 0x42, 0x43, 0x42, 0x44, 0x48,
        0x48, 0x43, 0x44, 0x46, 0x43, 0x44, 0x44, 0x48, 0x43, 0x43, 0x41, 0x42,
        0x43, 0x42, 0x43, 0x46, 0x45, 0x41, 0x48, 0x45, 0x48, 0x46, 0x41, 0x46,
        0x43, 0x43, 0x44, 0x47, 0x48, 0x44, 0x46, 0x42, 0x41, 0x42, 0x47, 0x44,
        0x43, 0x44, 0x45, 0x42, 0x44, 0x47, 0x46, 0x41, 0x42, 0x42, 0x48, 0x45,
        0x41, 0x44, 0x46, 0x48, 0x42, 0x42, 0x41, 0x43, 0x42, 0x43, 0x43, 0x43,
        0x46, 0x42, 0x41, 0x46, 0x45, 0x47, 0x47, 0x42, 0x47, 0x43, 0x43, 0x41,
        0x46, 0x42, 0x48, 0x44, 0x45, 0x46, 0x43, 0x48, 0x47, 0x44, 0x42, 0x44,
        0x48, 0x46, 0x45, 0x42, 0x46, 0x48, 0x43, 0x46, 0x44, 0x42, 0x42, 0x45,
        0x42, 0x45, 0x48, 0x45, 0x42, 0x46, 0x46, 0x44, 0x46, 0x47, 0x45, 0x47,
        0x48, 0x46, 0x43, 0x45, 0x47, 0x43, 0x41, 0x44, 0x45, 0x44, 0x43, 0x42,
        0x43, 0x48, 0x44, 0x41, 0x41, 0x41, 0x41, 0x47, 0x42, 0x45, 0x44, 0x47,
        0x42, 0x42, 0x41, 0x44, 0x48, 0x47, 0x47, 0x46, 0x48, 0x47, 0x42, 0x44,
        0x41, 0x46, 0x45, 0x43, 0x46, 0x48, 0x44, 0x48, 0x42, 0x46, 0x41, 0x42,
        0x48, 0x44, 0x48, 0x45, 0x42, 0x41, 0x48, 0x42, 0x48, 0x44, 0x42, 0x43,
        0x48, 0x47, 0x42, 0x42, 0x44, 0x46, 0x47, 0x44, 0x45, 0x48, 0x41, 0x43,
        0x48, 0x46, 0x47, 0x45, 0x46, 0x47, 0x42, 0x44, 0x43, 0x43, 0x46, 0x46,
        0x41, 0x42, 0x44, 0x43, 0x46, 0x48, 0x43, 0x46, 0x46, 0x43, 0x43, 0x47,
        0x47, 0x48, 0x47, 0x43, 0x46, 0x43, 0x48, 0x42, 0x47, 0x41, 0x45, 0x43,
        0x45, 0x42, 0x45, 0x42, 0x44, 0x48, 0x41, 0x43, 0x47, 0x46, 0x44, 0x42,
        0x46, 0x42, 0x41, 0x41, 0x41, 0x43, 0x44, 0x46, 0x44, 0x42, 0x43, 0x44,
        0x44, 0x48, 0x47, 0x41, 0x45, 0x41, 0x47, 0x46, 0x44, 0x41, 0x47, 0x41,
        0x46, 0x41, 0x48, 0x41, 0x48, 0x44, 0x45, 0x44, 0x46, 0x46, 0x43, 0x41,
        0x46, 0x44, 0x43, 0x46, 0x46, 0x42, 0x48, 0x43, 0x43, 0x47, 0x48, 0x45,
        0x44, 0x48, 0x48, 0x42, 0x43, 0x43, 0x44, 0x47, 0x41, 0x42, 0x42, 0x41,
        0x42, 0x42, 0x47, 0x41, 0x47, 0x44, 0x46, 0x47, 0x47, 0x48, 0x41, 0x43,
        0x46, 0x42, 0x42, 0x44, 0x48, 0x43, 0x48, 0x44, 0x43, 0x43, 0x48, 0x48,
        0x48, 0x41, 0x43, 0x42, 0x43, 0x47, 0x48, 0x41, 0x46, 0x43, 0x47, 0x46,
        0x42, 0x42, 0x43, 0x41, 0x47, 0x47, 0x46, 0x41, 0x47, 0x41, 0x46, 0x41,
        0x47, 0x42, 0x43, 0x48, 0x42, 0x42, 0x42, 0x44, 0x43, 0x47, 0x45, 0x44,
        0x42, 0x47, 0x46, 0x47, 0x41, 0x44, 0x45, 0x41, 0x41, 0x46, 0x48, 0x47,
        0x48, 0x42, 0x43, 0x47, 0x44, 0x48, 0x41, 0x41, 0x48, 0x42, 0x45, 0x42,
        0x45, 0x45, 0x45, 0x44, 0x48, 0x41, 0x45, 0x42, 0x48, 0x41, 0x46, 0x45,
        0x41, 0x45, 0x45, 0x47, 0x43, 0x42, 0x47, 0x44, 0x45, 0x42, 0x41, 0x47,
        0x43, 0x45, 0x41, 0x46, 0x45, 0x44, 0x45, 0x44, 0x45, 0x41, 0x43, 0x45,
        0x41, 0x48, 0x43, 0x45, 0x42, 0x43, 0x43, 0x43, 0x42, 0x46, 0x45, 0x44,
        0x46, 0x42, 0x43, 0x48, 0x42, 0x46, 0x44, 0x44, 0x41, 0x41, 0x47, 0x45,
        0x44, 0x43, 0x41, 0x46, 0x43, 0x44, 0x48, 0x44, 0x48, 0x45, 0x48, 0x41,
        0x47, 0x45, 0x47, 0x41, 0x44, 0x42, 0x43, 0x45, 0x41, 0x41, 0x41, 0x45,
        0x44, 0x41, 0x47, 0x48, 0x42, 0x42, 0x46, 0x41, 0x44, 0x44, 0x45, 0x43,
        0x46, 0x44, 0x47, 0x48, 0x43, 0x43, 0x45, 0x46, 0x44, 0x44, 0x45, 0x42,
        0x47, 0x47, 0x42, 0x43, 0x43, 0x47, 0x46, 0x43, 0x46, 0x43, 0x44, 0x47,
        0x48, 0x48, 0x47, 0x44, 0x46, 0x45, 0x47, 0x45, 0x43, 0x46, 0x45, 0x46,
        0x41, 0x43, 0x46, 0x45, 0x41, 0x43, 0x46, 0x46,
    ];

    #[test]
    fn short_section_round_trips() {
        let outcome = fgk_decompress_sections(&XD3_FGK_SHORT_STREAM, &[XD3_FGK_SHORT_PLAIN.len()])
            .expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_FGK_SHORT_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_FGK_SHORT_STREAM.len());
    }

    #[test]
    fn long_section_round_trips() {
        let outcome = fgk_decompress_sections(&XD3_FGK_LONG_STREAM, &[XD3_FGK_LONG_PLAIN.len()])
            .expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_FGK_LONG_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_FGK_LONG_STREAM.len());
    }

    /// Two sections decoded through one shared tree: the second section
    /// only decodes correctly because the tree carried over from the
    /// first. Decoding each from a fresh tree diverges on the second
    /// section's first byte.
    #[test]
    fn gathered_sections_share_one_tree() {
        let outcome =
            fgk_decompress_sections(&XD3_FGK_MULTI_GATHERED, &[349, 343]).expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_FGK_MULTI_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_FGK_MULTI_GATHERED.len());
    }

    #[test]
    fn truncated_stream_exhausts_input() {
        let truncated = &XD3_FGK_LONG_STREAM[..XD3_FGK_LONG_STREAM.len() / 2];
        let fault = decode_kind(truncated, &[XD3_FGK_LONG_PLAIN.len()]).unwrap_err();
        assert_eq!(fault, FgkFault::InputExhausted);
    }

    #[test]
    fn empty_input_exhausts_immediately() {
        let fault = decode_kind(&[], &[10]).unwrap_err();
        assert_eq!(fault, FgkFault::InputExhausted);
    }

    #[test]
    fn zero_output_budget_is_refused() {
        let fault = decode_kind(&XD3_FGK_SHORT_STREAM, &[0]).unwrap_err();
        assert_eq!(fault, FgkFault::OutputBudgetIsZero);
    }

    /// A first byte coded normally, then a second whose escape field
    /// names an unseen index the list no longer holds. After one symbol
    /// the unseen count is 255 — not a power of two, so the escape field
    /// widens to eight bits and can name 255, one past the largest valid
    /// index (254). The decoder walks the list, runs out, and refuses
    /// rather than returning whatever it stopped on.
    #[test]
    fn escape_past_unseen_list_is_refused() {
        let mut writer = BitWriter::new();
        // First symbol: the initial unseen count is 256, an exact power
        // of two, so the escape is eight bits and names symbol 0.
        writer.write_value(8, 0);
        // Second symbol: one bit walks the root to the unseen leaf (its
        // left child), then eight escape bits name index 255.
        writer.write_bit(false);
        writer.write_value(8, 255);
        let section = writer.finish();
        let fault = decode_kind(&section, &[2]).unwrap_err();
        assert_eq!(
            fault,
            FgkFault::ZeroIndexPastUnseenList { requested: 255, unseen: 255 }
        );
    }

    // FgkFault::WeightCounterOverflow and FgkFault::TreeStructureCorrupt
    // have no crafted cases. The first needs a node's weight past 2^32,
    // i.e. an output past four billion bytes, which the declared size
    // and InputExhausted foreclose long before. The second is the typed
    // landing for the shared invariant's guarantees — both children
    // present on every interior node, a unique highest-weight root, a
    // non-empty unseen list under any zero-weight decode — none of which
    // a bit stream can falsify without the decoder having already
    // diverged. They exist so the impossible surfaces as a verdict
    // rather than a panic, the way DJW's SelectorNamesMissingGroup does.
}
