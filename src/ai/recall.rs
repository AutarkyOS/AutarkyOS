//! Budgeted retrieval: what fits in the turn, and nothing more.
//!
//! Phase 4. The router says which subject a question belongs in; this picks the
//! nodes inside it and renders as many as a token budget admits.
//!
//! ### The budget is counted, never estimated
//!
//! `companion::turn` measures the system turn by encoding it the way `generate`
//! will -- same BOS, same tokenizer -- and says why: an estimate that ran short
//! would pin part of a turn and leave the rest to scroll. The same reasoning
//! applies with more force here, because this text is chosen *to* fill a
//! budget. So `fill` takes the counter as a closure and asks it after every
//! candidate, and the answer it returns is the real encoded length of the
//! string it produced rather than a sum of parts.
//!
//! Tokenisation is not additive at a boundary -- two pieces that encode to 10
//! and 12 tokens do not reliably encode to 22 when concatenated -- so summing
//! per-node counts would drift, always in the direction of admitting one node
//! too many. Re-encoding the accumulated block is exact and costs a handful of
//! encodes of a string that is by construction no longer than the budget.
//!
//! ### Per-node vectors, and what the router is actually for
//!
//! Scoring needs a vector per node, and `route`'s table holds only per-subject
//! sums. `Nodes` is that second table: one pooled head vector per node, written
//! by `forest embed` beside the first.
//!
//! **With it resident, routing buys nothing at this corpus size**, and saying so
//! is more useful than pretending otherwise: nine thousand cosines is five
//! million operations, which is nothing. The router earns its place when the
//! vectors do not fit, and until then its cost is measurable -- `recall` reports
//! how much of the unrouted answer the routed one found, which is exactly the
//! price of not looking everywhere.

use alloc::string::String;
use alloc::vec::Vec;

use crate::sysbox;

/// Where the per-node vectors live.
pub const NODES: &str = "/ai/route/nodes";

/// And the inverted index beside them.
pub const LEX: &str = "/ai/route/lex";

const MAGIC: &[u8; 8] = b"GLADOSNV";

/// One pooled vector per node, keyed by path.
pub struct Nodes {
    pub dim: usize,
    pub paths: Vec<String>,
    /// `paths.len() * dim`, row-major.
    pub vecs: Vec<f32>,
}

impl Nodes {
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn row(&self, i: usize) -> &[f32] {
        &self.vecs[i * self.dim..(i + 1) * self.dim]
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.paths.len() * (self.dim * 4 + 32));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.dim as u32).to_le_bytes());
        out.extend_from_slice(&(self.paths.len() as u32).to_le_bytes());
        for i in 0..self.paths.len() {
            let p = self.paths[i].as_bytes();
            out.extend_from_slice(&(p.len() as u16).to_le_bytes());
            out.extend_from_slice(p);
            for v in self.row(i) {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        out
    }

    /// Walks and never seeks, and lands on the last byte -- `v4.py`'s bargain,
    /// for its reason: a body of unnamed floats leaves a reader that disagreed
    /// about one dimension holding perfectly valid garbage.
    pub fn decode(b: &[u8]) -> Option<Nodes> {
        if b.len() < 16 || &b[..8] != MAGIC {
            return None;
        }
        let dim = u32::from_le_bytes(b[8..12].try_into().ok()?) as usize;
        let rows = u32::from_le_bytes(b[12..16].try_into().ok()?) as usize;
        if dim == 0 || dim > 1 << 16 {
            return None;
        }
        let mut n = Nodes {
            dim,
            paths: Vec::with_capacity(rows),
            vecs: Vec::with_capacity(rows * dim),
        };
        let mut at = 16usize;
        for _ in 0..rows {
            if at + 2 > b.len() {
                return None;
            }
            let pl = u16::from_le_bytes(b[at..at + 2].try_into().ok()?) as usize;
            at += 2;
            if at + pl + dim * 4 > b.len() {
                return None;
            }
            n.paths.push(String::from_utf8(b[at..at + pl].to_vec()).ok()?);
            at += pl;
            for _ in 0..dim {
                n.vecs.push(f32::from_le_bytes(b[at..at + 4].try_into().ok()?));
                at += 4;
            }
        }
        if at != b.len() {
            return None;
        }
        Some(n)
    }
}

static CACHE: crate::sync::Racy<Option<Nodes>> = crate::sync::Racy::new(None);

/// The node table, loaded once and kept.
///
/// Twenty megabytes at dim 576 over nine thousand nodes -- the price of not
/// reading and re-hashing the disk once per question. `forget` drops it, and
/// `forest embed` calls that when it writes a new one, so the cache cannot
/// outlive the table it came from.
///
/// **Not centred.** Rows are IDF-weighted and unit length by construction, so a
/// cosine against another such row is already a plain dot product. The routing
/// table's centroid belongs to the *subject* comparison and was measured there;
/// applying it here would take a constant out of one side of a different
/// comparison, which is exactly the both-sides-or-neither trap `route::centre`
/// is written to warn about.
pub fn with_nodes<R>(f: impl FnOnce(&Nodes) -> R) -> Option<R> {
    unsafe {
        let slot = CACHE.get();
        if slot.is_none() {
            *slot = Some(load()?);
        }
        slot.as_ref().map(f)
    }
}

pub fn forget() {
    unsafe { *CACHE.get() = None };
}

pub fn load() -> Option<Nodes> {
    Nodes::decode(&sysbox::read_blob(NODES)?)
}

pub fn store(n: &Nodes) -> bool {
    sysbox::write_blob(NODES, n.encode())
}

pub fn load_lex() -> Option<crate::ai::lex::Lex> {
    crate::ai::lex::Lex::decode(&sysbox::read_blob(LEX)?)
}

pub fn store_lex(l: &crate::ai::lex::Lex) -> bool {
    sysbox::write_blob(LEX, l.encode())
}

/// How much of the score comes from the embedding rather than the terms.
///
/// **Zero, and that is a measurement rather than a dismissal.** `forest bench`
/// swept it over a known-item task with 8,913 candidates and no string shared
/// between query and index:
///
///     mean pool      r@1  0.5%    MRR 0.0098
///     idf pool       r@1  5.5%    MRR 0.0799
///     terms          r@1 87.8%    MRR 0.9095
///
/// and every weight above zero came out worse than zero -- 84.8% at a=0.05,
/// 68.6% at a=0.25, and the embedding alone at 5.5%. So the
/// embedding channel is switched off for node retrieval, and the constant is
/// here rather than inlined so the shipped behaviour and the measurement cannot
/// drift apart in silence.
///
/// What this is *not* is a claim that embeddings are useless. It is one
/// checkpoint's embedding table, mean- and IDF-pooled with no forward pass,
/// against exact term matching on a corpus of questions -- where names and
/// numbers either appear or do not, and that is most of the signal. A different
/// model, or a fusion on ranks rather than on raw scores, may well move it. The
/// sweep is one command, and it prints every rung.
pub const MIX: f32 = 0.0;

/// A candidate to render: where it came from and how good it looked.
pub struct Cand {
    pub path: String,
    pub score: f32,
    pub body: String,
}

/// What a fill produced.
pub struct Filled {
    pub text: String,
    /// Indices into the candidate list, in the order they were taken.
    pub taken: Vec<usize>,
    /// The encoded length of `text`, from the counter that was passed in.
    pub tokens: usize,
    /// Candidates that were skipped because they did not fit, but a later
    /// smaller one did.
    pub skipped: usize,
}

/// Render one node into the block.
fn render_one(n: usize, c: &Cand) -> String {
    let mut s = String::new();
    s.push_str("--- ");
    // One-based, because this is read by a model and by a person and neither
    // counts from zero.
    s.push_str(&alloc::format!("{}", n + 1));
    s.push('\n');
    s.push_str(c.body.trim_end());
    s.push_str("\n\n");
    s
}

pub const PREAMBLE: &str = "Entries from the library that may bear on this:\n\n";

/// Greedily take candidates until the budget will not admit another.
///
/// **Best-first, and it keeps going after a miss.** A candidate that does not
/// fit is skipped rather than ending the fill, because the list is sorted by
/// score and not by size -- stopping at the first overflow would throw away
/// every smaller, slightly-worse entry behind a single large one, and the
/// budget would go unspent for no reason anybody could see. The count of those
/// is reported, since "three were skipped" and "there were only two" are
/// different facts about a corpus.
///
/// The counter is a closure so the budget arithmetic can be checked with no
/// model: a claim passes one that counts words and gets exact, predictable
/// answers out of the same code the real path runs.
pub fn fill<F: Fn(&str) -> usize>(cands: &[Cand], budget: usize, count: F) -> Filled {
    let mut out = Filled {
        text: String::new(),
        taken: Vec::new(),
        tokens: 0,
        skipped: 0,
    };
    // An empty block is not the preamble on its own: a heading promising
    // entries with nothing under it is worse than nothing at all, so the
    // preamble is only paid for once something fits beneath it.
    for (i, c) in cands.iter().enumerate() {
        let mut next = if out.taken.is_empty() {
            String::from(PREAMBLE)
        } else {
            out.text.clone()
        };
        next.push_str(&render_one(out.taken.len(), c));
        let n = count(&next);
        if n > budget {
            out.skipped += 1;
            continue;
        }
        out.text = next;
        out.tokens = n;
        out.taken.push(i);
    }
    out
}

/// What the reader and the budget arithmetic claim, with no model and no forest.
pub fn selftest() -> bool {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, LTRED};
    let mut ok = true;
    let mut check = |what: &str, pass: bool| {
        console::set_color(if pass { LTGREEN } else { LTRED });
        crate::kprintln!("  {}  {}", if pass { "ok  " } else { "FAIL" }, what);
        console::set_color(LTGRAY);
        ok &= pass;
    };

    // A counter that is easy to reason about: one token per whitespace-
    // separated word. The real one is the tokenizer; what is being checked
    // here is the arithmetic around it, which is the part with edges.
    let words = |s: &str| s.split_whitespace().count();

    let cand = |p: &str, score: f32, body: &str| Cand {
        path: String::from(p),
        score,
        body: String::from(body),
    };

    let one = alloc::vec![cand("/a", 1.0, "alpha beta gamma")];
    let f = fill(&one, 1000, words);
    check(
        "a block that fits is rendered whole, and counted by the counter given",
        f.taken == alloc::vec![0] && f.tokens == words(&f.text) && f.text.contains("alpha"),
    );
    // The claim the whole phase is for. Not "about the budget" -- never over it.
    check(
        "and its own length is what the budget was compared against",
        f.tokens <= 1000 && f.tokens > 0,
    );

    let f0 = fill(&one, 0, words);
    check(
        "a budget of zero renders nothing at all, not a bare heading",
        f0.text.is_empty() && f0.taken.is_empty() && f0.tokens == 0 && f0.skipped == 1,
    );
    // A heading with nothing under it promises entries and delivers none,
    // which is worse than silence -- so the preamble is only paid for once
    // something fits beneath it.
    let tight = fill(&one, words(PREAMBLE) + 1, words);
    check(
        "a budget that admits only the heading still renders nothing",
        tight.text.is_empty() && tight.taken.is_empty(),
    );

    let many = alloc::vec![
        cand("/a", 0.9, "aaa aaa aaa aaa aaa aaa aaa aaa"),
        cand("/b", 0.8, "bbb"),
        cand("/c", 0.7, "ccc"),
    ];
    // Best-first, so the big one is offered first; the budget refuses it and
    // the two small ones behind it are still taken. Stopping at the first
    // miss would leave the budget unspent with nothing saying why.
    let small = fill(&many, words(PREAMBLE) + 8, words);
    check(
        "a candidate that does not fit is skipped, not an end to the fill",
        small.taken == alloc::vec![1, 2] && small.skipped == 1,
    );
    check(
        "and the rendering is never over budget",
        small.tokens <= words(PREAMBLE) + 8 && small.tokens == words(&small.text),
    );
    // Numbering follows what was taken rather than the candidate list, or the
    // block would read "--- 1" then "--- 3" and a model would reasonably
    // conclude something had been withheld.
    check(
        "entries are numbered by what was kept, with no gaps",
        small.text.contains("--- 1") && small.text.contains("--- 2")
            && !small.text.contains("--- 3"),
    );

    let all = fill(&many, 10_000, words);
    check(
        "a budget that admits everything takes everything, in score order",
        all.taken == alloc::vec![0, 1, 2] && all.skipped == 0,
    );
    check(
        "an empty candidate list is an empty block rather than a heading",
        fill(&[], 10_000, words).text.is_empty(),
    );

    // --- the table -------------------------------------------------------
    let n = Nodes {
        dim: 2,
        paths: alloc::vec![String::from("/x/1"), String::from("/x/2")],
        vecs: alloc::vec![1.0, 0.0, 0.0, 1.0],
    };
    let enc = n.encode();
    check(
        "the node table round-trips through its own bytes",
        match Nodes::decode(&enc) {
            Some(d) => d.dim == 2 && d.paths == n.paths && d.vecs == n.vecs,
            None => false,
        },
    );
    let mut extra = enc.clone();
    extra.push(0);
    check(
        "and is refused when truncated, over-long, or not a table",
        Nodes::decode(&enc[..enc.len() - 1]).is_none()
            && Nodes::decode(&extra).is_none()
            && Nodes::decode(b"GLADOSXX________").is_none(),
    );

    ok
}
