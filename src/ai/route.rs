//! Routing a question to a branch of the forest.
//!
//! The ask this serves: a model must not consume the whole forest, it loads a
//! branch and works from there. So something has to decide *which* branch, and
//! this is the cheapest thing that can -- a mean of embedding rows per branch,
//! and a cosine against it.
//!
//! **No forward pass anywhere.** `vocab::pool` averages the embedding table's
//! rows for the tokens of a piece of text; there is no attention, no layer, no
//! KV cache. That is what makes routing over nine thousand nodes affordable on
//! this machine at all, and it is why this is the baseline the fitted probe in
//! Phase 3 has to beat rather than the thing it replaces.
//!
//! ### Two decisions that exist so the measurement is not a lie
//!
//! **The subject is never pooled.** A forest head is `subject | concept |
//! terms`, and the subject *is* the branch path -- so a branch descriptor built
//! from it would be answering the question by reading the label off the back,
//! and a query carrying one would be handing over the answer. Only the concept
//! and the terms go in, on both sides.
//!
//! **Accuracy is leave-one-out, and it costs nothing.** A branch vector is a
//! mean, so removing one node from it is `(sum - v) / (n - 1)` exactly. Every
//! node is therefore a held-out test point against a branch that has never seen
//! it, with no split to arrange and no second table to build. Scoring against a
//! table that contains the node being scored would be the leakage this project
//! has already got wrong twice in other places.
//!
//! ### What is stored
//!
//! Sums rather than means, with the counts beside them. A mean throws away
//! exactly what leave-one-out needs, and a table that could not be scored after
//! the fact would be a table nobody could check.

use alloc::string::String;
use alloc::vec::Vec;

use crate::kprintln;
use crate::sysbox;

/// Where the table lives once built.
pub const TABLE: &str = "/ai/route/forest";

const MAGIC: &[u8; 8] = b"GLADOSRT";

/// One row per branch: its path, how many nodes went into it, and their sum.
pub struct Table {
    pub dim: usize,
    pub names: Vec<String>,
    pub counts: Vec<u32>,
    /// `names.len() * dim`, row-major.
    pub sums: Vec<f32>,
    /// The mean of every node vector, subtracted before comparing.
    ///
    /// Mean-pooled embeddings of English text share a large common direction,
    /// so every cosine sits bunched near the top of its range and the part that
    /// distinguishes one subject from another is a small residual. Taking the
    /// centroid out leaves that residual, which is what the comparison is
    /// actually about. Empty means no centering, so a table written before this
    /// existed still reads as the thing it was.
    pub centroid: Vec<f32>,
}

impl Table {
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn row(&self, i: usize) -> &[f32] {
        &self.sums[i * self.dim..(i + 1) * self.dim]
    }

    /// The branch's mean, which is what a query is compared against.
    pub fn mean(&self, i: usize) -> Vec<f32> {
        let n = self.counts[i].max(1) as f32;
        let mut v: Vec<f32> = self.row(i).iter().map(|x| x / n).collect();
        self.centre(&mut v);
        v
    }

    /// Take the common direction out, in place. A no-op with no centroid.
    ///
    /// Applied to **both** sides or neither. Centering one and not the other
    /// compares a residual against a whole vector, which is not a smaller
    /// version of the right answer -- it is a different question with a
    /// perfectly plausible-looking cosine.
    pub fn centre(&self, v: &mut [f32]) {
        if self.centroid.len() != v.len() {
            return;
        }
        for (a, c) in v.iter_mut().zip(self.centroid.iter()) {
            *a -= *c;
        }
    }

    /// The branch's mean with one node's contribution taken back out.
    ///
    /// Exact, because a mean is a sum over a count and both are here. A branch
    /// of one has nothing left when its only node leaves, and answers `None`
    /// rather than a vector of zeros -- which would score as a real branch that
    /// happens to match nothing, and quietly make the accuracy look better.
    pub fn without(&self, i: usize, v: &[f32]) -> Option<Vec<f32>> {
        let n = self.counts[i];
        if n <= 1 {
            return None;
        }
        let k = (n - 1) as f32;
        // `v` is the raw node vector, so the subtraction happens on raw sums
        // and the centring comes after -- a constant shift commutes with a
        // mean, so this is the same vector either order, and doing it here
        // keeps `without` returning something directly comparable.
        let mut out: Vec<f32> =
            self.row(i).iter().zip(v.iter()).map(|(s, x)| (s - x) / k).collect();
        self.centre(&mut out);
        Some(out)
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| n == name)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.dim as u32).to_le_bytes());
        out.extend_from_slice(&(self.names.len() as u32).to_le_bytes());
        // Length-prefixed, so a table with no centroid and one with a centroid
        // are told apart by reading rather than by guessing from the total.
        out.extend_from_slice(&(self.centroid.len() as u32).to_le_bytes());
        for v in &self.centroid {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for i in 0..self.names.len() {
            let nm = self.names[i].as_bytes();
            out.extend_from_slice(&(nm.len() as u16).to_le_bytes());
            out.extend_from_slice(nm);
            out.extend_from_slice(&self.counts[i].to_le_bytes());
            for v in self.row(i) {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        out
    }

    /// Read a table back, or nothing if it is not one.
    ///
    /// Walks and never seeks, and asserts it landed on the last byte -- the
    /// bargain `v4.py` and `reference.py` both make, for the reason they give:
    /// a body with no names or lengths in it leaves a reader that disagreed
    /// about one dimension holding perfectly valid float32 garbage.
    pub fn decode(b: &[u8]) -> Option<Table> {
        if b.len() < 16 || &b[..8] != MAGIC {
            return None;
        }
        let dim = u32::from_le_bytes(b[8..12].try_into().ok()?) as usize;
        let rows = u32::from_le_bytes(b[12..16].try_into().ok()?) as usize;
        if dim == 0 || dim > 1 << 16 {
            return None;
        }
        if b.len() < 20 {
            return None;
        }
        let cn = u32::from_le_bytes(b[16..20].try_into().ok()?) as usize;
        if cn != 0 && cn != dim {
            return None;
        }
        let mut t = Table {
            dim,
            names: Vec::with_capacity(rows),
            counts: Vec::with_capacity(rows),
            sums: Vec::with_capacity(rows * dim),
            centroid: Vec::with_capacity(cn),
        };
        let mut at = 20usize;
        if at + cn * 4 > b.len() {
            return None;
        }
        for _ in 0..cn {
            t.centroid.push(f32::from_le_bytes(b[at..at + 4].try_into().ok()?));
            at += 4;
        }
        for _ in 0..rows {
            if at + 2 > b.len() {
                return None;
            }
            let nl = u16::from_le_bytes(b[at..at + 2].try_into().ok()?) as usize;
            at += 2;
            if at + nl + 4 + dim * 4 > b.len() {
                return None;
            }
            t.names.push(String::from_utf8(b[at..at + nl].to_vec()).ok()?);
            at += nl;
            t.counts.push(u32::from_le_bytes(b[at..at + 4].try_into().ok()?));
            at += 4;
            for _ in 0..dim {
                t.sums.push(f32::from_le_bytes(b[at..at + 4].try_into().ok()?));
                at += 4;
            }
        }
        if at != b.len() {
            return None;
        }
        Some(t)
    }
}

/// The concept and terms of a head, with the subject dropped.
///
/// `subject | concept | terms`. The subject is the label this is trying to
/// predict, so it is taken out on both sides -- see the module header. A head
/// with no separators is used whole, which is the honest thing to do with a
/// line written by something other than `tools/forest.py`.
pub fn queryable(head: &str) -> String {
    let mut parts = head.split(" | ");
    let first = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return String::from(first);
    }
    rest.join(" ")
}

/// The branch a node path belongs to: everything above its last component.
pub fn branch_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => path,
    }
}

/// Is this path component a shard rather than a subject?
///
/// `tools/forest.py` bounds directory fanout by splitting a category into
/// `part-00`, `part-01` and so on. Those are a **storage** decision: the two
/// halves of `add-sub/1-step` are the same subject cut in half at an arbitrary
/// point, and nothing distinguishes a question in one from a question in the
/// other.
fn is_shard(part: &str) -> bool {
    match part.strip_prefix("part-") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// The subject a node belongs to: its branch, with any shard suffix folded in.
///
/// **This was `branch_of` and the first measurement said so.** Keyed by branch,
/// leave-one-out top-1 came out at 7.6% against 1.8% chance -- a real signal,
/// and partly a measurement of an impossible task, because two of every three
/// classes were `part-00` and `part-01` of one category. A router cannot tell
/// those apart and neither can anything else; the split is arbitrary.
///
/// Folding them is not making the task easier, it is making it a task. What is
/// left is the distinction somebody would actually want: which subject, not
/// which shard of it.
pub fn subject_of(path: &str) -> &str {
    let b = branch_of(path);
    match b.rfind('/') {
        Some(i) if is_shard(&b[i + 1..]) => &b[..i],
        _ => b,
    }
}

/// Every branch's mean, computed once.
///
/// Taken out of the ranking on purpose. Scoring nine thousand nodes against
/// fifty-three branches calls the ranking nine thousand times, and a `mean`
/// per branch per call is half a million allocations of a vector that never
/// changes between them.
pub fn means(t: &Table) -> Vec<Vec<f32>> {
    (0..t.len()).map(|i| t.mean(i)).collect()
}

/// Rank the branches against a pooled query, best first.
///
/// Returns (index, cosine). A table row whose count is zero is skipped rather
/// than compared: an empty branch has no direction, and `cosine` answers 0 for
/// a zero vector, which would put it above every branch the query genuinely
/// disagrees with.
pub fn rank(t: &Table, m: &[Vec<f32>], q: &[f32]) -> Vec<(usize, f32)> {
    let mut out: Vec<(usize, f32)> = Vec::with_capacity(t.len());
    for i in 0..t.len() {
        if t.counts[i] == 0 {
            continue;
        }
        out.push((i, crate::ai::vocab::cosine(q, &m[i])));
    }
    // Descending by score, and by index where two are equal, so a run is
    // reproducible rather than merely repeatable.
    out.sort_by(|a, b| {
        b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal).then(a.0.cmp(&b.0))
    });
    out
}

/// Where a query's own branch came, given every branch's vector.
///
/// `own` is the index of the branch the node actually belongs to, and its
/// vector is supplied separately so a caller can pass the leave-one-out one.
/// Answers the rank, counting from zero.
pub fn rank_of(t: &Table, m: &[Vec<f32>], q: &[f32], own: usize, own_vec: &[f32]) -> usize {
    let mine = crate::ai::vocab::cosine(q, own_vec);
    let mut ahead = 0usize;
    for i in 0..t.len() {
        if i == own || t.counts[i] == 0 {
            continue;
        }
        // Strictly better only. A tie leaves the true branch ahead, which is
        // the generous reading -- stated because with fifty-three branches and
        // f32 cosines ties do happen, and counting them as misses would
        // understate the figure by an amount nobody could see.
        if crate::ai::vocab::cosine(q, &m[i]) > mine {
            ahead += 1;
        }
    }
    ahead
}

pub fn load() -> Option<Table> {
    Table::decode(&sysbox::read_blob(TABLE)?)
}

pub fn store(t: &Table) -> bool {
    sysbox::write_blob(TABLE, t.encode())
}

/// What the reader and the arithmetic claim, with no model and no forest.
pub fn selftest() -> bool {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, LTRED};
    let mut ok = true;
    let mut check = |what: &str, pass: bool| {
        console::set_color(if pass { LTGREEN } else { LTRED });
        kprintln!("  {}  {}", if pass { "ok  " } else { "FAIL" }, what);
        console::set_color(LTGRAY);
        ok &= pass;
    };

    check(
        "the subject is dropped, because it is the label being predicted",
        queryable("a/b | what is a group | group ring") == "what is a group group ring"
            && queryable("no separators here") == "no separators here",
    );
    check(
        "a branch is everything above the last component",
        branch_of("/pkg/forest/x/y/00001") == "/pkg/forest/x/y" && branch_of("bare") == "bare",
    );
    // A shard is a storage decision and not a subject, so it folds. Getting
    // this wrong is not a small error: it made two of every three classes a
    // coin flip nothing could win.
    check(
        "a part-NN shard folds into its subject, and a real name does not",
        subject_of("/f/arith/1-step/part-01/00007") == "/f/arith/1-step"
            && subject_of("/f/algebra/00007") == "/f/algebra"
            && subject_of("/f/partial/part-x/00007") == "/f/partial/part-x",
    );

    let t = Table {
        dim: 3,
        names: alloc::vec![String::from("alpha"), String::from("beta"), String::from("lone")],
        counts: alloc::vec![2, 4, 1],
        sums: alloc::vec![
            2.0, 0.0, 0.0, // alpha: two nodes summing to (2,0,0)
            0.0, 4.0, 0.0, // beta
            0.0, 0.0, 1.0, // lone: a single node
        ],
        centroid: Vec::new(),
    };

    check(
        "a mean is the sum over the count",
        t.mean(0) == alloc::vec![1.0, 0.0, 0.0] && t.mean(1) == alloc::vec![0.0, 1.0, 0.0],
    );
    // The arithmetic the whole accuracy figure rests on. Taking (2,0,0) out of
    // a branch whose sum is (2,0,0) over two nodes must leave the other node
    // exactly, not an average that still contains the one removed.
    check(
        "leave-one-out is exact: the other node, not a diluted mean",
        t.without(0, &[1.5, 0.0, 0.0]) == Some(alloc::vec![0.5, 0.0, 0.0]),
    );
    // A branch of one has nothing left. Answering zeros would score as a real
    // branch matching nothing, which flatters the figure by exactly the number
    // of singleton branches -- invisibly.
    check(
        "a branch of one cannot be left out of, and says so",
        t.without(2, &[0.0, 0.0, 1.0]).is_none(),
    );

    let q = [0.0f32, 1.0, 0.0];
    let m = means(&t);
    let r = rank(&t, &m, &q);
    check(
        "ranking puts the branch the query points at first",
        r.first().map(|(i, _)| *i) == Some(1),
    );
    check(
        "and every branch with nodes is ranked, none dropped",
        r.len() == 3,
    );
    check(
        "the true branch's own rank counts only what beat it",
        rank_of(&t, &m, &q, 1, &[0.0, 1.0, 0.0]) == 0
            && rank_of(&t, &m, &q, 0, &[1.0, 0.0, 0.0]) == 1,
    );

    let enc = t.encode();
    let back = Table::decode(&enc);
    check(
        "a table round-trips through its own bytes",
        match &back {
            Some(d) => {
                d.dim == t.dim && d.names == t.names && d.counts == t.counts && d.sums == t.sums
            }
            None => false,
        },
    );
    // Walks and never seeks, and lands on the last byte. A reader that stopped
    // early would hold perfectly valid floats belonging to nothing.
    check(
        "a truncated table is refused rather than read short",
        Table::decode(&enc[..enc.len() - 1]).is_none()
            && Table::decode(&enc[..8]).is_none()
            && Table::decode(b"not a table at all").is_none(),
    );
    let mut extra = enc.clone();
    extra.push(0);
    check(
        "and so is one with bytes left over",
        Table::decode(&extra).is_none(),
    );

    // Centring is a constant shift, so it must move every branch and the query
    // alike and change no ordering by itself. What it changes is the *spread*,
    // which is the thing the cosine had none of.
    let mut c = Table {
        dim: 3,
        names: t.names.clone(),
        counts: t.counts.clone(),
        sums: t.sums.clone(),
        centroid: alloc::vec![1.0, 1.0, 1.0],
    };
    check(
        "a centroid comes out of a branch mean",
        c.mean(0) == alloc::vec![0.0, -1.0, -1.0],
    );
    check(
        "a table with a centroid round-trips, and one without still reads",
        Table::decode(&c.encode()).map(|d| d.centroid) == Some(alloc::vec![1.0, 1.0, 1.0])
            && Table::decode(&t.encode()).map(|d| d.centroid.len()) == Some(0),
    );
    // A centroid of the wrong width is refused, not applied to part of a row.
    c.centroid = alloc::vec![1.0, 1.0];
    check(
        "a centroid that does not fit the dimension is refused at the reader",
        Table::decode(&c.encode()).is_none(),
    );

    ok
}
