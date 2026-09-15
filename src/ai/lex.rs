//! The lexical half of retrieval: which documents contain which tokens.
//!
//! An inverted index and a document-frequency table, both over the tokenizer's
//! own ids. Small -- about 1.3 MB over nine thousand nodes -- and it fixes the
//! two things mean-pooled embeddings get worst.
//!
//! ### Why mean pooling was the problem
//!
//! `vocab::pool` averages the embedding rows of every token equally. In "what
//! is the derivative of a polynomial" that gives `what`, `is`, `the` and `of`
//! the same say as `derivative` and `polynomial` -- four of the six vectors are
//! carrying no information about the question, and they are the four that
//! appear in every other document too. The result is a vector pointing mostly
//! where all English points, which is why every cosine came back between 0.66
//! and 0.76 and why a question about derivatives retrieved one about subgroups.
//!
//! Two corrections, both standard and both needing nothing but a count:
//!
//! - **Inverse document frequency.** A token appearing in almost every document
//!   distinguishes nothing, so weight it by `ln((N+1)/(df+1))`. `the` scores
//!   near zero; `polynomial` scores high.
//! - **A normalised row.** An embedding's *norm* is a property of how often the
//!   token was trained, not of how much it means here, so each row is scaled to
//!   unit length before it is weighted. Without this a common token with a
//!   large norm outvotes a rare one with a small one, which is the same bug
//!   again wearing a different hat.
//!
//! ### And the channel embeddings cannot supply
//!
//! An embedding match is a similarity; a term match is a fact. "Ralph" and
//! "175" and "posters" either appear or they do not, and for a corpus of
//! questions that is most of the signal. The postings list answers it exactly,
//! in one pass over the query's tokens, and it costs a megabyte.
//!
//! Neither replaces the other -- `forest bench` measures both alone and
//! combined over a grid, and the combination is chosen on the number rather
//! than on the argument.

use alloc::vec::Vec;

use crate::ai::tensor;

const MAGIC: &[u8; 8] = b"GLADOSLX";

/// Postings in CSR: `starts[t]..starts[t+1]` indexes `nodes`.
///
/// Flat rather than a `Vec` per token. Fifty thousand `Vec`s would be fifty
/// thousand allocations and three words of header each, for lists that are
/// mostly empty -- this is two arrays and one indirection.
pub struct Lex {
    pub vocab: usize,
    pub docs: u32,
    pub starts: Vec<u32>,
    pub nodes: Vec<u32>,
    /// How many documents each token appears in.
    pub df: Vec<u32>,
    /// How many *distinct* tokens each document has.
    pub len: Vec<u32>,
    /// How often each posting's token occurs in that posting's document.
    ///
    /// Parallel to `nodes`, one byte each and saturating. A token appearing
    /// more than 255 times in a node is a node that has stopped being a node,
    /// and the difference between 255 and 400 occurrences changes no ranking
    /// once the saturation below has had its say.
    pub tf: Vec<u8>,
}

/// How fast term frequency saturates. BM25's `k1`.
///
/// The second occurrence of a word says much less than the first and the
/// twentieth says almost nothing, which is what `tf*(k1+1)/(tf + k1*norm)`
/// encodes.
///
/// **Not on the shipped path, and that is a measured result rather than an
/// omission.** Saturating term frequency was the obvious fix for a ranking that
/// looked like it was counting words, and `forest bench` says it makes things
/// worse here -- 79.2% against 87.8% on long queries and 42.4% against 47.9% on
/// short ones. The reason is visible in the corpus: these are short questions
/// with almost no term repetition, so `tf` is nearly always 1 and the whole
/// saturation term collapses to a constant. What is left of BM25 is its
/// *length* normalisation, which sits inside the saturation where `k1`
/// multiplies it, and that measured worse than charging the sum directly.
///
/// So this is a fact about a corpus of short questions and not about BM25. The
/// constant, the `tf` column and the grid row all stay, because the day the
/// corpus grows longer documents the answer is one command away rather than a
/// rewrite.
pub const TF_K1: f32 = 1.2;

/// How much a document is charged for its length. BM25's `b`.
///
/// **Visible before it was measured, and then measured.** Asked "what is the
/// derivative of a polynomial", the first answer was a question about roulette
/// -- a long node that happened to contain `what`, `is`, `of` and `a`. None of
/// those is worth much alone, but a long document contains more of everything,
/// so it collects more small weights than a short one carrying the words that
/// mattered. Dividing by `1 - b + b*(len/avg)` charges for that.
///
/// **0.5, not the textbook 0.75**, because `forest bench` swept it over 198
/// known-item queries against 8,913 candidates and this corpus answered:
///
///     b=0.00  r@1 81.8%   b=0.50  r@1 87.8%   b=1.00  r@1 81.8%
///     b=0.25  r@1 83.8%   b=0.75  r@1 86.3%
///
/// An interior optimum rather than an end of the range, which is the difference
/// between a value chosen and a value defaulted to. The usual 0.75 is a good
/// prior over web documents; these are short questions of similar shape, and
/// they wanted less of a charge than that.
pub const LEN_B: f32 = 0.5;

impl Lex {
    /// `ln((N + 1) / (df + 1))`, which is never negative and never divides by
    /// zero. A token in every document scores near zero; one in a single
    /// document scores `ln(N)`.
    pub fn idf(&self, t: usize) -> f32 {
        let df = *self.df.get(t).unwrap_or(&0) as f32;
        tensor::lnf((self.docs as f32 + 1.0) / (df + 1.0))
    }

    pub fn posting(&self, t: usize) -> &[u32] {
        if t + 1 >= self.starts.len() {
            return &[];
        }
        let (a, b) = (self.starts[t] as usize, self.starts[t + 1] as usize);
        &self.nodes[a..b]
    }

    /// How much of the query's information each document accounts for.
    ///
    /// The score is the share of the query's **IDF mass** the document matches,
    /// so it lands in `0..1` and is comparable across queries of different
    /// lengths. A document matching `the` and nothing else scores almost
    /// nothing, where a count of matched terms would score it the same as one
    /// matching `polynomial`.
    ///
    /// Query tokens are deduplicated first: a word said twice is not twice the
    /// evidence, and without this a repeated term quietly doubles its own
    /// weight against every other.
    /// What ships, with the constants `forest bench` chose.
    ///
    /// The `Terms` family: presence, then a length charge on the sum. **Not
    /// BM25**, and the sweep is why -- putting the charge inside the saturation
    /// where `k1` multiplies it measured worse here, on both long and short
    /// queries. That is a fact about a corpus of short questions with little
    /// term repetition, not about BM25, and the grid keeps both so the day the
    /// corpus changes the answer is one command away.
    pub fn score(&self, query: &[usize], out: &mut [f32]) {
        let total = self.score_raw(query, out);
        self.finish(out, total, LEN_B);
    }

    /// The matched IDF mass per document, and the query's total.
    ///
    /// Split from the normalisation so a sweep over `b` pays for the postings
    /// walk once. Recomputing it per `b` would put the walk into the difference
    /// between the rows, which is the thing being compared.
    pub fn score_raw(&self, query: &[usize], out: &mut [f32]) -> f32 {
        for v in out.iter_mut() {
            *v = 0.0;
        }
        let mut seen: Vec<usize> = Vec::with_capacity(query.len());
        let mut total = 0.0f32;
        for t in query {
            if seen.contains(t) {
                continue;
            }
            seen.push(*t);
            let w = self.idf(*t);
            total += w;
            for n in self.posting(*t) {
                if let Some(s) = out.get_mut(*n as usize) {
                    *s += w;
                }
            }
        }
        total
    }

    /// Divide by the query's mass and charge each document for its length.
    ///
    /// `b` of zero is no length discount at all -- what this did before the
    /// roulette answer made the bias visible. `b` of one charges in full.
    pub fn finish(&self, out: &mut [f32], total: f32, b: f32) {
        if total <= 0.0 {
            return;
        }
        let avg = self.avg_len();
        for (n, v) in out.iter_mut().enumerate() {
            if *v == 0.0 {
                continue;
            }
            let l = *self.len.get(n).unwrap_or(&1) as f32;
            let norm = 1.0 - b + b * (l / avg);
            *v /= total * norm.max(1.0e-6);
        }
    }

    /// BM25 over the postings: IDF, saturating term frequency, length charge.
    ///
    /// **One function for both scorings.** At `k1 = 0` the saturation term is
    /// `tf*1/(tf + 0)` = 1, which is presence -- so the row this had before is
    /// this row with a knob at zero, and the sweep can compare them without two
    /// code paths that might differ for a second reason.
    ///
    /// Divided by the query's own IDF mass at the end, so the score is the
    /// share of what was asked that the document accounts for and is comparable
    /// across queries of different lengths.
    pub fn bm25(&self, query: &[usize], out: &mut [f32], k1: f32, b: f32) {
        for v in out.iter_mut() {
            *v = 0.0;
        }
        let avg = self.avg_len();
        let mut seen: Vec<usize> = Vec::with_capacity(query.len());
        let mut total = 0.0f32;
        for t in query {
            if seen.contains(t) {
                continue;
            }
            seen.push(*t);
            let w = self.idf(*t);
            total += w;
            if w <= 0.0 {
                continue;
            }
            let (a, z) = match self.range(*t) {
                Some(v) => v,
                None => continue,
            };
            for k in a..z {
                let n = self.nodes[k] as usize;
                let f = self.tf[k] as f32;
                let l = *self.len.get(n).unwrap_or(&1) as f32;
                let norm = 1.0 - b + b * (l / avg);
                if let Some(sc) = out.get_mut(n) {
                    *sc += w * (f * (k1 + 1.0)) / (f + k1 * norm).max(1.0e-6);
                }
            }
        }
        if total > 0.0 {
            for v in out.iter_mut() {
                *v /= total;
            }
        }
    }

    /// Where a token's postings start and stop. Public for the suite, which
    /// has to reach one to check that occurrences were counted.
    pub fn range_of(&self, t: usize) -> (usize, usize) {
        self.range(t).unwrap_or((0, 0))
    }

    fn range(&self, t: usize) -> Option<(usize, usize)> {
        if t + 1 >= self.starts.len() {
            return None;
        }
        Some((self.starts[t] as usize, self.starts[t + 1] as usize))
    }

    pub fn avg_len(&self) -> f32 {
        if self.len.is_empty() {
            return 1.0;
        }
        let mut s = 0.0f32;
        for l in &self.len {
            s += *l as f32;
        }
        (s / self.len.len() as f32).max(1.0)
    }

    /// Build from one token list per document.
    pub fn build(vocab: usize, docs: &[Vec<usize>]) -> Lex {
        let mut df = alloc::vec![0u32; vocab];
        // Counted once per document, not once per occurrence -- that is what
        // makes it *document* frequency and what stops a word repeated ten
        // times in one node looking as common as one appearing in ten nodes.
        let mut seen: Vec<usize> = Vec::new();
        let mut counts = alloc::vec![0u32; vocab];
        for d in docs {
            seen.clear();
            for t in d {
                if *t < vocab && !seen.contains(t) {
                    seen.push(*t);
                    counts[*t] += 1;
                }
            }
        }
        df.copy_from_slice(&counts);

        let mut starts = alloc::vec![0u32; vocab + 1];
        for t in 0..vocab {
            starts[t + 1] = starts[t] + counts[t];
        }
        let total = starts[vocab] as usize;
        let mut nodes = alloc::vec![0u32; total];
        let mut tf = alloc::vec![0u8; total];
        let mut len = alloc::vec![0u32; docs.len()];
        let mut at = starts.clone();
        let mut slot: Vec<usize> = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            seen.clear();
            slot.clear();
            for t in d {
                if *t >= vocab {
                    continue;
                }
                match seen.iter().position(|x| x == t) {
                    // Already posted: bump the count in the slot it went to.
                    Some(k) => tf[slot[k]] = tf[slot[k]].saturating_add(1),
                    None => {
                        seen.push(*t);
                        let where_ = at[*t] as usize;
                        slot.push(where_);
                        nodes[where_] = i as u32;
                        tf[where_] = 1;
                        at[*t] += 1;
                    }
                }
            }
            // Distinct, because that is what the postings count and a length
            // measured differently from what it normalises is not a length.
            len[i] = seen.len() as u32;
        }
        Lex { vocab, docs: docs.len() as u32, starts, nodes, df, len, tf }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + (self.starts.len() + self.nodes.len() + self.df.len()) * 4);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.vocab as u32).to_le_bytes());
        out.extend_from_slice(&self.docs.to_le_bytes());
        out.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for v in &self.len {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.starts {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.nodes {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.df {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&self.tf);
        out
    }

    /// Walks and never seeks, and lands on the last byte.
    pub fn decode(b: &[u8]) -> Option<Lex> {
        if b.len() < 20 || &b[..8] != MAGIC {
            return None;
        }
        let vocab = u32::from_le_bytes(b[8..12].try_into().ok()?) as usize;
        let docs = u32::from_le_bytes(b[12..16].try_into().ok()?);
        let total = u32::from_le_bytes(b[16..20].try_into().ok()?) as usize;
        if vocab == 0 || vocab > 1 << 22 {
            return None;
        }
        let want = 20 + (docs as usize + vocab + 1 + total + vocab) * 4 + total;
        if b.len() != want {
            return None;
        }
        let mut at = 20usize;
        let mut take = |n: usize, at: &mut usize| -> Vec<u32> {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(u32::from_le_bytes(b[*at..*at + 4].try_into().unwrap_or([0; 4])));
                *at += 4;
            }
            v
        };
        let len = take(docs as usize, &mut at);
        let starts = take(vocab + 1, &mut at);
        let nodes = take(total, &mut at);
        let df = take(vocab, &mut at);
        let tf = b[at..at + total].to_vec();
        at += total;
        if at != b.len() || starts.last().copied().unwrap_or(0) as usize != total {
            return None;
        }
        Some(Lex { vocab, docs, starts, nodes, df, len, tf })
    }
}

/// Pool a piece of text into one vector, weighted by how much each token says.
///
/// Replaces `vocab::pool`'s straight mean. Each row is scaled to unit length
/// first, then weighted by IDF, and the result is normalised -- so a cosine
/// against another such vector is a plain dot product, which is what makes
/// scoring nine thousand nodes cheap.
pub fn pool(
    model: &crate::ai::model::Model,
    tok: &crate::ai::tokenizer::Tokenizer,
    text: &str,
    lex: &Lex,
) -> Vec<f32> {
    let ids = tok.encode(text, false, false);
    pool_ids(model, &ids, lex)
}

pub fn pool_ids(model: &crate::ai::model::Model, ids: &[usize], lex: &Lex) -> Vec<f32> {
    let dim = model.cfg.dim;
    let mut v = alloc::vec![0.0f32; dim];
    let mut row = alloc::vec![0.0f32; dim];
    for id in ids {
        model.embed_into(*id, &mut row);
        let n = tensor::sqrtf(dot(&row, &row));
        if n <= 0.0 {
            continue;
        }
        // Unit row, then IDF. The division is folded into the weight so the
        // row is walked once rather than twice.
        let w = lex.idf(*id) / n;
        for (a, e) in v.iter_mut().zip(row.iter()) {
            *a += *e * w;
        }
    }
    normalise(&mut v);
    v
}

pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    let mut s = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        s += *x * *y;
    }
    s
}

/// Scale to unit length, or leave alone if there is no length to scale.
pub fn normalise(v: &mut [f32]) {
    let n = tensor::sqrtf(dot(v, v));
    if n > 0.0 {
        for a in v.iter_mut() {
            *a /= n;
        }
    }
}

pub fn selftest() -> bool {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, LTRED};
    let mut ok = true;
    let mut check = |what: &str, pass: bool| {
        console::set_color(if pass { LTGREEN } else { LTRED });
        crate::kprintln!("  {}  {}", if pass { "ok  " } else { "FAIL" }, what);
        console::set_color(LTGRAY);
        ok &= pass;
    };

    // Four documents over a vocabulary of six. Token 0 is in all four -- it is
    // the `the` of this corpus -- and token 5 is in one.
    let docs = alloc::vec![
        alloc::vec![0usize, 1, 2],
        alloc::vec![0usize, 1, 3],
        alloc::vec![0usize, 2],
        alloc::vec![0usize, 5, 5, 5],
    ];
    let lex = Lex::build(6, &docs);

    check(
        "document frequency counts documents, not occurrences",
        lex.df[0] == 4 && lex.df[1] == 2 && lex.df[5] == 1 && lex.df[4] == 0,
    );
    check(
        "a token in every document says nothing, a token in one says most",
        lex.idf(0) < 0.3 && lex.idf(5) > lex.idf(1) && lex.idf(1) > lex.idf(0),
    );
    check(
        "postings list the documents that contain a token, in order",
        lex.posting(1) == [0u32, 1] && lex.posting(5) == [3u32] && lex.posting(4).is_empty(),
    );

    // These three are about the IDF weighting, so the length discount is
    // switched off for them. A claim that moved when either knob moved could
    // not say which one broke it.
    let mut s = alloc::vec![0.0f32; 4];
    let flat = |l: &Lex, q: &[usize], out: &mut [f32]| {
        let t = l.score_raw(q, out);
        l.finish(out, t, 0.0);
    };
    flat(&lex, &[5], &mut s);
    check(
        "a rare term picks out its one document and scores it whole",
        (s[3] - 1.0).abs() < 1.0e-6 && s[0] == 0.0 && s[1] == 0.0,
    );
    // **Exactly zero, and the first version of this claim expected "a little".**
    // `ln((N+1)/(df+1))` of a token in every document is `ln(1)`, which is not
    // small, it is nothing -- so a query carrying only such tokens has no
    // information, every document ties, and the ranking among them is
    // arbitrary because there is nothing to rank by. That is the formula
    // working, and it is a better property than the one that was asserted.
    flat(&lex, &[0], &mut s);
    check(
        "a query of only-common terms discriminates nothing and ties everything",
        s.iter().all(|v| *v == 0.0),
    );
    // Which is what makes the score a share of IDF mass rather than a count of
    // matched terms: matching `the` earns nothing at all, where counting terms
    // would score it the same as matching the word that carries the question.
    flat(&lex, &[0, 5], &mut s);
    check(
        "matching the informative half is everything, matching the common half is nothing",
        (s[3] - 1.0).abs() < 1.0e-6 && s[0] == 0.0 && s[1] == 0.0,
    );
    // Said twice is not twice the evidence.
    let mut t = alloc::vec![0.0f32; 4];
    flat(&lex, &[5, 5, 5], &mut t);
    flat(&lex, &[5], &mut s);
    check("a term repeated in the query counts once", s == t);

    check(
        "a document's length is its distinct tokens, not its occurrences",
        lex.len == alloc::vec![3u32, 3, 2, 2],
    );
    // The roulette bug in miniature. Documents 0 and 1 both match the whole
    // query; document 0 is three times longer. Without a length discount they
    // tie and the sprawling one is as good as the exact one.
    //
    // **Four documents and not two**, which is the mistake the first version of
    // this made: with two, a term in both of them has `df == N` and therefore
    // an IDF of exactly zero, so the query carried no weight at all and there
    // was nothing to tie. A fixture too small to have a rare term cannot test
    // a rare term.
    let long_short = alloc::vec![
        alloc::vec![1usize, 2, 3, 4, 5, 0],
        alloc::vec![1usize, 2],
        alloc::vec![3usize],
        alloc::vec![4usize],
    ];
    let l2 = Lex::build(6, &long_short);
    let mut u = alloc::vec![0.0f32; 4];
    let tot = l2.score_raw(&[1, 2], &mut u);
    l2.finish(&mut u, tot, 0.0);
    check(
        "with no length discount a long document ties a short one on the same match",
        (u[0] - u[1]).abs() < 1.0e-6,
    );
    let tot = l2.score_raw(&[1, 2], &mut u);
    l2.finish(&mut u, tot, LEN_B);
    check(
        "and with one, the document that spent all of itself on the query wins",
        u[1] > u[0],
    );

    // --- term frequency, and the knob that turns it off -----------------
    //
    // Document 3 is `[0, 5, 5, 5]`: token 5 three times, in one document.
    check(
        "term frequency counts occurrences where document frequency counted documents",
        lex.tf[lex.range_of(5).0] == 3 && lex.df[5] == 1,
    );
    // **`k1 = 0` is presence**, exactly: the saturation term becomes
    // `tf*1/(tf+0)` = 1 whatever `tf` is. So the scoring this shipped before is
    // this scoring with the knob at zero, and the two are one function rather
    // than two that might drift apart for a second reason.
    let mut p0 = alloc::vec![0.0f32; 4];
    let mut p1 = alloc::vec![0.0f32; 4];
    lex.bm25(&[5], &mut p0, 0.0, 0.0);
    let t = lex.score_raw(&[5], &mut p1);
    lex.finish(&mut p1, t, 0.0);
    check(
        "bm25 with k1 = 0 is presence scoring, to the bit",
        p0 == p1,
    );
    // Three occurrences are worth more than one and nowhere near three times
    // more. That is the whole of what saturation is for: the second mention of
    // a word says much less than the first.
    let rep3 = alloc::vec![
        alloc::vec![9usize, 9, 9, 1],
        alloc::vec![9usize, 1],
        alloc::vec![2usize],
        alloc::vec![3usize],
    ];
    let l3 = Lex::build(10, &rep3);
    let mut u = alloc::vec![0.0f32; 4];
    l3.bm25(&[9], &mut u, TF_K1, 0.0);
    check(
        "three occurrences beat one, and by far less than three times",
        u[0] > u[1] && u[0] < u[1] * 2.0,
    );

    let enc = lex.encode();
    let back = Lex::decode(&enc);
    check(
        "the index round-trips through its own bytes",
        match &back {
            Some(d) => {
                d.vocab == 6
                    && d.docs == 4
                    && d.df == lex.df
                    && d.nodes == lex.nodes
                    && d.tf == lex.tf
                    && d.len == lex.len
            }
            None => false,
        },
    );
    let mut extra = enc.clone();
    extra.push(0);
    check(
        "and is refused when truncated, over-long, or not an index",
        Lex::decode(&enc[..enc.len() - 1]).is_none()
            && Lex::decode(&extra).is_none()
            && Lex::decode(b"GLADOSZZ____________").is_none(),
    );

    let mut v = alloc::vec![3.0f32, 4.0];
    normalise(&mut v);
    check(
        "normalising makes a cosine a dot product",
        (dot(&v, &v) - 1.0).abs() < 1.0e-6 && (v[0] - 0.6).abs() < 1.0e-6,
    );
    let mut z = alloc::vec![0.0f32, 0.0];
    normalise(&mut z);
    check("and a vector with no length is left alone rather than divided by zero", z == [0.0, 0.0]);

    ok
}
