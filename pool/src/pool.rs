//! What the pool knows: which coins it serves, and which shares were good.
//!
//! Deliberately free of sockets. Everything here is a pure function of state
//! plus a message, so the whole of share validation can be exercised without a
//! listener, a miner, or a network -- the same separation `update::decide` and
//! `code::locate` get, and for the same reason: the interesting failures are
//! decisions, and a decision that needs a TCP connection to reproduce is one
//! nobody reproduces.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mine::algo::{Algo, Hasher};
use crate::mine::hash::below_target;
use crate::mine::proto;
use crate::mine::u256::U256;

/// A coin this pool serves.
pub struct Coin {
    pub label: String,
    pub algo: Algo,
    /// What a miner's share must beat. Not the network's target: a share is
    /// proof of work done, and asking for network difficulty from a laptop
    /// means one share a geological age.
    pub share_target: U256,
    /// The network's own target, when a chain is behind this coin. `None` for
    /// a coin with no upstream, which is every coin today -- and it is `None`
    /// rather than a plausible constant, so `ev` prints "cannot say" instead of
    /// an expected value derived from a number nobody measured.
    pub network_target: Option<U256>,
    /// Where the header comes from. See `Source`.
    pub source: Source,
}

pub enum Source {
    /// The pool builds the header itself. No chain, so a share that beat the
    /// network target would still be worth nothing -- which is why a coin in
    /// this state is reported as such rather than quietly served.
    Local,
    /// An upstream Stratum V1 pool. Not implemented; the variant exists so the
    /// table has somewhere to put one and the report can say what is missing.
    Upstream { host: String, port: u16, user: String },
}

impl Source {
    pub fn name(&self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::Upstream { .. } => "upstream",
        }
    }
}

/// A job that has been handed out and may still have shares arriving for it.
#[derive(Clone)]
pub struct Issued {
    pub slot: u32,
    pub coin: String,
    pub algo: Algo,
    pub header: [u8; 80],
    pub target: U256,
    pub echo: proto::Echo,
}

/// What happened to a submitted share. One enum so a caller cannot invent a
/// state, and so "stale" and "wrong" stay apart -- they mean completely
/// different things about a miner and folding them loses the difference.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Good, and counted.
    Accepted,
    /// Correct arithmetic against a job we no longer hold. The miner did the
    /// work; the chain moved. Not the miner's fault and not counted against it.
    Stale,
    /// The hash does not meet the target it was issued. Either a bug at one
    /// end or a miner sending noise, and the pool cannot tell which.
    Bad,
    /// This exact nonce was already credited for this job.
    Duplicate,
    /// Parameters the algorithm refuses. The pool issued them, so this is the
    /// pool's own bug and says so rather than blaming the share.
    Unhashable,
}

impl Verdict {
    pub fn name(&self) -> &'static str {
        match self {
            Verdict::Accepted => "accepted",
            Verdict::Stale => "stale",
            Verdict::Bad => "bad",
            Verdict::Duplicate => "duplicate",
            Verdict::Unhashable => "unhashable",
        }
    }
}

/// One worker's record against one coin.
#[derive(Default, Clone)]
pub struct Tally {
    pub accepted: u64,
    pub stale: u64,
    pub bad: u64,
    pub duplicate: u64,
}

pub struct Pool {
    pub coins: Vec<Coin>,
    /// Jobs still accepting shares, newest last. Bounded, because a miner that
    /// never submits would otherwise grow this forever -- and because a job old
    /// enough to fall off is a job whose shares are stale by definition.
    issued: Vec<(String, Issued)>,
    /// `(job, nonce)` already credited. The duplicate check is per job rather
    /// than global: two coins can legitimately produce the same nonce, and a
    /// global set would refuse the second as a duplicate of work it is not.
    seen: Vec<(String, u32)>,
    tallies: HashMap<(String, String), Tally>,
    next_job: u64,
}

/// How many issued jobs to remember. Sixty-four is four coins' worth of a
/// couple of minutes at a thirty-second job cadence, which is comfortably
/// longer than any honest share takes to arrive.
const KEEP_JOBS: usize = 64;
/// Nonces remembered for the duplicate check. Larger than `KEEP_JOBS` because
/// one job can yield many shares, and a forgotten nonce is credited twice.
const KEEP_NONCES: usize = 4096;

impl Pool {
    pub fn new(coins: Vec<Coin>) -> Pool {
        Pool {
            coins,
            issued: Vec::new(),
            seen: Vec::new(),
            tallies: HashMap::new(),
            next_job: 1,
        }
    }

    /// Build the next job for a coin.
    ///
    /// The header is assembled here and the miner never sees a coinbase, which
    /// is the whole shape of the protocol and its whole trust cost. See
    /// `design/pool.md`.
    pub fn make_job(&mut self, slot: u32) -> Option<proto::Job> {
        let coin = self.coins.get(slot as usize)?;
        let label = coin.label.clone();
        let algo = coin.algo.clone();
        let target = coin.share_target;

        let id = self.next_job;
        self.next_job += 1;
        let job = format!("{id:08x}");

        // A local coin has no chain, so the header is this pool's own: a
        // version, a previous hash of nothing, a merkle root standing for an
        // empty block, and the clock. It is deliberately *not* a fixed fixture
        // -- an unchanging header means every job is the same search and a
        // miner that reported a share for one would report it for all of them.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[36..44].copy_from_slice(&id.to_le_bytes());
        header[68..72].copy_from_slice(&now.to_le_bytes());
        header[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());

        let issued = Issued {
            slot,
            coin: label.clone(),
            algo: algo.clone(),
            header,
            target,
            echo: Vec::new(),
        };
        self.issued.push((job.clone(), issued));
        if self.issued.len() > KEEP_JOBS {
            self.issued.remove(0);
        }

        Some(proto::Job {
            slot,
            coin: label,
            job,
            algo,
            header,
            target,
            echo: Vec::new(),
            clean: true,
        })
    }

    /// Validate a submitted share by computing the hash the miner computed.
    ///
    /// This is the one thing the pool cannot delegate and the reason it shares
    /// the kernel's source. Everything else here is bookkeeping.
    pub fn submit(&mut self, worker: &str, sh: &proto::Share) -> Verdict {
        let Some((_, job)) = self.issued.iter().find(|(id, _)| *id == sh.job) else {
            // Not counted against the worker. The arithmetic may have been
            // perfect; the job simply aged out.
            self.tally(worker, "?").stale += 1;
            return Verdict::Stale;
        };
        let job = job.clone();

        if self.seen.iter().any(|(j, n)| *j == sh.job && *n == sh.nonce) {
            self.tally(worker, &job.coin).duplicate += 1;
            return Verdict::Duplicate;
        }

        let Some(mut hasher) = Hasher::new(&job.algo, &job.header) else {
            // The pool issued these parameters, so this is the pool's bug.
            // Not tallied against the worker at all.
            return Verdict::Unhashable;
        };
        let digest = hasher.hash(&job.header, sh.nonce);

        if !below_target(&digest, &job.target) {
            self.tally(worker, &job.coin).bad += 1;
            return Verdict::Bad;
        }

        self.seen.push((sh.job.clone(), sh.nonce));
        if self.seen.len() > KEEP_NONCES {
            self.seen.remove(0);
        }
        self.tally(worker, &job.coin).accepted += 1;
        Verdict::Accepted
    }

    fn tally(&mut self, worker: &str, coin: &str) -> &mut Tally {
        self.tallies
            .entry((String::from(worker), String::from(coin)))
            .or_default()
    }

    /// The share log, which is the whole product of a non-custodial pool and
    /// the only thing standing in for trust. Sorted, so two runs of the same
    /// history print the same report rather than a `HashMap`'s order.
    pub fn ledger(&self) -> Vec<(String, String, Tally)> {
        let mut v: Vec<(String, String, Tally)> = self
            .tallies
            .iter()
            .map(|((w, c), t)| (w.clone(), c.clone(), t.clone()))
            .collect();
        v.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        v
    }

    pub fn slots(&self) -> u32 {
        self.coins.len() as u32
    }

    /// The share log as a publishable document.
    ///
    /// This is the whole product of a non-custodial pool. Layer 1 never holds
    /// a miner's coins, so there is nothing to audit by looking at a wallet;
    /// what a miner has instead is this record and whatever can be checked
    /// against it. `design/pool.md` says that out loud and it constrains the
    /// format rather than only the paperwork.
    ///
    /// **Canonical, so the digest means something.** Rows are sorted and every
    /// field is written in one fixed order, so two runs over the same history
    /// produce identical bytes -- a document whose hash depended on a
    /// `HashMap`'s iteration order would have a different digest every time it
    /// was regenerated, which is indistinguishable from a record that changed.
    ///
    /// The digest is over the rows and not over the whole file, because
    /// `generated_at` moves on every write and would otherwise make an
    /// unchanged log look edited.
    ///
    /// **This is not a Merkle root and does not claim to be.** A distributor
    /// needs a tree whose leaves are per-address payouts and whose proofs a
    /// contract can verify; this is a flat digest over a tally. It exists so
    /// the published record is fixed to a value now, and so the day the tree
    /// is built there is something to check it against.
    pub fn ledger_json(&self, epoch: u64, generated_at: u64) -> String {
        let rows = self.ledger();

        let mut canon = String::new();
        for (w, c, t) in &rows {
            // Tab-separated and newline-terminated rather than JSON, because
            // the digest must not depend on how a JSON writer spaces or
            // escapes. Two encoders that agree about a document can still
            // disagree about its bytes.
            canon.push_str(&format!(
                "{w}	{c}	{}	{}	{}	{}
",
                t.accepted, t.stale, t.bad, t.duplicate
            ));
        }
        let digest = crate::store::sha256::hash(canon.as_bytes());

        let mut s = String::from("{
");
        s.push_str(&format!("  \"epoch\": {epoch},
"));
        s.push_str(&format!("  \"generated_at\": {generated_at},
"));
        s.push_str(&format!(
            "  \"digest\": \"{}\",
",
            crate::mine::stratum::hex(&digest)
        ));
        s.push_str("  \"coins\": [
");
        for (i, c) in self.coins.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"slot\": {i}, \"label\": \"{}\", \"algo\": \"{}\", \"source\": \"{}\"}}{}
",
                c.label,
                c.algo.detail(),
                c.source.name(),
                if i + 1 == self.coins.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],
  \"shares\": [
");
        for (i, (w, c, t)) in rows.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"worker\": \"{w}\", \"coin\": \"{c}\", \"accepted\": {}, \"stale\": {}, \"bad\": {}, \"duplicate\": {}}}{}
",
                t.accepted,
                t.stale,
                t.bad,
                t.duplicate,
                if i + 1 == rows.len() { "" } else { "," }
            ));
        }
        s.push_str("  ]
}
");
        s
    }
}

/// A target easy enough that a laptop finds shares in seconds.
///
/// `leading` is how many leading zero *bits* a digest must have. Expressed in
/// bits rather than as a difficulty because a difficulty is a float and the
/// conversion is exactly where `stratum::decimal` records that `Json::as_i64`
/// reads `0.001` as zero.
pub fn target_with_leading_zeros(leading: u32) -> U256 {
    let mut b = [0xffu8; 32];
    let full = (leading / 8) as usize;
    for x in b.iter_mut().take(full.min(32)) {
        *x = 0;
    }
    if full < 32 {
        b[full] = 0xffu8 >> (leading % 8);
    }
    U256::from_be_bytes(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_pool() -> Pool {
        Pool::new(vec![Coin {
            label: String::from("test"),
            algo: Algo::Sha256d,
            // Eight bits, so a share turns up within a few hundred nonces.
            share_target: target_with_leading_zeros(8),
            network_target: None,
            source: Source::Local,
        }])
    }

    /// The check the whole pool rests on: a share is credited only when the
    /// pool can reproduce the hash the miner claims to have found.
    #[test]
    fn a_real_share_is_accepted_and_a_forged_one_is_not() {
        let mut p = a_pool();
        let job = p.make_job(0).unwrap();
        let mut h = Hasher::new(&job.algo, &job.header).unwrap();

        let mut good = None;
        for n in 0..200_000u32 {
            if below_target(&h.hash(&job.header, n), &job.target) {
                good = Some(n);
                break;
            }
        }
        let n = good.expect("no share inside 200k nonces at 8 leading bits");

        assert_eq!(
            p.submit("w1", &proto::Share { job: job.job.clone(), nonce: n, echo: vec![] }),
            Verdict::Accepted
        );
        // The same nonce again is a duplicate rather than a second credit.
        assert_eq!(
            p.submit("w1", &proto::Share { job: job.job.clone(), nonce: n, echo: vec![] }),
            Verdict::Duplicate
        );
        // A nonce that does not meet the target is refused however confidently
        // it is sent. `n + 1` is overwhelmingly not a solution.
        assert_eq!(
            p.submit("w1", &proto::Share { job: job.job.clone(), nonce: n.wrapping_add(1), echo: vec![] }),
            Verdict::Bad
        );
        // And a job the pool never issued is stale, not bad -- the distinction
        // decides whether a miner is misbehaving or merely late.
        assert_eq!(
            p.submit("w1", &proto::Share { job: String::from("ffffffff"), nonce: n, echo: vec![] }),
            Verdict::Stale
        );

        let led = p.ledger();
        let t = &led.iter().find(|(_, c, _)| c == "test").unwrap().2;
        assert_eq!((t.accepted, t.duplicate, t.bad), (1, 1, 1));
    }

    /// A share found under one algorithm must not be credited under another.
    /// This is what would break if `proto` dropped the algorithm field, and it
    /// would break silently: every share simply stops being accepted.
    #[test]
    fn a_share_is_validated_under_its_own_algorithm() {
        let mut p = Pool::new(vec![
            Coin {
                label: String::from("a"),
                algo: Algo::Sha256d,
                share_target: target_with_leading_zeros(8),
                network_target: None,
                source: Source::Local,
            },
            Coin {
                label: String::from("b"),
                algo: Algo::Blake2s,
                share_target: target_with_leading_zeros(8),
                network_target: None,
                source: Source::Local,
            },
        ]);
        let ja = p.make_job(0).unwrap();
        let mut ha = Hasher::new(&ja.algo, &ja.header).unwrap();
        let n = (0..200_000u32)
            .find(|n| below_target(&ha.hash(&ja.header, *n), &ja.target))
            .expect("no sha256d share found");

        // Under blake2s the same header and nonce give a different digest, so
        // this nonce is almost certainly not a solution there.
        let jb = p.make_job(1).unwrap();
        let mut hb = Hasher::new(&jb.algo, &jb.header).unwrap();
        assert_ne!(ha.hash(&ja.header, n), hb.hash(&jb.header, n));

        assert_eq!(
            p.submit("w", &proto::Share { job: ja.job, nonce: n, echo: vec![] }),
            Verdict::Accepted
        );
    }

    #[test]
    fn the_target_helper_means_what_it_says() {
        let t = target_with_leading_zeros(8);
        let b = t.to_be_bytes();
        assert_eq!(b[0], 0x00);
        assert_eq!(b[1], 0xff);
        // Zero leading bits is every digest, which is what a pool with the
        // difficulty turned all the way down should mean rather than an error.
        assert_eq!(target_with_leading_zeros(0).to_be_bytes()[0], 0xff);
    }

    /// The digest is a function of the record and of nothing else.
    ///
    /// The property that makes a published log worth publishing: regenerating
    /// it must not change it. A digest that moved with the clock, or with a
    /// map's iteration order, would make every routine republish look like an
    /// edit -- and a record nobody can tell has changed is not evidence.
    #[test]
    fn the_ledger_digest_depends_on_the_record_and_not_the_run() {
        let mut p = a_pool();
        let job = p.make_job(0).unwrap();
        let mut h = Hasher::new(&job.algo, &job.header).unwrap();
        let n = (0..200_000u32)
            .find(|n| below_target(&h.hash(&job.header, *n), &job.target))
            .expect("no share found");
        p.submit("w1", &proto::Share { job: job.job, nonce: n, echo: vec![] });

        let a = p.ledger_json(1, 1_000);
        let b = p.ledger_json(1, 9_999);
        let da = a.lines().find(|l| l.contains("digest")).unwrap();
        let db = b.lines().find(|l| l.contains("digest")).unwrap();
        assert_eq!(da, db, "the clock moved the digest");
        assert_ne!(a, b, "generated_at should still be recorded");

        // And a record that genuinely changed must change it, or the digest is
        // decoration rather than evidence.
        let job2 = p.make_job(0).unwrap();
        let mut h2 = Hasher::new(&job2.algo, &job2.header).unwrap();
        let n2 = (0..200_000u32)
            .find(|n| below_target(&h2.hash(&job2.header, *n), &job2.target))
            .expect("no second share found");
        p.submit("w2", &proto::Share { job: job2.job, nonce: n2, echo: vec![] });
        let c = p.ledger_json(1, 1_000);
        let dc = c.lines().find(|l| l.contains("digest")).unwrap();
        assert_ne!(da, dc, "a new share did not move the digest");
    }

    /// Two jobs must not be the same search. A fixed header would make every
    /// job identical, so a nonce found once is a share forever.
    #[test]
    fn two_jobs_are_two_different_searches() {
        let mut p = a_pool();
        let a = p.make_job(0).unwrap();
        let b = p.make_job(0).unwrap();
        assert_ne!(a.job, b.job);
        assert_ne!(a.header, b.header);
    }
}
