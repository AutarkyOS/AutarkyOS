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
use crate::mine::header;
use crate::mine::proto;
use crate::mine::u256::U256;

/// A coin this pool serves.
pub struct Coin {
    pub label: String,
    pub algo: Algo,
    /// Where a *new* miner starts, in leading zero bits. Only a starting
    /// point: `server.rs` moves each connection from here, per coin, so this
    /// is the operator's guess rather than a setting anybody has to get right.
    pub share_bits: u32,
    /// The same thing as a target, kept so a coin with no connection on it
    /// still reports something meaningful.
    pub share_target: U256,
    /// The network's own target, when a chain is behind this coin. `None` for
    /// a coin with no upstream, which is every coin today -- and it is `None`
    /// rather than a plausible constant, so `ev` prints "cannot say" instead of
    /// an expected value derived from a number nobody measured.
    pub network_target: Option<U256>,
    /// Where the header comes from. See `Source`.
    pub source: Source,
    /// The latest `mining.notify` from upstream. `None` for a local coin, and
    /// also for an upstream one that has not connected yet -- which is why
    /// `make_job` answers `None` rather than inventing a header.
    pub work: Option<Work>,
    /// Counter feeding extranonce2, so two jobs from one `mining.notify` search
    /// different coinbases. Monotonic and never reset within a connection: a
    /// repeat would hand two miners the same space and pay one of them for the
    /// other's work.
    pub e2: u64,
}

#[derive(Clone)]
pub enum Source {
    /// The pool builds the header itself. No chain, so a share that beat the
    /// network target would still be worth nothing -- which is why a coin in
    /// this state is reported as such rather than quietly served.
    Local,
    /// A real Stratum V1 pool upstream. Work comes from its `mining.notify`
    /// and qualifying shares go back as `mining.submit`.
    Upstream {
        host: String,
        port: u16,
        user: String,
        pass: String,
    },
}

impl Source {
    pub fn name(&self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::Upstream { .. } => "upstream",
        }
    }
}

/// What an upstream pool last told us, before any of it becomes a header.
///
/// Held verbatim rather than pre-assembled, because the extranonce2 changes per
/// job handed downstream and the coinbase has to be rebuilt around it -- which
/// is the whole mechanism by which two miners search different spaces.
#[derive(Clone)]
pub struct Work {
    pub job_id: String,
    pub prev_wire: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub branch: Vec<[u8; 32]>,
    pub version: u32,
    pub ntime: u32,
    pub nbits: u32,
    pub extranonce1: Vec<u8>,
    pub extranonce2_size: usize,
    /// What upstream will actually credit, from `mining.set_difficulty`. A
    /// share beating our own target is worth counting; a share beating this one
    /// is worth *sending*, and the two are different numbers on purpose.
    pub up_target: U256,
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
    /// Everything a `mining.submit` needs, kept from when the header was built.
    ///
    /// Stored rather than recomputed, for the reason `client::Template` gives
    /// about the same fields: formatting them a second time at submit is how a
    /// client sends a share for a header it never built. The miner's `echo`
    /// carries them too and is deliberately not trusted for this -- it comes
    /// back over the network and this did not.
    pub up: Option<UpstreamRef>,
}

/// The parts of an issued job that only matter if it goes back upstream.
#[derive(Clone)]
pub struct UpstreamRef {
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub ntime_be: Vec<u8>,
    pub up_target: U256,
}

/// A share good enough to be worth sending upstream.
#[derive(Clone)]
pub struct Forward {
    pub slot: u32,
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub ntime_be: Vec<u8>,
    pub nonce_be: Vec<u8>,
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
#[derive(Default, Clone, Debug, PartialEq)]
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
    /// Shares that beat upstream's target, waiting for the upstream thread.
    ///
    /// A queue rather than a call, because `Pool` holds no sockets -- the same
    /// split `server.rs` has, and the same shape the kernel's own `SHARES`
    /// queue uses between its hash loop and its socket task.
    forwards: Vec<Forward>,
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
            forwards: Vec::new(),
            next_job: 1,
        }
    }

    /// Build the next job for a coin.
    ///
    /// The header is assembled here and the miner never sees a coinbase, which
    /// is the whole shape of the protocol and its whole trust cost. See
    /// `design/pool.md`.
    /// Build the next job for a coin, at the difficulty this caller wants.
    ///
    /// **The difficulty is an argument and not a property of the coin**, which
    /// is what makes per-connection retargeting possible at all: every call
    /// takes a fresh job id, so two miners on one coin simply hold two
    /// `Issued` records with two targets and nothing has to be shared between
    /// them.
    pub fn make_job(&mut self, slot: u32, bits: u32) -> Option<proto::Job> {
        let coin = self.coins.get(slot as usize)?;
        let label = coin.label.clone();
        let algo = coin.algo.clone();
        let target = target_with_leading_zeros(bits);
        let work = coin.work.clone();
        let upstream = matches!(coin.source, Source::Upstream { .. });

        // An upstream coin with no work yet yields no job. Building one anyway
        // would mean inventing a header, and a miner would then spend real time
        // on a search that can never pay -- which from `mine coins` looks
        // exactly like a coin that is working.
        if upstream && work.is_none() {
            return None;
        }

        let id = self.next_job;
        self.next_job += 1;
        let job = format!("{id:08x}");

        let mut proof = None;
        let (header, up) = match &work {
            Some(w) => {
                // The extranonce2 is what makes two jobs from one `notify` into
                // two different searches, so it advances per job and not per
                // notify.
                let c = self.coins.get_mut(slot as usize)?;
                c.e2 = c.e2.wrapping_add(1);
                let counter = c.e2;

                let mut e2 = Vec::with_capacity(w.extranonce2_size);
                // Big-endian, so a hex dump reads in order. Which encoding is
                // used does not matter for validity; what matters is that the
                // same bytes reach the coinbase and the submit, which is why
                // they are stored below rather than formatted twice.
                for i in (0..w.extranonce2_size).rev() {
                    e2.push((counter >> (8 * (i % 8))) as u8);
                }

                let coinbase = header::coinbase(&w.coinb1, &w.extranonce1, &e2, &w.coinb2);
                let root = header::merkle_root(&coinbase, &w.branch);
                // The miner is shown the working. `extranonce1 || extranonce2`
                // goes as one field because the split is Stratum's answer to a
                // problem the miner does not have here: the pool varies the
                // second half, so where the boundary falls is nothing a miner
                // can use.
                let mut spliced = w.extranonce1.clone();
                spliced.extend_from_slice(&e2);
                if LIE.load(core::sync::atomic::Ordering::Relaxed) {
                    // One byte. The point is that a miner must refuse a proof
                    // that is *almost* right, not only one that is obviously
                    // malformed -- a check that only caught garbage would pass
                    // on every interesting lie.
                    spliced[0] ^= 0x01;
                }
                proof = Some(proto::Proof {
                    coinb1: w.coinb1.clone(),
                    extranonce: spliced,
                    coinb2: w.coinb2.clone(),
                    branch: w.branch.clone(),
                });
                let h = header::assemble(w.version, &w.prev_wire, &root, w.ntime, w.nbits, 0);
                let (ntime_be, _) = header::submit_hex(&h);
                (
                    h,
                    Some(UpstreamRef {
                        job_id: w.job_id.clone(),
                        extranonce2: e2,
                        ntime_be,
                        up_target: w.up_target,
                    }),
                )
            }
            None => {
                // A local coin has no chain, so the header is this pool's own:
                // a version, an id where the previous hash goes, and the clock.
                // Deliberately *not* a fixed fixture -- an unchanging header
                // means every job is the same search, and a nonce found once
                // would be a share forever.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                let mut h = [0u8; 80];
                h[0..4].copy_from_slice(&1u32.to_le_bytes());
                h[36..44].copy_from_slice(&id.to_le_bytes());
                h[68..72].copy_from_slice(&now.to_le_bytes());
                h[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
                (h, None)
            }
        };

        self.issued.push((
            job.clone(),
            Issued {
                slot,
                coin: label.clone(),
                algo: algo.clone(),
                header,
                target,
                echo: Vec::new(),
                up,
            },
        ));
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
            // Absent for a local coin, deliberately. There is no chain behind
            // one, so its "coinbase" would be a fabrication -- and a proof that
            // verifies against an invented header is worse than none, because
            // it looks like evidence.
            proof,
        })
    }

    /// Install what upstream just sent.
    pub fn set_work(&mut self, slot: usize, w: Work) -> bool {
        let Some(coin) = self.coins.get_mut(slot) else {
            return false;
        };
        coin.work = Some(w);
        true
    }

    /// Which coin an issued job belongs to.
    ///
    /// Asked of the pool rather than tracked a second time in the connection,
    /// because the pool is already the one thing that knows -- and two records
    /// of which job is which coin is the arrangement that eventually
    /// disagrees.
    pub fn slot_of_job(&self, job: &str) -> Option<usize> {
        self.issued
            .iter()
            .find(|(id, _)| id == job)
            .map(|(_, j)| j.slot as usize)
    }

    /// Where a new connection should start on this coin.
    pub fn start_bits(&self, slot: usize) -> u32 {
        self.coins.get(slot).map(|c| c.share_bits).unwrap_or(20)
    }

    /// Whether a coin has upstream work in hand.
    pub fn has_work(&self, slot: usize) -> bool {
        self.coins
            .get(slot)
            .map(|c| c.work.is_some())
            .unwrap_or(false)
    }

    /// Take the shares that beat upstream's target.
    ///
    /// Drains, so a caller that fails to send them loses them -- which is
    /// correct rather than careless: a share is only worth anything on the
    /// connection whose extranonce1 it was found under, so holding one for a
    /// reconnection would be keeping something already worthless.
    pub fn take_forwards(&mut self) -> Vec<Forward> {
        core::mem::take(&mut self.forwards)
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

        // Two targets, and the difference between them is the whole of being a
        // proxy. Ours decides what a miner is *credited* for and is set low
        // enough that a laptop reports in regularly; upstream's decides what is
        // worth *sending*, and most accepted shares do not meet it. One number
        // for both would either flood upstream with work it rejects or leave a
        // miner silent for hours.
        if let Some(up) = &job.up {
            if below_target(&digest, &up.up_target) {
                self.forwards.push(Forward {
                    slot: job.slot,
                    job_id: up.job_id.clone(),
                    extranonce2: up.extranonce2.clone(),
                    ntime_be: up.ntime_be.clone(),
                    nonce_be: sh.nonce.to_be_bytes().to_vec(),
                });
            }
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

    /// Read a ledger back, so a restart does not begin at zero.
    ///
    /// Only the *tallies* are restored. The coins come from the command line,
    /// which is authoritative: a file that disagreed about which algorithm a
    /// label means would otherwise silently change what the pool serves, and
    /// the operator would be reading their own config to find out why.
    ///
    /// Parsed with `crate::json`, which is the kernel's parser reading this
    /// program's own output -- one parser at both ends, for the reason the
    /// protocol gives.
    ///
    /// **What the digest can and cannot catch.** It is over the rows, so a
    /// truncated or corrupted file is refused rather than half-loaded. It is
    /// not a signature and proves nothing about *who* wrote the file: anybody
    /// who can edit it can recompute the digest. That is acceptable because
    /// this is the operator's own record on the operator's own disk, and it is
    /// written down because a digest is easy to mistake for more than it is.
    pub fn load_ledger(&mut self, text: &str) -> Result<usize, String> {
        let doc = crate::json::Json::parse(text.trim()).ok_or("not JSON")?;
        let rows = match doc.get("shares") {
            Some(crate::json::Json::Arr(items)) => items,
            _ => return Err(String::from("no shares array")),
        };

        let mut restored: Vec<((String, String), Tally)> = Vec::new();
        let mut canon = String::new();
        for r in rows.iter() {
            let worker = r.get("worker").and_then(|x| x.as_str()).ok_or("row has no worker")?;
            let coin = r.get("coin").and_then(|x| x.as_str()).ok_or("row has no coin")?;
            let n = |k: &str| -> Result<u64, String> {
                match r.get(k).and_then(|x| x.as_i64()) {
                    // Negative is refused rather than clamped. A count below
                    // zero is a file that has been edited or corrupted, and
                    // saturating it to zero would load the damage silently.
                    Some(v) if v >= 0 => Ok(v as u64),
                    Some(v) => Err(format!("{k} is {v}")),
                    None => Err(format!("row has no {k}")),
                }
            };
            let t = Tally {
                accepted: n("accepted")?,
                stale: n("stale")?,
                bad: n("bad")?,
                duplicate: n("duplicate")?,
            };
            canon.push_str(&format!(
                "{worker}\t{coin}\t{}\t{}\t{}\t{}\n",
                t.accepted, t.stale, t.bad, t.duplicate
            ));
            restored.push(((String::from(worker), String::from(coin)), t));
        }

        // The rows are canonicalised the same way `ledger_json` does, so this
        // check is against the writer rather than against a second idea of what
        // the document says.
        let want = doc.get("digest").and_then(|x| x.as_str()).unwrap_or("");
        let got = crate::mine::stratum::hex(&crate::store::sha256::hash(canon.as_bytes()));
        if want != got {
            return Err(format!("digest {want} does not match the rows ({got})"));
        }

        let n = restored.len();
        for (k, v) in restored {
            self.tallies.insert(k, v);
        }
        Ok(n)
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

/// Set by `--bad-proof`. Off unless an operator deliberately asked for it.
///
/// A global rather than a field on `Pool`, because it is a testing switch and
/// not a property of a coin: threading it through every constructor would put a
/// "tell lies" argument in the signature of ordinary code.
static LIE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn lie_about_proofs() {
    LIE.store(true, core::sync::atomic::Ordering::Relaxed);
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
            share_bits: 8,
            share_target: target_with_leading_zeros(8),
            network_target: None,
            source: Source::Local,
            work: None,
            e2: 0,
        }])
    }

    /// The check the whole pool rests on: a share is credited only when the
    /// pool can reproduce the hash the miner claims to have found.
    #[test]
    fn a_real_share_is_accepted_and_a_forged_one_is_not() {
        let mut p = a_pool();
        let job = p.make_job(0, 8).unwrap();
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
                share_bits: 8,
                share_target: target_with_leading_zeros(8),
                network_target: None,
                source: Source::Local,
                work: None,
                e2: 0,
            },
            Coin {
                label: String::from("b"),
                algo: Algo::Blake2s,
                share_bits: 8,
                share_target: target_with_leading_zeros(8),
                network_target: None,
                source: Source::Local,
                work: None,
                e2: 0,
            },
        ]);
        let ja = p.make_job(0, 8).unwrap();
        let mut ha = Hasher::new(&ja.algo, &ja.header).unwrap();
        let n = (0..200_000u32)
            .find(|n| below_target(&ha.hash(&ja.header, *n), &ja.target))
            .expect("no sha256d share found");

        // Under blake2s the same header and nonce give a different digest, so
        // this nonce is almost certainly not a solution there.
        let jb = p.make_job(1, 8).unwrap();
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
        let job = p.make_job(0, 8).unwrap();
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
        let job2 = p.make_job(0, 8).unwrap();
        let mut h2 = Hasher::new(&job2.algo, &job2.header).unwrap();
        let n2 = (0..200_000u32)
            .find(|n| below_target(&h2.hash(&job2.header, *n), &job2.target))
            .expect("no second share found");
        p.submit("w2", &proto::Share { job: job2.job, nonce: n2, echo: vec![] });
        let c = p.ledger_json(1, 1_000);
        let dc = c.lines().find(|l| l.contains("digest")).unwrap();
        assert_ne!(da, dc, "a new share did not move the digest");
    }

    fn some_work() -> Work {
        Work {
            job_id: String::from("job1"),
            prev_wire: [0x11; 32],
            coinb1: vec![0x01, 0x00, 0x00, 0x00],
            coinb2: vec![0xff, 0xff, 0xff, 0xff],
            branch: vec![[0xaa; 32], [0xbb; 32]],
            version: 1,
            ntime: 0x4dd7_f5c7,
            nbits: 0x1a44_b9f2,
            extranonce1: vec![0xde, 0xad, 0xbe, 0xef],
            extranonce2_size: 4,
            up_target: target_with_leading_zeros(24),
        }
    }

    fn upstream_pool() -> Pool {
        Pool::new(vec![Coin {
            label: String::from("chain"),
            algo: Algo::Sha256d,
            share_bits: 8,
            share_target: target_with_leading_zeros(8),
            network_target: None,
            source: Source::Upstream {
                host: String::from("nowhere"),
                port: 1,
                user: String::from("w"),
                pass: String::from("x"),
            },
            work: None,
            e2: 0,
        }])
    }

    /// An upstream coin with no work must not invent a header.
    ///
    /// The alternative is a miner spending real time on a search that can never
    /// pay, which from the report looks exactly like a coin that is working.
    #[test]
    fn an_upstream_coin_with_no_work_yields_no_job() {
        let mut p = upstream_pool();
        assert!(p.make_job(0, 8).is_none());
        assert!(!p.has_work(0));
        p.set_work(0, some_work());
        assert!(p.has_work(0));
        assert!(p.make_job(0, 8).is_some());
    }

    /// Two jobs from one `mining.notify` must be two different searches.
    ///
    /// The extranonce2 is the only thing separating them, so a counter that
    /// failed to advance would hand two miners identical work and pay one of
    /// them for the other's -- with both looking busy while it happened.
    #[test]
    fn two_jobs_from_one_notify_use_different_extranonces() {
        let mut p = upstream_pool();
        p.set_work(0, some_work());
        let a = p.make_job(0, 8).unwrap();
        let b = p.make_job(0, 8).unwrap();
        assert_ne!(a.header, b.header, "same header means the same search");
        // And the difference is in the merkle root, since that is the only part
        // of the header an extranonce reaches. Everything else is upstream's,
        // so a job differing anywhere else would mean something was invented.
        assert_eq!(a.header[..36], b.header[..36]);
        assert_ne!(a.header[36..68], b.header[36..68]);
        assert_eq!(a.header[68..], b.header[68..]);
    }

    /// A job carries its own working, and the working checks out.
    ///
    /// This is the pool verifying itself with the *miner's* function --
    /// `proto::proves` is the same code the kernel runs -- so a header assembly
    /// that drifted from the proof beside it would fail here rather than in a
    /// miner's log a week later.
    #[test]
    fn an_upstream_job_proves_its_own_header() {
        let mut p = upstream_pool();
        p.set_work(0, some_work());
        let job = p.make_job(0, 8).unwrap();
        let proof = job.proof.expect("an upstream job carried no proof");
        assert!(
            proto::proves(&proof, &job.header),
            "the pool's own proof does not produce the header it sent"
        );

        // A coinbase changed by one byte must not. Otherwise the check passes
        // on anything and is worse than absent, because it looks like evidence.
        let bent = proto::Proof {
            coinb1: proof.coinb1.clone(),
            extranonce: proof.extranonce.clone(),
            coinb2: {
                let mut c = proof.coinb2.clone();
                c.push(0x00);
                c
            },
            branch: proof.branch.clone(),
        };
        assert!(!proto::proves(&bent, &job.header));

        // And so must a branch in the wrong order, which is the mistake that
        // produces thirty-two perfectly plausible bytes.
        if proof.branch.len() >= 2 {
            let mut rev = proof.branch.clone();
            rev.reverse();
            let flipped = proto::Proof {
                coinb1: proof.coinb1.clone(),
                extranonce: proof.extranonce.clone(),
                coinb2: proof.coinb2.clone(),
                branch: rev,
            };
            assert!(!proto::proves(&flipped, &job.header));
        }
    }

    /// A local coin sends no proof, because it has no chain to prove anything
    /// about. A proof that verified against an invented header would be worse
    /// than none: it would look like evidence.
    #[test]
    fn a_local_coin_offers_no_proof() {
        let mut p = a_pool();
        assert!(p.make_job(0, 8).unwrap().proof.is_none());
    }

    /// A share is forwarded only when it beats *upstream's* target, not ours.
    ///
    /// One number for both would either flood upstream with work it rejects or
    /// leave a miner silent for hours, which is why there are two.
    #[test]
    fn only_shares_beating_the_upstream_target_are_forwarded() {
        let mut p = upstream_pool();
        // Ours easy, upstream's hard enough that almost nothing passes it.
        p.set_work(
            0,
            Work {
                up_target: target_with_leading_zeros(28),
                ..some_work()
            },
        );
        let job = p.make_job(0, 8).unwrap();
        let mut h = Hasher::new(&job.algo, &job.header).unwrap();

        let mut accepted = 0;
        for n in 0..200_000u32 {
            if below_target(&h.hash(&job.header, n), &job.target)
                && p.submit(
                    "w",
                    &proto::Share {
                        job: job.job.clone(),
                        nonce: n,
                        echo: vec![],
                    },
                ) == Verdict::Accepted
            {
                accepted += 1;
            }
        }
        assert!(accepted > 0, "no share met even the easy target");
        let fwd = p.take_forwards();
        assert!(
            fwd.len() < accepted,
            "every accepted share was forwarded, so the two targets are not distinct"
        );
        // Whatever was forwarded carries exactly what a `mining.submit` needs.
        for f in &fwd {
            assert_eq!(f.job_id, "job1");
            assert_eq!(f.extranonce2.len(), 4);
            assert_eq!(f.ntime_be.len(), 4);
            assert_eq!(f.nonce_be.len(), 4);
        }
        // Draining is draining: a share is only worth anything on the
        // connection whose extranonce1 it was found under.
        assert!(p.take_forwards().is_empty());
    }

    /// A restart must not lose a miner's record.
    ///
    /// The write and the read are the same canonicalisation, so this is a
    /// check that they agree rather than a check that a file exists -- and a
    /// disagreement is exactly what a digest over the rows is for.
    #[test]
    fn a_ledger_survives_being_written_and_read_back() {
        let mut p = a_pool();
        let job = p.make_job(0, 8).unwrap();
        let mut h = Hasher::new(&job.algo, &job.header).unwrap();
        let n = (0..200_000u32)
            .find(|n| below_target(&h.hash(&job.header, *n), &job.target))
            .expect("no share found");
        p.submit(
            "w1",
            &proto::Share {
                job: job.job.clone(),
                nonce: n,
                echo: vec![],
            },
        );
        // A refusal too, so the row carries more than one non-zero field and a
        // reader that restored only `accepted` would be caught.
        p.submit(
            "w1",
            &proto::Share {
                job: String::from("ffffffff"),
                nonce: n,
                echo: vec![],
            },
        );
        let doc = p.ledger_json(1, 1_000);

        let mut fresh = Pool::new(vec![Coin {
            label: String::from("test"),
            algo: Algo::Sha256d,
            share_bits: 8,
            share_target: target_with_leading_zeros(8),
            network_target: None,
            source: Source::Local,
            work: None,
            e2: 0,
        }]);
        let rows = fresh.load_ledger(&doc).expect("a ledger we just wrote was refused");
        assert!(rows > 0);
        assert_eq!(fresh.ledger(), p.ledger(), "the record changed on the way back");
    }

    /// A damaged ledger is refused whole rather than loaded in part.
    ///
    /// Half a record is worse than none: the counts would be wrong in a way
    /// nothing downstream could detect, where an empty tally is at least
    /// obviously empty and is announced.
    #[test]
    fn a_tampered_ledger_is_refused() {
        let mut p = a_pool();
        let job = p.make_job(0, 8).unwrap();
        let mut h = Hasher::new(&job.algo, &job.header).unwrap();
        let n = (0..200_000u32)
            .find(|n| below_target(&h.hash(&job.header, *n), &job.target))
            .expect("no share found");
        p.submit(
            "w1",
            &proto::Share {
                job: job.job,
                nonce: n,
                echo: vec![],
            },
        );
        let doc = p.ledger_json(1, 1_000);

        // Somebody gives themselves credit without recomputing the digest,
        // which is the whole shape this check catches.
        let doctored = doc.replace("\"accepted\": 1", "\"accepted\": 9999");
        assert_ne!(doctored, doc, "the test did not actually change anything");

        let mut fresh = a_pool();
        let err = fresh
            .load_ledger(&doctored)
            .expect_err("an edited ledger was accepted");
        assert!(err.contains("digest"), "refused for the wrong reason: {err}");
        // And nothing was loaded from it.
        assert!(fresh.ledger().is_empty());

        // Truncation is the accidental version of the same thing.
        let cut = &doc[..doc.len() / 2];
        assert!(fresh.load_ledger(cut).is_err());
    }

    /// Two jobs must not be the same search. A fixed header would make every
    /// job identical, so a nonce found once is a share forever.
    #[test]
    fn two_jobs_are_two_different_searches() {
        let mut p = a_pool();
        let a = p.make_job(0, 8).unwrap();
        let b = p.make_job(0, 8).unwrap();
        assert_ne!(a.job, b.job);
        assert_ne!(a.header, b.header);
    }
}
