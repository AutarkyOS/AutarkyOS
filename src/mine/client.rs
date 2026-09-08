//! The task that owns the pool connection.
//!
//! One task, one socket, and nothing else in the kernel ever touches that
//! handle. `mine off` sets an atomic and the task closes on its next wake;
//! closing it from the shell would put two tasks in the TCP state machine,
//! which is the thing `net`'s `StackGuard` and `tcp::at`'s masking exist to
//! prevent.
//!
//! ### Why the loop blocks rather than polls
//!
//! `tcp::service()` has one call site, the shell's idle loop, so the stack does
//! not advance while a command runs. But `tcp::wait_until` polls the NIC
//! sixteen times and runs `pump()` on every iteration, and `pump` services all
//! sixteen connection slots. **So a task blocked inside `recv_at` is driving
//! the whole stack**, and a task that polled `pending()` and yielded would
//! drive nothing and watch its own connection die.
//!
//! That is also why there is no `yield_now` here. `task::yield_now`'s own doc
//! records the hang that a hundred-times-a-second yield loop in `net::tcp`
//! caused, and `initiative` states the house rule. The waiting happens inside
//! `wait_until`'s `hlt`; the parked case is a plain spin that preemption shares
//! out.
//!
//! ### Waiting for a job and sending a share are the same wait
//!
//! There is one thread of control on the socket, so there is no conflict to
//! resolve, only a latency to bound. `RECV_MS` is that bound: a share found
//! while the task is blocked waits at most that long before the queue is
//! drained. Two hundred milliseconds against a share found once an hour is not
//! a trade worth widening `recv_at`'s signature for, and if it ever is, the
//! wake-predicate form is written up in the plan.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::net::tcp;
use crate::sync::{Racy, Spin};

use super::stratum::{self, Message};

/// How long a blocked read waits before the submit queue is drained.
const RECV_MS: u64 = 200;
/// How long to wait for the TCP handshake.
const CONNECT_MS: u64 = 8_000;
/// Reconnect backoff, doubling, in milliseconds.
const BACKOFF_MIN: u64 = 1_000;
const BACKOFF_MAX: u64 = 60_000;
/// Journal depth for `mine log`.
const JOURNAL: usize = 32;

/// Set by `mine on`, cleared by `mine off`. The task never exits.
pub static ENABLED: AtomicBool = AtomicBool::new(false);
/// Serial of the current template. Bumped on every job and on every
/// disconnection, so a hash loop can tell that its work is now worthless.
pub static JOB_SERIAL: AtomicU64 = AtomicU64::new(0);
/// Whether the handshake got all the way through.
pub static LIVE: AtomicBool = AtomicBool::new(false);
static SPAWNED: AtomicBool = AtomicBool::new(false);
static NEXT_ID: AtomicU64 = AtomicU64::new(3);
/// Share difficulty as the pool last set it, mantissa and scale.
static DIFF_M: AtomicU64 = AtomicU64::new(1);
static DIFF_S: AtomicU32 = AtomicU32::new(0);

/// Where to connect and as whom. Not the connection itself.
pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

pub static CONFIG: Spin<Option<Config>> = Spin::new(None);

/// The job in force, already reduced to what a hash loop needs.
pub struct Template {
    pub serial: u64,
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub header: [u8; 80],
    pub target: super::u256::U256,
}

pub static TEMPLATE: Spin<Option<Template>> = Spin::new(None);

/// Connection and share history, newest last.
static LOG: Racy<Vec<String>> = Racy::new(Vec::new());

pub fn note(s: &str) {
    let v = unsafe { &mut *LOG.get() };
    if v.len() == JOURNAL {
        v.remove(0);
    }
    v.push(String::from(s));
}

pub fn journal() -> Vec<String> {
    unsafe { &*LOG.get() }.clone()
}

pub fn difficulty() -> (u64, u32) {
    (DIFF_M.load(Ordering::Relaxed), DIFF_S.load(Ordering::Relaxed))
}

/// Where the session is. One enum so the report cannot invent a state.
#[derive(Clone, Copy, PartialEq)]
pub enum Phase {
    Off,
    Resolving,
    Connecting,
    Subscribed,
    Authorized,
    Live,
}

static PHASE: Racy<Phase> = Racy::new(Phase::Off);

pub fn phase() -> Phase {
    unsafe { *PHASE.get() }
}

fn set_phase(p: Phase) {
    unsafe { *PHASE.get() = p };
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Off => "off",
            Phase::Resolving => "resolving",
            Phase::Connecting => "connecting",
            Phase::Subscribed => "subscribed",
            Phase::Authorized => "authorized",
            Phase::Live => "live",
        }
    }
}

/// Start the connection task, once. A second `mine on` re-arms the atomic
/// rather than spawning again: `MAX_TASKS` is 24, slots are never reclaimed,
/// and on the GF63 most of them are already spoken for by idle tasks.
pub fn start() -> Result<(), &'static str> {
    if CONFIG.lock_irq().is_none() {
        return Err("no pool set -- try `mine pool <host:port>` first");
    }
    ENABLED.store(true, Ordering::Release);
    if SPAWNED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    match crate::task::spawn("stratum", stratum_task) {
        Some(_) => Ok(()),
        None => {
            SPAWNED.store(false, Ordering::Release);
            ENABLED.store(false, Ordering::Release);
            Err("no task slot free")
        }
    }
}

pub fn stop() {
    ENABLED.store(false, Ordering::Release);
}

/// A short spin, for the parked case. Not `yield_now`: see the module header.
fn idle() {
    for _ in 0..2000 {
        core::hint::spin_loop();
    }
}

/// Milliseconds since boot, off the TSC.
///
/// **Never `lapic::ticks()`.** That counter is the timer-interrupt count and
/// only the bootstrap processor advances it now, but the whole class of bug is
/// worth staying away from in code whose entire output is a rate.
fn now_ms() -> u64 {
    let mhz = crate::time::tsc_mhz();
    if mhz == 0 {
        return 0;
    }
    crate::time::rdtsc() / (mhz * 1000)
}

fn sleep_ms(ms: u64) {
    let deadline = now_ms() + ms;
    while now_ms() < deadline && ENABLED.load(Ordering::Acquire) {
        idle();
    }
}

struct Session {
    h: tcp::Handle,
    buf: Vec<u8>,
    e1: Vec<u8>,
    e2_size: usize,
    /// The job as the pool last described it, before a template is built.
    job: Option<stratum::Job>,
    /// Counter feeding extranonce2.
    e2: u64,
}

fn stratum_task() {
    let mut backoff = BACKOFF_MIN;
    loop {
        if !ENABLED.load(Ordering::Acquire) {
            if phase() != Phase::Off {
                set_phase(Phase::Off);
                LIVE.store(false, Ordering::Release);
                JOB_SERIAL.fetch_add(1, Ordering::AcqRel);
                *TEMPLATE.lock_irq() = None;
                note("disconnected on request");
            }
            idle();
            continue;
        }
        match connect() {
            Some(mut s) => {
                backoff = BACKOFF_MIN;
                run(&mut s);
                tcp::abort_at(s.h);
            }
            None => {
                sleep_ms(backoff);
                backoff = core::cmp::min(backoff * 2, BACKOFF_MAX);
            }
        }
        LIVE.store(false, Ordering::Release);
        // A share found against the old connection cannot be submitted on the
        // next one: `extranonce1` is per-connection, so the work is not merely
        // stale, it is unsubmittable.
        JOB_SERIAL.fetch_add(1, Ordering::AcqRel);
        *TEMPLATE.lock_irq() = None;
        if ENABLED.load(Ordering::Acquire) {
            set_phase(Phase::Connecting);
        }
    }
}

/// Resolve, connect, subscribe, authorize. `None` on any refusal.
fn connect() -> Option<Session> {
    let (host, port, user, pass) = {
        let g = CONFIG.lock_irq();
        let c = g.as_ref()?;
        (c.host.clone(), c.port, c.user.clone(), c.pass.clone())
    };

    set_phase(Phase::Resolving);
    let ip = match crate::net::dns::lookup(&host) {
        Ok(ip) => ip,
        Err(_) => {
            note("could not resolve the pool host");
            return None;
        }
    };

    set_phase(Phase::Connecting);
    let h = match tcp::open(ip, port, CONNECT_MS) {
        Ok(h) => h,
        Err(_) => {
            note("connection refused or timed out");
            return None;
        }
    };
    let mut s = Session {
        h,
        buf: Vec::new(),
        e1: Vec::new(),
        e2_size: 4,
        job: None,
        e2: 0,
    };

    if tcp::send_at(s.h, stratum::subscribe(1).as_bytes(), 5_000).is_err() {
        tcp::abort_at(s.h);
        return None;
    }
    if !await_id(&mut s, 1, |s, body| match stratum::subscribe_result(body) {
        Some((e1, size)) => {
            s.e1 = e1;
            s.e2_size = size;
            true
        }
        None => false,
    }) {
        note("the pool's subscribe reply could not be read");
        tcp::abort_at(s.h);
        return None;
    }
    set_phase(Phase::Subscribed);

    if tcp::send_at(s.h, stratum::authorize(2, &user, &pass).as_bytes(), 5_000).is_err() {
        tcp::abort_at(s.h);
        return None;
    }
    if !await_id(&mut s, 2, |_, _| true) {
        note("the pool refused this worker");
        tcp::abort_at(s.h);
        return None;
    }
    set_phase(Phase::Authorized);
    note("subscribed and authorized");
    Some(s)
}

/// Read until the response with `id` arrives, handling notifications on the way.
///
/// The notifications are not a distraction to be skipped: a pool sends
/// `set_difficulty` and the first `notify` *before* it answers the authorize on
/// several implementations, so a reader that discarded anything that was not
/// the awaited id would throw away the first job of every session.
fn await_id(
    s: &mut Session,
    id: u64,
    mut on_ok: impl FnMut(&mut Session, &crate::json::Json) -> bool,
) -> bool {
    let deadline = now_ms() + 15_000;
    while now_ms() < deadline {
        if !ENABLED.load(Ordering::Acquire) {
            return false;
        }
        if !fill(s) {
            return false;
        }
        loop {
            match stratum::take_line(&mut s.buf) {
                Ok(Some(line)) => match stratum::classify(&line) {
                    Ok(Message::Response { id: got, ok, body }) if got == id => {
                        return ok && on_ok(s, &body);
                    }
                    Ok(Message::Notify { method, params }) => handle_notify(s, &method, &params),
                    // Somebody else's id, or a line we cannot read. Neither is
                    // fatal: pools send things this client does not implement.
                    Ok(_) => {}
                    Err(_) => {}
                },
                Ok(None) => break,
                Err(_) => return false,
            }
        }
    }
    false
}

/// One blocking read. `false` when the peer has gone.
///
/// `recv_at` answers an empty vector for both a timeout and end of file, and
/// its own doc says so -- a handle has no `LAST_DATA` cushion to tell them
/// apart. So `alive` is asked every time round, or a dead pool reads as a quiet
/// one forever and the miner keeps hashing a job it can never submit.
fn fill(s: &mut Session) -> bool {
    let data = tcp::recv_at(s.h, RECV_MS);
    if data.is_empty() && !tcp::alive(s.h) {
        note("the pool closed the connection");
        return false;
    }
    s.buf.extend_from_slice(&data);
    true
}

fn run(s: &mut Session) {
    set_phase(Phase::Live);
    LIVE.store(true, Ordering::Release);
    while ENABLED.load(Ordering::Acquire) {
        if !fill(s) {
            return;
        }
        loop {
            match stratum::take_line(&mut s.buf) {
                Ok(Some(line)) => match stratum::classify(&line) {
                    Ok(Message::Notify { method, params }) => handle_notify(s, &method, &params),
                    Ok(Message::Response { .. }) => {}
                    Err(_) => {}
                },
                Ok(None) => break,
                Err(_) => {
                    note("the pool sent a line too long to be a message");
                    return;
                }
            }
        }
    }
}

fn handle_notify(s: &mut Session, method: &str, params: &crate::json::Json) {
    match method {
        "mining.set_difficulty" => {
            let Some(first) = params.idx(0) else { return };
            // The raw token, not `as_i64`. See `stratum::decimal`.
            let text = match first {
                crate::json::Json::Num(t) => t.as_str(),
                _ => return,
            };
            if let Some((m, sc)) = stratum::decimal(text) {
                DIFF_M.store(m, Ordering::Relaxed);
                DIFF_S.store(sc, Ordering::Relaxed);
                rebuild(s);
            }
        }
        "mining.notify" => {
            if let Some(job) = stratum::parse_job(params) {
                s.job = Some(job);
                s.e2 = s.e2.wrapping_add(1);
                rebuild(s);
            }
        }
        "mining.set_extranonce" => {
            // Some altcoin pools rotate this. A client that ignored it would
            // submit into a stale extranonce space and have every share
            // rejected with nothing in the message saying why.
            let Some(e1) = params.idx(0).and_then(|j| j.as_str()) else { return };
            let Some(bytes) = stratum::unhex(e1) else { return };
            s.e1 = bytes;
            if let Some(size) = params.idx(1).and_then(|j| j.as_i64()) {
                if (0..=64).contains(&size) {
                    s.e2_size = size as usize;
                }
            }
            rebuild(s);
        }
        "client.reconnect" => {
            // Refused rather than followed. Redirecting to an address no human
            // typed is not something this kernel should do quietly.
            note("the pool asked us to reconnect elsewhere; refused");
        }
        _ => {}
    }
}

/// Turn the current job, extranonce and difficulty into something hashable.
fn rebuild(s: &mut Session) {
    let Some(job) = s.job.as_ref() else { return };
    let (m, sc) = difficulty();
    let Some(target) = super::u256::target_for(m, sc) else { return };

    let mut e2 = Vec::with_capacity(s.e2_size);
    // Big-endian, so a hex dump reads in order. Which encoding does not matter
    // for validity; what matters is that the same bytes reach the coinbase and
    // the submit, which is why they are stored rather than formatted twice.
    for i in (0..s.e2_size).rev() {
        e2.push((s.e2 >> (8 * (i % 8))) as u8);
    }
    let coinbase = super::header::coinbase(&job.coinb1, &s.e1, &e2, &job.coinb2);
    let root = super::header::merkle_root(&coinbase, &job.branch);
    let header = super::header::assemble(
        job.version,
        &job.prev_wire,
        &root,
        job.ntime,
        job.nbits,
        0,
    );
    let serial = JOB_SERIAL.fetch_add(1, Ordering::AcqRel) + 1;
    *TEMPLATE.lock_irq() = Some(Template {
        serial,
        job_id: job.id.clone(),
        extranonce2: e2,
        header,
        target,
    });
}

pub fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}
