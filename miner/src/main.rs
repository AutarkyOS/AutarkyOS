//! A miner that speaks the pool's protocol and hashes on whatever is fastest.
//!
//! ```text
//! glados-miner --pool HOST:PORT --worker NAME [--xpu PATH] [--cpu]
//! ```
//!
//! The point of this program is that the pool has never had a second kind of
//! device on it. `design/pool.md`'s whole Part B claim is that the pool is
//! device-agnostic -- VarDiff per (connection, coin), a ledger denominated in
//! work rather than share count, the algorithm on the wire -- and all of that
//! was built and tested against one miner: the kernel, at a few hundred
//! kilohashes. A GPU at two-thirds of a gigahash is three and a half orders of
//! magnitude away, which is the honest test of every one of those decisions.
//!
//! ### The protocol is not implemented here
//!
//! It comes from `glados_pool::mine::proto`, which is the kernel's own
//! `src/mine/proto.rs` reached by `#[path]`. So the kernel, the pool and this
//! miner encode a share with one function. A protocol is where a second
//! implementation costs most and shows least -- a field read differently at
//! each end is a share rejected for a reason neither side can name -- and
//! `tools/poolclient.py` is the deliberate exception that exists to catch
//! exactly that, having already caught one byte-order bug by being separate.
//!
//! ### The GPU is a subprocess, not a linked library
//!
//! `cuda/xpu.cu` is built by `nvcc` and driven over a pipe. Linking it would
//! mean a `build.rs` that shells out to `nvcc`, a static library, and the CUDA
//! runtime dragged into this crate's link line -- a build with three ways to
//! silently produce yesterday's binary, on a project that has been bitten by
//! exactly that three times in one session. A pipe has one.
//!
//! It also means this program builds and runs with no CUDA toolkit at all,
//! which is what `--cpu` is for and what lets CI exercise everything except
//! the kernel launch itself.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use glados_pool::json::Json;
use glados_pool::mine::algo::{Algo, Hasher};
use glados_pool::mine::hash::below_target;
use glados_pool::mine::proto;
use glados_pool::mine::stratum::{hex, take_line};
use glados_pool::mine::u256::U256;

/// How many nonces to ask for in one go.
///
/// **Measured, because the first guess cost a third of the card.** A scan is
/// synchronous -- the GPU sits idle while the reply crosses the pipe and this
/// program decides what to do -- so too small a batch spends its life in that
/// gap, and `design/xpu.md` records the other half: a kernel that runs for
/// tens of milliseconds never leaves the idle clock at all.
///
/// On the RTX 3050, through the pool, with the pool on the same host:
///
///     32M    292.7 MH/s
///     128M   377.7 MH/s
///     512M   424.4 MH/s
///
/// 128M is the default rather than 512M because the loop only reads the socket
/// between scans, so the batch is also how late a new job can be noticed --
/// about a third of a second here against one and a quarter. Work done on a
/// job the chain has moved past is worth nothing, and the trade stops being
/// worth it well before the last twelve percent.
///
/// None of these reach the 0.645 GH/s that file measured, and the reason is in
/// it: that figure needs an idle host, and here the pool is running beside the
/// miner on the same machine.
const GPU_BATCH: u32 = 128_000_000;
/// The same in the terms a single host core can manage.
const CPU_BATCH: u32 = 500_000;

/// What actually computes hashes.
trait Backend {
    fn name(&self) -> &str;
    /// Install a job. `false` if this backend cannot compute that algorithm.
    fn set_job(&mut self, algo: &Algo, header: &[u8; 80], target: &U256) -> bool;
    /// Scan `count` nonces from `base`. Answers a nonce **in protocol order**.
    fn scan(&mut self, base: u32, count: u32) -> Option<u32>;
    fn batch(&self) -> u32;
}

// ------------------------------------------------------------------ the GPU

struct Xpu {
    batch: u32,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Xpu {
    fn start(path: &str) -> Result<Xpu, String> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{path}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let mut stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        let mut greeting = String::new();
        stdout
            .read_line(&mut greeting)
            .map_err(|e| format!("{path}: {e}"))?;
        if greeting.trim() != "ready" {
            return Err(format!("{path} said {:?} rather than ready", greeting.trim()));
        }
        Ok(Xpu { batch: GPU_BATCH, child, stdin, stdout })
    }

    fn ask(&mut self, line: &str) -> Result<String, String> {
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;
        let mut reply = String::new();
        self.stdout
            .read_line(&mut reply)
            .map_err(|e| format!("read: {e}"))?;
        Ok(reply.trim().to_string())
    }
}

impl Drop for Xpu {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"quit\n");
        let _ = self.child.wait();
    }
}

impl Backend for Xpu {
    fn name(&self) -> &str {
        "gpu"
    }

    fn set_job(&mut self, algo: &Algo, header: &[u8; 80], target: &U256) -> bool {
        // **sha256d only, and the refusal is the point.** `blake2s.cuh` is fast
        // and hashes a single 64-byte block, which is not what a blake2s chain
        // computes over an 80-byte header. Accepting that job would produce
        // wrong shares at half a gigahash a second, and a fast wrong hash is
        // indistinguishable from a fast right one from the inside.
        if !matches!(algo, Algo::Sha256d) {
            return false;
        }
        let line = format!("job {} {}\n", hex(header), hex(&target.to_be_bytes()));
        match self.ask(&line) {
            Ok(r) if r == "ok" => true,
            Ok(r) => {
                eprintln!("[gpu] refused a job: {r}");
                false
            }
            Err(e) => {
                eprintln!("[gpu] {e}");
                false
            }
        }
    }

    fn scan(&mut self, base: u32, count: u32) -> Option<u32> {
        // **The nonce changes meaning across this pipe, and getting it wrong is
        // a silently rejected share.** A header stores its nonce
        // little-endian, so the value the protocol carries and the value the
        // CUDA kernel indexes by are byte-swapped views of the same four bytes.
        //
        // Pinned by the strongest vector available: given block 125552's
        // header, the GPU answers `42a14695`, and that block's nonce is
        // `0x9546a142`.
        let line = format!("scan {:08x} {}\n", base.swap_bytes(), count);
        match self.ask(&line) {
            Ok(r) if r.starts_with("found ") => u32::from_str_radix(r[6..].trim(), 16)
                .ok()
                .map(|w| w.swap_bytes()),
            Ok(r) if r.starts_with("none") => None,
            Ok(r) => {
                eprintln!("[gpu] {r}");
                None
            }
            Err(e) => {
                eprintln!("[gpu] {e}");
                None
            }
        }
    }

    fn batch(&self) -> u32 {
        self.batch
    }
}

// ------------------------------------------------------------------ the CPU

/// One host core, using the kernel's own `Hasher`.
///
/// Not a fallback so much as the control: it computes every algorithm the
/// kernel does, so a job the GPU refuses is still worked, and a disagreement
/// between the two is visible on one machine.
struct Cpu {
    hasher: Option<Hasher>,
    header: [u8; 80],
    target: U256,
}

impl Backend for Cpu {
    fn name(&self) -> &str {
        "cpu"
    }

    fn set_job(&mut self, algo: &Algo, header: &[u8; 80], target: &U256) -> bool {
        match Hasher::new(algo, header) {
            Some(h) => {
                self.hasher = Some(h);
                self.header = *header;
                self.target = *target;
                true
            }
            None => false,
        }
    }

    fn scan(&mut self, base: u32, count: u32) -> Option<u32> {
        let h = self.hasher.as_mut()?;
        for i in 0..count {
            let n = base.wrapping_add(i);
            if below_target(&h.hash(&self.header, n), &self.target) {
                return Some(n);
            }
        }
        None
    }

    fn batch(&self) -> u32 {
        CPU_BATCH
    }
}

// ----------------------------------------------------------------- the loop

struct Job {
    slot: u32,
    id: String,
    coin: String,
    algo: Algo,
    header: [u8; 80],
    target: U256,
    echo: proto::Echo,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut pool = String::from("127.0.0.1:3334");
    let mut worker = String::from("glados-miner");
    let mut xpu_path = String::from("../cuda/xpu.exe");
    let mut force_cpu = false;
    let mut batch: Option<u32> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pool" => pool = it.next().cloned().unwrap_or(pool),
            "--worker" => worker = it.next().cloned().unwrap_or(worker),
            "--xpu" => xpu_path = it.next().cloned().unwrap_or(xpu_path),
            "--cpu" => force_cpu = true,
            "--batch" => batch = it.next().and_then(|v| v.parse().ok()),
            "-h" | "--help" => {
                println!("glados-miner --pool HOST:PORT --worker NAME [--xpu PATH] [--cpu] [--batch N]");
                return;
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let mut backend: Box<dyn Backend> = if force_cpu {
        Box::new(Cpu { hasher: None, header: [0u8; 80], target: U256::ZERO })
    } else {
        match Xpu::start(&xpu_path) {
            Ok(mut x) => {
                if let Some(b) = batch {
                    x.batch = b;
                }
                println!("[miner] gpu ready via {xpu_path}, {} nonces a scan", x.batch);
                Box::new(x)
            }
            Err(e) => {
                // Said out loud and then carried on. A miner that silently fell
                // back to one core would report a rate three orders of
                // magnitude below what was expected and look like a broken GPU
                // rather than an absent one.
                eprintln!("[miner] no gpu ({e}); hashing on this core instead");
                Box::new(Cpu { hasher: None, header: [0u8; 80], target: U256::ZERO })
            }
        }
    };

    if let Err(e) = run(&pool, &worker, backend.as_mut()) {
        eprintln!("[miner] {e}");
        std::process::exit(1);
    }
}

fn run(pool: &str, worker: &str, backend: &mut dyn Backend) -> Result<(), String> {
    let mut sock = TcpStream::connect(pool).map_err(|e| format!("{pool}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| format!("{e}"))?;
    sock.write_all(
        proto::encode_hello(1, worker, concat!("glados-miner/", env!("CARGO_PKG_VERSION")))
            .as_bytes(),
    )
    .map_err(|e| format!("hello: {e}"))?;
    println!("[miner] {worker} -> {pool}, hashing on the {}", backend.name());

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16384];
    // Indexed by the pool's slot number, so a device that can work one coin
    // and not another keeps the one it can.
    let mut jobs: Vec<Option<Job>> = Vec::new();
    let mut refused: Vec<bool> = Vec::new();
    let mut installed = String::new();
    let mut nonce: u32 = 0;
    let mut hashes: u64 = 0;
    let mut found = 0u64;
    let mut accepted = 0u64;
    let mut since = Instant::now();
    let mut next_id = 2u64;

    loop {
        match sock.read(&mut chunk) {
            Ok(0) => return Err(String::from("the pool closed the connection")),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("read: {e}")),
        }

        while let Ok(Some(line)) = take_line(&mut buf) {
            let Some(v) = Json::parse(line.trim()) else { continue };
            if v.get("method").and_then(|m| m.as_str()) == Some("glados.job") {
                let Some(p) = v.get("params").and_then(proto::parse_job) else {
                    continue;
                };
                // The proof is checked when one is offered, exactly as the
                // kernel does it -- `proves` is the same function. A pool that
                // misrepresents what it pays should not get this device's
                // hashes any more than it gets the kernel's.
                if let Some(pr) = &p.proof {
                    if !proto::proves(pr, &p.header) {
                        eprintln!("[miner] a job's proof does not match its header; refused");
                        continue;
                    }
                }
                let slot = p.slot as usize;
                let j = Job {
                    slot: p.slot,
                    id: p.job,
                    coin: p.coin,
                    algo: p.algo,
                    header: p.header,
                    target: p.target,
                    echo: p.echo,
                };
                if jobs.len() <= slot {
                    jobs.resize_with(slot + 1, || None);
                    refused.resize(slot + 1, false);
                }
                // A slot that was refused before is retried when its *algorithm*
                // changes, and not otherwise. Retrying every job would mean a
                // pipe round trip per refusal on a pool serving coins this
                // device cannot work, which on a busy table is most of them.
                if jobs[slot].as_ref().map(|o: &Job| o.algo != j.algo).unwrap_or(true) {
                    refused[slot] = false;
                }
                jobs[slot] = Some(j);
            } else if let Some(r) = v.get("result") {
                if r.get("slots").is_some() {
                    println!("[miner] welcomed");
                } else if let Some(verdict) = r.get("verdict").and_then(|x| x.as_str()) {
                    if r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
                        accepted += 1;
                    }
                    println!("[miner] share {verdict}");
                }
            }
        }

        // **Work the best job this device can, and keep it.**
        //
        // This held one job and dropped it the moment an unusable one arrived,
        // which on a pool serving several coins is a device that stops. It was
        // not subtle when measured: with sha256d and yespower on one pool, the
        // GPU went from 377 MH/s to 4.2, because every yespower job it could
        // not compute threw away the sha256d job it was working. Jobs are per
        // slot now and a refusal marks that slot rather than clearing
        // everything.
        let pick = jobs
            .iter()
            .enumerate()
            .find(|(i, j)| j.is_some() && !refused[*i])
            .map(|(i, _)| i);
        let Some(slot) = pick else { continue };
        let j = jobs[slot].as_ref().unwrap();

        if installed != j.id {
            if !backend.set_job(&j.algo, &j.header, &j.target) {
                // Not fatal, and the ordinary case for a single-algorithm
                // device on a multi-algorithm pool. The slot is marked and the
                // loop moves to whatever else is on offer.
                if !refused[slot] {
                    println!(
                        "[miner] the {} cannot compute {} for {}; leaving that coin alone",
                        backend.name(),
                        j.algo.name(),
                        j.coin
                    );
                }
                refused[slot] = true;
                continue;
            }
            installed = j.id.clone();
            nonce = 0;
            println!(
                "[miner] job {} on {} ({}), slot {}",
                j.id,
                j.coin,
                j.algo.name(),
                j.slot
            );
        }

        let count = backend.batch();
        let hit = backend.scan(nonce, count);
        nonce = nonce.wrapping_add(count);
        hashes += count as u64;

        if let Some(n) = hit {
            found += 1;
            let share = proto::Share {
                job: j.id.clone(),
                nonce: n,
                echo: j.echo.clone(),
            };
            sock.write_all(proto::encode_submit(next_id, &share).as_bytes())
                .map_err(|e| format!("submit: {e}"))?;
            next_id += 1;
            // Step past it, or the next scan finds the same nonce again and
            // the pool answers `duplicate` forever.
            nonce = n.wrapping_add(1);
        }

        if since.elapsed() >= Duration::from_secs(10) {
            let secs = since.elapsed().as_secs_f64();
            println!(
                "[miner] {:.3} MH/s over {} hashes, {} found, {} accepted",
                hashes as f64 / secs / 1e6,
                hashes,
                found,
                accepted
            );
            hashes = 0;
            since = Instant::now();
        }
    }
}
