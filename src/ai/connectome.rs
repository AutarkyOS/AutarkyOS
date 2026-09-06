//! A whole animal's wiring, loaded and run.
//!
//! `design/connectome.md` argues why this is the honest form of "integrate a
//! brain": a human synaptic map does not exist to download, but *C. elegans*
//! is a complete one -- every neuron, every synapse, traced -- and it is small
//! enough to live in a kernel heap as an ordinary graph. `tools/connectome.py`
//! flattens the published edge list into the `GLADOSXN` file this module reads.
//!
//! ### What this is, and what it is not
//!
//! It is the real wiring diagram, loadable and queryable, plus a *toy*
//! dynamical system run over it. The simulator is not biophysics: neurons are
//! not integrate-and-fire, chemical synapses carry no sign (the dataset does
//! not record excitatory vs inhibitory, so all are taken excitatory, which is
//! stated rather than hidden), and a step is `x <- tanh(gain * W x / scale)` --
//! a graph evolved in time, the same shape the Oracle already runs over fitted
//! telemetry, not a claim about worm behaviour. It is a demo with a real
//! substrate, labelled as one.
//!
//! ### Kept away from anything that decides
//!
//! Nothing here touches routing, the council, or the model. It is loaded on
//! request, run on request, and read on request, at exactly the arm's length
//! the Oracle is held at -- for the same reason: a fitted or evolved system is
//! interesting to watch and must never be mistaken for a thing that judges.
//!
//! ### The loader walks and never seeks
//!
//! The `GLADOSXN` body has no internal offsets, so one wrong length turns
//! everything after it into valid-looking garbage -- the same bargain
//! `tools/v4.py` makes for checkpoints. So the reader bounds-checks every field
//! and asserts it lands on the last byte, and `tools/connectome.py`'s own
//! `--verify` reader is the deliberately-separate second implementation.

use crate::sync::Racy;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const MAGIC: &[u8; 8] = b"GLADOSXN";

/// One connection: a directed chemical synapse or a symmetric gap junction.
#[derive(Clone, Copy)]
pub struct Edge {
    pub src: u32,
    pub dst: u32,
    pub weight: u16,
    pub electrical: bool,
}

/// The wiring diagram: names in id order, and the edges over those ids.
pub struct Connectome {
    pub names: Vec<String>,
    pub edges: Vec<Edge>,
    /// Per-node incoming weight total (min 1), computed once so the step can
    /// normalise and a hub like AVAL does not saturate on the first tick.
    in_scale: Vec<f32>,
}

/// The loaded graph, and the current activation state of the simulator. Both
/// on demand, both `None`/empty until `connectome load`. Single-core interior
/// mutability, like every other resident-state global here.
static LOADED: Racy<Option<Connectome>> = Racy::new(None);
static STATE: Racy<Vec<f32>> = Racy::new(Vec::new());

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Parse a `GLADOSXN` blob into a graph, or say why it will not. Walks and
/// bounds-checks every field, and requires landing exactly on the last byte:
/// a body with no internal lengths cannot be trusted to a reader that seeks.
pub fn parse(b: &[u8]) -> Result<Connectome, &'static str> {
    if b.len() < 24 || &b[..8] != MAGIC {
        return Err("not a GLADOSXN file");
    }
    let version = rd_u32(b, 8).unwrap();
    if version != 1 {
        return Err("unsupported GLADOSXN version");
    }
    let n_nodes = rd_u32(b, 12).unwrap() as usize;
    let n_edges = rd_u32(b, 16).unwrap() as usize;
    // reserved at 20 is ignored by design.
    let mut off = 24;

    let mut names = Vec::with_capacity(n_nodes);
    for _ in 0..n_nodes {
        let len = *b.get(off).ok_or("names run past end")? as usize;
        off += 1;
        let raw = b.get(off..off + len).ok_or("a name runs past end")?;
        let name = core::str::from_utf8(raw).map_err(|_| "a name is not UTF-8")?;
        names.push(name.to_string());
        off += len;
    }

    let mut edges = Vec::with_capacity(n_edges);
    let mut in_w = alloc::vec![0u32; n_nodes];
    for _ in 0..n_edges {
        let src = rd_u32(b, off).ok_or("edges run past end")?;
        let dst = rd_u32(b, off + 4).ok_or("edges run past end")?;
        let weight = rd_u16(b, off + 8).ok_or("edges run past end")?;
        let kind = *b.get(off + 10).ok_or("edges run past end")?;
        off += 11;
        if src as usize >= n_nodes || dst as usize >= n_nodes {
            return Err("an edge names a node that does not exist");
        }
        let electrical = kind == 1;
        in_w[dst as usize] += weight as u32;
        // A gap junction is symmetric, so it is incoming weight at both ends.
        if electrical {
            in_w[src as usize] += weight as u32;
        }
        edges.push(Edge { src, dst, weight, electrical });
    }

    if off != b.len() {
        return Err("trailing bytes -- the file is not the shape it claims");
    }

    let in_scale = in_w.iter().map(|&w| (w as f32).max(1.0)).collect();
    Ok(Connectome { names, edges, in_scale })
}

impl Connectome {
    pub fn node_count(&self) -> usize {
        self.names.len()
    }
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// The id of a named neuron, case-sensitive (the dataset's names are). None
    /// if there is no such node.
    pub fn node_of(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| n == name)
    }

    /// Everything this node connects to, as (name, weight, electrical). Includes
    /// the far end of a gap junction in both directions, since it is symmetric.
    pub fn neighbours(&self, i: usize) -> Vec<(&str, u16, bool)> {
        let mut out = Vec::new();
        for e in self.edges.iter() {
            if e.src as usize == i {
                out.push((self.names[e.dst as usize].as_str(), e.weight, e.electrical));
            } else if e.electrical && e.dst as usize == i {
                out.push((self.names[e.src as usize].as_str(), e.weight, e.electrical));
            }
        }
        out
    }

    /// One time step of the toy dynamics, `next = tanh(gain * W x / in_scale)`.
    /// Chemical edges push src into dst; electrical edges push both ways. Pure
    /// and deterministic: same state in, same state out.
    pub fn step(&self, state: &[f32], gain: f32) -> Vec<f32> {
        let n = self.names.len();
        let mut acc = alloc::vec![0.0f32; n];
        for e in self.edges.iter() {
            let w = e.weight as f32;
            let (s, d) = (e.src as usize, e.dst as usize);
            acc[d] += w * state[s];
            if e.electrical {
                acc[s] += w * state[d];
            }
        }
        let mut next = alloc::vec![0.0f32; n];
        for i in 0..n {
            next[i] = tanh(gain * acc[i] / self.in_scale[i]);
        }
        next
    }
}

/// tanh without libm: a rational approximation good to ~1e-3 over the range the
/// step ever produces, which is all a demo needs. Clamped, so a large argument
/// saturates to +-1 rather than overflowing.
fn tanh(x: f32) -> f32 {
    if x > 8.0 {
        return 1.0;
    }
    if x < -8.0 {
        return -1.0;
    }
    let x2 = x * x;
    // Pade-style approximation; monotone and odd over [-8, 8].
    let num = x * (135135.0 + x2 * (17325.0 + x2 * (378.0 + x2)));
    let den = 135135.0 + x2 * (62370.0 + x2 * (3150.0 + x2 * 28.0));
    (num / den).clamp(-1.0, 1.0)
}

// --- the resident, on-demand graph and its state -------------------------

/// Load a graph from a blob, replacing any loaded one, and zero the state.
pub fn load(bytes: &[u8]) -> Result<(usize, usize), &'static str> {
    let c = parse(bytes)?;
    let (n, e) = (c.node_count(), c.edge_count());
    unsafe {
        *STATE.get() = alloc::vec![0.0f32; n];
        *LOADED.get() = Some(c);
    }
    Ok((n, e))
}

pub fn loaded() -> bool {
    unsafe { (*LOADED.get()).is_some() }
}

pub fn info() -> Option<(usize, usize, usize, usize)> {
    let c = unsafe { (*LOADED.get()).as_ref()? };
    let chem = c.edges.iter().filter(|e| !e.electrical).count();
    Some((c.node_count(), c.edge_count(), chem, c.edge_count() - chem))
}

/// Set a node's activation, by name. The way a stimulus enters the system.
pub fn stim(name: &str, v: f32) -> bool {
    let c = unsafe { (*LOADED.get()).as_ref() };
    let Some(c) = c else { return false };
    let Some(i) = c.node_of(name) else { return false };
    let st = unsafe { &mut *STATE.get() };
    if i < st.len() {
        st[i] = v.clamp(-1.0, 1.0);
        true
    } else {
        false
    }
}

/// Advance the simulator `n` steps. Returns how many nodes are active (|x| >
/// 0.01) afterwards, a one-number pulse of how far the stimulus spread.
pub fn advance(n: usize, gain: f32) -> Option<usize> {
    let c = unsafe { (*LOADED.get()).as_ref()? };
    let st = unsafe { &mut *STATE.get() };
    for _ in 0..n {
        let next = c.step(st, gain);
        *st = next;
    }
    Some(st.iter().filter(|&&v| v.abs() > 0.01).count())
}

/// The most-active nodes right now, as (name, activation), for display.
pub fn top(k: usize) -> Vec<(String, f32)> {
    let c = unsafe { (*LOADED.get()).as_ref() };
    let Some(c) = c else { return Vec::new() };
    let st = unsafe { &*STATE.get() };
    let mut idx: Vec<usize> = (0..st.len()).collect();
    idx.sort_by(|&a, &b| st[b].abs().partial_cmp(&st[a].abs()).unwrap_or(core::cmp::Ordering::Equal));
    idx.into_iter()
        .take(k)
        .filter(|&i| st[i].abs() > 0.001)
        .map(|i| (c.names[i].clone(), st[i]))
        .collect()
}

/// Neighbours of a named node, for the shell.
pub fn neighbours_of(name: &str) -> Option<Vec<(String, u16, bool)>> {
    let c = unsafe { (*LOADED.get()).as_ref()? };
    let i = c.node_of(name)?;
    Some(
        c.neighbours(i)
            .into_iter()
            .map(|(n, w, e)| (n.to_string(), w, e))
            .collect(),
    )
}

/// Reset the simulator to all-zero without reloading the graph.
pub fn reset() {
    let st = unsafe { &mut *STATE.get() };
    for v in st.iter_mut() {
        *v = 0.0;
    }
}

/// The loader's edges, the query, and the step, on a tiny hand-built graph so
/// the real file is not needed to check the machinery. Pure; no I/O.
pub fn selftest() -> bool {
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   connectome  {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    // Three nodes A,B,C (sorted, as the tool writes them). Edges: A->B chem w2,
    // B->C chem w1, A--C electrical w1.
    let mut b = Vec::new();
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.extend_from_slice(&3u32.to_le_bytes()); // nodes
    b.extend_from_slice(&3u32.to_le_bytes()); // edges
    b.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for name in ["A", "B", "C"] {
        b.push(name.len() as u8);
        b.extend_from_slice(name.as_bytes());
    }
    let edge = |b: &mut Vec<u8>, s: u32, d: u32, w: u16, k: u8| {
        b.extend_from_slice(&s.to_le_bytes());
        b.extend_from_slice(&d.to_le_bytes());
        b.extend_from_slice(&w.to_le_bytes());
        b.push(k);
    };
    edge(&mut b, 0, 1, 2, 0); // A->B chemical
    edge(&mut b, 1, 2, 1, 0); // B->C chemical
    edge(&mut b, 0, 2, 1, 1); // A--C electrical

    let c = match parse(&b) {
        Ok(c) => c,
        Err(_) => {
            check(false, "the tiny graph parses");
            return ok;
        }
    };
    check(c.node_count() == 3 && c.edge_count() == 3, "node and edge counts");
    check(c.node_of("B") == Some(1), "name lookup");
    check(c.node_of("Z").is_none(), "an absent name is None");

    // A's neighbours: B (chemical, out) and C (electrical, symmetric).
    let na = c.neighbours(0);
    check(na.iter().any(|&(n, _, e)| n == "B" && !e), "A -> B chemical");
    check(na.iter().any(|&(n, _, e)| n == "C" && e), "A -- C electrical");

    // Stimulate A, step once: B and C should become positive (excitatory).
    let mut st = alloc::vec![0.0f32; 3];
    st[0] = 1.0;
    let s1 = c.step(&st, 1.0);
    check(s1[1] > 0.0, "a step drives B from A");
    check(s1[2] > 0.0, "a step drives C from A (electrical + via nothing yet)");
    // Determinism: same state in, same out.
    let s1b = c.step(&st, 1.0);
    check(s1 == s1b, "the step is deterministic");

    // The loader rejects the malformed.
    check(parse(b"nope").is_err(), "bad magic refused");
    let mut trunc = b.clone();
    trunc.pop();
    check(parse(&trunc).is_err(), "a truncated file is refused, not half-read");
    let mut trailing = b.clone();
    trailing.push(0);
    check(parse(&trailing).is_err(), "trailing bytes are refused");
    // An edge naming a node past the end is caught.
    let mut bad = Vec::new();
    bad.extend_from_slice(MAGIC);
    bad.extend_from_slice(&1u32.to_le_bytes());
    bad.extend_from_slice(&1u32.to_le_bytes()); // 1 node
    bad.extend_from_slice(&1u32.to_le_bytes()); // 1 edge
    bad.extend_from_slice(&0u32.to_le_bytes());
    bad.push(1);
    bad.push(b'A');
    edge(&mut bad, 0, 9, 1, 0); // dst 9 does not exist
    check(parse(&bad).is_err(), "an edge to a nonexistent node is refused");

    ok
}
