//! The forest: hierarchical knowledge, read one branch at a time.
//!
//! A tree is a school of thought, branching into specialisations. The point is
//! that a model never loads the whole thing -- it routes to a branch and takes
//! what fits in a budget. This module is the read side of that: what is here,
//! what it costs, and one node at a time.
//!
//! **A node is a head line and a body.** The head is `subject | concept |
//! terms` and is the whole of what an index would hold; the body carries the
//! concept, a method, machine-checkable steps and the original passage. The
//! head is first *so that a reader wanting only the index stops after one
//! line*, which is the property the whole retrieval design rests on.
//!
//! The format is line oriented, `key<space>value`, and a line whose first word
//! is not a key continues the field before it. That is why a body may contain
//! brackets, equals signs and blank lines with no escaping at all, and it is
//! `tools/forest.py` that writes it.
//!
//! ### Never `content_hash`, and that is not a preference
//!
//! `tree::content_hash` is a full recursive walk that SHA-256s every blob, and
//! `cmd_ls` calls it **per child** (`sysbox/mod.rs:1189`). So `ls` on a forest
//! directory hashes the entire forest, and `stat` and `du` walk it twice. This
//! module uses `children` and `blob_len` only, which are a `String` clone per
//! entry and a length read. Anything added here that reaches for a hash has
//! turned a listing into a full corpus rehash, and the only symptom is that
//! the machine appears to stop.
//!
//! ### Where it lives, and why not `/ai/forest`
//!
//! `/pkg/forest`, because a forest arrives as a `GLADOSPK` package and that is
//! where `pkg::install` puts packages (`pkg.rs:52`). A package already grafts
//! nested paths with `..` and absolute paths refused (`pkg.rs:133-135`), which
//! is exactly the property a corpus import needs, so there is no second import
//! path here and there should not be one.

use alloc::string::String;
use alloc::vec::Vec;

use crate::kprintln;
use crate::sysbox;

/// Where `pkg add` leaves a package named `forest`.
pub const ROOT: &str = "/pkg/forest";

/// Longest head line rendered by `forest tree`. Heads are one line by
/// construction; this bounds a malformed one rather than trusting the writer.
const HEAD_CLIP: usize = 100;

pub struct Census {
    pub trees: usize,
    pub branches: usize,
    pub nodes: usize,
    pub bytes: usize,
    /// Widest directory found. Watched because `tree::put` inserts at a sorted
    /// index and `ls` hashes per child, so width is punished twice where depth
    /// is free to 32 levels.
    pub widest: usize,
    pub deepest: usize,
}

/// Is this path a node rather than a branch?
///
/// Asked with `blob_len`, which answers `None` for a directory as well as for
/// a missing path -- deliberately, per its own doc. That conflation is fine
/// here because the walk already knows the path exists.
fn is_node(path: &str) -> Option<usize> {
    sysbox::blob_len(path)
}

fn walk(path: &str, depth: usize, c: &mut Census) {
    let kids = sysbox::children(path);
    if kids.is_empty() {
        return;
    }
    if kids.len() > c.widest {
        c.widest = kids.len();
    }
    if depth > c.deepest {
        c.deepest = depth;
    }
    let mut had_node = false;
    for name in kids {
        let mut sub = String::from(path);
        sub.push('/');
        sub.push_str(&name);
        match is_node(&sub) {
            Some(n) => {
                c.nodes += 1;
                c.bytes += n;
                had_node = true;
            }
            None => walk(&sub, depth + 1, c),
        }
    }
    if had_node {
        c.branches += 1;
    }
}

/// Census any root, so the claims below can measure a forest they built
/// themselves rather than whatever happens to be installed.
pub fn census_at(root: &str) -> Census {
    let mut c = Census {
        trees: 0,
        branches: 0,
        nodes: 0,
        bytes: 0,
        widest: 0,
        deepest: 0,
    };
    for t in trees_at(root) {
        c.trees += 1;
        let mut p = String::from(root);
        p.push('/');
        p.push_str(&t);
        walk(&p, 1, &mut c);
    }
    c
}

pub fn census() -> Census {
    census_at(ROOT)
}

pub fn trees_at(root: &str) -> Vec<String> {
    sysbox::children(root)
        .into_iter()
        .filter(|n| {
            let mut p = String::from(root);
            p.push('/');
            p.push_str(n);
            // A receipt is a blob beside the trees; a tree is a directory.
            sysbox::blob_len(&p).is_none()
        })
        .collect()
}

pub fn trees() -> Vec<String> {
    trees_at(ROOT)
}

/// The first line of a node, which is the whole of what an index holds.
///
/// This still reads the whole blob, because `sysbox::read_blob` clones and
/// there is no ranged read at the namespace layer -- `cas::read_blocks` exists
/// and is not wired through (`store/cas.rs:285`). Wiring it is what makes an
/// index affordable over a forest that does not fit in memory, and it is the
/// first thing to change when one does not.
pub fn head_of(path: &str) -> Option<String> {
    let b = sysbox::read_blob(path)?;
    let text = String::from_utf8(b).ok()?;
    let first = text.lines().next()?;
    let rest = first.strip_prefix("head ").unwrap_or(first);
    Some(String::from(rest))
}

pub fn report() {
    let c = census();
    if c.nodes == 0 {
        kprintln!("  no forest at {} -- 'pkg add' a forest package first", ROOT);
        return;
    }
    kprintln!("  {} tree(s), {} branch(es), {} node(s)", c.trees, c.branches, c.nodes);
    for t in trees() {
        let mut p = String::from(ROOT);
        p.push('/');
        p.push_str(&t);
        let mut sub = Census { trees: 0, branches: 0, nodes: 0, bytes: 0, widest: 0, deepest: 0 };
        walk(&p, 1, &mut sub);
        kprintln!("  {:<24} {:>6} node(s)  {:>9} B", t, sub.nodes, sub.bytes);
    }
}

pub fn report_tree(name: &str) {
    let mut p = String::from(ROOT);
    p.push('/');
    p.push_str(name);
    if sysbox::children(&p).is_empty() {
        kprintln!("  no tree '{}' -- 'forest' lists them", name);
        return;
    }
    let mut stack = alloc::vec![(p, 1usize)];
    let mut shown = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let kids = sysbox::children(&dir);
        let mut nodes = 0usize;
        let mut subdirs: Vec<String> = Vec::new();
        for k in kids {
            let mut sub = dir.clone();
            sub.push('/');
            sub.push_str(&k);
            if is_node(&sub).is_some() {
                nodes += 1;
            } else {
                subdirs.push(sub);
            }
        }
        if nodes > 0 {
            let short = dir.strip_prefix(ROOT).unwrap_or(&dir);
            kprintln!("  {:<44} {:>5} node(s)", short, nodes);
            shown += nodes;
        }
        // Reversed, so popping walks the branches in name order.
        for s in subdirs.into_iter().rev() {
            stack.push((s, depth + 1));
        }
    }
    kprintln!("  {} node(s) under {}", shown, name);
}

pub fn show(path: &str) {
    let full = if path.starts_with('/') {
        String::from(path)
    } else {
        let mut p = String::from(ROOT);
        p.push('/');
        p.push_str(path);
        p
    };
    match sysbox::read_blob(&full) {
        Some(b) => {
            let text = String::from_utf8_lossy(&b);
            for line in text.lines() {
                kprintln!("  {}", line);
            }
        }
        None => kprintln!("  no node at {}", full),
    }
}

/// What the forest costs, and what an index over it would cost.
///
/// The second figure is the one that decides whether bodies can stay in the
/// namespace. Getting it means reading every node, because the head is only
/// cheap to reach once something stores it separately -- so this command is
/// deliberately expensive and says so.
pub fn cost() {
    let c = census();
    if c.nodes == 0 {
        kprintln!("  no forest at {}", ROOT);
        return;
    }
    let mut heads = 0usize;
    for t in trees() {
        let mut p = String::from(ROOT);
        p.push('/');
        p.push_str(&t);
        heads += head_bytes(&p);
    }
    kprintln!("  {} node(s), {} B of bodies resident", c.nodes, c.bytes);
    kprintln!("  {} B of head lines -- what an index would hold", heads);
    let pct = if c.bytes == 0 { 0 } else { heads * 100 / c.bytes };
    kprintln!("  heads are {}% of the forest, so {}% could leave memory", pct, 100 - pct);
    kprintln!("  widest directory {}, deepest {} level(s) under the root", c.widest, c.deepest);
    kprintln!("  every node was read to measure this; nothing caches it yet");
}

fn head_bytes(dir: &str) -> usize {
    let mut total = 0usize;
    for name in sysbox::children(dir) {
        let mut sub = String::from(dir);
        sub.push('/');
        sub.push_str(&name);
        match is_node(&sub) {
            Some(_) => {
                if let Some(h) = head_of(&sub) {
                    total += h.len();
                }
            }
            None => total += head_bytes(&sub),
        }
    }
    total
}

pub fn command(rest: &str) {
    let mut w = rest.split_whitespace();
    match w.next().unwrap_or("") {
        "" => report(),
        "cost" => cost(),
        "tree" => match w.next() {
            Some(n) => report_tree(n),
            None => kprintln!("  usage: forest tree <name>"),
        },
        "show" => match w.next() {
            Some(p) => show(p),
            None => kprintln!("  usage: forest show <path under the root>"),
        },
        other => {
            kprintln!("  no such forest verb: {}", other);
            kprintln!("  forest              trees and node counts");
            kprintln!("  forest tree <name>  branches under one trunk");
            kprintln!("  forest show <path>  one node, head and body");
            kprintln!("  forest cost         resident bytes, and what an index would hold");
        }
    }
}

/// What the reader claims, checked with no forest installed and no model.
///
/// The claim that earns its place is the last one: this module must never
/// reach for a content hash, because `ls` doing exactly that is what makes
/// listing a forest hash the whole corpus. A test cannot see an absence, so
/// what is asserted instead is that the cheap accessors answer what the walk
/// needs -- a directory is told from a node by `blob_len` alone.
pub fn selftest() -> bool {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, LTRED};
    let mut ok = true;
    let mut check = |what: &str, pass: bool| {
        console::set_color(if pass { LTGREEN } else { LTRED });
        kprintln!("  {}  {}", if pass { "ok  " } else { "FAIL" }, what);
        console::set_color(LTGRAY);
        ok &= pass;
    };

    // A machine with no forest must answer emptily rather than faulting, since
    // that is every machine until somebody imports one. Against a root that
    // does not exist, so the claim holds whether or not one is installed --
    // the first version asked `c.nodes == 0 || c.nodes > 0` of the live root,
    // which is a tautology dressed as a check and could never have failed.
    let absent = census_at("/tmp/forest-absent");
    check(
        "a root that does not exist censuses to nothing rather than faulting",
        absent.trees == 0 && absent.nodes == 0 && absent.bytes == 0,
    );

    // And a forest built here censuses to exactly what was put in it. Two
    // nodes of known length under one branch of one tree: a walk that counted
    // the branch as a node, or recursed into a node as though it were a
    // branch, gets a different number for each of these.
    // Lengths taken from the strings rather than counted by hand. A claim that
    // asserts a number somebody worked out on paper fails the day the fixture
    // gains a character, and reads as a bug in the thing under test.
    let one = "head a | b | c\nkind t\n";
    let two = "head d | e | f\nkind t\nmore\n";
    sysbox::write_text("/tmp/forest-t/oak/limb/00000", one);
    sysbox::write_text("/tmp/forest-t/oak/limb/00001", two);
    let built = census_at("/tmp/forest-t");
    check(
        "a built forest censuses to what was put in it",
        built.trees == 1 && built.branches == 1 && built.nodes == 2,
    );
    check(
        "bytes are the nodes' own, and a directory contributes none",
        built.bytes == one.len() + two.len(),
    );

    // `blob_len` is the one predicate the walk uses to tell a branch from a
    // node, so the walk is only correct while it answers None for a directory.
    let dir_is_not_a_node = sysbox::blob_len("/ai").is_none();
    check("a directory is not mistaken for a node", dir_is_not_a_node);

    // And a real blob must read as one, or every node would be walked into as
    // though it were a branch and the census would silently be zero.
    sysbox::write_text("/tmp/forest-probe", "head a | b | c\nkind t\n");
    let blob_is_a_node = sysbox::blob_len("/tmp/forest-probe").is_some();
    check("a blob is a node", blob_is_a_node);

    // The head is the first line with its key stripped, because that is what
    // an index stores and what the router will pool over.
    let h = head_of("/tmp/forest-probe");
    check(
        "the head is the first line, with the key removed",
        h.as_deref() == Some("a | b | c"),
    );

    ok
}
