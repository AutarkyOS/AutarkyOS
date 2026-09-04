//! The conversation, as something the desktop can watch.
//!
//! `ask` writes the model's answer to the console and nowhere else: `generate`
//! returns `()`, and the tokens reach the screen through `emit`, which is a
//! `kprint!`. There is no transcript object and no way to get the text back. A
//! window that wanted to show a conversation therefore had nothing to show.
//!
//! This is the same shape `agent::LOG` uses for episodes -- a bounded ring in
//! the producing module, a `snapshot()` that clones, and a window that owns
//! nothing and reads it while drawing. The copy per frame is the whole
//! synchronisation story, because `Racy` is not a lock and the generating task
//! appends while the shell task paints.
//!
//! ### Why the tee is in `emit` and not in `generate`
//!
//! A token is not a string. A byte-fallback token is one arbitrary byte and a
//! multi-byte character can straddle two tokens, which is why `emit` buffers
//! and only prints what currently decodes. Teeing at the token level would
//! hand this module invalid UTF-8 fragments and it would have to solve the same
//! problem a second time, differently. `emit` is the one place in the kernel
//! where decoded text exists, so it is the only honest place to take a copy.
//!
//! The consequence worth having is that **the window and the console cannot
//! disagree about what the model said.** They are not two renderings of one
//! event; they are one string, written twice.
//!
//! ### Why it is gated
//!
//! `emit` is on the path of every decode in the system -- `gen`, `chat`, a
//! routing decision, an agent episode's tool choice, a nightly trial. Feeding
//! all of it into a conversation would splice an episode's reasoning into the
//! middle of an operator's sentence, which is the exact defect
//! `companion::interject_frame` exists to prevent one layer up. So a machine
//! turn is explicitly opened and closed around the generation that belongs to
//! it, and `feed` is a single atomic load away from free the rest of the time.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::Racy;

/// Who a line belongs to.
///
/// Three and not two: a note is neither the operator nor the machine speaking,
/// and rendering "no model loaded" as though the machine had said it would be
/// the window telling a small lie on the kernel's behalf.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Operator,
    Machine,
    Note,
}

#[derive(Clone)]
pub struct Line {
    pub who: Who,
    pub text: String,
}

/// Lines kept. The same figure `agent::LOG_CAP` uses, for the same reason: a
/// conversation that never ends must not grow memory without bound, and the
/// window can only show a screenful anyway.
const CAP: usize = 240;

static LINES: Racy<Vec<Line>> = Racy::new(Vec::new());

/// Whether decoded text currently belongs to the conversation.
static OPEN: AtomicBool = AtomicBool::new(false);

/// A copy, for a window that is drawing.
pub fn snapshot() -> Vec<Line> {
    unsafe { LINES.get().clone() }
}

pub fn is_open() -> bool {
    OPEN.load(Ordering::Acquire)
}

fn push(who: Who, text: String) {
    unsafe {
        let v = LINES.get();
        v.push(Line { who, text });
        let excess = v.len().saturating_sub(CAP);
        v.drain(..excess);
    }
}

/// The operator said something.
pub fn said(text: &str) {
    push(Who::Operator, String::from(text));
}

/// Something the kernel wants in the transcript that nobody said.
pub fn note(text: &str) {
    push(Who::Note, String::from(text));
}

pub fn clear() {
    unsafe { LINES.get().clear() };
}

/// Begin a machine turn. Decoded text appends to it until `close_turn`.
///
/// An empty line is pushed up front so `feed` always has somewhere to append
/// and never has to decide whether it is starting a turn -- a decision it would
/// get wrong exactly once, on a generation that produced nothing, leaving the
/// next answer appended to the previous one.
pub fn open_turn() {
    push(Who::Machine, String::new());
    OPEN.store(true, Ordering::Release);
}

pub fn close_turn() {
    OPEN.store(false, Ordering::Release);
    // A turn that produced nothing leaves a blank line that would read as the
    // machine having answered with silence. It answered with nothing, which is
    // a different thing and is worth saying.
    unsafe {
        let v = LINES.get();
        if let Some(last) = v.last_mut() {
            if last.who == Who::Machine && last.text.is_empty() {
                last.who = Who::Note;
                last.text = String::from("(nothing came back)");
            }
        }
    }
}

/// Decoded text, from `ai::emit`.
///
/// Newlines split lines because the window's scroll unit is a line; everything
/// else appends to the turn in progress. Returns immediately unless a turn is
/// open, which is the common case by a wide margin.
pub fn feed(s: &str) {
    if !OPEN.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        let v = LINES.get();
        for (i, part) in s.split('\n').enumerate() {
            if i > 0 {
                v.push(Line { who: Who::Machine, text: String::new() });
            }
            match v.last_mut() {
                Some(l) => l.text.push_str(part),
                // Only reachable if the ring was cleared mid-turn.
                None => v.push(Line { who: Who::Machine, text: String::from(part) }),
            }
        }
        let excess = v.len().saturating_sub(CAP);
        v.drain(..excess);
    }
}

/// Every state of the ring, without a model.
///
/// The claims that earn their place are the two that are wrong in a way
/// nothing would notice: text arriving while no turn is open (which would put
/// an agent episode's reasoning into somebody's conversation) and a newline
/// inside one piece (which decides whether the window's scroll unit means
/// anything).
pub fn selftest() -> bool {
    let saved = snapshot();
    clear();

    let mut ok = true;

    // Closed by default: a decode that is nobody's conversation stays out.
    feed("stray");
    ok &= snapshot().is_empty();

    said("hello");
    open_turn();
    feed("one");
    feed(" two");
    close_turn();
    let s = snapshot();
    ok &= s.len() == 2;
    ok &= s[0].who == Who::Operator && s[0].text == "hello";
    ok &= s[1].who == Who::Machine && s[1].text == "one two";

    // ...and it is closed again afterwards.
    feed("stray");
    ok &= snapshot().len() == 2;

    // A newline splits, because the window scrolls by line.
    clear();
    open_turn();
    feed("a\nb");
    feed("c");
    close_turn();
    let s = snapshot();
    ok &= s.len() == 2 && s[0].text == "a" && s[1].text == "bc";

    // A turn that said nothing says so, rather than leaving a blank the
    // window would render as the machine having replied with silence.
    clear();
    open_turn();
    close_turn();
    let s = snapshot();
    ok &= s.len() == 1 && s[0].who == Who::Note;

    // The ring is bounded.
    clear();
    for _ in 0..(CAP + 40) {
        note("x");
    }
    ok &= snapshot().len() == CAP;

    clear();
    unsafe { *LINES.get() = saved };
    ok
}
