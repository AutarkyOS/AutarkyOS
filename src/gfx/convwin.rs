//! The conversation, as a window you can type into.
//!
//! Every other window on this desktop is a view. This one takes the keyboard,
//! and that single difference decides most of what follows.
//!
//! ### It keeps focus, and that is now safe
//!
//! The standing rule is that a window handing focus back to the terminal is the
//! polite thing to do, because a focused app swallows keys the shell would have
//! read -- Minesweeper once consumed `echo after-mines` a byte at a time and
//! flagged a cell on the `f`. That rule cannot apply to a window whose whole
//! purpose is to be typed into.
//!
//! It no longer has to. `shell.rs` asks `kbd::last_was_serial()` before offering
//! a key to the desktop, on the stated grounds that a byte off the line is by
//! definition addressed to the shell. So a driven session reaches the shell
//! whatever has focus, and `win keys` remains the way to drive this window --
//! which is also the only way to test it, since serial cannot inject PS/2.
//!
//! ### It does not answer; it asks for an answer
//!
//! `key` runs on the shell task *inside* `desk::with(|d| ..)`, holding `&mut
//! Desktop`. `generate` calls `desk::pump_cursor()` between tokens. Generating
//! from a keystroke would therefore alias the desktop against itself -- the
//! hazard `with_engine` documents for the engine, one level up and with no
//! atomic watching for it. So Enter does the cheapest thing that can possibly
//! work: `agent::queue_say`, an atomic and a `String` move, and the borrow is
//! gone long before a token exists.
//!
//! ### It owns nothing but the caret
//!
//! The transcript is `convo::snapshot()`, cloned per frame, exactly as
//! `AgentLog` clones the agent's ring. The scroll is stored as *lines up from
//! the bottom*, which is what makes tail-following free: at zero the view is
//! pinned to the newest line by construction, and an answer arriving while the
//! operator is scrolled up pushes old text away instead of yanking the viewport
//! out from under them.

use super::{DeskApp, Framebuffer};
use super::theme::{self, Rect};
use crate::ai::convo::{self, Who};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;

/// The most that will be held in the input line.
///
/// Not a scroll: the field does not scroll, so a longer line would draw off
/// the window and across the desktop behind it. A prompt this long is a
/// paragraph, and the place for one of those is a file.
const INPUT_MAX: usize = 512;

pub struct Convo {
    scroll: Cell<usize>,
    input: String,
}

impl Convo {
    pub fn new() -> Self {
        Self { scroll: Cell::new(0), input: String::new() }
    }

    pub fn preferred() -> (u32, u32) {
        (640, 460)
    }
}

/// How a line is marked, and in what colour.
///
/// A prefix rather than indentation or a colour alone. Colour is the thing
/// this window is least sure of -- it is read on a framebuffer nobody has
/// calibrated, at 8x8 doubled -- and a transcript where the only signal of who
/// spoke is a hue is a transcript that stops working the moment somebody
/// screenshots it in greyscale.
fn mark(who: Who) -> (&'static str, super::Color) {
    match who {
        Who::Operator => ("> ", theme::TEXT),
        Who::Machine => ("  ", theme::TEXT),
        Who::Note => ("  ", theme::TEXT_DIM),
    }
}

impl DeskApp for Convo {
    /// Wide enough for a wrapped sentence, tall enough that an answer is not
    /// read through a letterbox.
    fn min_size(&self) -> (u32, u32) {
        (420, 260)
    }

    fn draw_in(&self, fb: &Framebuffer, client: Rect, focused: bool) {
        theme::panel(fb, client);
        let lh = theme::text_h();
        let cw = theme::text_w(1).max(1);

        // The input field sits at the foot, and the transcript gets the rest.
        // Laid out from the bottom up because the field's height is known and
        // the transcript's is whatever is left -- the other way round leaves a
        // window whose last line is half drawn.
        let pad = 6u32;
        let field_h = lh + 8;
        let area = Rect::new(
            client.x + pad,
            client.y + pad,
            client.w.saturating_sub(pad * 2),
            client.h.saturating_sub(pad * 3 + field_h),
        );
        let field = Rect::new(
            client.x + pad,
            client.y + client.h.saturating_sub(pad + field_h),
            client.w.saturating_sub(pad * 2),
            field_h,
        );

        let cols = (area.w / cw) as usize;
        let rows = (area.h / lh.max(1)) as usize;

        // Wrapped once, here, and scrolled by *display* row rather than by
        // source line. Scrolling by source line desynchronises from what is on
        // screen the moment any line wraps, which for model output is always.
        let lines = convo::snapshot();
        let mut flat: Vec<(Who, String)> = Vec::new();
        for l in lines.iter() {
            let (pfx, _) = mark(l.who);
            let budget = cols.saturating_sub(pfx.len()).max(1);
            if l.text.is_empty() {
                flat.push((l.who, String::new()));
                continue;
            }
            for (i, w) in super::agentwin::wrap(&l.text, budget).into_iter().enumerate() {
                let mut s = String::from(if i == 0 { pfx } else { "  " });
                s.push_str(&w);
                flat.push((l.who, s));
            }
        }

        let max_scroll = flat.len().saturating_sub(rows);
        let scroll = self.scroll.get().min(max_scroll);
        self.scroll.set(scroll);
        let start = flat.len().saturating_sub(scroll + rows);

        for k in 0..rows {
            let i = start + k;
            if i >= flat.len() {
                break;
            }
            let (_, fg) = mark(flat[i].0);
            theme::text(fb, area.x, area.y + (k as u32) * lh, &flat[i].1, fg, theme::FACE);
        }

        if flat.is_empty() {
            theme::text(
                fb,
                area.x,
                area.y,
                "say something.",
                theme::TEXT_DIM,
                theme::FACE,
            );
        }

        // The field. Sunken, because that is what every other place you type
        // on this desktop looks like.
        theme::well(fb, field, theme::HILIGHT);
        let tx = field.x + 4;
        let ty = field.y + 4;
        let shown = theme::tail_chars(&self.input, ((field.w - 8) / cw) as usize);
        theme::text(fb, tx, ty, &shown, theme::TEXT, theme::HILIGHT);

        // A caret only while focused, and only when nothing is being said.
        // Drawing one during a reply would invite typing into a field whose
        // contents cannot be sent yet, which is a control that lies.
        if focused && !crate::ai::convo::is_open() {
            let cx = tx + theme::text_w_of(&shown);
            fb.rect(cx, ty, 2, lh, theme::SIGNAL);
        }
    }

    fn key(&mut self, k: u8) -> bool {
        match k {
            b'\n' | b'\r' => {
                let line = String::from(self.input.trim());
                if line.is_empty() {
                    return false;
                }
                // Queue and get out. Everything expensive is somebody else's
                // task; see the module header for why that is not optional.
                if crate::ai::agent::queue_say(&line) {
                    self.input.clear();
                    // Any answer belongs at the bottom, so a send is also a
                    // decision to follow again.
                    self.scroll.set(0);
                } else {
                    convo::note("busy -- one at a time");
                }
                true
            }
            8 | 127 => {
                self.input.pop();
                true
            }
            0x20..=0x7E => {
                if self.input.chars().count() < INPUT_MAX {
                    self.input.push(k as char);
                }
                true
            }
            // Everything else is declined, which on this desktop means
            // swallowed rather than passed on -- Alt-Tab and the Start menu
            // are intercepted before an app is asked, so the window cannot
            // trap the keyboard by returning false here.
            _ => false,
        }
    }

    fn press(&mut self, _client: Rect, _x: i32, _y: i32) -> bool {
        false
    }

    fn wheel(&mut self, notches: i32) -> bool {
        let delta = (notches * 3) as isize;
        let next = self.scroll.get() as isize - delta;
        self.scroll.set(next.max(0) as usize);
        true
    }
}
