//! Repairs that survive a reboot, and the rule that stops one bricking a
//! machine.
//!
//! A repair decided at 03:00 on an unattended machine has to reach disk
//! without anybody typing anything, and the namespace cannot do that: a write
//! there lands in an in-memory tree, and reaching NVMe needs `store unlock`,
//! which is a person, once per boot. **The ESP is the only durable channel
//! that needs no human**, and `update` already owns the whole apparatus for
//! writing it safely -- a ranged gate, a verified write, and the firmware's own
//! reader on the way back in.
//!
//! ### The safety property is `update`'s, unchanged
//!
//! A repair is a change this machine made to itself while nobody was watching,
//! so the question that matters is not whether it helps. It is what happens
//! when it is catastrophic. The answer is the health flag, with the same shape
//! it has for a staged image:
//!
//! - the hook applies what the file says and writes `REPAIRS.FLG`
//! - `survived` deletes that flag when this boot reaches the shell
//! - a hook that finds the flag already there knows the last boot to apply
//!   these repairs never got that far, and **withdraws the newest entry**
//!
//! So a repair that prevents boot removes itself, in one reboot, with no
//! operator and no recovery media.
//!
//! ### The window is the whole boot, and that is why the clear is late
//!
//! `update`'s own health flag is resolved before `ExitBootServices`, because
//! the firmware's FAT driver is the only writer of the ESP that exists while a
//! *boot image* can still be swapped. Nothing here needs to swap anything, so
//! that constraint does not apply -- and this kernel can write its own ESP
//! afterwards, over NVMe, through `stage`'s ranged gate. `record` is the proof
//! that works.
//!
//! Clearing early would have been the obvious thing and would have bought a
//! window from the hook to the memory map: long enough to catch a repair that
//! stops the model loading, and blind to every repair that faults a subsystem,
//! which is the entire population of repairs this table can produce. Clearing
//! at the shell instead covers the selftests, the storage bring-up, the desktop
//! and the model, which is everything a repair could plausibly break.
//!
//! **A machine that cannot write its ESP therefore withdraws one repair per
//! boot**, since the flag it cannot clear reads as a boot that did not survive.
//! That is the safe direction -- a machine nobody can talk to reverts to
//! unmodified -- and it is stated here rather than left to be found.
//!
//! ### Small on purpose
//!
//! Eight entries and 512 bytes. A machine that has accumulated nine repairs
//! does not have nine problems, it has one problem upstream of all of them,
//! and a file that grows without bound is a file nothing reads.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Read by the firmware's file protocol at hook time, so UEFI separators.
pub const FILE: &str = "\\GLADOS\\REPAIRS.TXT";
/// Present between the hook applying repairs and this boot proving it survived.
pub const TRIAL: &str = "\\GLADOS\\REPAIRS.FLG";

/// The same two, spelled for our own FAT writer, which splits on '/'.
const FILE_FAT: &str = "/GLADOS/REPAIRS.TXT";
const TRIAL_FAT: &str = "/GLADOS/REPAIRS.FLG";

pub const MAX_ENTRIES: usize = 8;
pub const MAX_BYTES: usize = 512;

/// One repair: which subsystem it was adopted for, and which action it is.
///
/// Two fields and no timestamp, because there is no clock at hook time -- the
/// RTC is read long afterwards. Order in the file is the order they were
/// adopted, which is the only sequencing available and is the one the drop rule
/// needs.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    pub subsystem: String,
    pub action: String,
}

/// What a hook should do with what it found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// No file, or a file with nothing in it.
    Nothing,
    /// Apply every entry.
    Apply,
    /// The last boot that applied these never reported healthy. Drop the
    /// newest, write the rest back, and apply those.
    DropNewest,
}

/// The whole decision, as a pure function.
///
/// `update::decide` is the template and the reason is the same: every state
/// can then be asserted at boot with no disk, no ESP and nothing staged, which
/// is the only way a path that runs once per reboot gets tested at all.
pub fn decide(entries: usize, on_trial: bool) -> Action {
    if entries == 0 {
        // Nothing to drop and nothing to apply. A trial flag with no entries
        // behind it is a leftover rather than a verdict, and the caller clears
        // it.
        return Action::Nothing;
    }
    if on_trial {
        return Action::DropNewest;
    }
    Action::Apply
}

/// Parse the file. Unreadable lines are dropped rather than failing the file.
///
/// **Lenient on purpose, and only here.** Everywhere else in this tree a
/// malformed input is refused with a reason; this one is read at a point in
/// boot where there is nowhere to report to and nothing to be done about it. A
/// file with one corrupt line should cost that line, not the machine's ability
/// to apply the other seven -- or to withdraw the one that is killing it.
pub fn parse(bytes: &[u8]) -> Vec<Entry> {
    let text = core::str::from_utf8(bytes).unwrap_or("");
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(subsystem), Some(action)) = (it.next(), it.next()) else {
            continue;
        };
        // A third field means this line was written by something that
        // disagrees with this parser about the format, and guessing which two
        // of the three it meant is worse than skipping it.
        if it.next().is_some() {
            continue;
        }
        if out.len() == MAX_ENTRIES {
            break;
        }
        out.push(Entry { subsystem: subsystem.to_string(), action: action.to_string() });
    }
    out
}

pub fn render(entries: &[Entry]) -> String {
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!("{} {}\n", e.subsystem, e.action));
    }
    s
}

// ---------------------------------------------------------------------------
// The boot half: the firmware's reader, before `ExitBootServices`.
// ---------------------------------------------------------------------------

/// Read the file and decide, rewriting it when the last boot did not survive.
///
/// Answers the entries to apply, and a line to print. The caller applies them,
/// because applying means reaching into `repair`'s table and this module has no
/// business knowing what a repair *is* -- only where they are written down.
pub fn at_boot(
    bs: &crate::uefi::BootServices,
    image: crate::uefi::Handle,
) -> (Vec<Entry>, Option<String>) {
    let entries = match crate::uefi::read_file(bs, image, FILE) {
        Some(b) => parse(b.as_slice()),
        None => Vec::new(),
    };
    let on_trial = crate::uefi::read_file(bs, image, TRIAL).is_some();

    match decide(entries.len(), on_trial) {
        Action::Nothing => {
            if on_trial {
                crate::uefi::delete_file(bs, image, TRIAL);
            }
            (Vec::new(), None)
        }
        Action::Apply => {
            // Armed before anything is applied, so a machine that dies on the
            // very next instruction still leaves the evidence behind.
            crate::uefi::write_file(bs, image, TRIAL, b"1\n");
            let n = entries.len();
            (entries, Some(format!("{} repair(s) applied from the boot volume", n)))
        }
        Action::DropNewest => {
            let mut kept = entries;
            let dropped = match kept.pop() {
                Some(e) => e,
                // Unreachable: `decide` only says this with entries. Written as
                // a branch rather than an unwrap because this runs before the
                // fault reporter can paint anything.
                None => return (Vec::new(), None),
            };
            let note = if kept.is_empty() {
                crate::uefi::delete_file(bs, image, FILE);
                crate::uefi::delete_file(bs, image, TRIAL);
                format!(
                    "the last boot applying '{}' for {} did not survive -- withdrawn, and it was the only one",
                    dropped.action, dropped.subsystem
                )
            } else {
                crate::uefi::write_file(bs, image, FILE, render(&kept).as_bytes());
                // Re-armed rather than cleared: what is left has still not been
                // proven, and it is a set this machine has never booted.
                crate::uefi::write_file(bs, image, TRIAL, b"1\n");
                format!(
                    "the last boot applying '{}' for {} did not survive -- withdrawn, {} repair(s) left",
                    dropped.action,
                    dropped.subsystem,
                    kept.len()
                )
            };
            (kept, Some(note))
        }
    }
}

/// This boot reached the shell, so whatever was applied did not stop it.
///
/// Over NVMe rather than through the firmware, which is what buys the wide
/// window -- see the note at the top. Quiet on failure by design: there is
/// nothing an operator can do about it at this point, the consequence is that
/// one repair is withdrawn next boot, and `repair` says what is recorded
/// whenever somebody asks.
pub fn survived() {
    let Ok(esp) = super::stage::find_esp() else {
        return;
    };
    if esp.volume.find(TRIAL_FAT).is_err() {
        return;
    }
    let _ = super::stage::remove_some(&esp, &[TRIAL_FAT]);
}

// ---------------------------------------------------------------------------
// The running half: our own FAT writer, over the ranged NVMe gate.
// ---------------------------------------------------------------------------

/// Append one repair, so the next boot applies it before anything can fault.
///
/// The gate is `stage`'s, unchanged: a claim confined to the boot partition's
/// own LBA window, dropped on every path out including the ones that failed
/// halfway.
pub fn record(subsystem: &str, action: &str) -> Result<String, String> {
    // The file format is whitespace-separated, so a field containing a space
    // would write a line this module's own parser then discards -- a recorded
    // repair that silently is not one.
    if subsystem.split_whitespace().count() != 1 || action.split_whitespace().count() != 1 {
        return Err(String::from("a repair is two words, and neither may contain a space"));
    }
    // Refused here rather than written and ignored. The hook checks all of
    // this again when it applies -- so nothing unsafe gets through either way
    // -- but a line the hook will silently refuse is a line that takes a slot
    // in a capped file and pushes a real repair out of the eighth one, while
    // reading back from `repair` as though the machine is protected.
    //
    // Found by writing `repair record fmt skip-hwp`, which was accepted.
    let Some(a) = crate::repair::ACTIONS.iter().find(|a| a.name == action) else {
        return Err(format!(
            "'{}' is not a repair this kernel has -- `repair` lists the ones it does",
            action
        ));
    };
    // `retry` is the one: it applies nothing, so recording it asks the next
    // boot to do what it does anyway.
    if !a.persist {
        return Err(format!(
            "'{}' applies nothing, so recording it would ask the next boot to do what it does anyway",
            action
        ));
    }
    // Asked of `repair` rather than reimplemented here. The message is this
    // module's and the rule is not, which is the whole point -- two copies of
    // "is this offered" is how these two ends came to disagree.
    if !crate::repair::would_apply(subsystem, action) {
        return Err(format!(
            "'{}' is not offered for {} -- it is offered for {}",
            action,
            subsystem,
            a.offered_for.join(", ")
        ));
    }

    let esp = super::stage::find_esp()?;
    let existing = read_through(&esp);
    let want = Entry { subsystem: subsystem.to_string(), action: action.to_string() };
    if existing.contains(&want) {
        return Ok(format!("'{}' for {} is already recorded", action, subsystem));
    }
    if existing.len() >= MAX_ENTRIES {
        // Refused rather than rotated. Dropping the oldest to make room would
        // silently withdraw a repair the machine is currently relying on, and
        // at eight the interesting fact is the count rather than the newest
        // entry.
        return Err(format!(
            "{} repairs are already recorded, which is the cap -- a machine wanting a ninth has a fault upstream of all of them",
            existing.len()
        ));
    }

    let mut next = existing;
    next.push(want);
    let text = render(&next);
    if text.len() > MAX_BYTES {
        return Err(format!(
            "the file would be {} B, over the {} B cap",
            text.len(),
            MAX_BYTES
        ));
    }

    super::stage::put_one(&esp, FILE_FAT, text.as_bytes())?;
    Ok(format!("'{}' for {} recorded; it is applied from the next boot", action, subsystem))
}

/// Forget one repair, or every repair.
///
/// `None` drops the lot, which is what a machine somebody has actually fixed
/// should be given. The trial flag goes first: while it is gone the file is
/// inert, so an interrupted clear leaves a machine that applies what it had.
pub fn clear(which: Option<usize>) -> Result<String, String> {
    let esp = super::stage::find_esp()?;
    let existing = read_through(&esp);

    match which {
        None => super::stage::remove_some(&esp, &[TRIAL_FAT, FILE_FAT]),
        Some(i) if i < existing.len() => {
            let mut kept = existing;
            let gone = kept.remove(i);
            if kept.is_empty() {
                super::stage::remove_some(&esp, &[TRIAL_FAT, FILE_FAT])?;
            } else {
                super::stage::put_one(&esp, FILE_FAT, render(&kept).as_bytes())?;
            }
            Ok(format!("'{}' for {} is no longer recorded", gone.action, gone.subsystem))
        }
        Some(i) => Err(format!("there is no repair {}; {} are recorded", i, existing.len())),
    }
}

fn read_through(esp: &super::stage::Esp) -> Vec<Entry> {
    match esp.volume.find(FILE_FAT) {
        Ok(entry) => esp.volume.read_file(&entry).map(|b| parse(&b)).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// What is on the boot volume now, read through our own FAT reader.
pub fn stored() -> Result<Vec<Entry>, String> {
    Ok(read_through(&super::stage::find_esp()?))
}

pub fn selftest() -> bool {
    let mut ok = true;
    fn claim(ok: &mut bool, good: bool, what: &str) {
        crate::kprintln!("  {}   {}", if good { "ok " } else { "FAIL" }, what);
        *ok &= good;
    }

    // Every state of the decision, with no disk and nothing written -- the
    // whole reason it is a pure function. This path runs once per reboot and
    // would otherwise be tested by rebooting.
    claim(&mut ok, decide(0, false) == Action::Nothing, "no repairs recorded, nothing to do");
    claim(
        &mut ok,
        decide(0, true) == Action::Nothing,
        "a trial flag with no repairs behind it is a leftover, not a verdict",
    );
    claim(&mut ok, decide(3, false) == Action::Apply, "recorded repairs are applied");
    claim(
        &mut ok,
        decide(1, true) == Action::DropNewest,
        "and a boot that did not survive withdraws the newest",
    );
    claim(
        &mut ok,
        decide(MAX_ENTRIES, true) == Action::DropNewest,
        "however many are recorded",
    );

    // The parser. Lenient about lines and strict about what a line is: two
    // fields, because a third means this was written by something that
    // disagrees about the format.
    let p = parse(b"power skip-hwp\n\n# a note\nfmt retry\n");
    claim(
        &mut ok,
        p.len() == 2 && p[0].subsystem == "power" && p[1].action == "retry",
        "blank lines and comments are skipped and the rest survives",
    );
    claim(&mut ok, parse(b"power\n").is_empty(), "a line with one field is not a repair");
    claim(&mut ok, parse(b"power skip-hwp extra\n").is_empty(), "nor one with three");
    claim(
        &mut ok,
        parse(&[0xff, 0xfe, b'\n']).is_empty(),
        "bytes that are not text cost the file rather than the machine",
    );
    claim(
        &mut ok,
        {
            let mut s = String::new();
            for i in 0..MAX_ENTRIES + 4 {
                s.push_str(&format!("s{} a\n", i));
            }
            parse(s.as_bytes()).len() == MAX_ENTRIES
        },
        "a file longer than the cap is read up to the cap and no further",
    );

    // **What may be written down is what may be applied.** These two rules
    // live in different modules, and a recording end that was laxer than the
    // applying end would fill a capped file with lines the hook refuses --
    // while `repair` read them back as though the machine were protected. Both
    // halves are derived from the table, so the pair cannot drift apart.
    claim(
        &mut ok,
        crate::repair::ACTIONS.iter().all(|a| {
            // Aimed where the row itself says it belongs, so the claim keeps
            // meaning this as rows are added.
            let aimed_right = a.offered_for.first().copied().unwrap_or("any");
            !a.persist || crate::repair::would_apply(aimed_right, a.name)
        }),
        "every action that may be recorded is one the hook would then apply",
    );
    claim(
        &mut ok,
        crate::repair::ACTIONS
            .iter()
            .filter(|a| !a.offered_for.is_empty())
            .all(|a| !crate::repair::would_apply("nothing-by-this-name", a.name)),
        "and one aimed at the wrong subsystem is refused at both ends",
    );

    // Round-tripping is what the withdrawal rests on: a boot that drops the
    // newest entry rewrites the file, and a renderer this parser disagreed with
    // would corrupt the survivors while withdrawing the suspect.
    let entries = parse(b"power skip-hwp\nfmt retry\ncode retry\n");
    claim(
        &mut ok,
        parse(render(&entries).as_bytes()) == entries,
        "what is rendered parses back to what was rendered",
    );
    let mut kept = entries.clone();
    kept.pop();
    let back = parse(render(&kept).as_bytes());
    claim(
        &mut ok,
        back.len() == 2 && back[0] == entries[0] && back[1] == entries[1],
        "and withdrawing the newest leaves the older ones exactly as they were",
    );

    ok
}
