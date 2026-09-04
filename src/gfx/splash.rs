//! The boot screen.
//!
//! Not decoration. Boot takes a while -- 129 MB of weights come off a USB
//! stick, then eleven sets of test vectors run -- and on the GF63 there is no
//! serial port, so a machine that appears to be doing nothing is
//! indistinguishable from a machine that has hung. A progress bar is the
//! difference between "wait" and "reboot and give up".
//!
//! ### Nothing is hidden
//!
//! The console keeps a shadow grid in RAM, so while this owns the framebuffer
//! the boot log is still being written -- just not painted. `finish` gives the
//! screen back and repaints the lot, so the familiar text is there to read a
//! moment later, exactly as before. That matters more than the splash does:
//! the framebuffer is the only diagnostic channel this machine has.
//!
//! ### Why it looks like this
//!
//! Raised panel, sunken trough, two-pixel bevels, one bitmap font, four
//! colours out of sixteen. That is a Windows 3.x dialog, and it is also the
//! cheapest thing a framebuffer can draw: no blending, no antialiasing, no
//! gradients, no scaling. The aesthetic and the constraint are the same
//! choice, which is why it will still look right when there is a window
//! manager behind it.

use super::palette::{BLACK, DKGRAY, LTGRAY, WHITE};
use super::{font, primary};
use crate::sync::Racy;

/// How many `stage` calls make a full bar.
///
/// Kept in step with the call sites in `main` by hand. If it drifts the bar
/// finishes early or stops short -- ugly, never wrong, and never fatal, which
/// is the right failure mode for a progress indicator.
const STAGES: u32 = 9;

static STEP: Racy<u32> = Racy::new(0);
static ACTIVE: Racy<bool> = Racy::new(false);

pub fn active() -> bool {
    unsafe { *ACTIVE.get() }
}

/// Panel geometry, centred on whatever panel the firmware gave us.
///
/// Everything is stacked in order and the panel height falls out of the sum,
/// rather than each element being placed at some fraction of the whole. The
/// fractional version put the trough on top of the subtitle at one particular
/// resolution, which is the failure mode that arrangement always has.
struct Layout {
    px: u32,
    py: u32,
    pw: u32,
    ph: u32,
    scale: u32,
    logo_cy: u32,
    logo_r: u32,
    title_y: u32,
    sub_y: u32,
    bar_y: u32,
    bar_h: u32,
    label_y: u32,
}

fn layout(w: u32, h: u32) -> Layout {
    // Scale the whole thing off the panel width so a 1920x1080 laptop and an
    // 800x600 QEMU window both look deliberate rather than one being a
    // postage stamp.
    let scale = if w >= 1600 {
        3
    } else if w >= 1024 {
        2
    } else {
        1
    };
    let pw = (w * 3 / 5).max(320);
    let gh = font::GLYPH_H * scale;
    let pad = gh;
    let logo_r = (gh * 5).min(pw / 5);

    // Stack downward from the top of the panel.
    let mut y = pad;
    let logo_cy = y + logo_r;
    y = logo_cy + logo_r + pad;
    let title_y = y;
    y += font::GLYPH_H * (scale + 1) + pad / 2;
    let sub_y = y;
    y += gh + pad;
    let bar_y = y;
    let bar_h = gh;
    y += bar_h + pad / 2;
    let label_y = y;
    let ph = label_y + gh + pad;

    Layout {
        px: (w - pw) / 2,
        py: (h.saturating_sub(ph)) / 2,
        pw,
        ph,
        scale,
        logo_cy,
        logo_r,
        title_y,
        sub_y,
        bar_y,
        bar_h,
        label_y,
    }
}

/// Unit vectors scaled by 1000, one turn in 120 steps of three degrees, y
/// downward.
///
/// There is no floating point this early and a trig implementation for a logo
/// would be silly, so the vectors the mark needs are written down. Generated
/// rather than derived by hand: `tools/mklogo.py` holds the same construction
/// in floating point and is where the geometry changes first.
///
/// 120 rather than something smaller because the rim wants fifteen teeth and
/// each tooth wants a root wider than its tip. That needs four distinct angles
/// per tooth out of a table that divides evenly by fifteen, and a coarse table
/// forces the taper to round away.
const DIR120: [(i32, i32); 120] = [
    (1000, 0), (999, 52), (995, 105), (988, 156), (978, 208), (966, 259),
    (951, 309), (934, 358), (914, 407), (891, 454), (866, 500), (839, 545),
    (809, 588), (777, 629), (743, 669), (707, 707), (669, 743), (629, 777),
    (588, 809), (545, 839), (500, 866), (454, 891), (407, 914), (358, 934),
    (309, 951), (259, 966), (208, 978), (156, 988), (105, 995), (52, 999),
    (0, 1000), (-52, 999), (-105, 995), (-156, 988), (-208, 978), (-259, 966),
    (-309, 951), (-358, 934), (-407, 914), (-454, 891), (-500, 866), (-545, 839),
    (-588, 809), (-629, 777), (-669, 743), (-707, 707), (-743, 669), (-777, 629),
    (-809, 588), (-839, 545), (-866, 500), (-891, 454), (-914, 407), (-934, 358),
    (-951, 309), (-966, 259), (-978, 208), (-988, 156), (-995, 105), (-999, 52),
    (-1000, 0), (-999, -52), (-995, -105), (-988, -156), (-978, -208), (-966, -259),
    (-951, -309), (-934, -358), (-914, -407), (-891, -454), (-866, -500), (-839, -545),
    (-809, -588), (-777, -629), (-743, -669), (-707, -707), (-669, -743), (-629, -777),
    (-588, -809), (-545, -839), (-500, -866), (-454, -891), (-407, -914), (-358, -934),
    (-309, -951), (-259, -966), (-208, -978), (-156, -988), (-105, -995), (-52, -999),
    (0, -1000), (52, -999), (105, -995), (156, -988), (208, -978), (259, -966),
    (309, -951), (358, -934), (407, -914), (454, -891), (500, -866), (545, -839),
    (588, -809), (629, -777), (669, -743), (707, -707), (743, -669), (777, -629),
    (809, -588), (839, -545), (866, -500), (891, -454), (914, -407), (934, -358),
    (951, -309), (966, -259), (978, -208), (988, -156), (995, -105), (999, -52),
];

/// The star, as ten vertices alternating point and valley, first point upward.
///
/// Written out rather than derived from `DIR120` because the valleys sit at
/// 0.300 of the radius, which is not a step of any direction table. That figure
/// is the whole character of the star: 0.382 is where the five points meet edge
/// to edge and gives a fat, civic star, and the emblem wants slender arms with
/// deep valleys between them.
const STAR: [(i32, i32); 10] = [
    (0, -1000), (176, -243), (951, -309), (285, 93), (588, 809),
    (0, 300), (-588, 809), (-285, 93), (-951, -309), (-176, -243),
];

/// Fifteen teeth, on a pitch of eight steps: five of tooth, three of gap.
///
/// Fifteen divides 120, so the last gap closes onto the first tooth exactly and
/// the rim needs no fudge factor. Tooth wider than gap because the emblem is a
/// heavy industrial cog: equal tooth and gap reads as a sun, and a gap wider
/// than its tooth reads as a saw blade.
const TEETH: usize = 15;
const TOOTH_PITCH: usize = 8;
/// Steps spanned by a tooth at its root, and the step it is inset by at the
/// tip. The tip is two steps narrower than the root, which is the taper: sides
/// drawn straight out along the radius would splay, because arc length grows
/// with radius, and the teeth would fan out like petals.
const TOOTH_ROOT: usize = 5;
const TOOTH_INSET: usize = 1;
/// The gear body, as hundredths of the outer radius. Teeth stand from here out
/// to the full radius.
const BODY_PCT: i32 = 84;
/// The pale field the star sits on, as hundredths of the outer radius. It
/// leaves the body as a ring twelve hundredths wide, which is the dark band
/// between the field and the roots of the teeth.
const FIELD_PCT: i32 = 72;
/// The star, as hundredths of the outer radius. Inside the field with a margin,
/// so the points stop short of the ring instead of touching it and welding the
/// two shapes into one blob at small sizes.
const STAR_PCT: i32 = 60;
/// Half-width of the seam splitting the top point, in thousandths of the star
/// radius, and the smallest radius that gets one.
///
/// The seam is the emblem's one piece of detail and it is the first thing to go
/// when the mark is small: at the eight-pixel radius the taskbar asks for, a
/// seam is the whole point rather than a crease in it. Below the floor the star
/// is drawn solid.
const SEAM_HALF: i32 = 75;
const SEAM_MIN_R: i32 = 22;

/// The mark: a cogged wheel with a star on a pale field.
///
/// **The debt this repays.** The mark here was the iris from Aperture Science,
/// and the note in its place said a fork which renames every string while
/// keeping the silhouette has moved the problem instead of solving it. This is
/// AUTARK's own: a gear for a machine that makes itself, a star for the polity
/// it thinks it is, and a pale field between them so the two shapes stay legible
/// against each other. Nothing about it is traced.
///
/// Drawn parametrically. It costs no bytes on the ESP, scales from the eight
/// pixels the taskbar gives it to the eighty the splash does, and the geometry
/// is a table of directions and three radii.
///
/// Painted outward, in the order the shapes stack:
///
///   * twelve teeth as quads standing off the body, then the body as a disc.
///     Teeth first means the body's rim covers their inner edges, so no seam
///     shows where a quad meets the circle it grew from.
///   * the pale field, a plain disc.
///   * the star, as a fan of ten triangles from the centre. A fan rather than
///     an outline: an outline of a star at this size is two pixels wide and
///     disappears into the field at the icon sizes, and the mark has to survive
///     being small more than it has to be delicate.
///
/// The old iris had to be *cut*, since it is a disc with wedges taken out, and
/// the caller had to say what showed through the gaps. A gear has no holes. The
/// gaps between its teeth are simply never painted, so whatever was behind the
/// mark is still there and `Cut` went away with the blades.
///
/// Public because the desktop wall draws the same mark. One definition of what
/// the logo *is*, so the wall and the boot screen cannot drift apart --
/// `tools/mklogo.py` is a port of this and must be re-run if it changes.
pub fn mark(fb: &super::Framebuffer, cx: i32, cy: i32, r: i32, fg: super::Color, _bg: super::Color) {
    mark_with(fb, cx, cy, r, Face::Flat(fg));
}

/// What the blades themselves are made of.
///
/// Flat is the mark as a mark: a boot screen, a favicon, an icon on a bar.
/// `Ramp` is the mark as an object with light on it, which is what it becomes
/// on a wall that already has a sky and a horizon -- at that size and in that
/// company a flat disc reads as a sticker and a lit one reads as a sun.
#[derive(Clone, Copy)]
pub enum Face<'a> {
    Flat(super::Color),
    Ramp(&'a [(u8, super::Color)]),
}

/// The pale field the star sits on.
///
/// A constant of the mark instead of a parameter, because it is part of what
/// the mark *is*: the emblem is a dark gear, a light field and a dark star, and
/// a caller free to tint the field could produce something that is no longer
/// this logo. It is off-white so it reads as enamel on both the light boot
/// panel and the dark wall.
const FIELD: super::Color = super::Color::new(0xEC, 0xEC, 0xEA);

/// The metal the gear and the star are cut from.
///
/// Near-black instead of black. Against the boot panel's light grey a pure
/// black emblem reads as a hole punched in the panel; a hair above it reads as
/// iron, which is what the thing is meant to be.
pub const IRON: super::Color = super::Color::new(0x1A, 0x1A, 0x1A);

/// The ground the boot panel stands on, and the bar that fills across it.
///
/// The deep red the emblem is flown against. It replaced the 3.x blue, which
/// was inherited along with the panel and the bevels and was the one piece of
/// that inheritance carrying somebody else's identity rather than a drawing
/// convention: a raised panel is a way to draw, and a blue field is a flag.
const MAROON: super::Color = super::Color::new(0x8C, 0x14, 0x14);
const MAROON_DEEP: super::Color = super::Color::new(0x5E, 0x0D, 0x0D);

/// The mark, with the caller saying what the metal is made of.
///
/// One geometry and one set of constants for every size it is drawn at. Two
/// marks that agreed about where a tooth goes only while somebody kept them
/// agreeing would be the duplicated-layout bug wearing a logo.
pub fn mark_with(fb: &super::Framebuffer, cx: i32, cy: i32, r: i32, face: Face<'_>) {
    let scaled = |(dx, dy): (i32, i32), rad: i32| (cx + dx * rad / 1000, cy + dy * rad / 1000);
    // The face, applied to a triangle. A ramp is measured over the mark's own
    // bounding box, so a tooth is lit by the same gradient as the body under it
    // and the rim does not step in shade where the two meet.
    let top = (cy - r).max(0) as u32;
    let height = (2 * r).max(1) as u32;
    let metal = |a: (i32, i32), b: (i32, i32), c: (i32, i32)| match face {
        Face::Flat(fg) => fb.fill_triangle(a, b, c, fg),
        Face::Ramp(stops) => fb.fill_triangle_over(a, b, c, stops, top, height),
    };

    // Teeth first, then the body over their roots. That order means the body's
    // rim covers where each quad meets the circle it grew from, so no seam
    // shows along the root even when the quad's edge lands a pixel inside.
    let body = r * BODY_PCT / 100;
    for t in 0..TEETH {
        let i0 = t * TOOTH_PITCH;
        let root0 = DIR120[i0 % 120];
        let root1 = DIR120[(i0 + TOOTH_ROOT) % 120];
        let tip0 = DIR120[(i0 + TOOTH_INSET) % 120];
        let tip1 = DIR120[(i0 + TOOTH_ROOT - TOOTH_INSET) % 120];
        let a = scaled(root0, body);
        let b = scaled(root1, body);
        let c = scaled(tip1, r);
        let d = scaled(tip0, r);
        metal(a, b, c);
        metal(a, c, d);
    }
    match face {
        Face::Flat(fg) => fb.fill_circle(cx, cy, body, fg),
        Face::Ramp(stops) => fb.fill_circle_ramp(cx, cy, body, stops),
    }

    // The field, then the star standing on it.
    fb.fill_circle(cx, cy, r * FIELD_PCT / 100, FIELD);
    let sr = r * STAR_PCT / 100;
    let centre = (cx, cy);
    for v in 0..STAR.len() {
        let a = scaled(STAR[v], sr);
        let b = scaled(STAR[(v + 1) % STAR.len()], sr);
        metal(centre, a, b);
    }

    // The seam: a sliver of field taken back out of the top point, from the
    // apex down to the centre. Cut afterwards rather than drawn as two half
    // points, because the star is a fan and splitting one arm of a fan means
    // special-casing the arm either side of it as well.
    if r >= SEAM_MIN_R {
        let half = (sr * SEAM_HALF / 1000).max(1);
        let apex = scaled(STAR[0], sr);
        fb.fill_triangle((apex.0 - half, apex.1), (apex.0 + half, apex.1), centre, FIELD);
    }
}

/// The star alone, filled, at radius `r`.
///
/// Exposed so the button-sized reduction in `theme` draws the same star as the
/// full emblem instead of a second one that merely resembles it. That is the
/// duplicated-geometry bug the mark has already been through once: the boot
/// screen and the wall are one drawing for the same reason.
pub fn star(fb: &super::Framebuffer, cx: i32, cy: i32, r: i32, fg: super::Color) {
    let centre = (cx, cy);
    let scaled = |(dx, dy): (i32, i32)| (cx + dx * r / 1000, cy + dy * r / 1000);
    for v in 0..STAR.len() {
        fb.fill_triangle(centre, scaled(STAR[v]), scaled(STAR[(v + 1) % STAR.len()]), fg);
    }
}

fn centred_text(fb: &super::Framebuffer, cx: u32, y: u32, s: &str, scale: u32, fg: super::Color) {
    // Characters, not bytes. A byte count centres anything with an accent in
    // it too far to the left, by exactly the number of accents.
    let width = s.chars().count() as u32 * font::GLYPH_W * scale;
    let x = cx.saturating_sub(width / 2);
    fb.draw_text(x, y, s, fg, LTGRAY, scale);
}

/// Take the screen and draw the frame.
pub fn begin() {
    let Some(fb) = primary() else { return };
    unsafe {
        *STEP.get() = 0;
        *ACTIVE.get() = true;
    }
    crate::gfx::console::with(|c| c.set_visible(false));

    let (w, h) = (fb.width(), fb.height());
    let l = layout(w, h);

    fb.fill(MAROON);

    // The panel: face, raised bevel, then a black outer line so it separates
    // from the background the way a dialog does.
    fb.rect(l.px, l.py, l.pw, l.ph, LTGRAY);
    fb.bevel(l.px, l.py, l.pw, l.ph, true);
    fb.frame(l.px - 1, l.py - 1, l.pw + 2, l.ph + 2, BLACK);

    let cx = l.px + l.pw / 2;

    mark(
        &fb,
        cx as i32,
        (l.py + l.logo_cy) as i32,
        l.logo_r as i32,
        IRON,
        LTGRAY,
    );

    centred_text(&fb, cx, l.py + l.title_y, "AUTARK", l.scale + 1, BLACK);
    centred_text(
        &fb,
        cx,
        l.py + l.sub_y,
        "a model in the kernel",
        l.scale.max(1),
        DKGRAY,
    );

    // The trough. Sunken, because the bar sits inside it.
    let (bx, by, bw, bh) = bar_rect(&l);
    fb.rect(bx, by, bw, bh, WHITE);
    fb.bevel(bx, by, bw, bh, false);
    render(0, "starting");
}

fn bar_rect(l: &Layout) -> (u32, u32, u32, u32) {
    let bw = l.pw * 4 / 5;
    (l.px + (l.pw - bw) / 2, l.py + l.bar_y, bw, l.bar_h)
}

fn render(step: u32, label: &str) {
    let Some(fb) = primary() else { return };
    let l = layout(fb.width(), fb.height());
    let (bx, by, bw, bh) = bar_rect(&l);

    // Fill proportionally, inside the bevel so the trough edge stays visible.
    let inner_w = bw.saturating_sub(4);
    let filled = (inner_w * step.min(STAGES)) / STAGES;
    if filled > 0 {
        fb.rect(bx + 2, by + 2, filled, bh.saturating_sub(4), MAROON_DEEP);
    }

    let _ = (by, bh);
    // The label sits under the trough, on a repainted strip so a shorter name
    // does not leave the tail of a longer one behind it.
    let ly = l.py + l.label_y;
    fb.rect(l.px + 2, ly, l.pw - 4, font::GLYPH_H * l.scale, LTGRAY);
    centred_text(&fb, l.px + l.pw / 2, ly, label, l.scale.max(1), BLACK);
}

/// Advance one step and name what is happening.
pub fn stage(label: &str) {
    if !active() {
        return;
    }
    let step = unsafe {
        *STEP.get() += 1;
        *STEP.get()
    };
    render(step, label);
}

/// Change the label without advancing the bar.
///
/// For the moments boot pauses to ask the operator something -- the recovery
/// prompt is the only one so far. The question is printed to a console nobody
/// can currently see, so it has to be said here too.
pub fn note(label: &str) {
    if !active() {
        return;
    }
    let step = unsafe { *STEP.get() };
    render(step, label);
}

/// Give the framebuffer back and repaint the boot log over the top.
pub fn finish() {
    if !active() {
        return;
    }
    render(STAGES, "ready");
    unsafe { *ACTIVE.get() = false };
    crate::gfx::console::with(|c| {
        c.set_visible(true);
    });
    // The console has been writing to its shadow grid the whole time, so
    // reflowing it into the window's client area and repainting brings the
    // boot log back at the new origin -- nothing logged during boot is lost by
    // gaining a frame around it.
    crate::gfx::desk::init();
}

/// Abandon the splash immediately, keeping whatever is on screen.
///
/// For a fault: the reporter draws straight to the framebuffer, and a panic
/// behind a progress bar helps nobody.
pub fn abandon() {
    if !active() {
        return;
    }
    unsafe { *ACTIVE.get() = false };
    crate::gfx::console::with(|c| c.set_visible(true));
    // Deliberately *not* `ui::chrome()`. This is the fault path: the reporter
    // is about to draw and the console is the only diagnostic channel there
    // is, so the cheapest thing that makes text visible is the right thing.
    // Painting a window frame first would be decoration on the way to a halt.
    crate::gfx::console::redraw();
}
