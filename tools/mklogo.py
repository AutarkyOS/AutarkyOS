#!/usr/bin/env python3
"""Draw the AUTARK mark for the web.

This and `gfx::splash::mark_with` in the kernel are the same construction, in
integer arithmetic there and floating point here. If the geometry changes it
changes here first and the constants in splash.rs (DIR120, STAR, TEETH,
TOOTH_*, BODY_PCT, FIELD_PCT, STAR_PCT, SEAM_HALF) follow. Two drawings that
merely resemble each other is the thing being avoided: the boot screen, the
desktop wall, the window chrome and the favicon are one mark.

What the mark is
----------------
A cogged wheel, a pale field, and a five-pointed star with its top point split
by a seam. A gear for a machine that makes itself, a star for the polity it
believes it is.

Three figures that decide whether it reads correctly:

  * **Tooth wider than its gap.** Fifteen teeth on a pitch of 24 degrees, each
    15 degrees of tooth and 9 of gap. Equal tooth and gap reads as a sun; a gap
    wider than its tooth reads as a saw blade.
  * **Teeth that taper.** The sides are inset 3 degrees at the tip. Sides drawn
    straight out along the radius splay, because arc length grows with radius,
    and the teeth fan out like petals.
  * **Valleys at 0.30 of the star radius.** 0.382 is where the five points meet
    edge to edge and gives a fat, civic star. The emblem wants slender arms and
    deep valleys.

The predecessor here was the Aperture iris, which was a disc with wedges cut
out of it, so every renderer had to say what showed through the cuts. A gear
has no holes: the gaps between its teeth are simply never painted.
"""

import argparse
import binascii
import math
import struct
import zlib
from pathlib import Path

IRON = (0x1A, 0x1A, 0x1A)
FIELD = (0xEC, 0xEC, 0xEA)
DARK = (0x0E, 0x0E, 0x0E)

TEETH = 15
PITCH = 360.0 / TEETH        # 24 degrees
TOOTH_ROOT = 15.0            # degrees of tooth at the root
TOOTH_INSET = 3.0            # degrees the tip is drawn in on each side

# Fractions of the outer (tooth tip) radius.
BODY = 0.84
FIELD_R = 0.72
STAR_R = 0.60
STAR_INNER = 0.300           # valley radius, as a fraction of the star radius
SEAM_HALF = 0.075            # half-width of the seam, as a fraction of star radius


def unit(deg):
    a = math.radians(deg)
    return math.cos(a), math.sin(a)


def teeth(cx, cy, r):
    """The teeth, as quads. Root wider than tip, so each one tapers."""
    out = []
    body = r * BODY
    for i in range(TEETH):
        a0 = i * PITCH
        a1 = a0 + TOOTH_ROOT
        r0 = unit(a0)
        r1 = unit(a1)
        t0 = unit(a0 + TOOTH_INSET)
        t1 = unit(a1 - TOOTH_INSET)
        out.append([
            (cx + body * r0[0], cy + body * r0[1]),
            (cx + body * r1[0], cy + body * r1[1]),
            (cx + r * t1[0], cy + r * t1[1]),
            (cx + r * t0[0], cy + r * t0[1]),
        ])
    return out


def star_points(cx, cy, r):
    """Ten vertices alternating point and valley, first point straight up."""
    pts = []
    for k in range(10):
        a = -math.pi / 2 + k * math.pi / 5
        rad = r if k % 2 == 0 else r * STAR_INNER
        pts.append((cx + rad * math.cos(a), cy + rad * math.sin(a)))
    return pts


def in_poly(p, pts):
    """Ray casting. The star is not convex, so the triangle test the iris used
    does not apply to it."""
    x, y = p
    inside = False
    n = len(pts)
    for i in range(n):
        x0, y0 = pts[i]
        x1, y1 = pts[(i + 1) % n]
        if (y0 > y) != (y1 > y):
            xi = x0 + (y - y0) * (x1 - x0) / (y1 - y0)
            if x < xi:
                inside = not inside
    return inside


def in_tri(p, a, b, c):
    def side(p1, p2, p3):
        return (p1[0] - p3[0]) * (p2[1] - p3[1]) - (p2[0] - p3[0]) * (p1[1] - p3[1])
    d1, d2, d3 = side(p, a, b), side(p, b, c), side(p, c, a)
    return not (((d1 < 0) or (d2 < 0) or (d3 < 0)) and ((d1 > 0) or (d2 > 0) or (d3 > 0)))


def sample(x, y, cx, cy, r, quads, star, seam):
    """Which colour a point is, or None for the background.

    Painted in the order the shapes stack, innermost first: the star stands on
    the field, the field sits in the gear, and everything outside the gear is
    whatever was behind the mark.
    """
    d = math.hypot(x - cx, y - cy)
    if d <= r * STAR_R and in_poly((x, y), star) and not in_tri((x, y), *seam):
        return IRON
    if d <= r * FIELD_R:
        return FIELD
    if d <= r * BODY:
        return IRON
    if d <= r:
        for q in quads:
            if in_tri((x, y), q[0], q[1], q[2]) or in_tri((x, y), q[0], q[2], q[3]):
                return IRON
    return None


def render(size, bg=None, ss=4):
    """RGBA buffer of the mark at `size` pixels, supersampled `ss`x."""
    cx = cy = size / 2.0
    r = size / 2.0 * 0.98
    quads = teeth(cx, cy, r)
    star = star_points(cx, cy, r * STAR_R)
    half = r * STAR_R * SEAM_HALF
    apex = star[0]
    seam = ((apex[0] - half, apex[1]), (apex[0] + half, apex[1]), (cx, cy))

    px = bytearray(size * size * 4)
    inv = 1.0 / (ss * ss)
    for py_ in range(size):
        for px_ in range(size):
            acc = [0.0, 0.0, 0.0]
            hits = 0
            for sy in range(ss):
                for sx in range(ss):
                    c = sample(px_ + (sx + 0.5) / ss, py_ + (sy + 0.5) / ss,
                               cx, cy, r, quads, star, seam)
                    if c is not None:
                        acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]
                        hits += 1
            i = (py_ * size + px_) * 4
            if hits:
                px[i] = int(acc[0] / hits)
                px[i + 1] = int(acc[1] / hits)
                px[i + 2] = int(acc[2] / hits)
            px[i + 3] = int(hits * inv * 255)

    if bg:
        flat = bytearray(size * size * 4)
        for i in range(0, len(px), 4):
            al = px[i + 3] / 255.0
            for k in range(3):
                flat[i + k] = int(px[i + k] * al + bg[k] * (1 - al))
            flat[i + 3] = 255
        return flat
    return px


def png(path, w, h, rgba):
    stride = w * 4
    raw = b"".join(b"\x00" + bytes(rgba[y * stride:(y + 1) * stride]) for y in range(h))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", binascii.crc32(tag + data) & 0xFFFFFFFF))

    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b""))


def svg():
    """The same construction as vectors: the gear as one path, the field as a
    circle, and the star as a path with the seam punched out of it by
    fill-rule evenodd."""
    cx = cy = 50.0
    r = 49.0
    body = r * BODY
    hexes = "#{:02X}{:02X}{:02X}".format

    ring = (f"M {cx - body},{cy} a {body},{body} 0 1,0 {2 * body},0 "
            f"a {body},{body} 0 1,0 {-2 * body},0")
    tooth = []
    for q in teeth(cx, cy, r):
        tooth.append("M " + " L ".join(f"{x:.2f},{y:.2f}" for x, y in q) + " Z")

    star = star_points(cx, cy, r * STAR_R)
    half = r * STAR_R * SEAM_HALF
    apex = star[0]
    spath = "M " + " L ".join(f"{x:.2f},{y:.2f}" for x, y in star) + " Z"
    seam = (f"M {apex[0] - half:.2f},{apex[1]:.2f} L {apex[0] + half:.2f},{apex[1]:.2f} "
            f"L {cx:.2f},{cy:.2f} Z")

    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
            'role="img" aria-label="AUTARK cog and star">'
            f'<path d="{ring} {" ".join(tooth)}" fill="{hexes(*IRON)}"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r * FIELD_R:.2f}" fill="{hexes(*FIELD)}"/>'
            f'<path d="{spath} {seam}" fill="{hexes(*IRON)}" fill-rule="evenodd"/>'
            '</svg>')


def social(w, h, out):
    """Open Graph card: the mark on a dark field. No text, because rendering a
    wordmark means embedding a font, and every platform that shows this image
    shows the page title beside it."""
    px = bytearray(w * h * 4)
    for i in range(0, len(px), 4):
        px[i], px[i + 1], px[i + 2], px[i + 3] = DARK[0], DARK[1], DARK[2], 255
    size = int(h * 0.66)
    m = render(size, bg=DARK)
    ox, oy = (w - size) // 2, (h - size) // 2
    for y in range(size):
        d0 = ((oy + y) * w + ox) * 4
        s0 = (y * size) * 4
        px[d0:d0 + size * 4] = m[s0:s0 + size * 4]
    png(out, w, h, px)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/img")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    (out / "logo.svg").write_text(svg(), encoding="utf-8")
    made = ["logo.svg"]
    for s in (32, 180, 192, 512):
        png(out / f"icon-{s}.png", s, s, render(s))
        made.append(f"icon-{s}.png")
    social(1200, 630, out / "og.png")
    made.append("og.png")
    for f in made:
        print(f"  {f}  {(out / f).stat().st_size / 1024:.1f} KiB")


if __name__ == "__main__":
    main()
