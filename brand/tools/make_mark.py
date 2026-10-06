#!/usr/bin/env python3
"""Generate the "Verified by NPC" mark artwork.

DRAFT artwork for internal review only. Not for public use.
Public use requires Bayo's explicit approval AND counsel clearance.

The mark: a single tapered orange check, one gesture. No circle, no badge,
no generic blue checkmark. Built as a filled path so the stroke tapers from
a confident entry to a light exit, and the long-arm tip carries a forward
slice (the "NPC cut").

Geometry parameters live in VARIANTS below, so the mark is reproducible
from numbers, not from an Illustrator file.
"""
import math
import os

import cairosvg

BRAND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG_DIR = os.path.join(BRAND_DIR, "svg")
PNG_DIR = os.path.join(BRAND_DIR, "png")

NPC_ORANGE = "#FF6A00"
MONO_BLACK = "#181818"
MONO_WHITE = "#FFFFFF"

DRAFT_COMMENT = (
    "<!-- DRAFT artwork for internal review only. NOT for public use. "
    "Public use requires Bayo's explicit approval AND counsel clearance. -->"
)

# Variant parameters: centerline points (P0 entry, P1 vertex, P2 tip),
# half-widths at each joint, tip slice angle in degrees.
VARIANTS = {
    "primary": dict(
        color=NPC_ORANGE, P0=(21.0, 47.0), P1=(42.0, 66.0), P2=(79.0, 29.0),
        w0=8.5, w1=8.0, w2=3.5, tip_slice_deg=25.0,
    ),
    "small": dict(
        color=NPC_ORANGE, P0=(21.0, 47.0), P1=(42.0, 66.0), P2=(75.0, 31.0),
        w0=10.0, w1=9.5, w2=5.0, tip_slice_deg=15.0,
    ),
    "mono-black": dict(
        color=MONO_BLACK, P0=(21.0, 47.0), P1=(42.0, 66.0), P2=(79.0, 29.0),
        w0=8.5, w1=8.0, w2=3.5, tip_slice_deg=25.0,
    ),
    "mono-white": dict(
        color=MONO_WHITE, P0=(21.0, 47.0), P1=(42.0, 66.0), P2=(79.0, 29.0),
        w0=8.5, w1=8.0, w2=3.5, tip_slice_deg=25.0,
    ),
}

EXPORT_SIZES = [16, 32, 64, 128, 256, 512, 1024]


def _norm(v):
    x, y = v
    m = math.hypot(x, y)
    return (x / m, y / m)


def _add(a, b):
    return (a[0] + b[0], a[1] + b[1])


def _sub(a, b):
    return (a[0] - b[0], a[1] - b[1])


def _mul(v, s):
    return (v[0] * s, v[1] * s)


def _dot(a, b):
    return a[0] * b[0] + a[1] * b[1]


def check_path(P0, P1, P2, w0, w1, w2, tip_slice_deg):
    """Return an SVG path string for the filled tapered check."""
    d1 = _norm(_sub(P1, P0))
    d2 = _norm(_sub(P2, P1))
    # Outer (downward-facing) normals in SVG's y-down coordinates.
    n1 = (-d1[1], d1[0])
    n2 = (-d2[1], d2[0])
    if n1[1] < 0:
        n1 = _mul(n1, -1)
    if n2[1] < 0:
        n2 = _mul(n2, -1)

    def line_intersect(pa, da, pb, db):
        # Solve pa + t*da = pb + u*db.
        denom = da[0] * db[1] - da[1] * db[0]
        t = ((pb[0] - pa[0]) * db[1] - (pb[1] - pa[1]) * db[0]) / denom
        return _add(pa, _mul(da, t))

    # Entry butt cap.
    C1 = _add(P0, _mul(n1, w0))
    C2 = _sub(P0, _mul(n1, w0))
    # Vertex miters (outer and inner).
    Mo = line_intersect(_add(P0, _mul(n1, w1)), d1, _add(P1, _mul(n2, w1)), d2)
    Mi = line_intersect(_sub(P0, _mul(n1, w1)), d1, _sub(P1, _mul(n2, w1)), d2)
    # Tip: outer edge leads with a forward slice of tip_slice_deg.
    t = 2 * w2 * math.tan(math.radians(tip_slice_deg))
    To = _add(_add(P2, _mul(n2, w2)), _mul(d2, t))
    Ti = _sub(P2, _mul(n2, w2))

    pts = [C1, Mo, To, Ti, Mi, C2]
    d = "M " + " L ".join(f"{x:.2f} {y:.2f}" for x, y in pts) + " Z"
    return d


def build_svg(variant, color):
    d = check_path(
        variant["P0"], variant["P1"], variant["P2"],
        variant["w0"], variant["w1"], variant["w2"],
        variant["tip_slice_deg"],
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'{DRAFT_COMMENT}\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" '
        'viewBox="0 0 96 96">\n'
        f'  <path d="{d}" fill="{color}"/>\n'
        '</svg>\n'
    )


def main():
    os.makedirs(SVG_DIR, exist_ok=True)
    for name, v in VARIANTS.items():
        svg = build_svg(v, v["color"])
        svg_path = os.path.join(SVG_DIR, f"verified-by-npc-{name}.svg")
        with open(svg_path, "w") as f:
            f.write(svg)
        subdir = os.path.join(PNG_DIR, name)
        os.makedirs(subdir, exist_ok=True)
        for size in EXPORT_SIZES:
            out = os.path.join(subdir, f"verified-by-npc-{name}-{size}.png")
            cairosvg.svg2png(
                bytestring=svg.encode("utf-8"),
                write_to=out,
                output_width=size,
                output_height=size,
            )
        print(f"wrote {name}: svg + {len(EXPORT_SIZES)} pngs")


if __name__ == "__main__":
    main()
