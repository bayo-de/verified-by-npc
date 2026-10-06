#!/usr/bin/env python3
"""Build the mark review contact sheet (PNG) for internal review.

Not for public use. Shows all variants at multiple sizes on light and
dark grounds, with plain-language labels.
"""
import os

from PIL import Image, ImageDraw, ImageFont

BRAND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PNG_DIR = os.path.join(BRAND_DIR, "png")
OUT_DIR = os.path.join(BRAND_DIR, "preview")

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

W, H = 1800, 1920
LIGHT = (255, 255, 255)
DARK = (24, 24, 24)
INK = (24, 24, 24)
MUTED = (111, 111, 111)
ORANGE = (255, 106, 0)


def label(draw, xy, text, size=30, bold=False, fill=MUTED):
    font = ImageFont.truetype(FONT_BOLD if bold else FONT, size)
    draw.text(xy, text, font=font, fill=fill)


def paste_centered(canvas, png_path, box):
    """Paste a PNG scaled to fit inside box (x, y, w, h), centered."""
    img = Image.open(png_path).convert("RGBA")
    x, y, w, h = box
    s = min(w / img.width, h / img.height)
    img = img.resize((int(img.width * s), int(img.height * s)), Image.LANCZOS)
    cx = x + (w - img.width) // 2
    cy = y + (h - img.height) // 2
    canvas.alpha_composite(img, (cx, cy))


def row(canvas, y, bg, items, title, note, step=580, boxw=520):
    draw = ImageDraw.Draw(canvas)
    draw.rectangle([0, y, W, y + 560], fill=bg)
    ink = INK if bg == LIGHT else LIGHT
    muted = MUTED if bg == LIGHT else (170, 170, 170)
    label(draw, (80, y + 36), title, size=38, bold=True, fill=ink)
    label(draw, (80, y + 90), note, size=28, fill=muted)
    x = 80
    for name, size_px, caption in items:
        box = (x, y + 150, boxw, 300)
        png = os.path.join(PNG_DIR, name, f"verified-by-npc-{name}-{size_px}.png")
        if size_px <= 64:
            # True pixel size: paste the exact-size export, centered.
            img = Image.open(png).convert("RGBA")
            cx = box[0] + (box[2] - img.width) // 2
            cy = box[1] + (box[3] - img.height) // 2
            canvas.alpha_composite(img, (cx, cy))
        else:
            paste_centered(canvas, png, box)
        label(draw, (x, y + 470), caption, size=26, fill=muted)
        x += step
    return y + 560


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    canvas = Image.new("RGBA", (W, H), LIGHT)
    draw = ImageDraw.Draw(canvas)
    label(draw, (80, 40), "Verified by NPC mark, review sheet",
          size=48, bold=True, fill=INK)
    label(draw, (80, 110),
          "DRAFT for internal review only. Not for public use. "
          "Public use needs Bayo's tap plus counsel clearance.",
          size=30, fill=MUTED)

    y = 190
    y = row(canvas, y, LIGHT, [
        ("primary", 256, "Primary. NPC Orange #FF6A00.\n24 px and up."),
        ("small", 256, "Small variant. Heavier cut.\n16 to 32 px."),
        ("mono-black", 256, "Mono black.\nOne-color, light grounds."),
    ], "The three variants", "One gesture. No circle, no badge, no blue check.")
    y = row(canvas, y, LIGHT, [
        ("primary", 64, "Primary at 64 px"),
        ("primary", 32, "Primary at 32 px"),
        ("small", 32, "Small variant at 32 px"),
        ("small", 16, "Small variant at 16 px"),
    ], "Size ladder", "Below 24 px, switch to the small-size variant. Never below 16 px.",
       step=430, boxw=400)
    y = row(canvas, y, DARK, [
        ("mono-white", 256, "Mono white.\nOne-color, dark grounds."),
        ("primary", 256, "Primary on dark.\nOrange holds on black."),
    ], "On dark grounds", "White mono for one-color dark use. Orange primary may sit on dark.")

    out = os.path.join(OUT_DIR, "verified-by-npc-preview.png")
    canvas.convert("RGB").save(out)
    print("wrote", out)


if __name__ == "__main__":
    main()
