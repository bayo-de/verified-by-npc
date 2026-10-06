#!/usr/bin/env python3
"""Build the 2-minute demo walkthrough video for the plugin review.

Every verification shot is a REAL response from the demo API bundle
(api/serverless), rendered as a card: the exact JSON the plugin receives,
plus the Ed25519 signature headers. No mockups, no localhost leakage.
Stdlib + PIL + ffmpeg. No em-dashes in any caption.
"""
import base64
import json
import os
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

BASE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = BASE
FRAMES = os.path.join(OUT_DIR, "video-frames")
VIDEO = os.path.join(OUT_DIR, "verified-by-npc-demo-2min.mp4")

W, H = 1920, 1080
BG = (24, 24, 24)
CARD = (32, 32, 36)
INK = (244, 244, 244)
MUTED = (169, 169, 169)
GREEN = (88, 204, 140)
AMBER = (232, 180, 90)
ACCENT = (94, 86, 246)
CAPTION_H = 190

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def font(size, bold=False, mono=False):
    return ImageFont.truetype(
        MONO if mono else (FONT_B if bold else FONT), size)


def wrap(draw, text, fnt, max_w):
    words, lines, cur = text.split(), [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(trial, font=fnt) <= max_w:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    lines.append(cur)
    return lines


def caption_bar(img, text):
    d = ImageDraw.Draw(img)
    d.rectangle([0, H - CAPTION_H, W, H], fill=(18, 18, 18))
    d.rectangle([0, H - CAPTION_H, W, H - CAPTION_H + 3], fill=ACCENT)
    fnt = font(34)
    lines = wrap(d, text, fnt, W - 160)
    y = H - CAPTION_H + 36
    for line in lines[:2]:
        d.text((80, y), line, font=fnt, fill=INK)
        y += 52


def card_slide(title, subtitle):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.ellipse([W // 2 - 26, 300, W // 2 + 26, 352], outline=ACCENT, width=5)
    d.line([W // 2 - 12, 328, W // 2 - 2, 340], fill=ACCENT, width=5)
    d.line([W // 2 - 2, 340, W // 2 + 14, 316], fill=ACCENT, width=5)
    tf, sf = font(84, bold=True), font(36)
    tw = d.textlength(title, font=tf)
    d.text(((W - tw) / 2, 400), title, font=tf, fill=INK)
    for i, line in enumerate(wrap(d, subtitle, sf, W - 400)):
        lw = d.textlength(line, font=sf)
        d.text(((W - lw) / 2, 540 + i * 56), line, font=sf, fill=MUTED)
    return img


def _shorten(value, max_len=64):
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len - 3] + "..."
    return value


def _trim(obj):
    if isinstance(obj, dict):
        return {k: _trim(_shorten(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_trim(_shorten(v)) for v in obj]
    return _shorten(obj)


def api_card_slide(title, method, path, status, headers, body_obj,
                   verdict_line, verdict_ok):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    pad, top = 90, 60
    d.rectangle([pad, top, W - pad, H - CAPTION_H - 30], fill=CARD,
                outline=(70, 70, 78), width=2)
    x, y = pad + 40, top + 30
    tf = font(40, bold=True)
    d.text((x, y), title, font=tf, fill=INK)
    y += 62
    mf = font(26, mono=True)
    req = f"{method} {path}"
    d.text((x, y), req, font=mf, fill=MUTED)
    y += 44
    sf = font(30, bold=True)
    d.text((x, y), f"HTTP {status}", font=sf,
           fill=GREEN if status == 200 else AMBER)
    y += 14
    vl = font(28, bold=True)
    vw = d.textlength(verdict_line, font=vl)
    d.text((W - pad - 40 - vw, top + 96), verdict_line, font=vl,
           fill=GREEN if verdict_ok else AMBER)
    y += 46
    sig = headers.get("X-NPC-Signature", "")
    kid = headers.get("X-NPC-Key-ID", "")
    hf = font(22, mono=True)
    d.text((x, y), f"X-NPC-Signature: {sig[:48]}...",
           font=hf, fill=MUTED)
    y += 32
    d.text((x, y), f"X-NPC-Key-ID: {kid}", font=hf, fill=MUTED)
    y += 44
    jf = font(22, mono=True)
    body_text = json.dumps(_trim(body_obj), indent=2)
    max_lines = 20
    lines = body_text.splitlines()
    shown = lines[:max_lines]
    if len(lines) > max_lines:
        shown.append(f"... ({len(lines) - max_lines} more lines)")
    for line in shown:
        d.text((x, y), line[:110], font=jf, fill=(210, 210, 215))
        y += 30
    return img


def call_demo_api():
    """Run the real staged function; return list of response dicts."""
    sys.path.insert(0, os.path.join(
        BASE, "..", "api", "serverless", "stage",
        "netlify", "functions"))
    sys.path.insert(0, os.path.join(
        BASE, "..", "api", "serverless", "stage",
        "netlify", "functions", "api_pkgs"))
    import api as function  # noqa: E402
    with open(os.path.join(
            BASE, "..", "api", "serverless", "stage", "netlify",
            "functions", "api_pkgs", "demo_env.json"),
            encoding="utf-8") as f:
        key = json.load(f)["demo_verifier_key"]

    def ev(method, path, body=None):
        raw = json.dumps(body) if body is not None else None
        return {"httpMethod": method, "path": path,
                "headers": {"authorization": f"Bearer {key}"},
                "body": raw, "isBase64Encoded": False}

    calls = [
        ("Verify a product", "GET", "/v1/products/demo-tag-001", None,
         "verdict: verified (authentic)", True),
        ("Verify a credential", "GET", "/v1/credentials/demo-cred-001",
         None, "status: valid", True),
        ("Verify a claim", "POST", "/v1/claims/verify",
         {"claim_text": "the product shipped on demo date"},
         "matched: True, verdict: verified", True),
        ("Verify an AI agent", "GET",
         "/v1/agents/demo-agent-001/attestation", None,
         "verdict: verified", True),
        ("Unknown subject", "GET", "/v1/products/no-such-tag", None,
         "verdict: unknown (fail-closed)", False),
    ]
    out = []
    for title, method, path, body, verdict_line, ok in calls:
        resp = function.handler(ev(method, path, body), None)
        out.append((title, method, path, resp["statusCode"],
                    resp["headers"], json.loads(resp["body"]),
                    verdict_line, ok))
    return out


SECONDS_PER_SLIDE = 12


def main():
    os.makedirs(FRAMES, exist_ok=True)
    slides = []
    slides.append(card_slide(
        "Verified by NPC",
        "Is this real? Verify it. A two minute demo."))
    slides.append(card_slide(
        "One question",
        "Is this real? Products. Credentials. Claims. AI agents."))
    for (title, method, path, status, headers, body, verdict_line,
         ok) in call_demo_api():
        slides.append(api_card_slide(title, method, path, status,
                                     headers, body, verdict_line, ok))
    captions = [
        "The trust layer for commerce, inside the conversation.",
        "Five operations: verify product, credential, claim, agent. Plus a plain-language explainer.",
        "Verify a product: smart tag demo-tag-001 comes back authentic, with its provenance chain.",
        "Verify a credential: demo-cred-001 is valid. Revoked and expired are reported plainly.",
        "Verify a claim: a matched attestation shows the verdict, scope, and time bounds.",
        "Verify an AI agent: demo-agent-001 is verified, with scope and time bounds.",
        "Fail-closed: no record means the answer is unknown. Unknown is never a guess.",
    ]
    slides.append(card_slide(
        "Signed, always",
        "Every response carries an Ed25519 signature. Public keys are published for independent checking."))
    captions.append(
        "The plugin checks the signature on every answer before trusting it.")
    slides.append(card_slide(
        "Verifies only",
        "The plugin cannot issue attestations, and it never explains its checking methodology."))
    captions.append(
        "Ask it to record a verification or reveal the methodology and it declines.")
    slides.append(card_slide(
        "Verified by NPC",
        "Is this real? Verify it. npclabs.xyz"))
    captions.append("Version 1.0.0. Read-only. Signed. Fail-closed.")

    assert len(slides) == len(captions), (len(slides), len(captions))
    frame_files = []
    for i, (img, cap) in enumerate(zip(slides, captions)):
        caption_bar(img, cap)
        fp = os.path.join(FRAMES, f"slide-{i:02d}.png")
        img.save(fp)
        frame_files.append(fp)
        # keep the API cards as listing screenshots too
        if 2 <= i <= 6:
            img.save(os.path.join(
                OUT_DIR, f"listing-shot-{i - 1:02d}.png"))
    print(f"{len(frame_files)} slides rendered")

    lst = os.path.join(FRAMES, "slides.txt")
    with open(lst, "w") as f:
        for fp in frame_files:
            f.write(f"file '{fp}'\nduration {SECONDS_PER_SLIDE}\n")
        f.write(f"file '{frame_files[-1]}'\n")
    cmd = ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", lst,
           "-vf", "format=yuv420p", "-c:v", "libx264", "-crf", "20",
           "-preset", "veryfast", VIDEO]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-2000:])
        return 1
    dur = float(subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", VIDEO],
        capture_output=True, text=True).stdout.strip())
    print(f"video: {VIDEO} ({dur:.0f}s, {os.path.getsize(VIDEO)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
