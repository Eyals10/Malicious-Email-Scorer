"""Draws the risk gauge as an animated GIF: a short 'Analyzing...' scan, then the needle
sweeps up to the score and paints the band behind it from green to red."""
import colorsys
import io
import math
import sys
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

S = 3                                   # draw 3x bigger, then shrink: smooth edges
W, H = 600, 380                         # drawing size, before shrinking
OUT = (480, 304)                        # saved size: sharp in the ~300 px wide sidebar
CX, CY, R, BAND = 300, 255, 205, 46     # centre, radius, band thickness
BG, GREY, INK, MUTED = (255, 255, 255), (226, 228, 231), (60, 64, 67), (128, 134, 139)
STOPS = [(0, (52, 168, 83)), (35, (251, 188, 4)), (62, (250, 123, 23)), (100, (234, 67, 53))]
INTRO_FRAMES, INTRO_MS = 14, 60
SWEEP_FRAMES, SWEEP_MS = 22, 55
_BOX = [(CX - R) * S, (CY - R) * S, (CX + R) * S, (CY + R) * S]


def color_at(v: float) -> tuple[int, int, int]:
    """Band colour at score v. Blends hue, not RGB, so green -> yellow stays bright instead of olive."""
    for (v0, c0), (v1, c1) in zip(STOPS, STOPS[1:]):
        if v <= v1:
            t = (v - v0) / (v1 - v0)
            a = colorsys.rgb_to_hsv(*(x / 255 for x in c0))
            b = colorsys.rgb_to_hsv(*(x / 255 for x in c1))
            rgb = colorsys.hsv_to_rgb(*(p + (q - p) * t for p, q in zip(a, b)))
            return tuple(round(x * 255) for x in rgb)
    return STOPS[-1][1]


def _angle(v):
    return 180 + 1.8 * v   # 0 -> left, 100 -> right; Pillow counts clockwise from 3 o'clock


def _point(v, r):
    a = math.radians(_angle(v))
    return CX * S + r * S * math.cos(a), CY * S + r * S * math.sin(a)


def _cap(draw, v, color):
    """Round end of the band."""
    x, y = _point(v, R - BAND / 2)
    r = BAND * S / 2
    draw.ellipse([x - r, y - r, x + r, y + r], fill=color)


@lru_cache(maxsize=1)
def _layers():
    """Drawn once: the grey band, the fully coloured band (frames reveal part of it), the fonts."""
    grey = Image.new("RGB", (W * S, H * S), BG)
    d = ImageDraw.Draw(grey)
    d.arc(_BOX, 180, 360, fill=GREY, width=BAND * S)
    _cap(d, 0, GREY)
    _cap(d, 100, GREY)

    colored = Image.new("RGB", grey.size, BG)
    d = ImageDraw.Draw(colored)
    for i in range(400):  # many thin slices, each its own colour
        v = i / 4
        d.arc(_BOX, _angle(v), _angle(min(v + 0.4, 100)), fill=color_at(v), width=BAND * S)

    fonts = {size: ImageFont.load_default(size=size * S) for size in (18, 30, 64)}
    return grey, colored, fonts


def _frame(v: float, label: str | None = None) -> Image.Image:
    """The gauge with the needle at v. With a label (the intro), the band stays grey."""
    grey, colored, fonts = _layers()
    img = grey.copy()
    d = ImageDraw.Draw(img)
    if v > 0 and label is None:
        mask = Image.new("L", img.size, 0)
        ImageDraw.Draw(mask).pieslice(_BOX, 180, _angle(v), fill=255)
        img.paste(colored, (0, 0), mask)
        _cap(d, 0, color_at(0))
        _cap(d, v, color_at(v))

    for t in (30, 70):  # thin gaps where the verdict changes
        d.line([_point(t, R - BAND - 2), _point(t, R + 2)], fill=BG, width=4 * S)

    tip = _point(v, R - BAND - 14)
    a = math.radians(_angle(v))
    nx, ny = -math.sin(a) * 9 * S, math.cos(a) * 9 * S
    d.polygon([tip, (CX * S + nx, CY * S + ny), (CX * S - nx, CY * S - ny)], fill=INK)
    for radius, color in ((18, INK), (7, BG)):  # hub with a white dot
        r = radius * S
        d.ellipse([CX * S - r, CY * S - r, CX * S + r, CY * S + r], fill=color)

    for text, val in (("0", 0), ("100", 100)):
        x, _ = _point(val, R - BAND / 2)
        d.text((x, (CY + 28) * S), text, fill=MUTED, font=fonts[18], anchor="mt")
    if label is None:
        darker = tuple(round(c * 0.78) for c in color_at(v))  # pale yellow stays readable on white
        d.text((CX * S, (CY + 34) * S), str(round(v)), fill=darker, font=fonts[64], anchor="mt")
    else:
        d.text((CX * S, (CY + 50) * S), label, fill=MUTED, font=fonts[30], anchor="mt")
    return img.resize(OUT, Image.LANCZOS)


@lru_cache(maxsize=101)
def gauge_gif(score: int) -> bytes:
    """The animation for one score. Same score, same picture, so each is drawn once per server."""
    frames = []
    for i in range(INTRO_FRAMES):  # needle scans 0 -> 100 -> 0 while the dots cycle
        t = i / (INTRO_FRAMES - 1)
        frames.append(_frame(100 * math.sin(math.pi * t) ** 2, "Analyzing" + "." * (1 + (i // 3) % 3)))
    for i in range(SWEEP_FRAMES):  # eases out: fast start, slows near the score
        t = i / (SWEEP_FRAMES - 1)
        frames.append(_frame(score * (1 - (1 - t) ** 3)))
    durations = [INTRO_MS] * INTRO_FRAMES + [SWEEP_MS] * (SWEEP_FRAMES - 1) + [60_000]  # hold the end
    buf = io.BytesIO()
    frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:], duration=durations, optimize=True)
    return buf.getvalue()  # no loop setting, so it plays once


if __name__ == "__main__":
    # Runs while the Docker image is built: draw every possible score once and save it as a file,
    # so the server only sends ready files. Usage: python gauge.py OUTPUT_FOLDER
    out = Path(sys.argv[1])
    out.mkdir(exist_ok=True)
    scores = range(0, 101, 5)  # all signal points and caps are multiples of 5; main.py draws any other score on the fly
    with ProcessPoolExecutor() as pool:  # all CPU cores, for a shorter build
        for score, gif in zip(scores, pool.map(gauge_gif, scores)):
            (out / f"{score}.gif").write_bytes(gif)
