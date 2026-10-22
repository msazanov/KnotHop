#!/usr/bin/env python3
"""Генератор иконки KnotHop: SVG трёх вариантов, превью, VectorDrawable и legacy PNG.

Одна геометрия питает все выходы. Только стандартная библиотека, Pillow и rsvg-convert,
сети нет. Запуск из любого каталога: python3 design/icon/tools/gen.py
"""
import math
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ICON = Path(__file__).resolve().parent.parent
PREV = ICON / "previews"
RES = ICON / "android-res"

# Рекомендованный вариант, из которого собираются ресурсы Android: "a", "b" или "c".
RECOMMENDED = "c"

BG = "#0D2538"      # тёмно-сине-бирюзовый фон, одинаков для светлой и тёмной темы
LINE = "#F4F7FA"    # линия пути и промежуточные узлы
ACCENT = "#34D399"  # старт и выход
MONO = "#000000"    # монохром: Android берёт только альфа-канал
SW = 7.0            # толщина линии в единицах viewport
HALO = 2.6          # зазор с каждой стороны у «подныривания» линии
SAMPLES = 48        # отсчётов на сегмент Безье при поиске пересечений
SAFE_R = 33.0      # радиус безопасной зоны adaptive icon (диаметр 66 по центру)
CENTER = 54.0


# ---------- кривые ----------

def catmull_rom(pts, closed):
    """Кубические Безье, проходящие через pts (uniform Catmull-Rom)."""
    n = len(pts)
    segs = []
    for i in range(n if closed else n - 1):
        p1 = pts[i]
        p2 = pts[(i + 1) % n]
        if closed:
            p0 = pts[(i - 1) % n]
            p3 = pts[(i + 2) % n]
        else:
            # на концах отражаем соседнюю точку, чтобы касательная оставалась гладкой
            p0 = pts[i - 1] if i > 0 else (2 * p1[0] - p2[0], 2 * p1[1] - p2[1])
            p3 = pts[i + 2] if i + 2 < n else (2 * p2[0] - p1[0], 2 * p2[1] - p1[1])
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6)
        segs.append((p1, c1, c2, p2))
    return segs


def bez_pt(b, t):
    p0, p1, p2, p3 = b
    mt = 1 - t
    return (
        mt**3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t**3 * p3[0],
        mt**3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t**3 * p3[1],
    )


def split(b, t):
    """De Casteljau: делит кубическую Безье в точке t на (левую, правую) части."""
    p0, p1, p2, p3 = b

    def lerp(a, c):
        return (a[0] + (c[0] - a[0]) * t, a[1] + (c[1] - a[1]) * t)

    a = lerp(p0, p1)
    bb = lerp(p1, p2)
    c = lerp(p2, p3)
    d = lerp(a, bb)
    e = lerp(bb, c)
    f = lerp(d, e)
    return (p0, a, d, f), (f, e, c, p3)


def sub_bez(b, t0, t1):
    """Участок кубической Безье между параметрами t0 и t1."""
    if t0 > 0:
        _, b = split(b, t0)
        t1 = (t1 - t0) / (1 - t0)
    if t1 < 1:
        b, _ = split(b, t1)
    return b


class Curve:
    """Кривая из Безье с таблицей отсчётов: индекс u = k*SAMPLES + j, длина дуги по отсчётам."""

    def __init__(self, segs, closed):
        self.segs = segs
        self.closed = closed
        self.pts = [bez_pt(b, j / SAMPLES) for b in segs for j in range(SAMPLES)]
        self.pts.append(bez_pt(segs[-1], 1.0))
        self.arc = [0.0]
        for a, b in zip(self.pts, self.pts[1:]):
            self.arc.append(self.arc[-1] + math.dist(a, b))
        self.length = self.arc[-1]

    def s_of_u(self, u):
        m_max = len(self.arc) - 1
        u = min(max(u, 0.0), m_max)
        m = min(int(u), m_max - 1)
        f = u - m
        return self.arc[m] + f * (self.arc[m + 1] - self.arc[m])

    def u_of_s(self, s):
        lo, hi = 0, len(self.arc) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self.arc[mid] <= s:
                lo = mid
            else:
                hi = mid
        f = (s - self.arc[lo]) / (self.arc[hi] - self.arc[lo])
        return lo + f

    def point_u(self, u):
        k, t = self.seg_t(u)
        return bez_pt(self.segs[k], t)

    def seg_t(self, u):
        n = len(self.segs)
        u = min(max(u, 0.0), n * SAMPLES)
        k = min(int(u // SAMPLES), n - 1)
        return k, (u - k * SAMPLES) / SAMPLES

    def extract(self, u0, u1):
        """Безье, покрывающие участок параметра [u0, u1]."""
        out = []
        for k, b in enumerate(self.segs):
            lo, hi = k * SAMPLES, (k + 1) * SAMPLES
            a, c = max(u0, lo), min(u1, hi)
            if c - a > 1e-9:
                out.append(sub_bez(b, (a - lo) / SAMPLES, (c - lo) / SAMPLES))
        return out


def seg_hit(p, p2, q, q2):
    rx, ry = p2[0] - p[0], p2[1] - p[1]
    sx, sy = q2[0] - q[0], q2[1] - q[1]
    den = rx * sy - ry * sx
    if abs(den) < 1e-9:
        return None
    wx, wy = q[0] - p[0], q[1] - p[1]
    t = (wx * sy - wy * sx) / den
    u = (wx * ry - wy * rx) / den
    if 0 <= t < 1 and 0 <= u < 1:
        return t, u, (p[0] + t * rx, p[1] + t * ry)
    return None


def crossings(curve):
    """Самопересечения ломаной по отсчётам. Возвращает список {uA, uB, pt}."""
    P = curve.pts
    M = len(P) - 1
    found = []
    for i in range(M):
        for j in range(i + 4, M):
            if curve.closed and M - (j - i) < 4:
                continue  # соседние сегменты через замыкание
            hit = seg_hit(P[i], P[i + 1], P[j], P[j + 1])
            if not hit:
                continue
            t, u, pt = hit
            if any(math.dist(pt, c["pt"]) < 1.0 for c in found):
                continue
            found.append({"uA": i + t, "uB": j + u, "pt": pt})
    return found


def under_visits(xs):
    """Чередование over/under вдоль кривой. Возвращает u точек «под» и флаг, что чередование сошлось."""
    visits = sorted((u, i) for i, c in enumerate(xs) for u in (c["uA"], c["uB"]))
    alt = True
    for i in range(len(xs)):
        pos = [p for p, (_, j) in enumerate(visits) if j == i]
        if (pos[1] - pos[0]) % 2 == 0:
            alt = False
    unders = []
    for i in range(len(xs)):
        us = [(p, u) for p, (u, j) in enumerate(visits) if j == i]
        if alt:
            unders.append(next(u for p, u in us if p % 2 == 1))
        else:
            unders.append(us[-1][1])
    return unders, alt


def complement(cuts, lo, hi):
    out = []
    cur = lo
    for a, b in sorted(cuts):
        a, b = max(a, lo), min(b, hi)
        if a > cur + 1e-6:
            out.append((cur, a))
        cur = max(cur, b)
    if hi > cur + 1e-6:
        out.append((cur, hi))
    return out


# ---------- варианты ----------

def pretzel():
    """A: классический крендель — петля сверху, хвосты скрещиваются внизу."""
    # S — хвост внизу слева (старт), E — хвост внизу справа (выход); петля сверху,
    # хвосты идут крест-накрест под ней. Один промежуточный узел — на вершине петли.
    raw = [(40, 76), (68, 58), (76, 38), (54, 24), (32, 38), (40, 58), (68, 76)]
    k = 0.89  # сжатие к центру: Catmull-Rom дает выброс за контуры опорных точек
    pts = [(CENTER + k * (x - CENTER), CENTER + k * (y - CENTER)) for x, y in raw]
    return {
        "title": "A · Крендель: петля и скрещённые хвосты",
        "segs": catmull_rom(pts, False), "closed": False, "hub": False, "gap_ends": None,
        "nodes": [("start", None, 6.5, ACCENT), ("end", None, 6.5, ACCENT),
                  ("cp", 3, 5.5, LINE)],
    }


def trefoil(offset=math.pi / 3):
    """B: один непрерывный узел (проекция трилистника) с разрывом-«прыжком».

    offset сдвигает начало обхода: разрыв у конца линии не должен совпасть с перекрестием.
    """
    n = 36
    raw = []
    for k in range(n):
        t = offset + 2 * math.pi * k / n
        raw.append((math.sin(t) + 2 * math.sin(2 * t), math.cos(t) - 2 * math.cos(2 * t)))
    mx = sum(x for x, _ in raw) / n
    my = sum(y for _, y in raw) / n
    scale = 26.5 / max(math.hypot(x - mx, y - my) for x, y in raw)
    pts = [(CENTER + scale * (x - mx), CENTER + scale * (y - my)) for x, y in raw]
    return {
        "title": "B · Узел одной линией с прыжками",
        "segs": catmull_rom(pts, True), "closed": True, "hub": False, "gap_ends": 10.0,
        "nodes": [("start", None, 6.5, ACCENT), ("end", None, 6.5, ACCENT),
                  ("cp", 12, 5.5, LINE), ("cp", 24, 5.5, LINE)],
    }


def eight():
    """C: восьмёрка с тремя точками; центральный узел-хаб закрывает перекрёсток."""
    n = 32
    pts = []
    for k in range(n):
        t = 2 * math.pi * k / n
        pts.append((CENTER + 24 * math.cos(t), CENTER + 12 * math.sin(2 * t)))
    return {
        "title": "C · Восьмёрка: старт, хаб, выход",
        "segs": catmull_rom(pts, True), "closed": True, "hub": True, "gap_ends": None,
        "nodes": [("cp", 16, 7, ACCENT), ("cp", 0, 7, ACCENT), ("hub", None, 6.5, ACCENT)],
    }


# ---------- сборка элементов ----------

def fmt(v):
    s = "%.2f" % v
    s = s.rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def bez_d(beziers):
    p0 = beziers[0][0]
    parts = ["M%s %s" % (fmt(p0[0]), fmt(p0[1]))]
    for _, c1, c2, p3 in beziers:
        parts.append("C%s %s %s %s %s %s" % (fmt(c1[0]), fmt(c1[1]), fmt(c2[0]), fmt(c2[1]), fmt(p3[0]), fmt(p3[1])))
    return " ".join(parts)


def circle_d(cx, cy, r):
    return "M%s %s A%s %s 0 1 0 %s %s A%s %s 0 1 0 %s %s Z" % (
        fmt(cx - r), fmt(cy), fmt(r), fmt(r), fmt(cx + r), fmt(cy),
        fmt(r), fmt(r), fmt(cx - r), fmt(cy))


def build(spec):
    """Строит элементы переднего плана: {kind, d, color, r?} и диагностику."""
    curve = Curve(spec["segs"], spec["closed"])
    L = curve.length
    xs = crossings(curve)
    cuts = []
    if spec["gap_ends"]:
        h = spec["gap_ends"]
        cuts += [(0.0, h), (L - h, L)]
    diag = {"crossings": len(xs), "alt": None, "pieces": None}
    if not spec["hub"] and xs:
        unders, alt = under_visits(xs)
        diag["alt"] = alt
        for u in unders:
            s = curve.s_of_u(u)
            cuts.append((s - SW / 2 - HALO, s + SW / 2 + HALO))
    pieces = complement(cuts, 0.0, L)

    elems = []
    for s0, s1 in pieces:
        beziers = curve.extract(curve.u_of_s(s0), curve.u_of_s(s1))
        if beziers:
            elems.append({"kind": "stroke", "d": bez_d(beziers), "color": LINE, "beziers": beziers})

    diag["pieces"] = len(elems)
    first = elems[0]["beziers"][0][0]
    last = elems[-1]["beziers"][-1][3]
    hub_pt = xs[0]["pt"] if xs else None
    for where, idx, r, color in spec["nodes"]:
        if where == "start":
            c = first
        elif where == "end":
            c = last
        elif where == "cp":
            c = curve.point_u(idx * SAMPLES)
        else:
            c = hub_pt
        elems.append({"kind": "fill", "d": circle_d(c[0], c[1], r), "color": color, "center": c, "r": r})
    return elems, diag


def max_radius(elems):
    """Наибольшее расстояние от центра до края штриха или узла (для проверки безопасной зоны)."""
    worst = 0.0
    for e in elems:
        if e["kind"] == "stroke":
            for b in e["beziers"]:
                for j in range(21):
                    x, y = bez_pt(b, j / 20)
                    worst = max(worst, math.hypot(x - CENTER, y - CENTER) + SW / 2)
        else:
            cx, cy = e["center"]
            worst = max(worst, math.hypot(cx - CENTER, cy - CENTER) + e["r"])
    return worst


def recolor(elems, color):
    return [dict(e, color=color) for e in elems]


# ---------- выводы ----------

def svg_doc(elems, bg):
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="108" height="108" viewBox="0 0 108 108">']
    if bg:
        out.append('  <rect width="108" height="108" fill="%s"/>' % bg)
    for e in elems:
        if e["kind"] == "stroke":
            out.append('  <path d="%s" fill="none" stroke="%s" stroke-width="%s" stroke-linecap="round" stroke-linejoin="round"/>'
                       % (e["d"], e["color"], fmt(SW)))
        else:
            out.append('  <path d="%s" fill="%s"/>' % (e["d"], e["color"]))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def vector_drawable(elems=None, background=False, mono=False):
    head = ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
            '    android:width="108dp"\n'
            '    android:height="108dp"\n'
            '    android:viewportWidth="108"\n'
            '    android:viewportHeight="108">\n')
    body = []
    if background:
        body.append('    <path\n        android:fillColor="%s"\n        android:pathData="M0,0h108v108h-108z" />\n' % BG)
    else:
        for e in elems:
            color = "#FF000000" if mono else "#FF" + e["color"][1:]
            if e["kind"] == "stroke":
                body.append('    <path\n        android:fillColor="#00000000"\n'
                            '        android:pathData="%s"\n'
                            '        android:strokeColor="%s"\n'
                            '        android:strokeWidth="%s"\n'
                            '        android:strokeLineCap="round"\n'
                            '        android:strokeLineJoin="round" />\n' % (e["d"], color, fmt(SW)))
            else:
                body.append('    <path\n        android:fillColor="%s"\n        android:pathData="%s" />\n' % (color, e["d"]))
    return head + "".join(body) + "</vector>\n"


def render(svg, out, size):
    subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size), "-o", str(out), str(svg)], check=True)


def font(size):
    for p in ("/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size)


def circle_mask(img):
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, img.size[0] - 1, img.size[1] - 1), fill=255)
    out = img.copy()
    out.putalpha(mask)
    return out


def on(img, color):
    base = Image.new("RGBA", img.size, color)
    base.alpha_composite(img)
    return base


def sheet(rows, path):
    """rows: [(заголовок, [(картинка, фон, подпись), ...])]."""
    gap, margin, label_h, title_h = 20, 24, 22, 40
    cap_font = font(14)
    scratch = ImageDraw.Draw(Image.new("RGBA", (1, 1)))

    def cell_w(im, cap):
        return max(im.size[0], int(scratch.textlength(cap, font=cap_font)))

    row_w = [sum(cell_w(im, cap) for im, _, cap in items) + gap * (len(items) - 1) for _, items in rows]
    W = max(row_w) + 2 * margin
    H = margin + sum(title_h + max(im.size[1] for im, _, _ in items) + label_h + gap for _, items in rows) + margin
    canvas = Image.new("RGBA", (W, H), (255, 255, 255, 255))
    d = ImageDraw.Draw(canvas)
    y = margin
    for title, items in rows:
        d.text((margin, y), title, fill=(20, 20, 20, 255), font=font(24))
        y += title_h
        x = margin
        top = y
        for im, bgc, cap in items:
            w = cell_w(im, cap)
            cell = on(im, bgc)
            canvas.paste(cell, (x + (w - im.size[0]) // 2, top), cell)
            d.text((x + (w - int(scratch.textlength(cap, font=cap_font))) // 2, top + im.size[1] + 2),
                   cap, fill=(60, 60, 60, 255), font=cap_font)
            x += w + gap
        y += max(im.size[1] for im, _, _ in items) + label_h + gap
    canvas.save(path)


def main():
    PREV.mkdir(parents=True, exist_ok=True)
    tmp = PREV / "_tmp"
    tmp.mkdir(exist_ok=True)
    variants = {"a": pretzel(), "b": trefoil(), "c": eight()}
    rows = []
    fg = {}
    for key, spec in variants.items():
        elems, diag = build(spec)
        radius = max_radius(elems)
        print("variant-%s: crossings=%d alt=%s pieces=%d max_radius=%.2f (safe %.1f)"
              % (key, diag["crossings"], diag["alt"], diag["pieces"], radius, SAFE_R))
        if radius > SAFE_R:
            sys.exit("variant-%s выходит за безопасную зону" % key)
        fg[key] = elems
        full = svg_doc(elems, BG)
        svg = ICON / ("variant-%s.svg" % key)
        svg.write_text(full, encoding="utf-8")
        mono_svg = tmp / ("mono-%s.svg" % key)
        mono_svg.write_text(svg_doc(recolor(elems, MONO), None), encoding="utf-8")
        for size in (512, 192, 48):
            render(svg, PREV / ("variant-%s-%d.png" % (key, size)), size)
        render(mono_svg, PREV / ("variant-%s-mono-192.png" % key), 192)
        render(mono_svg, PREV / ("variant-%s-mono-48.png" % key), 48)

        im512 = Image.open(PREV / ("variant-%s-512.png" % key)).convert("RGBA")
        im192 = Image.open(PREV / ("variant-%s-192.png" % key)).convert("RGBA")
        im48 = Image.open(PREV / ("variant-%s-48.png" % key)).convert("RGBA")
        circ192 = circle_mask(im192)
        circ192.save(PREV / ("variant-%s-circle-192.png" % key))
        mono192 = Image.open(PREV / ("variant-%s-mono-192.png" % key)).convert("RGBA")
        mono48 = Image.open(PREV / ("variant-%s-mono-48.png" % key)).convert("RGBA")
        light, dark, white = (0xE9, 0xED, 0xF2, 255), (0x14, 0x18, 0x1F, 255), (255, 255, 255, 255)
        rows.append((spec["title"], [
            (im512, light, "512"),
            (im192, light, "192"),
            (im48, white, "48 светлая"),
            (im48, dark, "48 тёмная"),
            (circ192, light, "круг 192"),
            (mono192, white, "моно 192"),
            (mono48, white, "моно 48"),
        ]))

    sheet(rows, ICON / "preview-sheet.png")

    # Ресурсы Android для рекомендованного варианта
    elems = fg[RECOMMENDED]
    (RES / "drawable").mkdir(parents=True, exist_ok=True)
    (RES / "mipmap-anydpi-v26").mkdir(parents=True, exist_ok=True)
    (RES / "drawable" / "ic_launcher_foreground.xml").write_text(vector_drawable(elems), encoding="utf-8")
    (RES / "drawable" / "ic_launcher_background.xml").write_text(vector_drawable(background=True), encoding="utf-8")
    (RES / "drawable" / "ic_launcher_monochrome.xml").write_text(vector_drawable(elems, mono=True), encoding="utf-8")
    adaptive = ('<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@drawable/ic_launcher_background" />\n'
                '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
                '    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />\n'
                '</adaptive-icon>\n')
    (RES / "mipmap-anydpi-v26" / "ic_launcher.xml").write_text(adaptive, encoding="utf-8")
    (RES / "mipmap-anydpi-v26" / "ic_launcher_round.xml").write_text(adaptive, encoding="utf-8")

    full_svg = ICON / ("variant-%s.svg" % RECOMMENDED)
    legacy = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
    for density, size in legacy.items():
        d = RES / ("mipmap-%s" % density)
        d.mkdir(parents=True, exist_ok=True)
        square = tmp / ("legacy-%d.png" % size)
        render(full_svg, square, size)
        Image.open(square).convert("RGBA").save(d / "ic_launcher.png")
        circle_mask(Image.open(square).convert("RGBA")).save(d / "ic_launcher_round.png")
    for f in tmp.iterdir():
        f.unlink()
    tmp.rmdir()
    print("recommended: variant-%s; android-res written" % RECOMMENDED)


if __name__ == "__main__":
    main()
