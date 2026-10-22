#!/usr/bin/env python3
"""Генератор иконки KnotHop: брецель (pretzel) в трёх степенях «сетевости».

Выходы: SVG вариантов, PNG-превью, лист сравнения, VectorDrawable и legacy PNG.
Одна геометрия питает все выходы. Только стандартная библиотека, Pillow и rsvg-convert,
сети нет. Запуск: python3 design/icon/tools/gen.py
"""
import math
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ICON = Path(__file__).resolve().parent.parent
PREV = ICON / "previews"
RES = ICON / "android-res"

# Рекомендованный вариант для ресурсов Android: "a", "b" или "c".
RECOMMENDED = "b"  # маршрут вход → живот → выход

BG = "#0D2538"       # тёмно-синий фон, одинаков для светлой и тёмной темы
DOUGH = "#D98B3A"    # тесто: золотисто-коричневый
CRUST = "#A35A22"    # тёмный тон: нижняя «живот»-корка
SALT = "#FFF6E0"     # крупинки соли
ACCENT = "#34D399"   # ноды сети: старт, выход, хаб
NODE_W = "#F4F7FA"   # промежуточный узел
MONO = "#000000"     # монохром: Android берёт только альфа-канал

DOUGH_W = 9.0        # толщина теста: толще плеч-ножек только живот
BELLY_W = 11.5       # живот толще теста
ROUTE_W = 1.8        # тонкая линия маршрута
NODE_R = 2.6         # радиус узла: все ноды одинаковые
HALO = 2.2           # зазор у «подныривания» с каждой стороны
SAMPLES = 48         # отсчётов на сегмент Безье
SAFE_R = 33.0        # радиус безопасной зоны adaptive icon
CX, CY = 54.0, 53.0  # центр брецеля

SAMPLES_PER_SEG = SAMPLES


# ---------- кривые ----------

def catmull_rom(pts, closed=False):
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
    """De Casteljau: делит кубическую Безье в точке t."""
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
    if t0 > 0:
        _, b = split(b, t0)
        t1 = (t1 - t0) / (1 - t0)
    if t1 < 1:
        b, _ = split(b, t1)
    return b


class Curve:
    """Открытая кривая из Безье: отсчёты u = k*SAMPLES + j и длина дуги по отсчётам."""

    def __init__(self, segs):
        self.segs = segs
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

    def point_s(self, s):
        u = self.u_of_s(s)
        k = min(int(u // SAMPLES), len(self.segs) - 1)
        return bez_pt(self.segs[k], (u - k * SAMPLES) / SAMPLES)

    def extract(self, u0, u1):
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


# ---------- геометрия брецеля ----------
# Все координаты в viewBox 108, осевые линии полос. Центр фигуры по x — 54.
# A — левая половина: от левого конца живота вверх через левую долю, затем через
# скрутку вниз-вправо к правой ножке. B — её зеркало. T — впадина между долями сверху.
# Живот — нижняя дуга от левого конца до правого. Концы ножек лежат на животе
# и выступают за его наружный край.

X_HUB = (54.0, 52.0)  # единственная скрутка: здесь A и B перекрещиваются

A_PTS = [(32, 62), (29, 48), (33, 37), (41, 31), (47, 37), X_HUB, (61, 59), (68, 66), (75, 71)]
BELLY_PTS = [(32, 62), (37, 70), (54, 74), (71, 70), (76, 62)]
DIP_PTS = [(41, 31), (54, 33), (67, 31)]


def mirror(p):
    return (108 - p[0], p[1])


def pieces_pretzel():
    """Полосы теста в порядке рисования: раньше — под, позже — над.

    Живот рисуется первым, ножки поверх него (их концы выступают наружу).
    A и B перекрещиваются в X_HUB: A раньше, значит A получает разрыв.
    """
    return [
        {"name": "belly", "segs": catmull_rom(BELLY_PTS), "w": BELLY_W, "color": CRUST},
        {"name": "a", "segs": catmull_rom(A_PTS), "w": DOUGH_W, "color": DOUGH},
        {"name": "b", "segs": catmull_rom([mirror(p) for p in A_PTS]), "w": DOUGH_W, "color": DOUGH},
        {"name": "dip", "segs": catmull_rom(DIP_PTS), "w": DOUGH_W, "color": DOUGH},
    ]


# ---------- сборка элементов ----------

def build(pieces, extras, mono=False):
    """pieces — полосы теста с разрывами у перекрестий; extras — маршрут и узлы поверх."""
    curves = [Curve(p["segs"]) for p in pieces]
    cuts = [[] for _ in pieces]
    hubs = []
    for i in range(len(pieces)):
        for j in range(i + 1, len(pieces)):
            a, b = curves[i], curves[j]
            for ia in range(len(a.pts) - 1):
                for jb in range(len(b.pts) - 1):
                    h = seg_hit(a.pts[ia], a.pts[ia + 1], b.pts[jb], b.pts[jb + 1])
                    if not h:
                        continue
                    t, u, pt = h
                    sa = a.s_of_u(ia + t)
                    sb = b.s_of_u(jb + u)
                    # стык (конец одной полосы на другой) не считаем перекрестием
                    if not (0.5 < sa < a.length - 0.5 and 0.5 < sb < b.length - 0.5):
                        continue
                    if min(sa, a.length - sa) < 4 or min(sb, b.length - sb) < 4:
                        continue
                    half = pieces[i]["w"] / 2 + HALO
                    if any(math.dist(pt, q) < 1.0 for q in hubs):
                        continue  # одно перекрестие попадает в два соседних сегмента
                    hubs.append(pt)
                    cuts[i].append((sa - half, sa + half))  # i под j

    elems = []
    for p, c, cut in zip(pieces, curves, cuts):
        for s0, s1 in complement(cut, 0.0, c.length):
            beziers = c.extract(c.u_of_s(s0), c.u_of_s(s1))
            if beziers:
                elems.append({"kind": "stroke", "d": bez_d(beziers), "color": p["color"],
                              "w": p["w"], "beziers": beziers})
    if mono:
        return [dict(e, color=MONO) for e in elems], {"crossings": len(hubs)}

    for e in extras["routes"]:
        c = Curve(e["segs"])
        elems.append({"kind": "stroke", "d": bez_d(c.extract(0, len(c.segs) * SAMPLES)),
                      "color": e.get("color", ACCENT), "w": ROUTE_W, "beziers": c.segs})
    for x, y, r, color in extras["nodes"]:
        elems.append({"kind": "fill", "d": circle_d(x, y, r), "color": color, "center": (x, y), "r": r})
    for x, y, r in extras["salt"]:
        elems.append({"kind": "fill", "d": circle_d(x, y, r), "color": SALT, "center": (x, y), "r": r})
    return elems, {"crossings": len(hubs)}


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


def max_radius(elems):
    worst = 0.0
    for e in elems:
        if e["kind"] == "stroke":
            for b in e["beziers"]:
                for j in range(21):
                    x, y = bez_pt(b, j / 20)
                    worst = max(worst, math.hypot(x - 54, y - 54) + e["w"] / 2)
        else:
            cx, cy = e["center"]
            worst = max(worst, math.hypot(cx - 54, cy - 54) + e["r"])
    return worst


def recolor(elems, color):
    return [dict(e, color=color) for e in elems]


# ---------- варианты ----------

def node_at(p):
    """Узел на тесте: все ноды одинаковые, без центрального и выделенного."""
    return (p[0], p[1], NODE_R, ACCENT)


TIP_L = mirror(A_PTS[-1])  # вход: конец левой ножки на животе
TIP_R = A_PTS[-1]          # выход: конец правой ножки на животе
SHOULDER_L = A_PTS[2]
SHOULDER_R = mirror(A_PTS[2])
BELLY_MID = (54.0, 74.0)


def variant(key):
    """a — пять узлов-соли по тесту, без маршрута;
    b — то же + маршрут вход → живот → выход (рекомендую);
    c — то же + маршрут по контуру через обе доли и впадину."""
    pieces = pieces_pretzel()
    nodes = [node_at(p) for p in (TIP_L, SHOULDER_L, BELLY_MID, SHOULDER_R, TIP_R)]
    if key == "a":
        routes = []
        title = "A · Брецель, узлы-соль без маршрута"
    elif key == "b":
        routes = [{"segs": catmull_rom([TIP_L, BELLY_MID, TIP_R])}]
        title = "B · Маршрут: вход на левой ножке, выход на правой, через живот"
    else:
        contour = [TIP_L, A_PTS[1], SHOULDER_L, DIP_PTS[1], SHOULDER_R, mirror(A_PTS[1]), TIP_R]
        routes = [{"segs": catmull_rom(contour)}]
        title = "C · Маршрут по контуру: через обе доли и впадину"
    extras = {"routes": routes, "nodes": nodes, "salt": []}
    elems, diag = build(pieces, extras)
    mono_elems, _ = build(pieces, extras, mono=True)
    return {"title": title, "elems": elems, "mono": mono_elems, "diag": diag}


# ---------- выводы ----------

def svg_doc(elems, bg):
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="108" height="108" viewBox="0 0 108 108">']
    if bg:
        out.append('  <rect width="108" height="108" fill="%s"/>' % bg)
    for e in elems:
        if e["kind"] == "stroke":
            out.append('  <path d="%s" fill="none" stroke="%s" stroke-width="%s" stroke-linecap="round" stroke-linejoin="round"/>'
                       % (e["d"], e["color"], fmt(e["w"])))
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
                            '        android:strokeLineJoin="round" />\n' % (e["d"], color, fmt(e["w"])))
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
    rows = []
    built = {}
    for key in ("a", "b", "c"):
        v = variant(key)
        radius = max_radius(v["elems"])
        print("pretzel-%s: crossings=%d max_radius=%.2f (safe %.1f)"
              % (key, v["diag"]["crossings"], radius, SAFE_R))
        if radius > SAFE_R:
            sys.exit("pretzel-%s выходит за безопасную зону" % key)
        built[key] = v
        (ICON / ("pretzel-%s.svg" % key)).write_text(svg_doc(v["elems"], BG), encoding="utf-8")
        mono_svg = tmp / ("mono-%s.svg" % key)
        mono_svg.write_text(svg_doc(v["mono"], None), encoding="utf-8")
        svg = ICON / ("pretzel-%s.svg" % key)
        for size in (512, 192, 48):
            render(svg, PREV / ("pretzel-%s-%d.png" % (key, size)), size)
        render(mono_svg, PREV / ("pretzel-%s-mono-192.png" % key), 192)
        render(mono_svg, PREV / ("pretzel-%s-mono-48.png" % key), 48)

        im512 = Image.open(PREV / ("pretzel-%s-512.png" % key)).convert("RGBA")
        im192 = Image.open(PREV / ("pretzel-%s-192.png" % key)).convert("RGBA")
        im48 = Image.open(PREV / ("pretzel-%s-48.png" % key)).convert("RGBA")
        circ192 = circle_mask(im192)
        circ192.save(PREV / ("pretzel-%s-circle-192.png" % key))
        mono192 = Image.open(PREV / ("pretzel-%s-mono-192.png" % key)).convert("RGBA")
        mono48 = Image.open(PREV / ("pretzel-%s-mono-48.png" % key)).convert("RGBA")
        light, dark, white = (0xE9, 0xED, 0xF2, 255), (0x14, 0x18, 0x1F, 255), (255, 255, 255, 255)
        rows.append((v["title"], [
            (im512, light, "512"),
            (im192, light, "192"),
            (im48, white, "48 светлая"),
            (im48, dark, "48 тёмная"),
            (circ192, light, "круг 192"),
            (mono192, white, "моно 192"),
            (mono48, white, "моно 48"),
        ]))

    sheet(rows, ICON / "preview-sheet-pretzel.png")

    # Ресурсы Android для рекомендованного варианта
    v = built[RECOMMENDED]
    (RES / "drawable").mkdir(parents=True, exist_ok=True)
    (RES / "mipmap-anydpi-v26").mkdir(parents=True, exist_ok=True)
    (RES / "drawable" / "ic_launcher_foreground.xml").write_text(vector_drawable(v["elems"]), encoding="utf-8")
    (RES / "drawable" / "ic_launcher_background.xml").write_text(vector_drawable(background=True), encoding="utf-8")
    (RES / "drawable" / "ic_launcher_monochrome.xml").write_text(vector_drawable(v["mono"], mono=True), encoding="utf-8")
    adaptive = ('<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@drawable/ic_launcher_background" />\n'
                '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
                '    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />\n'
                '</adaptive-icon>\n')
    (RES / "mipmap-anydpi-v26" / "ic_launcher.xml").write_text(adaptive, encoding="utf-8")
    (RES / "mipmap-anydpi-v26" / "ic_launcher_round.xml").write_text(adaptive, encoding="utf-8")

    full_svg = ICON / ("pretzel-%s.svg" % RECOMMENDED)
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
    print("recommended: pretzel-%s; android-res written" % RECOMMENDED)


if __name__ == "__main__":
    main()
