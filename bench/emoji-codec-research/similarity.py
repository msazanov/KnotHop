#!/usr/bin/env python3
"""Визуальная схожесть кандидатов: рендер Noto Color Emoji -> 24x24 на белом -> евклидово расстояние.

Запуск: python3 -I similarity.py <candidates.txt> <NotoColorEmoji.ttf> [порог] [out-alphabet.txt]
Печатает ближайшие пары; с порогом - жадно выкидывает из каждой пары с расстоянием < порога более поздний символ.
Это оценка по ОДНОМУ шрифту (Noto): у Apple/Samsung/Twemoji рисунки другие, поэтому это дополнение к фильтрам по
имени/семейству, а не замена им.
"""
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFont

SZ = 24


def render(font, ch):
    im = Image.new('RGBA', (136, 128), (255, 255, 255, 255))
    ImageDraw.Draw(im).text((0, 0), ch, font=font, embedded_color=True)
    im = im.convert('RGB').resize((SZ, SZ), Image.LANCZOS)
    return np.asarray(im, dtype=np.float32).reshape(-1) / 255.0


def main():
    cands = []
    for ln in open(sys.argv[1], encoding='utf-8'):
        p = ln.rstrip('\n').split('\t')
        if len(p) >= 5:
            cands.append((p[1], p[4]))
    font = ImageFont.truetype(sys.argv[2], 109)
    X = np.stack([render(font, c) for c, _ in cands])
    n = len(cands)
    # расстояния, нормированные на sqrt(размерности): 0 - одинаковые, ~0.3+ - явно разные
    sq = (X ** 2).sum(1)
    D = np.sqrt(np.maximum(sq[:, None] + sq[None, :] - 2 * X @ X.T, 0)) / np.sqrt(X.shape[1])
    iu = np.triu_indices(n, 1)
    order = np.argsort(D[iu])
    print(f'кандидатов: {n}; ближайшие пары:')
    for k in order[:40]:
        i, j = iu[0][k], iu[1][k]
        print(f'  {D[i, j]:.4f}  {cands[i][0]} {cands[j][0]}  ({cands[i][1]} / {cands[j][1]})')
    vals = D[iu]
    print('квантили расстояний пар:', {q: round(float(np.quantile(vals, q)), 3) for q in (0.001, 0.01, 0.05, 0.5)})
    if len(sys.argv) > 3:
        thr = float(sys.argv[3])
        keep = []
        dropped = []
        for i in range(n):
            clash = [j for j in keep if D[i, j] < thr]
            if clash:
                dropped.append((cands[i][0], cands[clash[0]][0]))
            else:
                keep.append(i)
        print(f'порог {thr}: осталось {len(keep)} из {n}, выкинуто {len(dropped)}')
        if len(sys.argv) > 4:
            with open(sys.argv[4], 'w', encoding='utf-8') as f:
                f.write(''.join(cands[i][0] for i in keep) + '\n')
        for thr2 in (0.02, 0.03, 0.04, 0.05, 0.06, 0.08):
            kp = []
            for i in range(n):
                if all(D[i, j] >= thr2 for j in kp):
                    kp.append(i)
            print(f'  порог {thr2}: осталось {len(kp)}')


if __name__ == '__main__':
    main()
