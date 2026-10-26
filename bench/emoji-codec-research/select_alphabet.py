#!/usr/bin/env python3
"""Отбор «универсальных» эмодзи из emoji-test.txt (данные недоверенные: только парсим).

Запуск: python3 -I select_alphabet.py <emoji-test.txt> <emoji-data.txt> [outdir]
Печатает воронку фильтров для порогов версии Emoji и пишет кандидатов в outdir/candidates-E<ver>.txt.
Порядок кандидатов - порядок файла (стабильный, как в текущем emoji_alphabet.rs).
"""
import re
import sys
from collections import Counter

LINE = re.compile(r'^([0-9A-F ]+?)\s*;\s*([a-z-]+)\s*#\s*(\S+)\s+E(\d+\.\d+)\s+(.*)$')

# Семейства «разные оттенки одного и того же» - оставляем не больше одного представителя.
# Матчим по CLDR-имени; здесь явный список слов-цветов и форм.
COLOR_WORDS = {'red', 'orange', 'yellow', 'green', 'blue', 'purple', 'brown', 'black', 'white', 'pink', 'grey', 'gray'}
FAMILY_PATTERNS = [
    ('heart', re.compile(r'\bheart\b')),               # 💛💚💙💜🧡🤎🖤🤍💖💗💓💞💕💝💘 - путаются на мелких размерах
    ('circle', re.compile(r'\b(circle|large .* square|square)\b')),
    ('diamond', re.compile(r'\bdiamond\b')),
    ('moon', re.compile(r'\bmoon\b')),
    ('clock', re.compile(r'\bo.clock\b|\bthirty\b')),
    ('cat-face', re.compile(r'\bcat\b.*\bface\b|\bface\b.*\bcat\b|\bcat with\b|\bcat face\b')),
    ('monkey', re.compile(r'\bmonkey\b')),
]


def parse_emoji_test(path):
    out = []
    group = sub = ''
    with open(path, encoding='utf-8') as f:
        for ln in f:
            ln = ln.rstrip('\n')
            if ln.startswith('# group:'):
                group = ln.split(':', 1)[1].strip()
            elif ln.startswith('# subgroup:'):
                sub = ln.split(':', 1)[1].strip()
            m = LINE.match(ln)
            if not m:
                continue
            cps = [int(x, 16) for x in m.group(1).split()]
            out.append(dict(cps=cps, status=m.group(2), ch=m.group(3), ver=float(m.group(4)),
                            name=m.group(5), group=group, sub=sub))
    return out


def parse_emoji_data(path, prop):
    s = set()
    with open(path, encoding='utf-8') as f:
        for ln in f:
            ln = ln.split('#', 1)[0].strip()
            if not ln:
                continue
            r, p = [x.strip() for x in ln.split(';')]
            if p != prop:
                continue
            a, _, b = r.partition('..')
            for cp in range(int(a, 16), int(b or a, 16) + 1):
                s.add(cp)
    return s


def funnel(entries, modbase, emoji_pres, maxver):
    steps = []
    cur = [e for e in entries if e['status'] == 'fully-qualified']
    steps.append(('fully-qualified (все)', len(cur)))
    cur = [e for e in cur if len(e['cps']) == 1]
    steps.append(('ровно один код-пойнт (нет ZWJ, FE0F, тона, пар)', len(cur)))
    cur = [e for e in cur if e['cps'][0] in emoji_pres]
    steps.append(('Emoji_Presentation=Yes (не нужен FE0F)', len(cur)))
    cur = [e for e in cur if e['ver'] <= maxver]
    steps.append((f'Emoji <= {maxver}', len(cur)))
    cur = [e for e in cur if e['sub'] != 'flag' and e['group'] != 'Flags']
    steps.append(('без флагов', len(cur)))
    cur = [e for e in cur if e['cps'][0] not in modbase]
    steps.append(('без Emoji_Modifier_Base (люди/руки: вид и пол зависят от вендора)', len(cur)))
    return steps, cur


def family_of(e):
    nm = e['name'].lower()
    for fam, pat in FAMILY_PATTERNS:
        if pat.search(nm):
            return fam
    return None


def dedupe_families(cur):
    """Из каждого семейства оставляем первого (по порядку файла)."""
    seen = set()
    out = []
    dropped = Counter()
    for e in cur:
        fam = family_of(e)
        if fam is None:
            out.append(e)
        elif fam not in seen:
            seen.add(fam)
            out.append(e)
        else:
            dropped[fam] += 1
    return out, dropped


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    entries = parse_emoji_test(sys.argv[1])
    modbase = parse_emoji_data(sys.argv[2], 'Emoji_Modifier_Base')
    epres = parse_emoji_data(sys.argv[2], 'Emoji_Presentation')
    outdir = sys.argv[3] if len(sys.argv) > 3 else None
    print(f'разобрано строк emoji-test: {len(entries)}; modifier_base={len(modbase)}; emoji_presentation={len(epres)}')
    for maxver in (5.0, 11.0, 12.0, 13.0, 15.0, 99.0):
        steps, cur = funnel(entries, modbase, epres, maxver)
        print(f'\n== порог Emoji <= {maxver} ==')
        for n, c in steps:
            print(f'  {c:5d}  {n}')
        astral = sum(1 for e in cur if e['cps'][0] > 0xFFFF)
        print(f'        из них астральных (U+1xxxx): {astral}, BMP: {len(cur) - astral}')
        ded, dr = dedupe_families(cur)
        print(f'  {len(ded):5d}  после 1 представителя на семейство (сердца/круги/квадраты/ромбы/луны/часы/коты/обезьяны); сброшено {dict(dr)}')
        if outdir:
            import os
            os.makedirs(outdir, exist_ok=True)
            with open(f'{outdir}/candidates-E{maxver}.txt', 'w', encoding='utf-8') as f:
                for e in ded:
                    f.write(f"{e['cps'][0]:X}\t{e['ch']}\tE{e['ver']}\t{e['sub']}\t{e['name']}\n")


if __name__ == '__main__':
    main()
