#!/usr/bin/env python3
"""Таблицы длин и проверка идеи «частые отрезки (AAAAA) -> один эмодзи» на случайных телах v4.

Запуск: python3 -I experiments.py [alphabet-strict.txt] [emoji_alphabet.rs] [число тел, по умолчанию 100000]
Детерминировано (seed фиксирован). Текущий алфавит читается из emoji_alphabet.rs только на чтение.
"""
import math
import os
import random
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from codec import ALLOWED_LEN, Codec, b64url, make_body, digits_needed  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
STRICT = open(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'out', 'alphabet-strict.txt'), encoding='utf-8').read().strip()
RS = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, '..', 'rns-iroh-node', 'src', 'emoji_alphabet.rs')
NBODIES = int(sys.argv[3]) if len(sys.argv) > 3 else 100_000
LEGACY = re.search(r'ALPHABET: &str = "(.*?)";', open(RS, encoding='utf-8').read(), re.S).group(1)
rng = random.Random(0x52414E44)


def rand_body(n):
    hs = set()
    while len(hs) < n:
        hs.add(rng.randbytes(16))
    return make_body(list(hs), rng.randbytes(24))


def legacy_encode(data: bytes, chars: str) -> str:
    """Порт emoji.rs::encode: число -> цифры основания len(chars), ведущие нулевые байты -> нулевой знак."""
    base = len(chars)
    z = len(data) - len(data.lstrip(b'\0'))
    x = int.from_bytes(data[z:], 'big')
    ds = []
    while x:
        x, r = divmod(x, base)
        ds.append(r)
    return chars[0] * z + ''.join(chars[d] for d in reversed(ds))


def utf8(s):
    return len(s.encode('utf-8'))


# ---- 1. таблица длин ------------------------------------------------------------------------------------------
print('## Длины тела приглашения v4 (L = 28+16n байт)\n')
print('Бит на знак: ' + ', '.join(f'N={n}: {math.log2(n):.3f}' for n in (64, 256, 512, 780, 1024, 1058, 2048, 4096)))
print()
SAMPLE = 10_000
rows = []
for n in range(1, 9):
    L = 28 + 16 * n
    bodies = [rand_body(n) for _ in range(SAMPLE)]
    leg = [legacy_encode(b, LEGACY) for b in bodies]
    leg_g = [len(s) for s in leg]
    leg_b = [utf8(s) for s in leg]
    strict = Codec(STRICT)
    sg = strict.dlen[L]
    sb = [utf8(strict.encode(b)) for b in bodies[:2000]]
    r = dict(n=n, L=L,
             b64=len(b64url(bodies[0])), b64np=len(b64url(bodies[0], '')),
             leg=f'{min(leg_g)}-{max(leg_g)} (ср. {sum(leg_g)/SAMPLE:.1f})', leg_bytes=f'{min(leg_b)}-{max(leg_b)}',
             strict=sg, strict_bytes=f'{min(sb)}-{max(sb)}')
    for N in (256, 512, 1024, 2048, 4096):
        r[f'bp{N}'] = -(-8 * L // (N.bit_length() - 1))
    r['bn1184'] = digits_needed(1184, L)
    rows.append(r)

hdr = ['n', 'тело Б', 'kh-b64 (симв=Б)', 'b64 без kh-', 'текущий 1058: глифы', 'текущий: UTF-8 Б', 'strict 780: глифы', 'strict: UTF-8 Б',
       '256', '512', '1024', '2048', '4096', 'bignum 1184']
print('| ' + ' | '.join(hdr) + ' |')
print('|' + '---|' * len(hdr))
for r in rows:
    print(f"| {r['n']} | {r['L']} | {r['b64']} | {r['b64np']} | {r['leg']} | {r['leg_bytes']} | {r['strict']} | {r['strict_bytes']} | "
          f"{r['bp256']} | {r['bp512']} | {r['bp1024']} | {r['bp2048']} | {r['bp4096']} | {r['bn1184']} |")
print('\n(256..4096 - упаковка битов, глифов на тело; UTF-8 для них ~4 Б/глиф. 2048/4096 реальных однокодпоинтных эмодзи не существует.)')
print(f"Средний размер знака strict-алфавита в UTF-8: {sum(utf8(c) for c in STRICT)/len(STRICT):.3f} Б; текущего: {sum(utf8(c) for c in LEGACY)/len(LEGACY):.3f} Б")

# ---- 2. идея «частые отрезки -> один эмодзи» -----------------------------------------------------------------
print(f'\n## Словарь/RLE на {NBODIES} случайных телах\n')
bodies = [rand_body(1 + (i % 8)) for i in range(NBODIES)]
tot_len = {n: 0 for n in range(1, 9)}

# 2a. Прогон одинаковых символов в base64url-тексте (без kh-): сколько символов можно сэкономить RLE'ем.
# Любая RLE-схема тратит служебный знак: ESC + символ + счётчик = 3 знака на прогон >= 4 символов -> экономия run-3.
saved = Counter()
bodies_with_run = Counter()
max_run = 0
for b in bodies:
    s = b64url(b, '')
    i = 0
    got = 0
    while i < len(s):
        j = i
        while j < len(s) and s[j] == s[i]:
            j += 1
        run = j - i
        max_run = max(max_run, run)
        for thr in (3, 4, 5):
            if run >= thr:
                saved[thr] += max(run - 3, 0) if thr >= 4 else 0
                bodies_with_run[thr] += 1
        i = j
print(f'a) base64url, прогоны одинаковых символов: тел с прогоном >=3: {bodies_with_run[3]}, >=4: {bodies_with_run[4]}, >=5: {bodies_with_run[5]}; '
      f'максимальный прогон: {max_run}')
tot_chars = sum(len(b64url(b, '')) for b in bodies)
print(f'   символов всего {tot_chars}; ожидаемое число "AAAAA" (5 одинаковых) на всё множество: {tot_chars/64**4:.1f} прогонов длины>=5 любым символом '
      f'(для конкретно "AAAAA": {tot_chars/64**5:.3f})')
print(f'   экономия RLE (ESC+символ+счётчик заменяет прогон >=4): всего {saved[4]} символов на {NBODIES} тел = {saved[4]/NBODIES:.6f} символа на тело')

# 2b. Эмодзи-форма: знаки с резервом R "повтор предыдущего знака k раз" (k=2..R+1). Основание цифр уменьшается до N-R.
for N0, alphabet in ((780, STRICT),):
    base_plain = Codec(alphabet)
    for R in (1, 2, 4, 8):
        sub = Codec(alphabet[:N0 - R])
        extra = 0
        savedg = 0
        runs3 = 0
        for b in bodies:
            L = len(b)
            d_plain = base_plain.dlen[L]
            d_res = sub.dlen[L]
            extra += d_res - d_plain
            s = sub.encode(b)
            i = 0
            while i < len(s):
                j = i
                while j < len(s) and s[j] == s[i]:
                    j += 1
                run = j - i
                if run >= 3:
                    runs3 += 1
                    # знак + токен REP(run-1) занимает 2 знака вместо run (токены только до R+1 повторов)
                    k = min(run - 1, R + 1)
                    savedg += k - 1 if k >= 2 else 0
                i = j
        print(f'b) глиф-RLE, N={N0}, резерв R={R} токенов: прибавка длины из-за уменьшения основания {extra/NBODIES:+.4f} глифа/тело, '
              f'экономия от повторов {savedg/NBODIES:.6f} глифа/тело (прогонов >=3: {runs3}); итого {(extra - savedg)/NBODIES:+.4f}')

# 2c. Словарь частых k-грамм: берём D самых частых k-грамм на ОБУЧАЮЩЕЙ половине и меряем покрытие на ТЕСТОВОЙ.
# Если «частые» отрезки существуют на самом деле, покрытие на тесте будет выше равномерного D/64^k; для случайных данных
# обучающие «частые» k-граммы - шум выборки, и на тесте покрытие равно равномерному.
print('c) словарь k-грамм base64url: обучение на первой половине тел, покрытие на второй (D/64^k - равномерная ожидаемая доля):')
half = NBODIES // 2
for k in (3, 4, 5):
    train, test = Counter(), Counter()
    for part, cnt in ((bodies[:half], train), (bodies[half:], test)):
        for b in part:
            s = b64url(b, '')
            for i in range(len(s) - k + 1):
                cnt[s[i:i + k]] += 1
    ttot = sum(test.values())
    for D in (64, 1024):
        words = [w for w, _ in train.most_common(D)]
        cov_train = sum(train[w] for w in words) / sum(train.values())
        cov_test = sum(test[w] for w in words) / ttot
        print(f'   k={k}, D={D}: покрытие на обучении {cov_train*100:.4f}%, на тесте {cov_test*100:.4f}%, равномерное {D/64**k*100:.4f}% '
              f'(тест/равномерное = {cov_test/(D/64**k):.2f})')

# ---- 3. структурная избыточность: отсортированные хеши -------------------------------------------------------------
print('\n## Реальная избыточность тела: отсортированный набор хешей (n! порядков) и checksum\n')
for n in (1, 3, 8):
    bits = math.log2(math.factorial(n))
    print(f'n={n}: log2(n!) = {bits:.2f} бит = {bits/9.6:.2f} глифа strict-алфавита (достижимо только перечислимым кодом набора)')
print('checksum4 = 32 бит = 3,3 глифа; не избыточность, а защита от ошибки копирования')
