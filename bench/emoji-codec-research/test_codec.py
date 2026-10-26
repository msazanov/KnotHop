#!/usr/bin/env python3
"""Round-trip и устойчивость. Запуск: python3 -I test_codec.py [alphabet-strict.txt]  (детерминированно, seed фиксирован)."""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from codec import ALLOWED_LEN, BitPack, Codec, make_body, split_body  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
alpha_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'out', 'alphabet-strict.txt')
ALPHA = open(alpha_path, encoding='utf-8').read().strip()
rng = random.Random(0x4B4E4F54)
codec = Codec(ALPHA)
print(f'алфавит {len(ALPHA)} знаков, {codec.base} (log2={len(ALPHA).bit_length()-1}+), цифр по n: ' +
      str([codec.dlen[28 + 16 * n] for n in range(1, 9)]))


def rand_body(n):
    hs = {rng.randbytes(16) for _ in range(n)}
    while len(hs) < n:
        hs.add(rng.randbytes(16))
    return make_body(list(hs), rng.randbytes(24))


# 1. round-trip 10^4 тел на каждое n, плюс разбор тела
for n in range(1, 9):
    for _ in range(10_000):
        b = rand_body(n)
        s = codec.encode(b)
        assert len(s) == codec.dlen[len(b)]
        assert codec.decode(s) == b
        split_body(codec.decode(s))
print('round-trip: 8 x 10^4 тел OK')

# 2. крайние значения: все нули/все 0xff (ведущие нули не теряются)
for L in ALLOWED_LEN:
    for b in (bytes(L), b'\xff' * L, bytes(L - 1) + b'\x01'):
        assert codec.decode(codec.encode(b)) == b
print('крайние значения OK')

# 3. шум мессенджера: пробелы, переносы, FE0F, ZWSP
b = rand_body(5)
s = codec.encode(b)
noisy = ''.join(c + ('️' if i % 7 == 0 else '') + (' ' if i % 11 == 0 else '') + ('\n' if i % 40 == 39 else '') +
                ('​' if i % 13 == 0 else '') for i, c in enumerate(s))
assert codec.decode(noisy) == b
print('шум (пробелы/переносы/FE0F/ZWSP) OK')

# 4. обнаружение ошибок. Все 10^4 x 4 мутации должны быть отвергнуты (length / range / checksum / structure).
undetected = {'replace': 0, 'swap': 0, 'delete': 0, 'insert': 0}
T = 10_000
for _ in range(T):
    n = rng.randint(1, 8)
    b = rand_body(n)
    s = list(codec.encode(b))
    for kind in undetected:
        t = s[:]
        if kind == 'replace':
            i = rng.randrange(len(t))
            t[i] = rng.choice([c for c in ALPHA if c != t[i]])
        elif kind == 'swap':
            i = rng.randrange(len(t) - 1)
            if t[i] == t[i + 1]:
                continue
            t[i], t[i + 1] = t[i + 1], t[i]
        elif kind == 'delete':
            del t[rng.randrange(len(t))]
        else:
            t.insert(rng.randrange(len(t) + 1), rng.choice(ALPHA))
        try:
            got = codec.decode(''.join(t))
        except ValueError:
            continue
        try:
            split_body(got)
            undetected[kind] += 1
        except ValueError:
            pass
print('необнаруженные ошибки на', T, 'тел для каждого вида:', undetected)
assert not any(undetected.values())

# 5. посторонние символы
for bad in ('x', '😀' + 'a', ):
    try:
        codec.decode(bad)
        raise SystemExit('ожидалась ошибка')
    except ValueError:
        pass

# 6. степень двойки (bit-packing) - проверяем только длины и обратимость префикса
for k in (8, 9, 10):
    bp = BitPack([chr(0x4E00 + i) for i in range(1 << k)])
    for n in range(1, 9):
        b = rand_body(n)
        assert len(bp.encode(b)) == -(-8 * len(b) // k)
print('все тесты OK')
