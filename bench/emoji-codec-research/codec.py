#!/usr/bin/env python3
"""Прототип эмодзи-кодека тела приглашения v4 (исследование; не заменяет bench/rns-iroh-node/src/emoji.rs).

Схема «число в системе счисления N, фиксированное число цифр»:
  * длина тела L известна из набора допустимых {28+16n, n=1..8};
  * d(L) = минимальное d, при котором N^d >= 256^L (точная целочисленная арифметика, без float);
  * тело как большое число big-endian -> d цифр основания N, слева дополняются нулевой цифрой (без спецслучая нулей);
  * декодер: пропускает пробелы/переводы строк/FE0F/FE0E/200B, остальное вне алфавита - ошибка;
    по числу цифр d однозначно восстанавливает L (иначе ошибка), требует value < 256^L (лишняя проверка ошибок).
Контрольная сумма (checksum4) живёт в самом теле и проверяется вызывающим кодом (здесь - `split_body`).
"""
import hashlib
import math

ALLOWED_LEN = {28 + 16 * n: n for n in range(1, 9)}
IGNORABLE = {'️', '︎', '​'}


def digits_needed(base, nbytes):
    d = 0
    cap = 1
    lim = 256 ** nbytes
    while cap < lim:
        cap *= base
        d += 1
    return d


class Codec:
    def __init__(self, alphabet):
        chars = list(alphabet)
        assert len(set(chars)) == len(chars), 'повторы в алфавите'
        assert not any(c in IGNORABLE or c.isspace() or c == '‍' for c in chars)
        self.chars = chars
        self.base = len(chars)
        self.index = {c: i for i, c in enumerate(chars)}
        self.dlen = {L: digits_needed(self.base, L) for L in ALLOWED_LEN}
        by_d = {}
        for L, d in self.dlen.items():
            by_d.setdefault(d, []).append(L)
        assert all(len(v) == 1 for v in by_d.values()), 'число цифр должно однозначно определять длину'
        self.len_by_digits = {d: v[0] for d, v in by_d.items()}

    def encode(self, body: bytes) -> str:
        L = len(body)
        if L not in self.dlen:
            raise ValueError(f'недопустимая длина тела {L}')
        x = int.from_bytes(body, 'big')
        out = []
        for _ in range(self.dlen[L]):
            x, r = divmod(x, self.base)
            out.append(self.chars[r])
        assert x == 0
        return ''.join(reversed(out))

    def decode(self, s: str) -> bytes:
        if len(s) > 4096:
            raise ValueError('слишком длинный ввод')
        digs = []
        for pos, c in enumerate(s):
            if c in IGNORABLE or c.isspace():
                continue
            i = self.index.get(c)
            if i is None:
                raise ValueError(f'символ {c!r} (позиция {pos}) не из алфавита')
            digs.append(i)
        L = self.len_by_digits.get(len(digs))
        if L is None:
            raise ValueError(f'{len(digs)} знаков: не соответствует ни одному n=1..8')
        x = 0
        for d in digs:
            x = x * self.base + d
        if x >= 256 ** L:
            raise ValueError('значение вне диапазона тела')
        return x.to_bytes(L, 'big')


class BitPack:
    """Степень двойки: k = log2 N бит на знак, тело добивается нулевыми битами справа до кратного k.
    Декодер проверяет, что добивающие биты нулевые. Длина тела определяется числом знаков (как у Codec)."""

    def __init__(self, alphabet):
        chars = list(alphabet)
        n = len(chars)
        assert n & (n - 1) == 0 and n > 1
        self.chars, self.k = chars, n.bit_length() - 1
        self.index = {c: i for i, c in enumerate(chars)}
        self.dlen = {L: -(-8 * L // self.k) for L in ALLOWED_LEN}

    def encode(self, body: bytes) -> str:
        bits = 8 * len(body)
        d = self.dlen[len(body)]
        x = int.from_bytes(body, 'big') << (d * self.k - bits)
        return ''.join(self.chars[(x >> (self.k * (d - 1 - i))) & ((1 << self.k) - 1)] for i in range(d))


def b64url(body: bytes, prefix='kh-') -> str:
    import base64
    return prefix + base64.urlsafe_b64encode(body).decode().rstrip('=')


# ---- тело v4 (структура как в ADR 0019 §3) ----------------------------------------------------------------------

def checksum4(raw: bytes) -> bytes:
    return hashlib.sha256(b'knothop-invite-v4' + raw).digest()[:4]


def make_body(hashes, pin: bytes) -> bytes:
    assert 1 <= len(hashes) <= 8 and len(pin) == 24 and all(len(h) == 16 for h in hashes)
    raw = b''.join(sorted(hashes)) + pin
    return raw + checksum4(raw)


def split_body(body: bytes):
    """-> (hashes, pin) либо ValueError (длина, порядок/повтор, нулевой pin, checksum)."""
    if len(body) not in ALLOWED_LEN:
        raise ValueError('длина')
    raw, ck = body[:-4], body[-4:]
    if checksum4(raw) != ck:
        raise ValueError('checksum')
    n = ALLOWED_LEN[len(body)]
    hs = [raw[16 * i:16 * i + 16] for i in range(n)]
    if any(hs[i] >= hs[i + 1] for i in range(n - 1)):
        raise ValueError('порядок/повтор хешей')
    pin = raw[16 * n:]
    if pin == bytes(24):
        raise ValueError('нулевой pin')
    return hs, pin


def bits_per_glyph(n):
    return math.log2(n)
