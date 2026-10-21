import os, time, hashlib
import RNS
from RNS.Cryptography import Token
from RNS.Cryptography import Provider
print("RNS crypto provider:", Provider.PROVIDER, "(0=internal pure python, 1=cryptography/OpenSSL)")
tok = Token(os.urandom(64))
for size in (400, 16000, 400000):
    data = os.urandom(size); n = max(5, int(30_000_000 / size))
    t = time.perf_counter()
    for _ in range(n): ct = tok.encrypt(data)
    te = time.perf_counter() - t
    t = time.perf_counter()
    for _ in range(n): tok.decrypt(ct)
    td = time.perf_counter() - t
    print("Token size=%6d  encrypt %5.0f MiB/s  decrypt %5.0f MiB/s" % (size, n*size/te/1048576, n*size/td/1048576))
d = os.urandom(1<<20); t = time.perf_counter()
for _ in range(100): hashlib.sha256(d).digest()
print("sha256 %.0f MiB/s" % (100/(time.perf_counter()-t)))
