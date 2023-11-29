import hashlib
import math
import random

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# by https://en.wikipedia.org/wiki/ElGamal_signature_scheme

# 1. Key generation
# 1-1. Parameter generation
p = getPrime(1024)
q = getPrime(1024)
H = 'sha256'
g = random.randint(1, p - 1)

# 1-2. Per-user keys
x = random.randint(1, p - 2)
y = pow(g, x, p)

m = b'afan'


# 2. Signing
def sign(m, p, g, x, H):
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) != 1:
            continue
        r = pow(g, k, p)
        h = hashlib.new(H)
        h.update(m)
        hm = int(h.hexdigest(), 16)
        s = (hm - x * r) * pow(k, -1, p - 1) % (p - 1)
        if s != 0:
            return r, s


# 3. Verifying
def verify(m, r, s, H):
    if (r <= 0) | (r >= p) | (s <= 0) | (s >= p - 1):
        return False
    h = hashlib.new(H)
    h.update(m)
    hm = int(h.hexdigest(), 16)
    return pow(g, hm, p) == (pow(y, r, p) * pow(r, s, p)) % p


r, s = sign(m, p, g, x, H)  # 簽名
print(verify(m, r, s, H))  # 驗證
