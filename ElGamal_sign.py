import hashlib
import math
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


# by https://en.wikipedia.org/wiki/ElGamal_signature_scheme

def key_generation():
    # Parameter generation
    p = getPrime(1024)
    q = getPrime(1024)
    H = 'sha256'
    g = random.randint(1, p - 1)

    # Per-user keys
    x = random.randint(1, p - 2)
    y = pow(g, x, p)

    return p, q, H, g, x, y


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


def verify(m, r, s, p, g, y, H):
    if (r <= 0) or (r >= p) or (s <= 0) or (s >= p - 1):
        return False
    h = hashlib.new(H)
    h.update(m)
    hm = int(h.hexdigest(), 16)
    return pow(g, hm, p) == (pow(y, r, p) * pow(r, s, p)) % p


# Key generation
p, q, H, g, x, y = key_generation()

m = b'afan'

# Signing
r, s = sign(m, p, g, x, H)
verification_result = verify(m, r, s, p, g, y, H)

# Output result
print("Signature Verification Result:", verification_result)
