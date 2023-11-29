import hashlib
import math
import random

from Crypto.Util.number import getPrime, long_to_bytes

while True:
    p = getPrime(1024)
    q = (p - 1) // 2
    if math.gcd(p, q) == 1:
        break

while True:
    a = pow(q, -1, p)
    if math.gcd(a, q) == 1:
        break
s = random.randint(1, q - 1)
v = pow(a, -s, q)
H = 'sha256'

m = b'afan'


def sign(m, q, H):
    r = random.randint(1, q - 1)
    x = pow(a, r, p)
    # print(x)
    x = long_to_bytes(x)
    mx = m + x

    h = hashlib.new(H)
    h.update(mx)
    hmx = int(h.hexdigest(), 16)
    e = hmx
    y = (r + s * e) % q
    return e, y


def verify(m, e, y, v, p, q, a, H):
    x = (pow(a, y, p) * pow(v, e, p)) % p
    # print(x)
    x = long_to_bytes(x)
    mx = m + x

    h = hashlib.new(H)
    h.update(mx)
    hmx = int(h.hexdigest(), 16)

    if e == hmx:
        return True
    return False


e, y = sign(m, q, H)
print(verify(m, e, y, v, p, q, a, H))
