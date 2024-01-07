import hashlib
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


def key_generation():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    H = 'sha256'
    pk = (N, e, H)  # 公鑰
    sk = d  # 私鑰
    return pk, sk


def user(m, pk):
    h = hashlib.new(pk[2])
    h.update(m)
    hm = int(h.hexdigest(), 16)
    r = random.randint(2, pk[0] - 1)
    return (pow(r, pk[1], pk[0]) * hm) % pk[0], r


def signer(_m, sk, N):
    return pow(_m, sk, N)


def verify(m, pk, sk, r, _sigma):
    h = hashlib.new(pk[2])
    h.update(m)
    hm = int(h.hexdigest(), 16)
    return pow(hm, sk, pk[0]) == (_sigma * pow(r, -1, pk[0])) % pk[0]


# Key generation
pk, sk = key_generation()

m = b'afan'

# User signing
_m, r = user(m, pk)

# Signer signing
_sigma = signer(_m, sk, pk[0])

# Verification
verification_result = verify(m, pk, sk, r, _sigma)

# Output result
print("Blind Signature Verification Result:", verification_result)
