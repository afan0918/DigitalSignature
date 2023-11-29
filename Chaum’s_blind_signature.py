import hashlib
import random

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

p = getPrime(1024)
q = getPrime(1024)

N = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
H = 'sha256'
pk = (N, e, H)  # 公鑰
sk = d  # 私鑰

m = b'afan'


# m = bytes_to_long(m)


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


_m, r = user(m, pk)  # 用公鑰簽名
_sigma = signer(_m, sk, N)
print(verify(m, pk, sk, r, _sigma))  # 用私鑰驗證
# print(long_to_bytes(m))
