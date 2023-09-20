import hashlib

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

p = getPrime(1024)
q = getPrime(1024)

N = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
H = 'sha256'
pk = (N, e, H)  # 公鑰
sk = (d, H)  # 私鑰

m = b'afan'


def sign(m, sk, N):
    h = hashlib.new(sk[1])
    h.update(m)
    hm = int(h.hexdigest(), 16)
    return pow(hm, sk[0], N)


def verify(pk, m, a):
    h = hashlib.new(pk[2])
    h.update(m)
    hm = int(h.hexdigest(), 16)
    return hm == pow(a, pk[1], pk[0])


a = sign(m, sk, N)  # 用公鑰簽名
print(verify(pk, m, a))  # 用私鑰驗證
print(m)
