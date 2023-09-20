from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

p = getPrime(1024)
q = getPrime(1024)

N = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
pk = (N, e)  # 公鑰
sk = d  # 私鑰

m = b'afan'
m = bytes_to_long(m)


def sign(m, d, N):
    return pow(m, d, N)


def verify(pk, m, a):
    return m == pow(a, pk[1], pk[0])


a = sign(m, sk, N)  # 用公鑰簽名
print(verify(pk, m, a))  # 用私鑰驗證
print(long_to_bytes(m))
