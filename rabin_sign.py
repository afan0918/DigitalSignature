import hashlib
import random
import string

import gmpy2
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# 老師講的方式不知道為什麼實現不出來，參考以下連結
# p, q 特別小是因為這樣算比較快，實務運用上再調大
# https://cryptography.fandom.com/wiki/Rabin_signature_algorithm

p = getPrime(8)
q = getPrime(8)

N = p * q
H = 'sha256'
pk = N  # 公鑰
padding_length = 100

m = b'afan'


def sign(m, N, H):
    while True:
        u = ''.join(random.SystemRandom().choice(string.printable) for _ in range(padding_length))
        u = u.encode('utf-8')

        h = hashlib.new(H)
        h.update(m + u)
        hm = int(h.hexdigest(), 16)
        if gmpy2.iroot(hm % N, 2)[1]:
            return (u, gmpy2.iroot(hm % N, 2)[0])


def verify(sk, m, N, H):
    h = hashlib.new(H)
    h.update(m + sk[0])
    hm = int(h.hexdigest(), 16) % N
    return pow(sk[1], 2) == hm


sk = sign(m, pk, H)  # 用私鑰簽名
print(sk)
print(verify(sk, m, pk, H))  # 用公鑰驗證
