import hashlib
import random
import string

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# 參考 https://iotazh.gitbook.io/iota-guidebook/tangle/transaction/ots

m = b'afan'

H = 'sha256'


def generate_numbers(length):
    nums = []
    for _ in range(length):
        nums.append(getPrime(256))
    return nums


def generate_pk(sk):
    nums = []
    for x in sk:
        h = hashlib.new(H)
        h.update(long_to_bytes(x))
        hx = int(h.hexdigest(), 16)
        nums.append(hx)
    return nums


sk_a = generate_numbers(256)  # 第一組私鑰
sk_b = generate_numbers(256)  # 第二組私鑰
pk_a = generate_pk(sk_a)
pk_b = generate_pk(sk_b)
sk = (sk_a, sk_b)
pk = (pk_a, pk_b)


def sign(m, pk):
    h = hashlib.new(H)
    h.update(m)
    hm = int(h.hexdigest(), 16)
    hm_bit = bin(hm)[2:]
    sign_list = []
    for i in range(len(hm_bit)):
        sign_list.append(pk[int(hm_bit[i])][i])
        pk[0 if int(hm_bit[i]) else 1][i] = -1
    return sign_list


def verify(m, pk):
    h = hashlib.new(H)
    h.update(m)
    hm = int(h.hexdigest(), 16)
    hm_bit = bin(hm)[2:]
    for i in range(len(hm_bit)):
        if pk[0 if int(hm_bit[i]) else 1][i]!=-1:
            return False
    return True


signed_list = sign(m, pk)  # 用公鑰簽名
print(verify(m, pk))  # 用私鑰驗證
