import hashlib
from Crypto.Util.number import getPrime, long_to_bytes

# 參考 https://iotazh.gitbook.io/iota-guidebook/tangle/transaction/ots


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


def sign(m, sk):
    h = hashlib.new(H)
    h.update(m)
    hm = int(h.hexdigest(), 16)
    hm_bit = bin(hm)[2:]
    sign_list = []
    for i in range(len(hm_bit)):
        sign_list.append(sk[int(hm_bit[i])][i])
    return sign_list


def verify(m, sk, pk):
    h = hashlib.new(H)
    h.update(m)
    hm = int(h.hexdigest(), 16)
    hm_bit = bin(hm)[2:]
    for i in range(len(hm_bit)):
        h = hashlib.new(H)
        h.update(long_to_bytes(sk[i]))
        h_sk = int(h.hexdigest(), 16)
        if h_sk != pk[1 if int(hm_bit[i]) else 0][i]:
            return False
    return True


m = b'afan'
H = 'sha256'

sk_a = generate_numbers(256)  # 第一組私鑰
sk_b = generate_numbers(256)  # 第二組私鑰
pk_a = generate_pk(sk_a)
pk_b = generate_pk(sk_b)
sk = (sk_a, sk_b)
pk = (pk_a, pk_b)

signed_sk_list = sign(m, sk)  # 用私鑰簽名
verification_result = verify(m, signed_sk_list, pk)  # 用公私鑰驗證，這裡的私鑰是一半的數字被歸零或省略的私鑰
print("Signature Verification Result:", verification_result)
