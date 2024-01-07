import hashlib
import random
import string
import gmpy2
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def generate_keypair(bit_length=8):
    # 產生兩個特別小的質數 p 和 q
    # 一定要這樣選是因為不然會算很久
    p = getPrime(bit_length)
    q = getPrime(bit_length)

    # 計算 N
    N = p * q

    # 選擇 Hash 函數
    hash_function = 'sha256'

    # 返回公鑰
    public_key = N

    return public_key, hash_function

def sign(message, public_key, hash_function, padding_length=100):
    while True:
        # 生成隨機填充
        u = ''.join(random.SystemRandom().choice(string.printable) for _ in range(padding_length))
        u = u.encode('utf-8')

        # 計算消息和填充的哈希值
        h = hashlib.new(hash_function)
        h.update(message + u)
        hashed_message = int(h.hexdigest(), 16)

        # 檢查是否存在平方根
        if gmpy2.iroot(hashed_message % public_key, 2)[1]:
            return (u, gmpy2.iroot(hashed_message % public_key, 2)[0])

def verify(signature, message, public_key, hash_function):
    u, sqrt_hashed_message = signature

    # 計算消息和填充的哈希值
    h = hashlib.new(hash_function)
    h.update(message + u)
    hashed_message = int(h.hexdigest(), 16) % public_key

    # 驗證簽章
    return (pow(sqrt_hashed_message, 2, public_key) == hashed_message) or (pow(public_key - sqrt_hashed_message, 2, public_key) == hashed_message)

# 生成金鑰對
public_key, hash_function = generate_keypair()

# 訊息
message = b'afan'

# 用私鑰簽署
signature = sign(message, public_key, hash_function)

# 用公鑰驗證
verification_result = verify(signature, message, public_key, hash_function)

# 輸出結果
print("Signature Verification Result:", verification_result)
