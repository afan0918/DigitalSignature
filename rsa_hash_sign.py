import hashlib
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def generate_keypair(bit_length=1024):
    # 產生兩個大質數 p 和 q
    p = getPrime(bit_length)
    q = getPrime(bit_length)

    # 計算 N 和歐拉函數(phi)
    N = p * q
    phi = (p - 1) * (q - 1)

    # 選擇一個公鑰 e
    e = 65537

    # 計算私鑰 d
    d = pow(e, -1, phi)

    # 選擇 Hash 函數
    hash_function = 'sha256'

    # 返回公鑰和私鑰
    public_key = (N, e, hash_function)
    private_key = (d, hash_function)

    return public_key, private_key

def sign(message, private_key, N):
    # 使用 Hash 函數計算消息的哈希值
    h = hashlib.new(private_key[1])
    h.update(message)
    hashed_message = int(h.hexdigest(), 16)

    # 使用私鑰簽署哈希值
    signature = pow(hashed_message, private_key[0], N)

    return signature

def verify(public_key, message, signature):
    # 使用 Hash 函數計算消息的哈希值
    h = hashlib.new(public_key[2])
    h.update(message)
    hashed_message = int(h.hexdigest(), 16)

    # 使用公鑰驗證簽章
    return hashed_message == pow(signature, public_key[1], public_key[0])

# 生成金鑰對
public_key, private_key = generate_keypair()

# 訊息轉換為數字
message = b'afan'

# 用私鑰簽署
signature = sign(message, private_key, public_key[0])

# 用公鑰驗證
verification_result = verify(public_key, message, signature)

# 輸出結果
print("Signature Verification Result:", verification_result)
print("Original Message:", message)
