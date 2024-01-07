import hashlib
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


def key_generation():
    # 隨機從 Zq 中選擇 x
    x = random.randint(1, q - 1)
    # 計算 y = g^x
    y = pow(g, x, p)
    # 輸出公鑰 (g, y, H) 和私鑰 x
    return (g, y, H), x


def partially_blind_sign(private_key, blinded_message):
    # 從 Zq 中選擇一個隨機值 k
    k = random.randint(1, q - 1)
    # 計算 r = g^k
    r = pow(g, k, p)
    # 計算 e = H(r||blinded_message)
    h_input = bytes(str(r) + blinded_message, 'utf-8')
    e = int.from_bytes(hashlib.sha256(h_input).digest(), byteorder='big') % q
    # 計算 s = k - x * e
    s = (k - private_key * e) % q
    # 簽名 = (s, e)
    return (s, e)


def verify(public_key, signature, blinded_message):
    # 解析公鑰 (g, y, H)
    g, y, H = public_key
    # 解析簽名 (s, e)
    s, e = signature
    # 計算 r = g^s * y^e mod p
    r = (pow(g, s, p) * pow(y, e, p)) % p
    # 計算 H(r||blinded_message)
    h_input = bytes(str(r) + blinded_message, 'utf-8')
    e_prime = int.from_bytes(hashlib.sha256(h_input).digest(), byteorder='big') % q
    # 驗證 e_prime 是否等於 e
    return e_prime == e


if __name__ == "__main__":
    p = getPrime(1024)
    q = (p - 1) // 2
    g = 2
    H = hashlib.sha256

    # 生成密鑰
    public_key, private_key = key_generation()

    # 要簽名的資訊
    message = "afan^^"

    # 部分盲簽名
    signature = partially_blind_sign(private_key, message)

    # 驗證（提供要盲簽消息的部分以進行驗證）
    verification_result = verify(public_key, signature, message)
    print("Partially Blind Schnorr Signature Verification Result:", verification_result)
