from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(i: str, o: str, key: bytes, iv: bytes):
    with open(i, 'rb') as f:
        data = f.read()

    with open(o, 'wb') as f:
        f.write(unpad((AES.new(key, AES.MODE_CBC, iv)).decrypt(data), AES.block_size))


def to_signed_64(val: int) -> int:
    val &= 0xFFFFFFFFFFFFFFFF
    if val >= 0x8000000000000000:
        val -= 0x10000000000000000
    return val

def calc_iv_bytes(filename: str) -> bytes:
    v7 = 95719367
    for c in filename:
        v7 = (v7 * 31 + ord(c)) & 0xFFFFFFFFFFFFFFFF

    v10 = 19478245
    for c in reversed(filename):
        v10 = (v10 * 31 + ord(c)) & 0xFFFFFFFFFFFFFFFF

    v7 = to_signed_64(v7)
    v10 = to_signed_64(v10)

    return v7.to_bytes(8, 'little', signed=True) + v10.to_bytes(8, 'little', signed=True)

filename = "zh_c5a9ea35f3a3e8327f0188c21019c7ae.bundle"
iv = calc_iv_bytes(filename)

decrypt(filename, filename + ".dec", bytes.fromhex("a7 3c c5 f9 0b c3 21 b2 51 75 6a 93 b7 0a 93 38"), iv)