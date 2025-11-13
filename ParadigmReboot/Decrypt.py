import os
import sys
from multiprocessing import Pool, cpu_count
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


KEY = bytes.fromhex("a7 3c c5 f9 0b c3 21 b2 51 75 6a 93 b7 0a 93 38")


def to_signed_64(val: int) -> int:
    val &= 0xFFFFFFFFFFFFFFFF
    if val >= 0x8000000000000000:
        val -= 0x10000000000000000
    return val


def calc_iv(filename: str) -> bytes:
    v7 = 95719367
    for c in filename:
        v7 = (v7 * 31 + ord(c)) & 0xFFFFFFFFFFFFFFFF

    v10 = 19478245
    for c in reversed(filename):
        v10 = (v10 * 31 + ord(c)) & 0xFFFFFFFFFFFFFFFF

    v7 = to_signed_64(v7)
    v10 = to_signed_64(v10)

    return v7.to_bytes(8, "little", signed=True) + v10.to_bytes(
        8, "little", signed=True
    )


def decrypt(file_path: str):
    with open(file_path, "rb") as f:
        enc = f.read()

    cipher = AES.new(
        KEY,
        AES.MODE_CBC,
        calc_iv(os.path.basename(file_path)),
    )
    with open(file_path, "wb") as f:
        f.write(unpad(cipher.decrypt(enc), AES.block_size))


def find(root_dir: str) -> list[str]:
    bundle = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".bundle"):
                bundle.append(os.path.join(root, file))
    return bundle


if __name__ == "__main__":
    with Pool(processes=cpu_count()) as pool:
        pool.map(decrypt, find(sys.argv[1]))
