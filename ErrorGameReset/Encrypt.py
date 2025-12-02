import os
import json
import xxhash
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import pad
from Cryptodome.Hash import SHA1


if __name__ == "__main__":
    with open("Saves_Enc.json", "r", encoding="utf-8") as f:
        com = json.dumps(json.load(f), separators=(",", ":"), ensure_ascii=False)
        ori = com.encode("utf-8")

    pla = b"\x41\x43\x54\x6b\x00\x01" + b"\x88\xb2\x7e\x7e" + ori
    salt_iv = os.urandom(16)

    with open("Saves.json", "wb") as f:
        f.write(
            (xxhash.xxh32(pla, seed=0x6031D5ED).intdigest() ^ 0x7E7EB288).to_bytes(
                4, "little"
            )
        )
        f.write(salt_iv)
        f.write(
            (
                AES.new(
                    PBKDF2(
                        "FH`[GBsrAd&%^as*#SDFds",
                        salt_iv,
                        dkLen=16,
                        count=10,
                        hmac_hash_module=SHA1,
                    ),
                    AES.MODE_CBC,
                    salt_iv,
                )
            ).encrypt(pad(pla, AES.block_size))
        )
