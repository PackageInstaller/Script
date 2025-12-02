import json
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad
from Cryptodome.Hash import SHA1


if __name__ == "__main__":
    with open("Saves.json", "rb") as f:
        f.read(4)
        salt_iv = f.read(16)
        enc = f.read()

    dec = unpad(
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
        ).decrypt(enc),
        AES.block_size,
    )
    with open("Saves_Enc.json", "w", encoding="utf-8") as f:
        json.dump(
            json.loads((dec[10 : dec.rfind(b"}") + 1]).decode("utf-8")),
            f,
            indent=4,
            ensure_ascii=False,
        )
