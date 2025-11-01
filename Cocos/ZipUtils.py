import zlib
import struct
from typing import Optional
from PIL import Image
from texture2ddecoder import decode_etc2a8


class ZipUtils:
    def __init__(
        self,
        key_part1: Optional[int] = None,
        key_part2: Optional[int] = None,
        key_part3: Optional[int] = None,
        key_part4: Optional[int] = None,
    ):
        """
        Args:
            key_part1-4: 解密密钥的四个部分，仅在处理 CCZp 格式时需要
                        如果只处理 CCZ! 格式，可以不传入密钥
        """
        if key_part1 and key_part2 and key_part3 and key_part4:
            self.s_uEncryptedPvrKeyParts = [key_part1, key_part2, key_part3, key_part4]
        else:
            self.s_uEncryptedPvrKeyParts = None

    def _generate_key_stream(self, initial_sum: int) -> list[int]:
        s_uEncryptionKey = [0] * 1024

        v8 = initial_sum
        v5 = 0

        while True:
            v6 = 0
            v7 = 0
            v8 = (v8 - 0x61C88647) & 0xFFFFFFFF
            v9 = v8 >> 2
            while v7 != 1023:
                v10 = ((v7 & 0xFF) ^ (v9 & 0xFF)) & 3
                mx = (
                    ((v5 >> 5) ^ (s_uEncryptionKey[v6 + 1] << 2))
                    + ((s_uEncryptionKey[v6 + 1] >> 3) ^ (v5 << 4))
                ) & 0xFFFFFFFF
                mx ^= (
                    (v8 ^ s_uEncryptionKey[v6 + 1])
                    + (self.s_uEncryptedPvrKeyParts[v10] ^ v5)
                ) & 0xFFFFFFFF
                s_uEncryptionKey[v6] = (s_uEncryptionKey[v6] + mx) & 0xFFFFFFFF
                v5 = s_uEncryptionKey[v6]
                v6 += 1
                v7 += 1

            y = s_uEncryptionKey[0]
            mx = (((v5 >> 5) ^ (y << 2)) + ((y >> 3) ^ (v5 << 4))) & 0xFFFFFFFF
            mx ^= (
                (v8 ^ y) + (self.s_uEncryptedPvrKeyParts[((~v9) & 3)] ^ v5)
            ) & 0xFFFFFFFF
            s_uEncryptionKey[1023] = (s_uEncryptionKey[1023] + mx) & 0xFFFFFFFF
            v5 = s_uEncryptionKey[1023]

            if v8 == 0xB54CDA56:
                break

        return s_uEncryptionKey

    def _decrypt_data(
        self, encrypted_uints: list[int], key_stream: list[int]
    ) -> list[int]:
        num_uints = len(encrypted_uints)
        if num_uints == 0:
            return []
        key_idx, i = 0, 0
        limit = min(num_uints, 512)
        while i < limit:
            encrypted_uints[i] ^= key_stream[key_idx]
            key_idx = (key_idx + 1) % 1024
            i += 1
        while i < num_uints:
            encrypted_uints[i] ^= key_stream[key_idx]
            key_idx = (key_idx + 1) % 1024
            i += 64
        return encrypted_uints

    def inflateCCZBuffer(self, content: bytes) -> bytes | Image.Image:
        file_len = len(content)
        if file_len < 16:
            return b""
        header = content[0:4]

        if header == b"CCZp":
            try:
                if self.s_uEncryptedPvrKeyParts is None:
                    print("错误: CCZp 格式需要提供解密密钥")
                    return b""

                initial_sum = struct.unpack(">H", content[4:6])[0]
                if initial_sum != 0:
                    return b""
                key_stream = self._generate_key_stream(initial_sum)
                data_len_bytes = file_len - 12
                num_uints = data_len_bytes // 4
                encrypted_uints = list(
                    struct.unpack_from(f"<{num_uints}I", content, 12)
                )
                decrypted_uints = self._decrypt_data(encrypted_uints, key_stream)
                if not decrypted_uints:
                    return b""
                buffer = b"".join(
                    [struct.pack("<I", val) for val in decrypted_uints[1:]]
                )
                mod = data_len_bytes % 4
                if mod > 0:
                    buffer += content[-mod:]
                return zlib.decompress(buffer)
            except Exception:
                return b""
        elif header == b"CCZ!":
            try:
                pvr_data = zlib.decompress(content[16:])
                if len(pvr_data) < 52 or pvr_data[0:4] != b"PVR\x03":
                    return b""
                h = struct.unpack("<IQIIIIIIIII", pvr_data[4:52])
                flags, p_format_64, height, width, metadata_size = (
                    h[0],
                    h[1],
                    h[4],
                    h[5],
                    h[10],
                )
                p_format = p_format_64 & 0xFFFFFFFF if (p_format_64 >> 32) == 0 else -1
                if p_format != 23:
                    return b""
                decoded_pixels = decode_etc2a8(
                    pvr_data[52 + metadata_size :], width, height
                )
                is_premultiplied = (flags & 0x02) != 0
                corrected = bytearray(len(decoded_pixels))
                for i in range(0, len(decoded_pixels), 4):
                    b, g, r, a = decoded_pixels[i : i + 4]
                    if is_premultiplied and a > 0:
                        r, g, b = (
                            min(255, int(r * 255 / a)),
                            min(255, int(g * 255 / a)),
                            min(255, int(b * 255 / a)),
                        )
                    elif is_premultiplied and a == 0:
                        r, g, b = 0, 0, 0
                    corrected[i : i + 4] = [r, g, b, a]

                return Image.frombytes("RGBA", (width, height), bytes(corrected))
            except Exception:
                return b""
        return b""
