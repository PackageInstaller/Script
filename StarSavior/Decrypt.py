import argparse
import os

class Decrypt:
    _KEY = bytes([0xAA, 0xBB])
    _EXPANDED_KEY = (_KEY * (128 // len(_KEY) + 1))[:128]

    def __init__(self, base_stream):
        self._base_stream = base_stream

    def _process_xor(self, data, stream_position):
        db = bytearray(data)
        dc = len(db)
        sp = max(0, stream_position)
        ep = min(128, stream_position + dc)

        if sp >= ep:
            return bytes(db)

        for i in range(sp, ep):
            di = i - stream_position
            if 0 <= di < dc:
                db[di] ^= self._EXPANDED_KEY[i]
        return bytes(db)

    def read(self, count=-1):
        cp = self._base_stream.tell()
        od = self._base_stream.read(count)
        if not od:
            return b''
        return self._process_xor(od, cp)

def decrypt(file):
    with open(file, 'rb') as f:
        dec = Decrypt(f).read()
    with open(file, 'wb') as f:
        f.write(dec)
    print(f"解密: {file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path')
    args = parser.parse_args()

    for root, dirs, files in os.walk(args.path):
        for filename in files:
            file = os.path.join(root, filename)
            decrypt(file)