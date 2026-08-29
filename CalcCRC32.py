import lzma
import struct
import zlib
import sys
import os
import lz4.block
from io import BytesIO, BufferedReader


class BitStream:
    SEEK_ABS = 0
    SEEK_REL = 1
    BIGENDIAN = 1
    LITTLEENDIAN = 0

    def __init__(self, bs, bigEndian=LITTLEENDIAN):
        if type(bs) == bytearray or type(bs) == bytes:
            bs = BufferedReader(BytesIO(bs))
        self.bs = bs
        currentOffset = bs.tell()
        bs.seek(0, os.SEEK_END)
        self.fileSize = bs.tell()
        bs.seek(currentOffset, os.SEEK_SET)
        self.setEndian(bigEndian)

    def getBytes(self):
        return self.bs.read()

    def getBytearray(self):
        return bytearray(self.bs.read())

    def setEndian(self, bigEndian=LITTLEENDIAN):
        self.endian = "<" if bigEndian == self.LITTLEENDIAN else ">"

    def getBufferedReader(self):
        return self.bs

    def readBytes(self, numBytes: int):
        return self.bs.read(numBytes)

    def readBool(self):
        return struct.unpack(f'{self.endian}?', self.bs.read(1))[0]

    def readByte(self):
        return struct.unpack(f'{self.endian}b', self.bs.read(1))[0]

    def readUByte(self):
        return struct.unpack(f'{self.endian}B', self.bs.read(1))[0]

    def readShort(self):
        return struct.unpack(f'{self.endian}h', self.bs.read(2))[0]

    def readUShort(self):
        return struct.unpack(f'{self.endian}H', self.bs.read(2))[0]

    def readInt(self):
        return struct.unpack(f'{self.endian}i', self.bs.read(4))[0]

    def readUInt(self):
        return struct.unpack(f'{self.endian}I', self.bs.read(4))[0]

    def readFloat(self):
        return struct.unpack(f'{self.endian}f', self.bs.read(4))[0]

    def readDouble(self):
        return struct.unpack(f'{self.endian}d', self.bs.read(8))[0]

    def readInt64(self):
        return struct.unpack(f'{self.endian}q', self.bs.read(8))[0]

    def readUInt64(self):
        return struct.unpack(f'{self.endian}Q', self.bs.read(8))[0]

    def readUInt24(self):
        d = self.bs.read(3)
        if self.endian == "<":
            return int(d[0]) | (int(d[1]) << 8) | (int(d[2]) << 16)
        return int(d[2]) | (int(d[1]) << 8) | (int(d[0]) << 16)

    def readHalfFloat(self):
        return struct.unpack(f'{self.endian}e', self.bs.read(2))[0]

    def readString(self, sep=0x00, encoding='utf-8'):
        bytearr = []
        while True:
            byte = struct.unpack(f'{self.endian}b', self.bs.read(1))[0]
            if byte == sep:
                break
            bytearr.append(byte)
        return bytes(bytearr).decode(encoding)

    def readline(self):
        return self.bs.readline()

    def readlines(self):
        return self.bs.readlines()

    def seek(self, addr: int, isRelative=SEEK_ABS):
        if isRelative != self.SEEK_ABS and isRelative != self.SEEK_REL:
            raise Exception(
                "Parameter isRelative must be SEEK_ABS or SEEK_REL.")
        self.bs.seek(addr, os.SEEK_SET if isRelative ==
                     self.SEEK_ABS else os.SEEK_CUR)

    def tell(self):
        return self.bs.tell()

    def checkEOF(self):
        return self.bs.tell() >= self.fileSize


class UnityBundleCRC:
    def __init__(self, file_path):
        self.file_path = file_path
        f = open(file_path, "rb")
        self.reader = BitStream(BufferedReader(
            f), bigEndian=BitStream.BIGENDIAN)

    def parse_and_calculate(self):
        signature = self.reader.readString()  # "UnityFS"
        if signature != "UnityFS":
            raise ValueError("Only UnityFS format is supported")

        version = self.reader.readUInt()
        version_player = self.reader.readString()
        version_engine = self.reader.readString()

        print(f"Signature: {signature}, Version: {version}")
        print(f"Engine: {version_engine}")

        bundle_size = self.reader.readInt64()
        compressed_block_info_size = self.reader.readUInt()
        uncompressed_block_info_size = self.reader.readUInt()
        flags = self.reader.readUInt()

        if version >= 7:
            curr = self.reader.tell()
            align = (16 - (curr % 16)) % 16
            if align > 0:
                self.reader.seek(align, BitStream.SEEK_REL)

        block_info_data = self.reader.readBytes(compressed_block_info_size)

        block_info_comp_flag = flags & 0x3F
        if block_info_comp_flag in (2, 3):  # LZ4 / LZ4HC
            block_info_raw = lz4.block.decompress(
                block_info_data, uncompressed_size=uncompressed_block_info_size)
        elif block_info_comp_flag == 0:  # None
            block_info_raw = block_info_data
        else:
            raise NotImplementedError(
                f"BlockInfo compression method {block_info_comp_flag} is not implemented")

        bi_reader = BitStream(block_info_raw, bigEndian=BitStream.BIGENDIAN)
        uncompressed_data_hash = bi_reader.readBytes(16)
        block_count = bi_reader.readUInt()

        blocks = []
        for _ in range(block_count):
            u_size = bi_reader.readUInt()    # Uncompressed size
            c_size = bi_reader.readUInt()    # Compressed size
            b_flags = bi_reader.readUShort()  # Compression flags
            blocks.append(
                {'u_size': u_size, 'c_size': c_size, 'flags': b_flags})

        # Calculate data stream CRC
        print(f"Starting CRC calculation for {len(blocks)} blocks...")
        running_crc = 0

        # Alignment before the start of the data blocks
        if flags & 0x200:
            curr = self.reader.tell()
            align = (16 - (curr % 16)) % 16
            if align > 0:
                self.reader.seek(align, BitStream.SEEK_REL)

        for i, block in enumerate(blocks):
            compressed_data = self.reader.readBytes(block['c_size'])

            comp_type = block['flags'] & 0x3F
            if comp_type == 1:  # LZMA
                props, rest = compressed_data[:5], compressed_data[5:]
                raw_data = lzma.decompress(props + struct.pack('<Q', block['u_size']) + rest)
            elif comp_type in (2, 3):
                raw_data = lz4.block.decompress(compressed_data, uncompressed_size=block['u_size'])
            elif comp_type == 0:
                raw_data = compressed_data
            else:
                raise ValueError(
                    f"Block {i} uses an unsupported compression type: {comp_type}")

            running_crc = zlib.crc32(raw_data, running_crc)

        final_crc = running_crc & 0xFFFFFFFF
        print(f"Calculation finished!\nCalculated CRC32: {final_crc:08X}")
        return final_crc

    def close(self):
        self.reader.bs.close()


if __name__ == "__main__":
    bundle_path = sys.argv[1]
    if os.path.exists(bundle_path):
        try:
            calc = UnityBundleCRC(bundle_path)
            result = calc.parse_and_calculate()
            calc.close()
        except Exception as e:
            print(f"Error: {e}")
    else:
        print(f"File not found: {bundle_path}")
