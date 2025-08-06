import texture2ddecoder
import lz4.block
import struct
from PIL import Image

def decompress(compressed_data: bytes) -> bytearray:

    total_uncompressed_size = struct.unpack('<I', compressed_data[4:8])[0]

    final_buffer = bytearray()
    current_pos = 8
    last_decompressed_block = b""

    block_index = 0
    while current_pos < len(compressed_data):
        if current_pos + 4 > len(compressed_data): 
            break
        compressed_block_size = struct.unpack('<I', compressed_data[current_pos : current_pos + 4])[0]
        current_pos += 4
        if compressed_block_size == 0: 
            break

        compressed_block = compressed_data[current_pos : current_pos + compressed_block_size]
        current_pos += compressed_block_size

        try:
            decompressed_chunk = lz4.block.decompress(
                compressed_block,
                uncompressed_size=16 * 1024,
                dict=last_decompressed_block
            )
            final_buffer.extend(decompressed_chunk)
            last_decompressed_block = decompressed_chunk
            block_index += 1
        except Exception as e:
            print(f"LZ4解压缩错误{e}")
            break

    return final_buffer[:total_uncompressed_size]


def convert_to_image(pkm_data: bytes, output_path: str):

    header_fields = struct.unpack_from('>HHHHH', pkm_data, 6)
    
    etc_format_enum = header_fields[0]
    width = header_fields[1]
    height = header_fields[2]

    if etc_format_enum in [2, 3, 4, 10, 11]:
        mode = "RGBA"
        decoder_func = texture2ddecoder.decode_etc2a8
    elif etc_format_enum in [1, 9]:
        mode = "RGB"
        decoder_func = texture2ddecoder.decode_etc2

    pixel_data = pkm_data[16:]
    decoded_pixels = decoder_func(pixel_data, width, height)

    image = Image.frombytes(mode, (width, height), decoded_pixels)
    image.save(output_path, 'PNG')

if __name__ == "__main__":
    with open("ljzzy_1.jpg", "rb") as f:
        comp = f.read()

    convert_to_image(bytes(decompress(comp)), "decompress.png")