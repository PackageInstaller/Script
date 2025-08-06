import texture2ddecoder
import lz4.block
import struct
from PIL import Image


class LZ4StreamDecoder:
    def __init__(self):
        self.dictionary = b""
        self.buffer_size = 0x4000
        
    def decompress_continue(self, compressed_data, compressed_size):
        if compressed_size == 0:
            return b"", True

        try: 
            decompressed = lz4.block.decompress(
                compressed_data,
                uncompressed_size=self.buffer_size,
                dict=self.dictionary
            )
            self.dictionary = decompressed
            return decompressed, True
        except Exception as e:
            print(f"LZ4解压缩错误{e}")
            return b"", False



def block_decompress(stream_decoder, data_ptr):

    if len(data_ptr) < 4:
        return b"", 4, False

    compressed_size = struct.unpack('<I', data_ptr[:4])[0]
    bytes_consumed = 4
    
    if compressed_size == 0:
        return b"", bytes_consumed, True
        
    if len(data_ptr) < 4 + compressed_size:
        return b"", bytes_consumed, False
        
    compressed_block = data_ptr[4:4 + compressed_size]
    bytes_consumed += compressed_size
    
    decompressed_data, success = stream_decoder.decompress_continue(
        compressed_block, compressed_size
    )
    
    return decompressed_data, bytes_consumed, success


def init_with_lz4_etc2_data(compressed_data):

    stream_decoder = LZ4StreamDecoder()
    total_uncompressed_size = struct.unpack('<I', compressed_data[4:8])[0]
    output_buffer = bytearray()
    
    current_pos = 8 
    buffer_index = 0 
    
    while current_pos < len(compressed_data):
        remaining_data = compressed_data[current_pos:]
        
        decompressed_chunk, bytes_consumed, _ = block_decompress(
            stream_decoder, remaining_data
        )
        
        current_pos += bytes_consumed
        
        if len(decompressed_chunk) == 0:
            break
            
        output_buffer.extend(decompressed_chunk)

        buffer_index = (buffer_index + 1) % 2 

    if len(output_buffer) > total_uncompressed_size:
        output_buffer = output_buffer[:total_uncompressed_size]
    
    return bytes(output_buffer)


def get_pkm_width(pkm_data):
    if len(pkm_data) < 16:
        return 0
    return struct.unpack('>H', pkm_data[8:10])[0]


def get_pkm_height(pkm_data):
    if len(pkm_data) < 16:
        return 0
    return struct.unpack('>H', pkm_data[10:12])[0]


def get_pkm_format(pkm_data):
    if len(pkm_data) < 16:
        return 0
    return struct.unpack('>H', pkm_data[6:8])[0]


def init_with_etc2_data(pkm_data, data_size):

    width = get_pkm_width(pkm_data)
    height = get_pkm_height(pkm_data)
    etc_format = get_pkm_format(pkm_data)
    

    if etc_format in [2, 3, 4, 10, 11]:
        mode = "RGBA"
        decoder_func = texture2ddecoder.decode_etc2a8
    elif etc_format in [1, 9]:
        mode = "RGB" 
        decoder_func = texture2ddecoder.decode_etc2
    else:
        print(f"不支持的ETC格式: {etc_format}")
        return None
    

    decoded_pixels = decoder_func(pkm_data[16:], width, height)
    image = Image.frombytes(mode, (width, height), decoded_pixels)
    return image



def decrypt(input_file, output_file):

    with open(input_file, "rb") as f:
        compressed_data = f.read()
    
    pkm_data = init_with_lz4_etc2_data(compressed_data)
    image = init_with_etc2_data(pkm_data, len(pkm_data))
    image.save(output_file, 'PNG')

if __name__ == "__main__":
    decrypt("gn_tb_216.png", "dec.png")
