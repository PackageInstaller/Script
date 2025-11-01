import io
import os
import sys
import shutil
from pathlib import Path
from typing import List, Optional, Tuple
import struct
from dataclasses import dataclass


MANIFEST_FILE_SIGN = 0x594F4F  # YOO
SUPPORTED_VERSIONS = ["1.5.2", "2.0.0", "2.3.1", "2.3.17"]

class BufferReader:
    """二进制数据读取器"""
    
    def __init__(self, data: bytes):
        self.buffer = data
        self.index = 0
        
    @property
    def is_valid(self) -> bool:
        """检查缓冲区是否有效"""
        return self.buffer is not None and len(self.buffer) > 0
    
    @property
    def capacity(self) -> int:
        """获取缓冲区容量"""
        return len(self.buffer)
    
    def _check_reader_index(self, count: int):
        """检查读取索引是否越界"""
        if self.index + count > len(self.buffer):
            raise IndexError(f"缓冲区溢出: 尝试读取 {count} 字节，索引 {self.index}，缓冲区大小: {len(self.buffer)}")
    
    def read_bytes(self, count: int) -> bytes:
        """读取指定数量的字节"""
        self._check_reader_index(count)
        data = self.buffer[self.index:self.index + count]
        self.index += count
        return data
    
    def read_byte(self) -> int:
        """读取单个字节"""
        return struct.unpack('<B', self.read_bytes(1))[0]
    
    def read_bool(self) -> bool:
        """读取布尔值"""
        return self.read_byte() != 0
    
    def read_int16(self) -> int:
        """读取16位整数（小端序）"""
        return struct.unpack('<h', self.read_bytes(2))[0]
    
    def read_uint16(self) -> int:
        """读取16位无符号整数（小端序）"""
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def read_int32(self) -> int:
        """读取32位整数（小端序）"""
        return struct.unpack('<i', self.read_bytes(4))[0]
    
    def read_uint32(self) -> int:
        """读取32位无符号整数（小端序）"""
        return struct.unpack('<I', self.read_bytes(4))[0]
    
    def read_int64(self) -> int:
        """读取64位整数（小端序）"""
        return struct.unpack('<q', self.read_bytes(8))[0]
    
    def skip_utf8(self):
        """跳过UTF-8字符串而不解析"""
        length = self.read_uint16()
        if length > 0:
            self._check_reader_index(length)
            self.index += length
    
    def read_utf8(self) -> str:
        """读取UTF-8字符串"""
        length = self.read_uint16()
        if length == 0:
            return ""
        string_bytes = self.read_bytes(length)
        return string_bytes.decode('utf-8')
    
    def read_utf8_array(self) -> List[str]:
        """读取UTF-8字符串数组"""
        count = self.read_uint16()
        return [self.read_utf8() for _ in range(count)]
    
    def read_int32_array(self) -> List[int]:
        """读取32位整数数组"""
        count = self.read_uint16()
        return [self.read_int32() for _ in range(count)]


@dataclass
class PackageAsset:
    """资源包中的资源信息"""
    address: str = ""
    asset_path: str = ""
    asset_guid: str = ""
    asset_tags: List[str] = None
    bundle_id: int = 0
    depend_ids: List[int] = None  # 仅在1.5.2版本中使用
    depend_bundle_ids: List[int] = None  # 2.3.12版本中使用
    
    def __post_init__(self):
        if self.asset_tags is None:
            self.asset_tags = []
        if self.depend_ids is None:
            self.depend_ids = []
        if self.depend_bundle_ids is None:
            self.depend_bundle_ids = []


@dataclass
class PackageBundle:
    """资源包信息"""
    bundle_name: str = ""
    unity_crc: int = 0
    file_hash: str = ""
    file_crc: str = ""
    file_size: int = 0
    # 1.5.2版本字段
    is_raw_file: bool = False
    load_method: int = 0
    reference_ids: List[int] = None
    # 2.0.0版本字段
    encrypted: bool = False
    depend_ids: List[int] = None
    # 2.3.12版本字段
    depend_bundle_ids: List[int] = None
    # 通用字段
    tags: List[str] = None
    
    def __post_init__(self):
        if self.reference_ids is None:
            self.reference_ids = []
        if self.depend_ids is None:
            self.depend_ids = []
        if self.depend_bundle_ids is None:
            self.depend_bundle_ids = []
        if self.tags is None:
            self.tags = []


@dataclass
class PackageManifest:
    """资源包清单"""
    file_version: str = ""
    enable_addressable: bool = False
    support_extensionless: bool = False  # 2.3.17版本新增
    location_to_lower: bool = False
    include_asset_guid: bool = False
    replace_asset_path_with_address: bool = False  # 2.3.17版本新增
    output_name_style: int = 0
    build_bundle_type: int = 0  # 2.3.12版本新增
    build_pipeline: str = ""  # 2.0.0+版本使用
    package_name: str = ""
    package_version: str = ""
    package_note: str = ""  # 2.3.12版本新增
    asset_list: List[PackageAsset] = None
    bundle_list: List[PackageBundle] = None
    
    def __post_init__(self):
        if self.asset_list is None:
            self.asset_list = []
        if self.bundle_list is None:
            self.bundle_list = []


class YooAssetDeserializer:
    """YooAsset通用反序列化器"""
    
    def __init__(self, binary_data: bytes):
        self.buffer = BufferReader(binary_data)
        self.manifest: Optional[PackageManifest] = None
        self.version: Optional[str] = None
    
    def deserialize(self) -> PackageManifest:
        """反序列化清单文件"""
        if not self.buffer.is_valid:
            raise ValueError("无效的缓冲区数据")
        
        self._deserialize_file_header()
        
        if self.version == "1.5.2":
            self._deserialize_v152()
        elif self.version == "2.0.0":
            self._deserialize_v200()
        elif self.version == "2.3.1":
            self._deserialize_v2312()
        elif self.version == "2.3.17":
            self._deserialize_v2317()
        else:
            raise ValueError(f"不支持的版本: {self.version}")
        
        return self.manifest
    
    def _deserialize_file_header(self):
        """反序列化文件头"""
        file_sign = self.buffer.read_uint32()
        if file_sign != MANIFEST_FILE_SIGN:
            raise ValueError(f"期望: 0x{MANIFEST_FILE_SIGN:X}, 实际: 0x{file_sign:X}")
        
        file_version = self.buffer.read_utf8()
        if file_version not in SUPPORTED_VERSIONS:
            raise ValueError(f"不支持的文件版本: {file_version}")
        
        self.version = file_version
        
        self.manifest = PackageManifest()
        self.manifest.file_version = file_version
        self.manifest.enable_addressable = self.buffer.read_bool()
        
        # 2.3.17版本新增SupportExtensionless字段
        if self.version == "2.3.17":
            self.manifest.support_extensionless = self.buffer.read_bool()
        
        self.manifest.location_to_lower = self.buffer.read_bool()
        self.manifest.include_asset_guid = self.buffer.read_bool()
        
        # 2.3.17版本新增ReplaceAssetPathWithAddress字段
        if self.version == "2.3.17":
            self.manifest.replace_asset_path_with_address = self.buffer.read_bool()
        
        self.manifest.output_name_style = self.buffer.read_int32()
        
        # 2.0.0+版本新增字段
        if self.version in ["2.0.0", "2.3.1", "2.3.17"]:
            if self.version in ["2.3.1", "2.3.17"]:
                self.manifest.build_bundle_type = self.buffer.read_int32()
            self.manifest.build_pipeline = self.buffer.read_utf8()
        
        self.manifest.package_name = self.buffer.read_utf8()
        self.manifest.package_version = self.buffer.read_utf8()
        
        # 2.3.1+版本新增PackageNote字段
        if self.version in ["2.3.1", "2.3.17"]:
            self.manifest.package_note = self.buffer.read_utf8()
        
        if self.manifest.enable_addressable and self.manifest.location_to_lower:
            raise ValueError("Addressable 不支持，location_to_lower 为 true")
        
        if not self.manifest.enable_addressable and self.manifest.replace_asset_path_with_address:
            raise ValueError("ReplaceAssetPathWithAddress 需要启用 Addressable")
    
    def _deserialize_v152(self):
        """反序列化1.5.2版本的资源列表和Bundle列表"""
        asset_count = self.buffer.read_int32()
        self.manifest.asset_list = []
        
        for _ in range(asset_count):
            asset = PackageAsset()
            asset.address = self.buffer.read_utf8()
            asset.asset_path = self.buffer.read_utf8()
            asset.asset_guid = self.buffer.read_utf8()
            asset.asset_tags = self.buffer.read_utf8_array()
            asset.bundle_id = self.buffer.read_int32()
            asset.depend_ids = self.buffer.read_int32_array()
            self.manifest.asset_list.append(asset)
        
        bundle_count = self.buffer.read_int32()
        self.manifest.bundle_list = []
        
        for _ in range(bundle_count):
            bundle = PackageBundle()
            bundle.bundle_name = self.buffer.read_utf8()
            bundle.unity_crc = self.buffer.read_uint32()
            bundle.file_hash = self.buffer.read_utf8()
            bundle.file_crc = self.buffer.read_utf8()
            bundle.file_size = self.buffer.read_int64()
            bundle.is_raw_file = self.buffer.read_bool()
            bundle.load_method = self.buffer.read_byte()
            bundle.tags = self.buffer.read_utf8_array()
            bundle.reference_ids = self.buffer.read_int32_array()
            self.manifest.bundle_list.append(bundle)
    
    def _deserialize_v200(self):
        """反序列化2.0.0版本的资源列表和Bundle列表"""
        asset_count = self.buffer.read_int32()
        self.manifest.asset_list = []
        
        for _ in range(asset_count):
            asset = PackageAsset()
            asset.address = self.buffer.read_utf8()
            asset.asset_path = self.buffer.read_utf8()
            asset.asset_guid = self.buffer.read_utf8()
            asset.asset_tags = self.buffer.read_utf8_array()
            asset.bundle_id = self.buffer.read_int32()
            # 注意：2.0.0版本的PackageAsset没有DependIDs字段
            self.manifest.asset_list.append(asset)
        
        bundle_count = self.buffer.read_int32()
        self.manifest.bundle_list = []
        
        for _ in range(bundle_count):
            bundle = PackageBundle()
            bundle.bundle_name = self.buffer.read_utf8()
            bundle.unity_crc = self.buffer.read_uint32()
            bundle.file_hash = self.buffer.read_utf8()
            bundle.file_crc = self.buffer.read_utf8()
            bundle.file_size = self.buffer.read_int64()
            bundle.encrypted = self.buffer.read_bool()
            bundle.tags = self.buffer.read_utf8_array()
            bundle.depend_ids = self.buffer.read_int32_array()
            self.manifest.bundle_list.append(bundle)
    
    def _deserialize_v2312(self):
        """反序列化2.3.12版本的资源列表和Bundle列表"""
        asset_count = self.buffer.read_int32()
        self.manifest.asset_list = []
        
        for _ in range(asset_count):
            asset = PackageAsset()
            asset.address = self.buffer.read_utf8()
            asset.asset_path = self.buffer.read_utf8()
            asset.asset_guid = self.buffer.read_utf8()
            asset.asset_tags = self.buffer.read_utf8_array()
            asset.bundle_id = self.buffer.read_int32()
            asset.depend_bundle_ids = self.buffer.read_int32_array()  # 2.3.12版本使用DependBundleIDs
            self.manifest.asset_list.append(asset)
        
        # 反序列化Bundle列表
        bundle_count = self.buffer.read_int32()
        self.manifest.bundle_list = []
        
        for _ in range(bundle_count):
            bundle = PackageBundle()
            bundle.bundle_name = self.buffer.read_utf8()
            bundle.unity_crc = self.buffer.read_uint32()
            bundle.file_hash = self.buffer.read_utf8()
            bundle.file_crc = self.buffer.read_utf8()
            bundle.file_size = self.buffer.read_int64()
            bundle.encrypted = self.buffer.read_bool()
            bundle.tags = self.buffer.read_utf8_array()
            bundle.depend_bundle_ids = self.buffer.read_int32_array()  # 2.3.12版本使用DependBundleIDs
            self.manifest.bundle_list.append(bundle)
    
    def _deserialize_v2317(self):
        """反序列化2.3.17版本的资源列表和Bundle列表"""
        asset_count = self.buffer.read_int32()
        self.manifest.asset_list = []
        
        # 判断是否需要替换AssetPath
        replace_asset_path = self.manifest.enable_addressable and self.manifest.replace_asset_path_with_address
        
        for _ in range(asset_count):
            asset = PackageAsset()
            asset.address = self.buffer.read_utf8()
            
            if replace_asset_path:
                # 如果启用替换，则用Address代替AssetPath，并跳过解析
                asset.asset_path = asset.address
                self.buffer.skip_utf8()
            else:
                asset.asset_path = self.buffer.read_utf8()
            
            asset.asset_guid = self.buffer.read_utf8()
            asset.asset_tags = self.buffer.read_utf8_array()
            asset.bundle_id = self.buffer.read_int32()
            asset.depend_bundle_ids = self.buffer.read_int32_array()
            self.manifest.asset_list.append(asset)
        
        # 反序列化Bundle列表
        bundle_count = self.buffer.read_int32()
        self.manifest.bundle_list = []
        
        for _ in range(bundle_count):
            bundle = PackageBundle()
            bundle.bundle_name = self.buffer.read_utf8()
            bundle.unity_crc = self.buffer.read_uint32()
            bundle.file_hash = self.buffer.read_utf8()
            bundle.file_crc = str(self.buffer.read_uint32())  # 2.3.17版本FileCRC改为UInt32
            bundle.file_size = self.buffer.read_int64()
            bundle.encrypted = self.buffer.read_bool()
            bundle.tags = self.buffer.read_utf8_array()
            bundle.depend_bundle_ids = self.buffer.read_int32_array()
            self.manifest.bundle_list.append(bundle)


def find_bytes_files(root_path: Path) -> Tuple[str, List[Path]]:

    manifest_files_dirs = list(root_path.rglob("ManifestFiles"))

    if manifest_files_dirs:
        all_manifest_files = []
        for manifest_dir in manifest_files_dirs:
            if manifest_dir.is_dir():
                all_manifest_files.extend(list(manifest_dir.glob("*.bytes")))
        
        if all_manifest_files:
            return "hotfix", all_manifest_files

    bytes_files = list(root_path.rglob("*.bytes"))
    if bytes_files:
        return "apk", bytes_files
    
    return "none", []


def convert_bundle_name_to_path(bundle_name: str) -> str:
    if not bundle_name:
        return ""
    
    if '.' in bundle_name:
        name_part, ext_part = bundle_name.rsplit('.', 1)
        path = name_part.replace('_', os.sep) + '.' + ext_part
    else:
        path = bundle_name.replace('_', os.sep)
    
    return path


def process_manifest_file(bytes_file: Path) -> Optional[PackageManifest]:
    """读取并反序列化单个清单文件"""
    try:
        binary_data = bytes_file.read_bytes()
        deserializer = YooAssetDeserializer(binary_data)
        return deserializer.deserialize()
    except Exception as e:
        print(f"处理 {bytes_file.name} 时出错: {e}")
        return None


def extract_apk_assets(root_path: Path, bytes_files: List[Path], output_dir: Path):

    apk_dir = output_dir / "Apk"
    apk_dir.mkdir(parents=True, exist_ok=True)
    
    all_bundles = {}
    for bytes_file in bytes_files:
        manifest = process_manifest_file(bytes_file)
        if manifest:
            print(f"{bytes_file.name}, 版本: {manifest.file_version}, 包名: {manifest.package_name}, Bundles: {len(manifest.bundle_list)}")
            for bundle in manifest.bundle_list:
                all_bundles[bundle.file_hash] = bundle
    
    bundle_files_found = 0
    for file_path in root_path.rglob("*"):
        if file_path.is_file() and file_path.stem in all_bundles:
            bundle = all_bundles[file_path.stem]
            target_path_str = convert_bundle_name_to_path(bundle.bundle_name)
            
            if target_path_str:
                target_file = apk_dir / target_path_str
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, target_file)
                bundle_files_found += 1
    
    print(f"总共提取了 {bundle_files_found} 个文件")


def extract_hotfix_assets(root_path: Path, bytes_files: List[Path], output_dir: Path):

    update_dir = output_dir / "Update"
    update_dir.mkdir(parents=True, exist_ok=True)
    
    all_bundles_map = {}
    for bytes_file in bytes_files:
        manifest = process_manifest_file(bytes_file)
        if not manifest:
            continue
        print(f"{bytes_file.name}, 版本: {manifest.file_version}, 包名: {manifest.package_name}, Bundles: {len(manifest.bundle_list)}")
        for bundle in manifest.bundle_list:
            all_bundles_map[bundle.file_hash] = bundle
    
    if not all_bundles_map:
        print("\n所有清单均未包含任何资源包信息，提取结束")
        return

    files_extracted = 0
    found_hashes = set()

    for data_file_path in root_path.rglob("__data"):
        if not data_file_path.is_file():
            continue

        parent_dir = data_file_path.parent
        file_hash = parent_dir.name

        if file_hash in all_bundles_map and file_hash not in found_hashes:
            bundle = all_bundles_map[file_hash]
            target_path_str = convert_bundle_name_to_path(bundle.bundle_name)
            
            if target_path_str:
                target_file = update_dir / target_path_str
                target_file.parent.mkdir(parents=True, exist_ok=True)
                
                shutil.copy2(data_file_path, target_file)
                files_extracted += 1
                found_hashes.add(file_hash)

    print(f"总共提取了 {files_extracted} 个文件")


def main():

    if len(sys.argv) != 2:
        print("用法: python Extract.py 输入目录")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    
    if not input_path.exists() or not input_path.is_dir():
        print(f"错误: 输入目录 '{input_path}' 不存在或不是目录")
        sys.exit(1)

    asset_type, bytes_files = find_bytes_files(input_path)
    
    if asset_type == "none":
        print("未找到 .bytes 文件")
        sys.exit(1)
    
    script_dir = Path(__file__).parent
    output_dir = script_dir
    
    if asset_type == "apk":
        print(f"检测到: APK 资产 ({len(bytes_files)} 个清单文件)")
        extract_apk_assets(input_path, bytes_files, output_dir)
    elif asset_type == "hotfix":
        print(f"检测到: 热更资产 ({len(bytes_files)} 个清单文件)")
        extract_hotfix_assets(input_path, bytes_files, output_dir)

if __name__ == "__main__":
    main()