import json
import base64
import struct
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import IntEnum


class CatalogFileType(IntEnum):
    """Catalog文件类型枚举"""

    NONE = 0
    JSON = 1
    BINARY = 2


class ObjectType(IntEnum):
    """序列化对象类型枚举（JSON格式）"""

    AsciiString = 0
    UnicodeString = 1
    UInt16 = 2
    UInt32 = 3
    Int32 = 4
    Hash128 = 5
    Type = 6
    JsonObject = 7


@dataclass
class SerializedType:
    """序列化类型"""

    assembly_name: str = ""
    class_name: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"assembly_name": self.assembly_name, "class_name": self.class_name}

    def get_assembly_short_name(self) -> str:
        """获取程序集短名称（逗号前的部分）"""
        if "," not in self.assembly_name:
            return self.assembly_name
        return self.assembly_name.split(",", 1)[0]

    def get_match_name(self) -> str:
        """获取匹配名称（用于类型判断）"""
        return f"{self.get_assembly_short_name()}; {self.class_name}"


@dataclass
class ObjectInitializationData:
    """对象初始化数据"""

    id: str = ""
    object_type: Optional[SerializedType] = None
    data: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "object_type": self.object_type.to_dict() if self.object_type else None,
            "data": self.data,
        }


@dataclass
class CommonInfo:
    """AssetBundleRequestOptions的通用信息"""

    timeout: int = 0
    redirect_limit: int = 0
    retry_count: int = 0
    asset_load_mode: int = (
        0  # 0=RequestedAssetAndDependencies, 1=AllPackedAssetsAndDependencies
    )
    chunked_transfer: bool = False
    use_crc_for_cached_bundle: bool = False
    use_unity_web_request_for_local_bundles: bool = False
    clear_other_cached_versions_when_loaded: bool = False
    version: int = 3  # 用于判断写入时包含哪些字段

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeout": self.timeout,
            "redirect_limit": self.redirect_limit,
            "retry_count": self.retry_count,
            "asset_load_mode": self.asset_load_mode,
            "chunked_transfer": self.chunked_transfer,
            "use_crc_for_cached_bundle": self.use_crc_for_cached_bundle,
            "use_unity_web_request_for_local_bundles": self.use_unity_web_request_for_local_bundles,
            "clear_other_cached_versions_when_loaded": self.clear_other_cached_versions_when_loaded,
            "version": self.version,
        }


@dataclass
class AssetInfo:
    """资产信息（ResourceLocation）"""

    key: str
    internal_id: str
    provider_id: str
    primary_key: str
    dependency_hash_code: int = 0
    dependency_key: Optional[str] = None
    dependencies: Optional[List["AssetInfo"]] = None
    bundle_name: str = ""
    bundle_size: int = 0
    crc: str = ""
    hash: str = ""
    resource_type: Optional[SerializedType] = None
    data: Optional[Dict[str, Any]] = None
    hash_code: int = 0
    common_info: Optional[CommonInfo] = None  # AssetBundleRequestOptions的CommonInfo


class BinaryReader:
    """二进制读取器"""

    def __init__(self, data: bytes):
        self.data = data
        self.position = 0
        self.version = 1
        self.string_cache: Dict[int, str] = {}
        self.offset_cache: Dict[int, List[int]] = {}
        self.resource_cache: Dict[int, str] = {}

    @property
    def pos(self) -> int:
        return self.position

    @pos.setter
    def pos(self, value: int):
        self.position = value

    def read(self, length: int) -> bytes:
        """读取指定长度的字节"""
        result = self.data[self.position : self.position + length]
        self.position += length
        return result

    @property
    def u8(self) -> int:
        """读取无符号8位整数"""
        return self.read(1)[0]

    @property
    def u16(self) -> int:
        """读取无符号16位整数"""
        return struct.unpack("<H", self.read(2))[0]

    @property
    def u32(self) -> int:
        """读取无符号32位整数"""
        return struct.unpack("<I", self.read(4))[0]

    @property
    def i32(self) -> int:
        """读取有符号32位整数"""
        return struct.unpack("<i", self.read(4))[0]

    @property
    def i64(self) -> int:
        """读取有符号64位整数"""
        return struct.unpack("<q", self.read(8))[0]

    @property
    def bool_val(self) -> bool:
        """读取布尔值"""
        return self.u8 != 0

    def str(self, length: int, encoding: str = "utf-8") -> str:
        """读取指定长度的字符串"""
        return self.read(length).decode(encoding, errors="ignore")

    def read_basic_string(self, offset: int, unicode: bool) -> str:
        """读取基本字符串"""
        self.pos = offset - 4
        length = self.i32
        data = self.read(length)
        return data.decode("utf-16le" if unicode else "ascii", errors="ignore")

    def read_dynamic_string(self, offset: int, unicode: bool, sep: str) -> str:
        """读取动态字符串"""
        self.pos = offset
        parts = []

        while True:
            part_string_offset = self.u32
            next_part_offset = self.u32
            parts.append(self.read_encoded_string(part_string_offset))

            if next_part_offset == 0xFFFFFFFF:
                break
            self.pos = next_part_offset

        if len(parts) == 1:
            return parts[0]

        return sep.join(parts if self.version <= 1 else reversed(parts))

    def read_encoded_string(self, offset: int, sep: str = "\0") -> Optional[str]:
        """读取编码字符串"""
        if offset == 0xFFFFFFFF:
            return None

        if offset in self.string_cache:
            return self.string_cache[offset]

        unicode = (offset & 0x80000000) != 0
        dynamic_string = (offset & 0x40000000) != 0 and sep != "\0"
        offset = offset & 0x3FFFFFFF

        if dynamic_string:
            result = self.read_dynamic_string(offset, unicode, sep)
        else:
            result = self.read_basic_string(offset, unicode)

        self.string_cache[offset] = result
        return result

    def read_offset_array(self, offset: int) -> List[int]:
        """读取偏移数组"""
        if offset == 0xFFFFFFFF:
            return []

        if offset in self.offset_cache:
            return self.offset_cache[offset]

        self.pos = offset - 4
        byte_size = self.i32

        if byte_size % 4 != 0:
            raise ValueError("数组大小必须是4的倍数")

        elem_count = byte_size // 4
        result = [self.u32 for _ in range(elem_count)]

        self.offset_cache[offset] = result
        return result

    def read_serialized_type(self, offset: int) -> SerializedType | None:
        """读取序列化类型"""
        if offset == 0xFFFFFFFF:
            return None

        self.pos = offset
        assembly_name_offset = self.u32
        class_name_offset = self.u32

        return SerializedType(
            assembly_name=self.read_encoded_string(assembly_name_offset, ".") or "",
            class_name=self.read_encoded_string(class_name_offset, ".") or "",
        )

    def read_object_initialization_data(self, offset: int) -> ObjectInitializationData:
        """读取对象初始化数据"""
        if offset == 0xFFFFFFFF:
            return ObjectInitializationData()

        self.pos = offset
        id_offset = self.u32
        object_type_offset = self.u32
        data_offset = self.u32

        return ObjectInitializationData(
            id=self.read_encoded_string(id_offset) or "",
            object_type=self.read_serialized_type(object_type_offset),
            data=self.read_encoded_string(data_offset) or "",
        )

    def read_hash128(self, offset: int) -> str:
        """读取Hash128，返回hex字符串"""
        if offset == 0 or offset == 0xFFFFFFFF:
            return ""

        self.pos = offset
        hash_bytes = self.read(16)
        return hash_bytes.hex()

    def read_common_info(self, offset: int) -> Optional[CommonInfo]:
        """读取CommonInfo"""
        if offset == 0 or offset == 0xFFFFFFFF:
            return None

        self.pos = offset
        timeout = struct.unpack("<h", self.read(2))[0]  # short
        redirect_limit = self.u8
        retry_count = self.u8
        flags = self.i32

        return CommonInfo(
            timeout=timeout,
            redirect_limit=redirect_limit,
            retry_count=retry_count,
            asset_load_mode=flags & 1,
            chunked_transfer=(flags & 2) != 0,
            use_crc_for_cached_bundle=(flags & 4) != 0,
            use_unity_web_request_for_local_bundles=(flags & 8) != 0,
            clear_other_cached_versions_when_loaded=(flags & 16) != 0,
            version=3,
        )

    def read_asset_bundle_request_options(self, offset: int) -> Dict[str, Any]:
        """读取AssetBundleRequestOptions"""
        self.pos = offset
        hash_offset = self.u32
        bundle_name_offset = self.u32
        crc = self.u32
        bundle_size = self.u32
        common_info_offset = self.u32
        hash_value = self.read_hash128(hash_offset)
        common_info = self.read_common_info(common_info_offset)

        return {
            "bundle_name": self.read_encoded_string(bundle_name_offset, "_") or "",
            "bundle_size": bundle_size,
            "crc": f"0x{crc:08x}",
            "hash": hash_value,
            "common_info": common_info,
        }

    def decode_object(self, offset: int) -> Any:
        """解码对象"""
        if offset == 0xFFFFFFFF:
            return None

        self.pos = offset
        type_name_offset = self.u32
        object_offset = self.u32

        is_default_object = object_offset == 0xFFFFFFFF

        if type_name_offset == 0:
            return None

        serialized_type = self.read_serialized_type(type_name_offset)
        if not serialized_type:
            return None

        match_name = serialized_type.get_match_name()

        if "System.Int32" in match_name:
            if is_default_object:
                return 0
            self.pos = object_offset
            return self.i32

        elif "System.Int64" in match_name:
            if is_default_object:
                return 0
            self.pos = object_offset
            return self.i64

        elif "System.Boolean" in match_name:
            if is_default_object:
                return False
            self.pos = object_offset
            return self.bool_val

        elif "System.String" in match_name:
            if is_default_object:
                return ""
            self.pos = object_offset
            string_offset = self.u32
            sep = self.str(2, "utf-16le")
            return self.read_encoded_string(string_offset, sep)

        elif "UnityEngine.Hash128" in match_name:
            if is_default_object:
                return None
            return self.read_hash128(object_offset)

        elif "AssetBundleRequestOptions" in match_name:
            if is_default_object:
                return None
            return self.read_asset_bundle_request_options(object_offset)

        else:
            return None


class UnityCatalogReader:
    """Unity Addressables Catalog读取器"""

    def __init__(self, catalog_path: str):
        """
        初始化catalog读取器

        Args:
            catalog_path: catalog文件路径（支持JSON和二进制格式）
        """
        self.catalog_path = catalog_path
        self.locator_id = ""
        self.build_result_hash = ""
        self.version = 1
        self.instance_provider_data: Optional[ObjectInitializationData] = None
        self.scene_provider_data: Optional[ObjectInitializationData] = None
        self.resource_provider_data: List[ObjectInitializationData] = []
        self.assets: Dict[str, AssetInfo] = {}

        file_type = self._detect_file_type()

        if file_type == CatalogFileType.JSON:
            print("json格式catalog文件")
            self._load_json_catalog()
        elif file_type == CatalogFileType.BINARY:
            print("二进制格式catalog文件")
            self._load_binary_catalog()
        else:
            raise ValueError(f"不支持的catalog文件类型: {catalog_path}")

    def _detect_file_type(self) -> CatalogFileType:
        """检测catalog文件类型"""
        try:
            with open(self.catalog_path, "rb") as f:
                data = f.read(4)
                magic = struct.unpack("<I", data)[0]
                if magic == 0x0DE38942 or magic == 0x4289E30D:
                    return CatalogFileType.BINARY
                else:
                    return CatalogFileType.JSON

        except Exception:
            return CatalogFileType.NONE

    def _load_json_catalog(self):
        """加载JSON格式的catalog文件"""
        with open(self.catalog_path, "r", encoding="utf-8") as f:
            catalog_data = json.load(f)

        self.locator_id = catalog_data.get("m_LocatorId", "")
        self.build_result_hash = catalog_data.get("m_BuildResultHash", "")

        print(f"Catalog版本: {self.version}")
        print(f"定位器ID: {self.locator_id}")

        self._parse_json_provider_data(catalog_data)
        self._parse_json_resources(catalog_data)

    def _parse_json_provider_data(self, catalog_data: Dict[str, Any]):
        """解析JSON格式的Provider数据"""
        instance_data = catalog_data.get("m_InstanceProviderData", {})
        if instance_data:
            obj_type_data = instance_data.get("m_ObjectType", {})
            self.instance_provider_data = ObjectInitializationData(
                id=instance_data.get("m_Id", ""),
                object_type=(
                    SerializedType(
                        assembly_name=obj_type_data.get("m_AssemblyName", ""),
                        class_name=obj_type_data.get("m_ClassName", ""),
                    )
                    if obj_type_data
                    else None
                ),
                data=instance_data.get("m_Data", ""),
            )
        scene_data = catalog_data.get("m_SceneProviderData", {})
        if scene_data:
            obj_type_data = scene_data.get("m_ObjectType", {})
            self.scene_provider_data = ObjectInitializationData(
                id=scene_data.get("m_Id", ""),
                object_type=(
                    SerializedType(
                        assembly_name=obj_type_data.get("m_AssemblyName", ""),
                        class_name=obj_type_data.get("m_ClassName", ""),
                    )
                    if obj_type_data
                    else None
                ),
                data=scene_data.get("m_Data", ""),
            )

        resource_providers = catalog_data.get("m_ResourceProviderData", [])
        for provider_data in resource_providers:
            obj_type_data = provider_data.get("m_ObjectType", {})
            self.resource_provider_data.append(
                ObjectInitializationData(
                    id=provider_data.get("m_Id", ""),
                    object_type=(
                        SerializedType(
                            assembly_name=obj_type_data.get("m_AssemblyName", ""),
                            class_name=obj_type_data.get("m_ClassName", ""),
                        )
                        if obj_type_data
                        else None
                    ),
                    data=provider_data.get("m_Data", ""),
                )
            )

    def _parse_json_resources(self, catalog_data: Dict[str, Any]):
        """解析JSON格式的资源数据"""
        key_data = base64.b64decode(catalog_data["m_KeyDataString"])
        entry_data = base64.b64decode(catalog_data["m_EntryDataString"])
        extra_data = base64.b64decode(catalog_data["m_ExtraDataString"])
        bucket_data = base64.b64decode(catalog_data["m_BucketDataString"])

        kds = BinaryReader(key_data)
        eds = BinaryReader(entry_data)
        xds = BinaryReader(extra_data)
        bds = BinaryReader(bucket_data)

        bucket_count = bds.u32
        buckets = []
        for _ in range(bucket_count):
            offset = bds.i32
            entry_count = bds.i32
            entries = [bds.i32 for _ in range(entry_count)]
            buckets.append({"offset": offset, "entries": entries})

        key_count = kds.u32
        keys = []
        for i in range(key_count):
            if i < len(buckets):
                kds.pos = buckets[i]["offset"]

            obj_type = kds.u8
            if obj_type == 0:  # ASCII string
                keys.append(kds.str(kds.u32))
            elif obj_type == 1:  # Unicode string
                keys.append(kds.str(kds.u32, "utf-16le"))
            elif obj_type in (2, 3, 4):  # 数字类型
                keys.append(str(kds.u32 if obj_type in (2, 3) else kds.i32))
            else:
                keys.append(f"key_{len(keys)}")

        internal_ids = catalog_data["m_InternalIds"]
        internal_id_prefixes = catalog_data.get("m_InternalIdPrefixes", [])
        provider_ids = catalog_data["m_ProviderIds"]

        resource_types = []
        for rt_data in catalog_data.get("m_resourceTypes", []):
            resource_types.append(
                SerializedType(
                    assembly_name=rt_data.get("m_AssemblyName", ""),
                    class_name=rt_data.get("m_ClassName", ""),
                )
            )

        legacy_keys = catalog_data.get("m_Keys", None)

        entry_count = eds.u32
        print(f"找到 {entry_count} 个资源组")

        locations = []
        for i in range(entry_count):
            ii = eds.i32  # internal_id index
            pi = eds.i32  # provider_id index
            dki = eds.i32  # dependency_key index
            dh = eds.i32  # dependency hash
            di = eds.i32  # data index
            pk = eds.i32  # primary_key index
            rt = eds.i32  # resource_type index

            obj_data = None
            if di >= 0:
                xds.pos = di
                obj_type = xds.u8
                if obj_type == 7:  # JSON object
                    assembly_name = xds.str(xds.u8)
                    class_name = xds.str(xds.u8)
                    json_str = xds.str(xds.i32, "utf-16le")
                    try:
                        obj_data = json.loads(json_str)
                    except:
                        obj_data = {}
            internal_id = internal_ids[ii] if ii < len(internal_ids) else ""
            if internal_id_prefixes and "#" in internal_id:
                split_idx = internal_id.index("#")
                try:
                    prefix_idx = int(internal_id[:split_idx])
                    if prefix_idx < len(internal_id_prefixes):
                        internal_id = (
                            internal_id_prefixes[prefix_idx]
                            + internal_id[split_idx + 1 :]
                        )
                except:
                    pass

            provider_id = provider_ids[pi] if pi < len(provider_ids) else ""
            if legacy_keys:
                primary_key = legacy_keys[pk] if pk < len(legacy_keys) else f"key_{i}"
            else:
                primary_key = keys[pk] if pk < len(keys) else f"key_{i}"

            dependency_key = keys[dki] if dki >= 0 and dki < len(keys) else None
            resource_type = (
                resource_types[rt] if rt >= 0 and rt < len(resource_types) else None
            )
            asset = AssetInfo(
                key=primary_key,
                internal_id=internal_id,
                provider_id=provider_id,
                primary_key=primary_key,
                dependency_hash_code=dh,
                dependency_key=str(dependency_key) if dependency_key else None,
                resource_type=resource_type,
                hash_code=hash(internal_id) * 31 + hash(provider_id),
            )
            if obj_data and isinstance(obj_data, dict):
                asset.bundle_name = obj_data.get("m_BundleName", "")
                asset.bundle_size = obj_data.get("m_BundleSize", 0)
                asset.crc = f"0x{obj_data.get('m_Crc', 0):08x}"
                asset.hash = obj_data.get("m_Hash", "")
                asset.data = obj_data
                common_info_version = 1
                if "m_ChunkedTransfer" in obj_data:
                    if "m_AssetLoadMode" in obj_data:
                        common_info_version = 3
                    else:
                        common_info_version = 2

                asset.common_info = CommonInfo(
                    timeout=obj_data.get("m_Timeout", 0),
                    redirect_limit=obj_data.get("m_RedirectLimit", 0),
                    retry_count=obj_data.get("m_RetryCount", 0),
                    asset_load_mode=obj_data.get("m_AssetLoadMode", 0),
                    chunked_transfer=obj_data.get("m_ChunkedTransfer", False),
                    use_crc_for_cached_bundle=obj_data.get(
                        "m_UseCrcForCachedBundles", False
                    ),
                    use_unity_web_request_for_local_bundles=obj_data.get(
                        "m_UseUWRForLocalBundles", False
                    ),
                    clear_other_cached_versions_when_loaded=obj_data.get(
                        "m_ClearOtherCachedVersionsWhenLoaded", False
                    ),
                    version=common_info_version,
                )

            locations.append(asset)

        for i, bucket in enumerate(buckets):
            if i < len(keys):
                for entry_idx in bucket["entries"]:
                    if entry_idx < len(locations):
                        location = locations[entry_idx]
                        self.assets[location.primary_key] = location

        print(f"解析完成，共 {len(self.assets)} 个资产")

    def _load_binary_catalog(self):
        """加载二进制格式的catalog文件"""
        with open(self.catalog_path, "rb") as f:
            binary_data = f.read()

        reader = BinaryReader(binary_data)

        signature = reader.read(4)
        version = reader.u32

        if version not in (1, 2):
            raise ValueError(f"不支持的二进制版本: {version}")

        reader.version = version

        keys_offset = reader.u32
        id_offset = reader.u32
        instance_provider_offset = reader.u32
        scene_provider_offset = reader.u32
        init_objects_array_offset = reader.u32

        # 版本1的某些子版本没有BuildResultHashOffset
        if version == 1 and keys_offset == 32:
            build_result_hash_offset = 0xFFFFFFFF
        else:
            build_result_hash_offset = reader.u32

        self.locator_id = reader.read_encoded_string(id_offset) or ""
        self.build_result_hash = (
            reader.read_encoded_string(build_result_hash_offset) or ""
        )
        self.version = version

        print(f"Catalog版本: {version}")
        print(f"定位器ID: {self.locator_id}")

        self.instance_provider_data = reader.read_object_initialization_data(
            instance_provider_offset
        )
        self.scene_provider_data = reader.read_object_initialization_data(
            scene_provider_offset
        )

        resource_provider_offsets = reader.read_offset_array(init_objects_array_offset)
        self.resource_provider_data = []
        for rp_offset in resource_provider_offsets:
            self.resource_provider_data.append(
                reader.read_object_initialization_data(rp_offset)
            )

        self._parse_binary_resources(reader, keys_offset)

    def _parse_binary_resources(self, reader: BinaryReader, keys_offset: int):
        key_location_offsets = reader.read_offset_array(keys_offset)
        total_groups = len(key_location_offsets) // 2
        print(f"找到 {total_groups} 个资源组")

        for i in range(0, len(key_location_offsets), 2):
            group_index = i // 2

            try:
                key_offset = key_location_offsets[i]
                location_list_offset = key_location_offsets[i + 1]
                location_offsets = reader.read_offset_array(location_list_offset)

                for location_offset in location_offsets:
                    try:
                        self._read_binary_resource_location(reader, location_offset)
                    except Exception as e:
                        continue

            except Exception as e:
                print(f"处理资源组 {group_index} 失败: {e}")
                continue

        print(f"解析完成，共 {len(self.assets)} 个资产")

    def _read_binary_resource_location(self, reader: BinaryReader, offset: int):
        """读取二进制格式的资源位置"""
        if offset in reader.resource_cache:
            return

        reader.pos = offset

        primary_key_offset = reader.u32
        internal_id_offset = reader.u32
        provider_id_offset = reader.u32
        dependencies_offset = reader.u32
        dependency_hash_code = reader.i32
        data_offset = reader.u32
        type_offset = reader.u32

        primary_key = (
            reader.read_encoded_string(primary_key_offset, "/") or f"res_{offset}"
        )
        internal_id = reader.read_encoded_string(internal_id_offset, "/") or ""
        provider_id = reader.read_encoded_string(provider_id_offset, ".") or ""
        resource_type = reader.read_serialized_type(type_offset)
        data = reader.decode_object(data_offset)
        hash_code = hash(internal_id) * 31 + hash(provider_id)

        asset = AssetInfo(
            key=primary_key,
            internal_id=internal_id,
            provider_id=provider_id,
            primary_key=primary_key,
            dependency_hash_code=dependency_hash_code,
            resource_type=resource_type,
            hash_code=hash_code,
        )

        if data and isinstance(data, dict):
            asset.bundle_name = data.get("bundle_name", "")
            asset.bundle_size = data.get("bundle_size", 0)
            asset.crc = data.get("crc", "")
            asset.hash = data.get("hash", "")
            asset.common_info = data.get("common_info")
            asset.data = data

        if dependencies_offset != 0xFFFFFFFF:
            try:
                dependency_offsets = reader.read_offset_array(dependencies_offset)
                dependencies = []

                for dep_offset in dependency_offsets:
                    self._read_binary_resource_location(reader, dep_offset)
                    if dep_offset in reader.resource_cache:
                        dep_key = reader.resource_cache[dep_offset]
                        if dep_key in self.assets:
                            dependencies.append(self.assets[dep_key])

                asset.dependencies = dependencies if dependencies else None
                if len(dependency_offsets) == 1:
                    dep_offset = dependency_offsets[0]
                    if dep_offset in reader.resource_cache:
                        asset.dependency_key = reader.resource_cache[dep_offset]
            except Exception as e:
                pass

        reader.resource_cache[offset] = primary_key
        self.assets[primary_key] = asset

    def get_asset_list(self) -> List[Dict[str, Any]]:
        """获取详细的资产列表"""
        asset_list = []

        for asset in self.assets.values():
            data_dict = None
            if asset.data and isinstance(asset.data, dict):
                data_dict = asset.data.copy()
                if "common_info" in data_dict and isinstance(
                    data_dict["common_info"], CommonInfo
                ):
                    data_dict["common_info"] = data_dict["common_info"].to_dict()

            asset_info = {
                "key": asset.key,
                "internal_id": asset.internal_id,
                "provider_id": asset.provider_id,
                "primary_key": asset.primary_key,
                "dependency_hash_code": asset.dependency_hash_code,
                "dependency_key": asset.dependency_key,
                "bundle_name": asset.bundle_name,
                "bundle_size": asset.bundle_size,
                "crc": asset.crc,
                "hash": asset.hash,
                "hash_code": asset.hash_code,
                "resource_type": (
                    asset.resource_type.to_dict() if asset.resource_type else None
                ),
                "common_info": (
                    asset.common_info.to_dict() if asset.common_info else None
                ),
                "data": data_dict,
            }
            if asset.dependencies:
                asset_info["dependencies"] = [
                    {
                        "key": dep.key,
                        "internal_id": dep.internal_id,
                        "provider_id": dep.provider_id,
                        "primary_key": dep.primary_key,
                    }
                    for dep in asset.dependencies
                ]

            asset_list.append(asset_info)

        return asset_list

    def export_to_json(self, output_path: str = "assets.json"):
        """导出所有资产信息到JSON文件"""
        all_assets = self.get_asset_list()
        provider_stats = {}
        for asset in all_assets:
            provider_type = (
                asset["provider_id"].split(".")[-1]
                if "." in asset["provider_id"]
                else asset["provider_id"]
            )
            provider_stats[provider_type] = provider_stats.get(provider_type, 0) + 1
        export_data = {
            "catalog_info": {
                "version": self.version,
                "locator_id": self.locator_id,
                "build_result_hash": self.build_result_hash,
                "total_assets": len(all_assets),
                "export_timestamp": __import__("datetime").datetime.now().isoformat(),
            },
            "provider_data": {
                "instance_provider": (
                    self.instance_provider_data.to_dict()
                    if self.instance_provider_data
                    else None
                ),
                "scene_provider": (
                    self.scene_provider_data.to_dict()
                    if self.scene_provider_data
                    else None
                ),
                "resource_providers": (
                    [rp.to_dict() for rp in self.resource_provider_data]
                    if self.resource_provider_data
                    else []
                ),
            },
            "statistics": {"provider_types": provider_stats},
            "assets": all_assets,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        print(f"已保存到{output_path}")
        return output_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "用法: python unity_catalog_reader.py <catalog文件路径> [输出文件名(默认: assets.json)]"
        )
        sys.exit(1)

    catalog_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) >= 3 else "assets.json"
    reader = UnityCatalogReader(catalog_path)
    reader.export_to_json(output_path)
