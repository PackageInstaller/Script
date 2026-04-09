"""
YooAsset 常量定义

包含文件签名、支持版本号等全局常量。
"""

# 清单文件签名 (YOO)
MANIFEST_FILE_SIGN: int = 0x594F4F

# 内置目录文件签名
BUILDIN_CATALOG_FILE_SIGN: int = 0x133C5EE

# 支持的清单版本列表
SUPPORTED_VERSIONS: list[str] = [
    "1.5.2",
    "2.0.0",
    "2.3.1",
    "2025.8.28",
    "2025.9.30",
]

# 内置目录版本
BUILDIN_CATALOG_VERSION: str = "1.0.0"
