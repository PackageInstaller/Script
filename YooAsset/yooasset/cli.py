"""
YooAsset 命令行入口
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .extractor import (
    find_bytes_files,
    extract_apk_assets,
    extract_hotfix_assets,
)

logger = logging.getLogger("yooasset")


def _setup_logging(verbose: bool = False) -> None:
    """配置日志格式和级别"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main(argv: list[str] | None = None) -> None:
    """CLI

    Args:
        argv: 命令行参数列表，默认使用 sys.argv
    """
    parser = argparse.ArgumentParser(
        prog="yooasset",
        description="YooAsset 资产提取工具 — 解析清单文件并还原资产目录结构",
    )
    parser.add_argument(
        "input_dir",
        type=Path,
        help="包含 .bytes 清单文件的输入目录（APK 解包目录或热更缓存目录）",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="输出目录（默认: 当前脚本所在目录）",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="显示详细调试信息",
    )

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    input_path: Path = args.input_dir
    if not input_path.exists() or not input_path.is_dir():
        logger.error("输入目录 '%s' 不存在或不是目录", input_path)
        sys.exit(1)

    asset_type, bytes_files = find_bytes_files(input_path)

    if asset_type == "none":
        logger.error("未找到 .bytes 文件")
        sys.exit(1)

    # 确定输出目录
    output_dir: Path = args.output or Path(__file__).resolve().parent.parent

    if asset_type == "apk":
        logger.info("检测到: APK 资产 (%d 个清单文件)", len(bytes_files))
        extract_apk_assets(input_path, bytes_files, output_dir)
    elif asset_type == "hotfix":
        logger.info("检测到: 热更资产 (%d 个清单文件)", len(bytes_files))
        extract_hotfix_assets(input_path, bytes_files, output_dir)


if __name__ == "__main__":
    main()
