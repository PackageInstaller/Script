import os
import re
import argparse
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from PIL import Image


def resize_image_nearest(image_path, new_size, output_path):
    try:
        image = Image.open(image_path)
        resized_image = image.resize(new_size, Image.Resampling.NEAREST)
        resized_image.save(output_path)
    except Exception as e:
        return f"处理 {image_path} 时出错: {str(e)}"


def process_atlas_file(atlas_file):
    results = []
    try:
        with open(atlas_file, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except Exception as e:
        return [f"读取文件 {atlas_file} 时出错: {str(e)}"]

    current_image = None
    correct_size = None

    image_pattern = re.compile(r"([^#]+)\.png")
    size_pattern = re.compile(r"size:\s*(\d+),\s*(\d+)")

    for line in lines:
        image_match = image_pattern.search(line)
        size_match = size_pattern.search(line)

        if image_match:
            current_image = image_match.group(1) + ".png"
        elif size_match:
            width, height = map(int, size_match.groups())
            correct_size = (width, height)
            if current_image and correct_size:
                image_path = os.path.join(os.path.dirname(atlas_file), current_image)
                if os.path.exists(image_path):
                    try:
                        current_img_size = Image.open(image_path).size
                        if current_img_size != correct_size:
                            result = resize_image_nearest(
                                image_path, correct_size, image_path
                            )
                            results.append(result)
                    except Exception as e:
                        results.append(f"处理图片 {image_path} 时出错: {str(e)}")
                else:
                    results.append(f"图片文件不存在: {image_path}")
                current_image = None
                correct_size = None
    return results


def find_atlas_files(spine_folder):
    atlas_files = []
    if not os.path.exists(spine_folder):
        print(f"错误: 路径 '{spine_folder}' 不存在")
        return atlas_files

    for root, dirs, files in os.walk(spine_folder):
        for file in files:
            if file.endswith(".atlas"):
                atlas_files.append(os.path.join(root, file))

    return atlas_files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("spine_folder")

    args = parser.parse_args()
    spine_folder = args.spine_folder
    atlas_files = find_atlas_files(spine_folder)

    if not atlas_files:
        print("未找到任何.atlas文件")
        return

    print(f"找到 {len(atlas_files)} 个atlas文件")

    with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2) as executor:
        results = executor.map(process_atlas_file, atlas_files)

    total_processed = 0
    for result_list in results:
        for result in result_list:
            if result:
                print(result)
                total_processed += 1

    print(f"\n处理完成! 总共处理了 {total_processed} 个操作")


if __name__ == "__main__":
    main()
