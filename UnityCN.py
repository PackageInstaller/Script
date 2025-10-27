import os
import argparse
import UnityPy
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed


def process(ip, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write((UnityPy.load(ip)).file.save())
    return True, None


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", required=True, help="输入文件夹")
    parser.add_argument("-o", required=True, help="输出文件夹")
    parser.add_argument("-k", required=True, help="32位十六进制字符串格式的解密密钥")
    a = parser.parse_args()

    key_bytes = bytes.fromhex(a.k)
    UnityPy.set_assetbundle_decrypt_key(key_bytes)

    tasks = []
    for r, _, files in os.walk(a.i):
        for n in files:
            ip = os.path.join(r, n)
            rp = os.path.relpath(r, a.i)
            tasks.append((ip, os.path.join(a.o, rp, n)))
    sc = 0
    fc = 0

    with ThreadPoolExecutor(max_workers=32) as e:
        fp = {e.submit(process, ip, op): ip for ip, op in tasks}
        pb = tqdm(as_completed(fp), total=len(tasks), desc="处理中", unit="个文件")

        for future in pb:
            ip = fp[future]
            s, em = future.result()
            if s:
                sc += 1
            else:
                fc += 1
                pb.set_postfix_str(f"失败: {os.path.basename(ip)}")

    print(f"成功: {sc} 个")
    print(f"失败: {fc} 个")


if __name__ == "__main__":
    main()
