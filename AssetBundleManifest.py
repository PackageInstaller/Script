import json
from pathlib import Path
from typing import List, Dict
import UnityPy
import pandas as pd


def load_manifest(ab_path: Path) -> Dict:
    env = UnityPy.load(str(ab_path))
    for obj in env.objects:
        if obj.type.name == "AssetBundleManifest":
            return obj.read_typetree()
    return {}


def parse_manifest(tree: Dict) -> List[Dict]:
    index_to_name = {int(idx): name for idx, name in tree.get("AssetBundleNames", [])}

    results = []
    for entry in tree.get("AssetBundleInfos", []):
        idx: int = int(entry[0])
        raw_info: Dict = entry[1]
        name = index_to_name.get(idx)

        h_bytes = raw_info["AssetBundleHash"]
        hash_hex = "".join(f"{h_bytes[f'bytes[{i}]']:02x}" for i in range(16))

        deps_idx = raw_info.get("AssetBundleDependencies", [])
        deps_names = [index_to_name.get(d) for d in deps_idx]

        results.append(
            {
                "Index": idx,
                "AssetBundleName": name,
                "AssetBundleHash": hash_hex,
                "DepsIndex": deps_idx,
                "AssetBundleDependencies": deps_names,
            }
        )
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("ab")
    parser.add_argument("-o")
    args = parser.parse_args()
    ab_path = Path(args.ab).expanduser()
    parsed = parse_manifest(load_manifest(ab_path))

    out_path = Path(args.o)
    if out_path.suffix.lower() == ".json":
        out_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=4))
    elif out_path.suffix.lower() == ".csv":
        df = pd.json_normalize(parsed)
        df.to_csv(out_path, index=False)
