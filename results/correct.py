import os
import csv
import json
from collections import defaultdict
import argparse

def get_versions_from_field(field):
    """将字段内容按分号分割，去除空白"""
    if not field:
        return []
    return [v.strip() for v in field.split(';') if v.strip()]

def get_binxray_negatives(filepath):
    """
    读取 BinXray 下的 csv，统计 false_negative、cant_tell、no_diff 三列
    返回 {(CVE, version)}
    """
    result = set()
    if not os.path.exists(filepath):
        return result
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = row.get('CVE', '').strip()
            for col in ['false_negative', 'cant_tell', 'no_diff','failed_versions']:
                versions = get_versions_from_field(row.get(col, ''))
                for version in versions:
                    if cve and version:
                        result.add((cve, version))
    return result

def get_other_negatives(filepath):
    """
    读取其他目录下的 csv，只统计 false_negative 列
    返回 {(CVE, version)}
    """
    result = set()
    if not os.path.exists(filepath):
        print("file not exist")
        return result
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = row.get('CVE', '').strip()
            for col in ['false_negative','failed_versions']:
                versions = get_versions_from_field(row.get(col, ''))
                for version in versions:
                    if cve and version:
                        result.add((cve, version))
    return result

def main():
    parser = argparse.ArgumentParser(description='统计 correction')
    parser.add_argument('-proj', required=True, help='指定 project 名称')
    args = parser.parse_args()
    project_name = args.proj

    dirs = [
        ('BinXray', get_binxray_negatives),
        ('PatchDiscovery', get_other_negatives),
        # ('PS3', get_other_negatives)
    ]
    out_dir = 'correction'  # 输出目录，可根据需要修改

    all_results = []
    for d, func in dirs:
        filename = f'{project_name}_result.csv'
        filepath = os.path.join(d, filename)
        all_results.append(func(filepath))

    # 取三个集合的交集
    intersection = set.intersection(*all_results) if all_results else set()
    print(intersection)
    # 组织 correction.json 格式
    correction = {}
    version_cve_map = defaultdict(list)
    for cve, version in intersection:
        version_cve_map[version].append(cve)
    for version, cves in version_cve_map.items():
        correction[version] = []
        for cve in cves:
            correction[version].append({
                cve: {
                    "commit": "",
                    "source": "",
                    "result": ""
                }
            })
    correction['total'] = "0"

    # 写入文件
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    out_path = os.path.join(out_dir, f"{project_name}_correction.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(correction, f, indent=4, ensure_ascii=False)
    print(f"已生成 {out_path}")

if __name__ == "__main__":
    main()