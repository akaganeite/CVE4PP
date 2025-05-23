import json
import argparse
import glob
from collections import defaultdict
import os

def filter_invalid_reference():
    # 初始化合并字典
    merged = defaultdict(list)
    
    # 查找所有_CWE.json文件
    for cve_file in glob.glob("./cveinfo/*/*_parsed.json"):
        program_name = os.path.basename(cve_file).split("_")[0]
        filtered = []
        with open(cve_file, 'r') as f:
            data = json.load(f)
        for entry in data:
            if not entry.get("references") or not entry.get("last_vuln_version"):
                continue
            filtered.append(entry)
        # 保存结果
        
        dir_path, _ = os.path.split(cve_file)
        os.makedirs(dir_path, exist_ok=True)
        with open(f"./cveinfo/{program_name}/{program_name}_filtered.json", 'w') as f:
            json.dump(filtered, f, indent=2, ensure_ascii=False)

def sort_key(cve_entry):

    cve_id = cve_entry["id"]
    # 拆分CVE-ID，例如 "CVE-2010-4008" -> ["CVE", "2010", "4008"]
    parts = cve_id.split('-')
    year = int(parts[1])  # 年份部分
    num = int(parts[2])   # 编号部分
    return (-year, -num)  # 负号实现降序排列

def cve_sort(program):
    cve_file = f"./cveinfo/{program}/{program}_filtered.json"
    with open(cve_file, 'r') as f:
            data = json.load(f)
    sorted_data = sorted(data, key=sort_key)
    with open(cve_file, 'w') as f:
        json.dump(sorted_data, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='filter invalid CVEs')
    parser.add_argument('-p', '--program',  help='程序名称')
    parser.add_argument('-s', '--sort',  help='按年份编号倒序排列', action='store_true')
    args = parser.parse_args()
    if args.program and args.sort:
        cve_sort(args.program)
    elif args.sort:
        filter_invalid_reference()
    else:
        print("请提供程序名称")
        exit(1)