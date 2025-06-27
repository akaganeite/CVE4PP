import json
import argparse

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Process CVE and release data')
    parser.add_argument('project', type=str, help='Project name (e.g., openssl)')
    return parser.parse_args()

args = parse_arguments()
PROJ = args.project
with open(f"{PROJ}/testset.json", "r") as f:
    json_data = f.read()

# 1. 解析 JSON 字符串为 Python 字典对象
data = json.loads(json_data)

# 2. 创建一个集合来存储所有版本（自动去重）
all_versions = set()

# 3. 遍历每个 CVE 条目
for cve_id, cve_data in data.items():
    print(f"Processing CVE: {cve_id}")
    
    # 添加所有漏洞版本
    for version in cve_data.get("vuln", []):
        all_versions.add(version)
    
    # 添加所有补丁版本
    for version in cve_data.get("patch", []):
        all_versions.add(version)
    
    # 输出目标日期
    print(f"  Target Date: {cve_data.get('target_date', '')}")

# 4. 将去重后的版本排序并写入文件
with open(f"{PROJ}/versions", "w") as f:
    # 按版本名排序
    sorted_versions = sorted(all_versions)
    for version in sorted_versions:
        f.write(version + "\n")

print("\n所有版本已保存到 versions 文件中:")
print(f"共找到 {len(all_versions)} 个唯一版本")