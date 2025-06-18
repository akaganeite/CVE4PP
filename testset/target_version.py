import os
import sys
import json
import csv
import random
import pickle
import argparse
import datetime
from collections import defaultdict
from datetime import datetime as dt

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Process CVE and release data')
    parser.add_argument('project', type=str, help='Project name (e.g., openssl)')
    return parser.parse_args()

def read_valid_file(project_dir):
    """读取valid文件，返回CVE字典和列表"""
    valid_path = os.path.join(project_dir, "valid")
    if not os.path.exists(valid_path):
        print(f"Error: Valid file not found at {valid_path}")
        sys.exit(1)
    
    cve_list = []
    cve_date_map = {}
    
    with open(valid_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
                
            cve_id = parts[0]
            cve_list.append(cve_id)
            
            if len(parts) >= 2:
                try:
                    # 验证和解析日期
                    date_str = parts[1]
                    date_obj = dt.strptime(date_str, "%Y-%m-%d").date()
                    cve_date_map[cve_id] = date_obj
                except ValueError:
                    print(f"Warning: Invalid date format for {cve_id}: {date_str}")
                    cve_date_map[cve_id] = None
            else:
                cve_date_map[cve_id] = None
    
    if not cve_list:
        print("Error: No valid CVEs found in valid file")
        sys.exit(1)
    
    return cve_list, cve_date_map

def get_existing_testset(project_dir):
    """获取已存在的测试集"""
    testset_path = os.path.join(project_dir, "testset.json")
    existing_cves = set()
    
    if os.path.exists(testset_path):
        try:
            with open(testset_path, 'r') as f:
                testset = json.load(f)
                existing_cves = set(testset.keys())
        except Exception as e:
            print(f"Warning: Error reading existing testset: {str(e)}")
    
    return existing_cves

def get_existing_ground_truth(project_dir):
    """获取已存在的ground truth"""
    ground_truth_path = os.path.join(project_dir, "ground_truth.json")
    existing_cves = set()
    
    if os.path.exists(ground_truth_path):
        try:
            with open(ground_truth_path, 'r') as f:
                ground_truth = json.load(f)
                existing_cves = set(ground_truth.keys())
        except Exception as e:
            print(f"Warning: Error reading existing ground truth: {str(e)}")
    
    return existing_cves

def create_release_map(project):
    """创建发布版本-时间映射"""
    release_file = os.path.join("..", "releases", f"{project}.csv")
    if not os.path.exists(release_file):
        print(f"Error: Release file not found at {release_file}")
        sys.exit(1)
    
    release_map = {}
    date_format = "%Y-%m-%d"
    
    with open(release_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # 跳过标题行
        for row in reader:
            if len(row) >= 2:
                version = row[0].strip()
                release_time = row[1].strip()
                
                # 尝试解析日期
                try:
                    date_obj = dt.strptime(release_time, date_format).date()
                    release_map[version] = date_obj
                except ValueError:
                    # 如果日期格式无效，跳过该版本
                    print(f"Warning: Invalid date format for version {version}: {release_time}")
    
    return release_map

def find_cpe_vendor_product(project):
    """定义CPE厂商和产品映射"""
    vendor_map = {
        "openssl": ["openssl", "openssl"],
        "libtiff": ["libtiff", "libtiff"],
        "libjpeg-turbo": ["libjpeg-turbo", "libjpeg-turbo"],
        "httpd": ["apache", "httpd"],
        "tomcat": ["apache", "tomcat"],
        "nghttp2": ["nghttp2", "nghttp2"],
        "openssh": ["openssh", "openssh"],
        "bind": ["isc", "bind"],
        "systemd": ["systemd", "systemd"],
        "sqlite": ["sqlite", "sqlite"],
        "zlib": ["zlib", "zlib"],
        "gcc": ["gnu", "gcc"],
        "binutils": ["gnu", "binutils"],
        "curl": ["haxx", "curl"],
    }
    return vendor_map.get(project.lower(), [project, project])

def normalize_version(project, version):
    """
    根据项目和版本前缀规范化版本号
    规则：
      - 对于以0或1开头的版本：OpenSSL_0_9_8 格式
      - 对于以3开头的版本：openssl-3.0.0 格式
      - 其他格式：保留原样
    """
    # 项目特定的前缀映射
    version_prefixes = {
        "openssl": {
            "0": "OpenSSL_{}",
            "1": "OpenSSL_{}",
            "3": "openssl-{}",
            "default": "{}"  # 默认保留原样
        },
        "httpd": {
            "0": "Apache_{}",
            "1": "Apache_{}",
            "2": "apache-{}",
            "default": "{}"
        },
        "curl": {
            "default": "{}"
        },
        "binutils": {
            "default": "{}"
        },
        "sqlite": {
            "default": "{}"
        },
        # 其他项目的映射规则...
    }
    
    # 如果项目不在映射中，使用通用规则
    if project not in version_prefixes:
        if version.startswith("0.") or version.startswith("1."):
            return f"{project.capitalize()}_{version.replace('.', '_').replace(':', '-')}"
        elif version.startswith("2.") or version.startswith("3."):
            return f"{project}-{version.replace(':', '-')}"
        else:
            return version
    
    # 获取项目特定的映射
    project_rules = version_prefixes[project]
    
    # 确定第一个字符作为前缀类型
    prefix_char = version[0] if version else ''
    
    # 获取适当的转换规则
    template = project_rules.get(prefix_char, project_rules["default"])
    
    # 执行转换
    if "{" in template:
        # 处理带特殊字符的版本
        normalized = version.replace(':', '-')
        
        # 对于0/1前缀：点替换为下划线
        if prefix_char in ["0", "1"]:
            normalized = normalized.replace('.', '_')
        
        return template.format(normalized)
    else:
        return template

def parse_cve_data(project, cve_list, vendor, product):
    """解析CVE数据文件并规范化版本号"""
    raw_file = os.path.join("..", "rawdata", f"{project}_raw.json")
    if not os.path.exists(raw_file):
        print(f"Error: Raw JSON file not found at {raw_file}")
        sys.exit(1)
    
    with open(raw_file, 'r') as f:
        cve_data = json.load(f)
    
    results = defaultdict(lambda: {"vuln": set(), "patch": set()})
    
    for item in cve_data:
        cve_id = item.get("id", "")
        if not cve_id or cve_id not in cve_list:
            continue
        
        vulnerable_configs = item.get("vulnerable_configuration", [])
        for config in vulnerable_configs:
            # 解析CPE字符串 (cpe:2.3:a:vendor:product:version:update)
            parts = config.split(':')
            if len(parts) < 5:
                continue
            
            # 检查厂商和产品是否匹配
            config_vendor = parts[3]
            config_product = parts[4]
            if config_vendor != vendor or config_product != product:
                continue
            
            # 提取版本部分（主要版本和更新标识）
            version_part = parts[5]
            update_part = parts[6] if len(parts) > 6 else None
            
            # 合并主要版本和更新标识
            if version_part in ['*', '-']:  # 跳过通配符和空白
                continue
                
            # 合并更新标识（如果有且不是通配符）
            if update_part and update_part not in ['*', '-']:
                full_version = f"{version_part}:{update_part}"
            else:
                full_version = version_part
                
            normalized_version = normalize_version(project, full_version)
            results[cve_id]["vuln"].add(normalized_version)
    
    return results

def add_patch_versions(ground_truth, release_map):
    """为每个CVE添加补丁版本"""
    # 收集所有版本，按发布日期排序
    sorted_versions = sorted(
        release_map.keys(),
        key=lambda v: release_map.get(v, datetime.date.min)
    )
    
    for cve_id, data in ground_truth.items():
        vuln_versions = list(data["vuln"])
        if not vuln_versions:
            continue
            
        # 找到最大的漏洞版本索引
        max_index = 0
        for version in vuln_versions:
            try:
                idx = sorted_versions.index(version)
                if idx > max_index:
                    max_index = idx
            except ValueError:
                continue
        
        # 添加此索引之后的版本作为补丁版本
        for version in sorted_versions[max_index + 1:]:
            data["patch"].add(version)

def create_testset(ground_truth, existing_testset, release_map, cve_date_map):
    """
    创建测试集，为每个CVE找到离指定日期最近的三个版本
    """
    testset = existing_testset.copy() if existing_testset else {}
    new_cves = 0
    skipped_cves = 0
    
    for cve_id, data in ground_truth.items():
        # 如果CVE已在测试集中，跳过
        if cve_id in testset:
            continue
            
        vuln_versions = list(data["vuln"])
        patch_versions = list(data["patch"])
        
        # 获取CVE的目标日期
        target_date = cve_date_map.get(cve_id)
        
        # 如果目标日期无效，使用今天日期作为默认
        if not target_date:
            print(f"Warning: No valid date for {cve_id}, using current date")
            target_date = datetime.date.today()
        
        # 确保至少有一个漏洞版本和一个补丁版本
        if not vuln_versions or not patch_versions:
            print(f"Skipping {cve_id}: Not enough versions (vuln: {len(vuln_versions)}, patch: {len(patch_versions)})")
            skipped_cves += 1
            continue
        
        # 计算日期差异函数
        def date_diff(date_str):
            """计算日期差异（天数）"""
            if not date_str:
                return float('inf')
            return abs((target_date - date_str).days)
        
        # 为所有版本添加发布日期
        vuln_with_dates = [(v, release_map.get(v)) for v in vuln_versions]
        patch_with_dates = [(v, release_map.get(v)) for v in patch_versions]
        
        # 按日期差异排序（最接近的排在最前面）
        vuln_sorted = sorted(
            vuln_with_dates, 
            key=lambda x: date_diff(x[1])
        )[:min(3, len(vuln_with_dates))]
        
        patch_sorted = sorted(
            patch_with_dates, 
            key=lambda x: date_diff(x[1])
        )[:min(3, len(patch_with_dates))]
        
        # 提取版本号
        vuln_selected = [v[0] for v in vuln_sorted]
        patch_selected = [v[0] for v in patch_sorted]
        
        # 检查结果
        if not vuln_selected or not patch_selected:
            print(f"Skipping {cve_id}: Could not find versions with known dates")
            skipped_cves += 1
            continue
            
        testset[cve_id] = {
            "vuln": vuln_selected,
            "patch": patch_selected,
            "target_date": target_date.strftime("%Y-%m-%d")
        }
        new_cves += 1
        
        # 记录实际选择的版本和日期
        print(f"Added {cve_id} (target: {target_date}):")
        for version in vuln_selected:
            date_str = release_map.get(version, "unknown").strftime("%Y-%m-%d") if release_map.get(version) else "unknown"
            print(f"  Vuln: {version} ({date_str})")
        for version in patch_selected:
            date_str = release_map.get(version, "unknown").strftime("%Y-%m-%d") if release_map.get(version) else "unknown"
            print(f"  Patch: {version} ({date_str})")
    
    print(f"\nAdded {new_cves} new CVEs to testset, skipped {skipped_cves} CVEs")
    return testset, new_cves

def main():
    args = parse_arguments()
    project = args.project
    
    # 1. 确保项目目录存在
    project_dir = os.path.join(".", project)
    os.makedirs(project_dir, exist_ok=True)
    
    # 2. 读取valid文件
    cve_list, cve_date_map = read_valid_file(project_dir)
    print(f"Found {len(cve_list)} CVEs in valid file")
    
    # 3. 检查已有的测试集和ground truth
    existing_testset_cves = get_existing_testset(project_dir)
    existing_ground_truth_cves = get_existing_ground_truth(project_dir)
    
    if existing_testset_cves:
        print(f"Found existing testset with {len(existing_testset_cves)} CVEs")
    
    if existing_ground_truth_cves:
        print(f"Found existing ground truth with {len(existing_ground_truth_cves)} CVEs")
    
    # 4. 区分需要处理的CVE类型
    ground_truth_cves = []
    testset_cves = []
    
    for cve in cve_list:
        # 检查是否需要处理ground truth
        if cve in existing_ground_truth_cves:
            print(f"Skipping ground truth for {cve}: already exists")
        else:
            ground_truth_cves.append(cve)
        
        # 检查是否需要处理testset
        if cve in existing_testset_cves:
            print(f"Skipping testset for {cve}: already exists")
        else:
            testset_cves.append(cve)
    
    print(f"\nProcessing {len(ground_truth_cves)} new CVEs for ground truth")
    print(f"Processing {len(testset_cves)} new CVEs for testset")
    
    # 5. 创建发布版本映射
    release_map = create_release_map(project)
    
    # 保存release map
    # release_pkl_path = os.path.join(project_dir, "releases.pkl")
    # with open(release_pkl_path, 'wb') as pkl_file:
    #     pickle.dump(release_map, pkl_file)
    # print(f"Saved release map to {release_pkl_path}")
    
    # 6. 确定vendor和product
    vendor, product = find_cpe_vendor_product(project)
    print(f"Using vendor: {vendor}, product: {product} for CPE matching")
    
    # 7. 解析原始数据文件（仅处理需要ground truth的CVE）
    if ground_truth_cves:
        new_ground_truth = parse_cve_data(project, ground_truth_cves, vendor, product)
        
        # 8. 添加补丁版本（仅处理需要ground truth的CVE）
        add_patch_versions(new_ground_truth, release_map)
    else:
        new_ground_truth = {}
        print("No new ground truth data to process")
    
    # 9. 读取或创建ground truth文件
    ground_truth_path = os.path.join(project_dir, "ground_truth.json")
    current_ground_truth = {}
    
    # 如果已有ground truth文件，先读取
    if os.path.exists(ground_truth_path):
        with open(ground_truth_path, 'r') as f:
            current_ground_truth = json.load(f)
    
    # 合并新的ground truth数据
    for cve_id, data in new_ground_truth.items():
        current_ground_truth[cve_id] = {
            "vuln": list(data["vuln"]),
            "patch": list(data["patch"])
        }
    
    # 保存更新后的ground truth
    with open(ground_truth_path, 'w') as json_file:
        json.dump(current_ground_truth, json_file, indent=2)
    print(f"Updated ground truth at {ground_truth_path}")
    
    # 10. 创建测试集（仅处理需要testset的CVE）
    # 先读取现有的测试集（如果有）
    testset_path = os.path.join(project_dir, "testset.json")
    existing_testset = {}
    if os.path.exists(testset_path):
        with open(testset_path, 'r') as f:
            existing_testset = json.load(f)
    
    # 创建新的测试集（使用发布日期排序版本）
    if testset_cves:
        # 获取所有需要testset的CVE的ground truth数据
        testset_ground_truth = {}
        for cve in testset_cves:
            if cve in current_ground_truth:
                testset_ground_truth[cve] = {
                    "vuln": set(current_ground_truth[cve]["vuln"]),
                    "patch": set(current_ground_truth[cve]["patch"])
                }
            elif cve in new_ground_truth:
                testset_ground_truth[cve] = new_ground_truth[cve]
            else:
                print(f"Warning: No ground truth found for {cve}, skipping testset creation")
        
        # 创建测试集 - 新增cve_date_map参数
        testset, new_cves_added = create_testset(
            testset_ground_truth, 
            existing_testset,
            release_map,
            cve_date_map  # 新增参数
        )
    else:
        testset = existing_testset
        new_cves_added = 0
        print("No new CVEs for testset to process")
    
    # 保存测试集
    with open(testset_path, 'w') as json_file:
        json.dump(testset, json_file, indent=2)
    print(f"Updated testset at {testset_path} with {len(testset)} CVEs ({new_cves_added} new)")
    
    print("\nProcess completed successfully!")

if __name__ == "__main__":
    main()