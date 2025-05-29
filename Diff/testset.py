
import csv
import json
from collections import defaultdict
from datetime import datetime
import os
from dateutil import parser
from packaging import version  # 需要安装 packaging 包：pip install packaging

def parse_dates(file_path):
    """解析 binutils.csv 返回版本时间字典"""
    version_dates = {}
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # 跳过标题
        for row in reader:
            if len(row) >= 2:
                version = row[0].strip()
                raw_date = row[1].strip().split()[0]  # 提取日期部分
                try:
                    dt = parser.parse(raw_date)
                    version_dates[version] = dt.date()
                except:
                    print(f"日期解析失败: {row}")
    return version_dates

def find_nearest_versions(cve_date, version_dates, num=6):
    """查找最近的 num 个版本"""
    date_list = [(v, d) for v, d in version_dates.items()]
    # 按时间差排序
    sorted_versions = sorted(
        date_list,
        key=lambda x: abs((x[1] - cve_date).days)
    )[:num]
    # 按实际日期排序
    sorted_by_date = sorted(sorted_versions, key=lambda x: x[1])
    return sorted_by_date



REPO_LIST = [
    # "binutils",
    # "openssl",
    # "curl",
    "ffmpeg",
    # "sqlite",
    # "libxml2",
]

# ---------------------- 新增版本号处理函数 ----------------------
def parse_version(v_str):
    """将版本字符串解析为可比较的Version对象（支持SemVer）"""
    try:
        return version.parse(v_str)
    except:
        # 处理非常规版本号（例如 "1.2.3a" -> "1.2.3.a"）
        cleaned = v_str.replace('-', '.').replace('_', '.')
        return version.parse(cleaned)

def sort_versions_by_number(version_dates):
    """按版本号顺序排序（不依赖时间）"""
    return sorted(
        version_dates.keys(),
        key=lambda v: parse_version(v)
    )

# ---------------------- 新增版本号查找逻辑 ----------------------
def find_nearest_by_version(target_version, sorted_versions, num=6):
    """按版本号顺序查找最近的num个版本"""
    try:
        idx = sorted_versions.index(target_version)
    except ValueError:
        return []

    # 计算窗口范围
    start = max(0, idx - num//2)
    end = min(len(sorted_versions), idx + num//2 + 1)
    return sorted_versions[start:end]

# ---------------------- 修改后的核心函数 ----------------------
def generate_testset_json(details_file, version_dates, output_file,project, mode='time'):
    cve_data = defaultdict(lambda: {"cve_id": "", "vuln_versions": [], "patch_versions": []})
    
    # 预排序版本号（如果使用版本号模式）
    sorted_versions = sort_versions_by_number(version_dates) if mode == 'version' else None
    
    with open(details_file, 'r') as f:
        for line in f:
            parts = line.strip().split(' ', 2)
            if len(parts) < 3:
                continue
                
            cve_id = parts[0]
            # print(f"Processing CVE: {cve_id}")
            cve_date = datetime.strptime(parts[1], "%Y-%m-%d").date()
            
            if mode == 'time':
                # 原时间模式逻辑
                nearest = find_nearest_versions(cve_date, version_dates)
                if len(nearest) < 6:
                    continue
                vuln_versions = [ver for ver, _ in nearest[:3]]
                patch_versions = [ver for ver, _ in nearest[-3:]]
            elif mode == 'version':
                # 新版本号模式逻辑（需要从描述中提取目标版本）
                # 这里假设描述中包含类似 "affects X.Y.Z" 的文本
                target_ver = extract_target_version(cve_id,project)  # 需要实现提取逻辑
                if not target_ver:
                    continue
                nearest = find_nearest_by_version(target_ver, sorted_versions)
                if len(nearest) < 6:
                    continue
                vuln_versions = nearest[:3]
                patch_versions = nearest[-3:]
            
            # 存储到数据结构
            cve_entry = cve_data[cve_id]
            cve_entry["cve_id"] = cve_id
            cve_entry["vuln_versions"] = vuln_versions
            cve_entry["patch_versions"] = patch_versions

    # 转换为列表格式并保存
    result = list(cve_data.values())
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

# ---------------------- 辅助函数（需根据实际情况实现）---------------------
def extract_target_version(cve_id,project):
    """从描述文本中提取目标版本号（示例实现）"""
    # 读取{project}_filtered.json,拿到cve-id对应的last_vuln_version
    with open(f"../cveinfo/{project}/{project}_filtered.json", 'r') as f:
        data = json.load(f)
    for item in data:
        if item['id'] == cve_id[:-8]:
            return item.get('last_vuln_version')

# ---------------------- 主函数调整 ----------------------
if __name__ == "__main__":
    for root, dirs, files in os.walk("."):
        project = os.path.basename(root)
        if project not in REPO_LIST: 
            continue
            
        # 读取版本数据
        project_versions = parse_dates(f"../releases/{project}.csv")
        
        # 生成两种模式的测试集
        for mode in ['time', 'version']:  # 同时生成两种模式
            generate_testset_json(
                details_file=f"{project}/details",
                version_dates=project_versions,
                output_file=f"{project}/testset_{mode}.json",
                project=project,
                mode=mode
            )