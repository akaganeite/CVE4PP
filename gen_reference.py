import os
import re
from collections import defaultdict
import sys

# from binaries.reference.Binxray import project_path

# 基础路径设置
BASE_DIR = os.getcwd()
VALID_BASE = os.path.expanduser("/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/")

def extract_cve_info(filename):
    """从文件名中提取CVE编号和文件类型"""
    match = re.match(r'(CVE-\d{4}-\d+)-(vuln|patch)-([0-9a-f]+)-', filename)
    if match:
        return match.group(1), match.group(2), match.group(3)
    return None, None, None

def parse_valid_file(filepath, cve_id):
    """解析details文件获取函数名"""
    try:
        with open(filepath, 'r') as f:
            # 读取文件所有行
            lines = f.readlines()
            cve_functions = []
            for line in lines:
                line = line.strip()#.split('|')[0]
                if not line:
                    continue
                    
                # 分割行数据：第一部分是CVE+commit，第二部分是日期，剩下的是函数列表
                parts = line.split(" ")
                if not parts:
                    continue
                    
                # 检查CVE是否匹配（忽略commit部分）
                if parts[0] == cve_id:
                    # 提取函数部分（第二列之后的所有内容）
                    func_part = parts[-1]
                    
                    # 处理可能的函数列表格式
                    functions = []
                    for func in func_part.split(','):
                        func = func.strip()
                        # 过滤无效的函数名
                        functions.append(func)
                    
                    cve_functions.extend(functions)
            
            # 返回去重的函数列表
            return ",".join(sorted(set(cve_functions)))
    
    except Exception as e:
        print(f"Error reading details file {filepath}: {str(e)}")
        return ""

# 遍历所有项目目录
if len(sys.argv) != 2:
        print("Usage: python gen_reference.py <project_name> ")
        sys.exit(1)
    
project_name = sys.argv[1]
print(f"Processing project: {project_name}")
project_path=f"../binaries/reference/{project_name}-new"
# 步骤1: 收集项目下的所有CVE文件
cve_files = defaultdict(dict)
for filename in os.listdir(project_path):
    cve_id, file_type, commit_hash = extract_cve_info(filename)
    print(cve_id, file_type, commit_hash)
    if not cve_id:
        continue
    if ".i64" in filename:
        continue
    # 记录文件路径 (/binaries/reference/...)
    file_path = f"/binaries/reference/{project_name}-new/{filename}"
    if file_type == "vuln":
        cve_files[cve_id]["vuln"] = file_path
        cve_files[cve_id]["vuln_commit"] = commit_hash
    elif file_type == "patch":
        cve_files[cve_id]["patch"] = file_path
        cve_files[cve_id]["patch_commit"] = commit_hash

# 步骤2: 处理details文件获取函数名
valid_file = os.path.join(VALID_BASE, project_name, "valid")
for cve_id in list(cve_files.keys()):
    # 尝试两种commit格式匹配details文件
    commit_candidates = [
        cve_files[cve_id].get("patch_commit"),
        cve_files[cve_id].get("vuln_commit")
    ]
    
    for commit in commit_candidates:
        if not commit:
            continue
        functions = parse_valid_file(valid_file,cve_id)
        cve_files[cve_id]["functions"] = functions
        break
    else:
        cve_files[cve_id]["functions"] = ""

# 步骤3: 生成项目文件
output_path = os.path.join(project_path, project_name)
with open(output_path, 'w') as out_file:
    for cve_id, files in cve_files.items():
        vuln_path = files.get("vuln", "")
        patch_path = files.get("patch", "")
        functions = files.get("functions", "")
        if functions == "":
            continue
        for function in functions.split(','):
            line = f"{cve_id},{vuln_path},{patch_path},{function}\n"
            out_file.write(line)

print("Processing completed!")