import re
import csv
from collections import defaultdict
import os

# 1. 读取test文件，建立映射 (CVE, func, binary_path) -> label
TEST_PATH = os.path.join(os.path.dirname(__file__), '../../../binaries/Robin/test')
LOG_PATH = os.path.join(os.path.dirname(__file__), 'patch_detection_full.log')
CSV_PATH = os.path.join(os.path.dirname(__file__), 'results.csv')
OUTPUT_CSV_PATH = os.path.join(os.path.dirname(__file__), 'results_with_project.csv')

# 读取test文件
test_map = dict()  # (CVE, func, binary_path) -> label
with open(TEST_PATH, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split(',')
        if len(parts) < 4:
            continue
        cve, binary_path, func, label = parts[:4]
        test_map[(cve, func, os.path.basename(binary_path))] = int(label)

# 2. 读取log文件，提取(CVE, func, binary_path) -> score 和 (CVE, func) -> project
log_map = dict()  # (cve, func, binary) -> score
cve_func_to_project_map = dict() # (cve, func) -> project
with open(LOG_PATH, 'r') as f:
    cve = func = binary = project = None
    for line in f:
        if line.startswith('CVE ID:'):
            cve = line.strip().split(':')[1].strip()
        elif line.startswith('Target Binary:'):
            binary_full_path = line.strip().split(':', 1)[1].strip()
            binary = os.path.basename(binary_full_path)
            match = re.search(r'/binaries/target/([^/]+)/', binary_full_path)
            if match:
                project = match.group(1)
        elif line.startswith('Vulnerable Function Name:'):
            func = line.strip().split(':', 1)[1].strip()
        elif 'Overall Score is:' in line:
            score = float(line.strip().split(':')[1].strip())
            if cve and func and binary:
                log_map[(cve, func, binary)] = score
                if project:
                    cve_func_to_project_map[(cve, func)] = project
            # 重置，防止串行
            cve = func = binary = project = None

# 3. 读取results.csv，并存入map方便查找
rows = []
row_map = dict()  # (CVE, func) -> row
with open(CSV_PATH, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append(row)
        row_map[(row['CVE'], row['func'])] = row

# 4. 统计新字段，优先补充到原有行，找不到才新建
# 从test和log数据中收集所有 (cve, func) 键
all_cve_func_keys_from_data = set()
for cve, func, _ in test_map.keys():
    all_cve_func_keys_from_data.add((cve, func))
for cve, func, _ in log_map.keys():
    all_cve_func_keys_from_data.add((cve, func))

# 遍历所有收集到的 (cve, func) 对
for cve, func in sorted(list(all_cve_func_keys_from_data)):
    
    # 查找或创建CSV中的行
    if (cve, func) in row_map:
        row = row_map[(cve, func)]
    else:
        # 如果CSV中没有，则创建新行
        row = {'CVE': cve, 'func': func}
        row_map[(cve, func)] = row
        rows.append(row)

    # 初始化/重置统计字段
    succeed = 0
    false_positive = []
    false_negative = []

    # 遍历test_map中所有与当前(cve, func)相关的二进制文件
    for (tcve, tfunc, tbinary), label in test_map.items():
        if tcve == cve and tfunc == func:
            score = log_map.get((cve, func, tbinary))
            if score is None:
                continue
            
            # 核心逻辑：比较label和score
            if label == -1 and score > 0:
                false_positive.append(tbinary)
            elif label == 1 and score < 0:
                false_negative.append(tbinary)
            elif (label * score) > 0: # 符号相同
                succeed += 1
    
    # 更新行数据
    row['succeed'] = str(succeed)
    row['false positive'] = ','.join(sorted(false_positive))
    row['false negative'] = ','.join(sorted(false_negative))
    row['project'] = cve_func_to_project_map.get((cve, func), '')

# 5. 输出新的csv
project_order = ['ffmpeg', 'openssl', 'libxml2', 'binutils', 'curl', 'sqlite']
def project_sort_key(row):
    proj = row.get('project', '')
    if proj in project_order:
        return (project_order.index(proj), proj, row.get('CVE', ''), row.get('func', ''))
    else:
        return (len(project_order), proj, row.get('CVE', ''), row.get('func', ''))
rows_sorted = sorted(rows, key=project_sort_key)

fieldnames = ['project', 'CVE', 'func', 'succeed', 'targets', 'false positive', 'false negative', 'failed versions']
with open(OUTPUT_CSV_PATH, 'w', encoding='utf-8', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows_sorted)

print(f"解析完成，结果已保存到 {OUTPUT_CSV_PATH}")

        