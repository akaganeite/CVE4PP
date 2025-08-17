import argparse
import json
import os

parser = argparse.ArgumentParser(description='Parse valid file to jsonl')
parser.add_argument('-proj', required=True, help='项目名称')
parser.add_argument('-o', '--output', default=None, help='输出文件名，默认为stdout')
parser.add_argument('-target', required=True, help='target文件路径')
args = parser.parse_args()

valid_cves = []
# 从bitcode目录读取CVE信息
bitcode_dir = f"../../bitcode/reference/{args.proj}"
if os.path.exists(bitcode_dir):
    bc_files = [f for f in os.listdir(bitcode_dir) if f.endswith('.bc')]
    cve_files = {}
    
    # 收集所有CVE的patch和vuln文件
    for bc_file in bc_files:
        if '_patch.bc' in bc_file:
            cve = bc_file.replace('_patch.bc', '')
            if cve not in cve_files:
                cve_files[cve] = {}
            cve_files[cve]['patch'] = True
        elif '_vuln.bc' in bc_file:
            cve = bc_file.replace('_vuln.bc', '')
            if cve not in cve_files:
                cve_files[cve] = {}
            cve_files[cve]['vuln'] = True
    
    # 只有同时存在patch和vuln文件的CVE才加入valid_cves
    for cve, files in cve_files.items():
        if files.get('patch', False) and files.get('vuln', False):
            valid_cves.append(cve)
    
    print(f"从{bitcode_dir}找到{len(valid_cves)}个有效CVE")
else:
    print(f"警告：bitcode目录不存在: {bitcode_dir}")

results = []
input_file = os.path.join(args.proj, "valid")
with open(input_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        cve = parts[0]
        if cve not in valid_cves:
            continue
        # date = parts[1]  # 未用
        commit = parts[2]
        proj = parts[3]  # 未用
        func_field = parts[4]
        # 可能有多个函数名，用逗号或空格分隔
        funcs = [fn.strip() for fn in func_field.split(',') if fn.strip()]
        for func in funcs:
            result = {
                "CVE": cve,
                "func": func,
                "vuln": "",
                "patch": "",
                "file": proj,  # file字段为commithash后面那个字段
                "commit": commit,
                "project": args.proj
            }
            results.append(result)

# 输出valid的json
if args.output:
    fout = open(args.output, 'w')
    for item in results:
        fout.write(json.dumps(item, ensure_ascii=False) + '\n')
else:
    fout = None
    for item in results:
        print(json.dumps(item, ensure_ascii=False))

def write_target_json(item):
    if fout:
        fout.write(json.dumps(item, ensure_ascii=False) + '\n')
    else:
        print(json.dumps(item, ensure_ascii=False))

# 读取target文件并输出第二种json
cve_count = {}
with open(args.target, 'r') as tf:
    for line in tf:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) < 4:
            continue
        cve = parts[0]
        file_path = parts[1]
        func = parts[2]
        label = parts[3]
        file_name = os.path.basename(file_path)
        ground_truth = 'vuln' if label == '-1' else 'patch'
        # commit无法直接从target获取，需从valid查找
        commit = ''
        for v in results:
            if v['CVE'] == cve and v['func'] == func:
                commit = v['commit']
                break
        # 统计每个CVE的vuln和patch数量
        if cve not in cve_count:
            cve_count[cve] = {'vuln': 0, 'patch': 0}
        if cve_count[cve][ground_truth] >= 3:
            continue  # 跳过多余的vuln或patch
        cve_count[cve][ground_truth] += 1
        item = {
            "file": file_name,
            "cve": cve,
            "commit": commit,
            "ground_truth": ground_truth,
            "project": args.proj
        }
        if cve in valid_cves:
            write_target_json(item)

if fout:
    fout.close()