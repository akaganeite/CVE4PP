# Given a project name, this script will create a json file with the project name and a list of CVEs.
import subprocess
import json
import sys
import argparse

try:
    from packaging.version import parse as parse_version
except ImportError:
    print("请先安装packaging库：pip install packaging")
    sys.exit(1)



def extract_vendor_product(command):
    """从命令参数中提取厂商和产品名称"""
    try:
        index = command.index('-p')
        product_arg = command[index + 1]
    except (ValueError, IndexError):
        print("错误：找不到-p参数")
        sys.exit(1)
    
    parts = [p for p in product_arg.split(':') if p]
    if len(parts) < 2:
        print("错误：参数格式应为:vendor:product:")
        sys.exit(1)
    return parts[-2], parts[-1]  # 返回厂商和产品名称

def run_cve_search(command):
    """执行CVE搜索命令"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败：{e}")
        sys.exit(1)

def run_command_and_format(command):
    # 1. 执行命令
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding='utf-8'
    )
    
    if result.returncode != 0:
        print(f"命令执行失败：{result.stderr}")
        return []
    
    # 2. 处理输出（假设每个JSON对象单独一行）
    raw_output = result.stdout
    json_lines = [line.strip() for line in raw_output.splitlines() if line.strip()]
    
    # 3. 解析并封装
    parsed_data = []
    for line in json_lines:
        try:
            data = json.loads(line)
            parsed_data.append(data)
        except json.JSONDecodeError as e:
            print(f"JSON解析错误：{e}，行内容：{line}")
    
    return parsed_data

# def analyze_versions(vulnerable_products, target_vendor, target_product):
#     """分析受影响版本范围"""
#     versions = []
#     match_string = f"{target_vendor}:{target_product}"
#     for cpe in vulnerable_products:
#         if match_string not in cpe:
#             continue
#         parts = cpe.split(':')

#         for i,part in enumerate(parts):
#             if part == target_vendor and parts[i+1] == target_product and parts[i+2] not in ('*', '-'):
#                 if parts[i+3] not in ('*', '-'):
#                     versions.append(f"{parts[i+2]}-{parts[i+3]}")
#                 else:
#                     versions.append(parts[i+2])
    
#     return versions
def analyze_versions(vulnerable_products, target_vendor, target_product):
    """分析受影响版本范围"""
    versions = []
    match_string = f"{target_vendor}:{target_product}"
    for cpe in vulnerable_products:
        if match_string not in cpe:
            continue
        parts = cpe.split(':')

        for i,part in enumerate(parts):
            if part == target_vendor and parts[i+1] == target_product and parts[i+2] not in ('*', '-'):
                if parts[i+3] not in ('*', '-'):
                    versions=f"{parts[i+2]}-{parts[i+3]}"
                else:
                    versions=parts[i+2]
    
    return versions

def process_cve_data(output, target_vendor, target_product):
    """处理CVE数据并生成结果"""
    cve_data= output
    
    processed = []
    for entry in cve_data:
        # 版本分析
        vuln_version = analyze_versions(
            entry.get('vulnerable_product', []),
            target_vendor,
            target_product
        )
        # print(version_range)
        
        # 引用过滤
        filtered_refs = [
            ref for ref in entry.get('references', [])
            if any(kw in ref.lower() for kw in ['git', target_product])
        ]
        
        # 构建结果条目
        result_entry = {
            'id': entry.get('id'),
            'cwe': entry.get('cwe', []),
            'summary': entry.get('summary', ''),
            'references': filtered_refs
        }
        
        if vuln_version:
            result_entry['last_vuln_version'] = vuln_version
        
        processed.append(result_entry)
        print(f"processed CVE ID: {entry.get('id')}")
    
    return processed

def parse_raw_data(vendor, product):
    with open(f"./rawdata/{product}_raw.json", "r") as f:
        data = json.load(f)  # 正确用法
    # 处理数据
    result_data = process_cve_data(data, vendor, product)
    
    # 保存结果
    output_file = f"./cveinfo/{product}_parsed.json"
    with open(output_file, 'w') as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)
    
    print(f"分析完成！结果已保存至 {output_file}")

def get_raw_result(command):
    
    # 提取厂商和产品信息
    _, product = extract_vendor_product(command)
    
    # 执行CVE搜索
    data_list = run_command_and_format(command)
    
    # 保存到文件
    try:
        with open(f"./rawdata/{product}_raw.json", "w", encoding="utf-8") as f:
            json.dump(data_list, f, indent=2, ensure_ascii=False)
        print("结果已保存到 cve_results.json")
    except IOError as e:
        print(f"文件保存失败：{e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help="vendor:product")
    parser.add_argument('-r', action='store_true', help="获取原始数据")
    parser.add_argument('-a', action='store_true', help="分析数据")
    args = parser.parse_args()

    if args.p is None:
        print("请提供参数 -p")
        sys.exit(1)

    command = [
        '../cve-search/bin/search.py',
        '-p', f':{args.p}:',  # 使用 f-string 动态插入参数值
        '--only-if-vulnerable',
        '-o', 'json'
    ]
    # 提取厂商和产品信息
    vendor, product = extract_vendor_product(command)
    print(f"厂商: {vendor}, 产品: {product}")
    if args.r:
        get_raw_result(command)
    elif args.a:
        parse_raw_data(vendor, product)
    else:
        print("请提供参数 -r 或 -a")