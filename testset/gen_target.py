import sys
import json
import re

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <project_name> <output_file>")
        sys.exit(1)
    
    project_name = sys.argv[1]
    output_file = sys.argv[2]
    # 打开或创建输出文件

    cve_file = f"../Diff/{project_name}/valid2"
    
    # 读取testset.json
    try:
        with open(f'./{project_name}/testset.json', 'r') as f:
            testset_data = json.load(f)
    except FileNotFoundError:
        print("Error: testset.json not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in testset.json")
        sys.exit(1)
    
    # 创建CVE号到测试数据的映射
    # cve_map = {item['cve_id']: item for item in testset_data}
    
    # 读取CVE文件
    try:
        with open(cve_file, 'r') as f:
            cve_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {cve_file} not found")
        sys.exit(1)
    res =""
    # 处理每行CVE数据
    for line in cve_lines:
        # 解析CVE行：CVE号 日期 函数列表
        # (line,binary) = line.strip().split('|')[0]
        # parts = re.split(r'\s+', line.strip(), 2)
        parts = line.strip().split(" ")
        if len(parts) < 3:
            continue
            
        cve_id = parts[0].split('_')[0]  # 提取CVE号的前缀
        funcs_str = parts[-1]  # 提取函数列表，去掉括号及其后的内容
        binary = parts[-2].split(" ")[-1]
        print(binary)
        # 分割函数列表
        functions = [f.strip() for f in funcs_str.split(',') if f.strip()]
        
        # 查找对应的测试数据
        cve_data = testset_data.get(cve_id)
        if not cve_data:
            continue
            
        # 为每个函数生成6行输出
        for func in functions:
            # 漏洞版本输出（3行）
            for version in cve_data.get("vuln", []):
                bin_path = f"/binaries/target/{project_name}/{project_name}-{version}-o0-{binary}"
                res += f"{cve_id.split('_')[0]},{bin_path},{func},-1\n"
                print(f"{cve_id.split('_')[0]},{bin_path},{func},-1")
            
            # 修复版本输出（3行）
            for version in cve_data.get("patch", []):
                bin_path = f"/binaries/target/{project_name}/{project_name}-{version}-o0-{binary}"
                res += f"{cve_id.split('_')[0]},{bin_path},{func},1\n"
                print(f"{cve_id.split('_')[0]},{bin_path},{func},1")
    with open(output_file, 'w') as f:
        f.write(res)

if __name__ == "__main__":
    main()