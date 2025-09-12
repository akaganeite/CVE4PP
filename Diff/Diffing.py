import json
from pathlib import Path
import argparse

def parse_ground_truth(filepath):
    """
    读取基准真相文件 (valid)，并返回一个 {cve: {'functions': set, 'metadata': str}} 格式的字典。
    该文件格式为: CVE DATE HASH TOOL func1,func2,...
    """
    ground_truth = {}
    if not filepath.exists():
        print(f"警告: 未找到基准真相文件: {filepath}")
        return ground_truth
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            # 至少需要 CVE, DATE, HASH, TOOL, FUNCS 五个部分
            if len(parts) >= 5:
                cve = parts[0]
                # 元数据是 DATE, HASH, TOOL
                metadata = " ".join(parts[1:4])
                # 函数列表是最后一个元素，以逗号分隔
                funcs_str = parts[4]
                functions = set(f for f in funcs_str.split(',') if f)
                ground_truth[cve] = {'functions': functions, 'metadata': metadata}
    return ground_truth

def parse_source_diff(filepath, project):
    """
    读取 source_diff.json 文件，并返回一个 {cve: {functions}} 格式的字典。
    """
    source_funcs = {}
    if not filepath.exists():
        print(f"警告: 未找到源码 diff 文件: {filepath}")
        return source_funcs
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    project_data = data.get(project, {})
    for cve, cve_data in project_data.items():
        functions = set()
        analysis_list = cve_data.get("analysis", [])
        for item in analysis_list:
            if "function" in item:
                functions.add(item["function"])
        source_funcs[cve] = functions
    return source_funcs

def parse_bin_diff(filepath):
    """
    读取 bin_diff.json 文件，并返回一个 {cve: {functions}} 格式的字典。
    """
    bin_funcs = {}
    if not filepath.exists():
        print(f"警告: 未找到二进制 diff 文件: {filepath}")
        return bin_funcs
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    for cve, analysis_list in data.items():
        functions = set()
        for item in analysis_list:
            if "function" in item:
                functions.add(item["function"])
        bin_funcs[cve] = functions
    return bin_funcs

def compare_results(project):
    """
    为指定项目比较基准真相、源码分析和二进制分析的结果。
    """
    # 定义文件路径 (相对于 New/Diff/ 目录)
    base_path = Path('.')
    valid_file = base_path / '../testset' / project / 'valid'
    source_diff_file = base_path / project / 'source_diff.json'
    bin_diff_file = base_path / project / 'bin_diff.json'

    # --- 加载数据 ---
    print(f"[*] 正在加载基准真相: {valid_file}")
    ground_truth = parse_ground_truth(valid_file)
    
    print(f"[*] 正在加载源码分析结果: {source_diff_file}")
    source_analysis = parse_source_diff(source_diff_file, project)
    
    print(f"[*] 正在加载二进制分析结果: {bin_diff_file}")
    bin_analysis = parse_bin_diff(bin_diff_file)

    if not ground_truth:
        print("错误: 未找到基准真相数据，无法进行比较。")
        return

    non_sec_results = {}
    valid2_lines = []

    # --- 比较逻辑 ---
    print("\n[*] 开始比较...")
    for cve, valid_data in ground_truth.items():
        s_valid = valid_data['functions']
        metadata = valid_data['metadata']
        
        s_source = source_analysis.get(cve, set())
        s_bin = bin_analysis.get(cve, set())

        # 规则: 找出在源码分析中存在但在二进制分析中缺失的函数 (用于 non-sec.json)
        non_sec_funcs = s_source - s_bin
        if non_sec_funcs:
            non_sec_results[cve] = sorted(list(non_sec_funcs))

        # 新规则: valid2的输出只看source_diff和details的对比，不看bin_diff
        # 1. 和valid中CVE的函数对比，如果有区别
        if s_source != s_valid:
            # 2. 将全部区别的CVE和对应的函数(source_diff中的函数)，输出为valid2
            if s_source: # 仅当有函数可报告时才添加
                # 使用原始元数据重建行
                line = f"{cve} {metadata} {','.join(sorted(list(s_source)))}"
                valid2_lines.append(line)

    # --- 写入输出文件 ---
    output_dir = base_path / project
    output_dir.mkdir(exist_ok=True)

    # 写入 non-sec.json
    non_sec_file = output_dir / 'non-sec.json'
    print(f"\n[*] 正在将非安全相关的发现写入: {non_sec_file}")
    with open(non_sec_file, 'w', encoding='utf-8') as f:
        json.dump(non_sec_results, f, indent=4)

    # 写入 valid2
    valid2_file = output_dir / 'valid2'
    print(f"[*] 正在将差异结果写入: {valid2_file}")
    with open(valid2_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid2_lines))
        
    print("\n[*] 比较完成。")

if __name__ == '__main__':
    # 设置命令行参数解析器以接受项目名称
    parser = argparse.ArgumentParser(description="比较源码、二进制和基准真相的分析结果。")
    parser.add_argument("project", help="要分析的项目名称 (例如 'binutils')")
    args = parser.parse_args()
    
    compare_results(args.project)