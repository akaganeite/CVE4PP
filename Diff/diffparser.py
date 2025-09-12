import json
import re
import argparse
from pathlib import Path

def parse_details_file(filepath):
    """
    解析 details 文件，返回 CVE 到 commit hash 的映射。
    支持 'CVE-ID_hash' 和 'CVE-ID hash' 两种格式。
    """
    cve_to_hash = {}
    if not filepath.exists():
        print(f"错误: 未找到 details 文件: {filepath}")
        return cve_to_hash
        
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
            
            cve_id_part = parts[0]
            commit_hash = ""

            if '_' in cve_id_part:
                # 格式: CVE-2014-8484_bd25671c6f20
                try:
                    cve_id, commit_hash = cve_id_part.rsplit('_', 1)
                    cve_to_hash[cve_id] = commit_hash
                except ValueError:
                    print(f"警告: 无法解析行: {line.strip()}")
            elif len(parts) >= 2:
                # 格式: CVE-2014-8485 493a33860c71 ...
                cve_id = parts[0]
                commit_hash = parts[1]
                cve_to_hash[cve_id] = commit_hash
            else:
                print(f"警告: 无法解析行: {line.strip()}")

    return cve_to_hash

def normalize_code_line(line):
    """移除行中的空格和圆括号"""
    return line.replace(" ", "").replace("(", "").replace(")", "")

def analyze_diff(diff_content, function_name):
    """
    在 diff 内容中找到指定函数的 hunk，并比较其 +/- 行。
    如果标准化后的 +/- 行完全一致，返回 True，否则返回 False。
    """
    # 正则表达式匹配 hunk header，可能包含函数上下文
    hunk_header_pattern = re.compile(r'@@ .*? @@.*?' + re.escape(function_name), re.DOTALL)
    hunks = diff_content.split('@@')
    
    relevant_hunk = ""
    # 找到包含函数名的 hunk
    # 遍历由 '@@' 分割的块
    for i in range(1, len(hunks), 2):
        header_and_body = hunks[i] + hunks[i+1] if i+1 < len(hunks) else hunks[i]
        if function_name in header_and_body:
            relevant_hunk = "@@" + header_and_body
            break

    if not relevant_hunk:
        # print(f"  -> 未找到函数 '{function_name}' 的 hunk。")
        return False # 无法确认，保守地认为有变化

    plus_lines = []
    minus_lines = []
    for line in relevant_hunk.splitlines():
        if line.startswith('+'):
            line_content = line[1:]
            # 新增：忽略内容为空或仅包含空格的行
            if line_content.strip():
                plus_lines.append(line_content)
        elif line.startswith('-'):
            line_content = line[1:]
            # 新增：忽略内容为空或仅包含空格的行
            if line_content.strip():
                minus_lines.append(line_content)

    # 如果过滤后没有 +/- 行，说明变化只是空行，我们认为这不算实质性变更
    if not plus_lines and not minus_lines:
        return True

    normalized_plus = normalize_code_line("".join(plus_lines))
    normalized_minus = normalize_code_line("".join(minus_lines))

    return normalized_plus == normalized_minus

def filter_non_sec_json(project):
    """
    主函数，读取 non-sec.json，分析 diff，并过滤结果。
    """
    base_path = Path('.')
    project_path = base_path / project
    
    non_sec_file = project_path / 'non-sec.json'
    details_file = project_path / 'details'
    diff_dir = project_path / 'diff_files'

    if not non_sec_file.exists():
        print(f"错误: 未找到 non-sec.json 文件: {non_sec_file}")
        return

    print("[*] 正在加载 non-sec.json...")
    with open(non_sec_file, 'r', encoding='utf-8') as f:
        non_sec_data = json.load(f)

    print("[*] 正在解析 details 文件...")
    cve_to_hash = parse_details_file(details_file)
    if not cve_to_hash:
        return

    filtered_data = {}
    print("[*] 开始分析和过滤函数...")

    for cve, functions in non_sec_data.items():
        if cve not in cve_to_hash:
            print(f"警告: 在 details 文件中未找到 CVE '{cve}' 的 commit hash。")
            continue

        commit_hash = cve_to_hash[cve]
        diff_filename = f"{project}_{cve}_{commit_hash}.diff"
        diff_file = diff_dir / diff_filename
        
        if not diff_file.exists():
            print(f"警告: 未找到 CVE '{cve}' 的 diff 文件: {diff_file}")
            continue

        with open(diff_file, 'r', encoding='utf-8', errors='ignore') as f:
            diff_content = f.read()

        kept_functions = []
        print(f"--- 正在处理 CVE: {cve} ---")
        for func in functions:
            is_signature_change_only = analyze_diff(diff_content, func)
            if is_signature_change_only:
                print(f"  [keep] '{func}' no code changes")
                kept_functions.append(func)
            else:
                print(f"  [remove] '{func}' has changes")
                
        
        if kept_functions:
            filtered_data[cve] = kept_functions

    print("\n[*] 过滤完成")
    with open(f"{project_path}/non-sec-parsed.json", 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=4)

    print("[*] 完成！")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="过滤 non-sec.json 文件，移除包含实质性代码变更的函数。")
    parser.add_argument("project", help="要处理的项目名称 (例如 'binutils')")
    args = parser.parse_args()
    
    filter_non_sec_json(args.project)