import json
from pathlib import Path

# 要处理的项目列表
PROJECTS = [
    "binutils", "curl", "ffmpeg", "freetype", "imagemagick",
    "libxml2", "openjpeg", "openssl", "sqlite", "tcpdump",
]

def aggregate_and_filter():
    """
    聚合所有项目的 source_diff.json 文件，
    同时使用 non-sec-parsed.json 的内容进行过滤。
    """
    base_path = Path('.')
    aggregated_data = {}

    print("[*] 开始聚合和过滤过程...")

    for project in PROJECTS:
        print(f"--- 正在处理项目: {project} ---")
        
        source_diff_path = base_path / project / 'source_diff.json'
        # 假设过滤后的非安全相关函数文件名为 non-sec-parsed.json
        non_sec_path = base_path / project / 'non-sec-parsed.json'

        # 1. 加载 source_diff.json
        if not source_diff_path.exists():
            print(f"  [警告] 未找到 source_diff.json 文件于 '{project}'。跳过。")
            continue
        with open(source_diff_path, 'r', encoding='utf-8') as f:
            source_data = json.load(f)
        
        # 2. 加载 non-sec-parsed.json
        non_sec_data = {}
        if non_sec_path.exists():
            with open(non_sec_path, 'r', encoding='utf-8') as f:
                non_sec_data = json.load(f)
        else:
            print(f"  [信息] 未找到 non-sec-parsed.json 文件于 '{project}'。将不会进行过滤。")

        # 获取特定于项目的数据
        project_source_data = source_data.get(project, {})
        if not project_source_data:
            print(f"  [警告] 在 source_diff.json 中未找到项目 '{project}' 的数据。")
            continue

        # 3. 过滤和聚合
        for cve, cve_data in project_source_data.items():
            # 获取此 CVE 的非安全相关函数列表
            non_sec_funcs = set(non_sec_data.get(cve, []))
            
            if not non_sec_funcs:
                # 如果没有要过滤的函数，直接添加整个 CVE 数据
                if cve not in aggregated_data:
                    aggregated_data[cve] = cve_data
                continue

            # 如果有要过滤的函数，则处理 analysis 列表
            original_analysis = cve_data.get("analysis", [])
            filtered_analysis = [
                item for item in original_analysis 
                if item.get("function") not in non_sec_funcs
            ]

            # 只有在过滤后 analysis 列表不为空时，才将此 CVE 添加到结果中
            if filtered_analysis:
                # 创建一个新的 cve_data 副本以避免修改原始数据（虽然在这里不是必须的）
                new_cve_data = cve_data.copy()
                new_cve_data["analysis"] = filtered_analysis
                if cve not in aggregated_data:
                    aggregated_data[cve] = new_cve_data
            else:
                print(f"  [信息] 过滤后，CVE '{cve}' 的函数列表为空，已忽略。")

    # 4. 写入最终的聚合文件
    output_file = base_path / 'aggregated_source_diff.json'
    print(f"\n[*] 聚合完成，正在将结果写入: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(aggregated_data, f, indent=4)

    print("[*] 完成！")

def aggregate_non_sec_cves():
    """
    聚合所有项目 non-sec.json 文件中的 CVE 列表。
    """
    base_path = Path('.')
    all_non_sec_cves = set()

    print("\n[*] 开始聚合 non-sec.json 中的 CVE...")

    for project in PROJECTS:
        print(f"--- 正在处理项目: {project} ---")
        
        non_sec_path = base_path / project / 'non-sec.json'

        if non_sec_path.exists():
            try:
                with open(non_sec_path, 'r', encoding='utf-8') as f:
                    non_sec_data = json.load(f)
                # 假设 non-sec.json 的顶层键是 CVE ID
                cves = non_sec_data.keys()
                all_non_sec_cves.update(cves)
                print(f"  [信息] 从 '{project}' 的 non-sec.json 中找到 {len(cves)} 个 CVE。")
            except json.JSONDecodeError:
                print(f"  [错误] 无法解析 non-sec.json 文件于 '{project}'。")
            except Exception as e:
                print(f"  [错误] 处理 non-sec.json 时出错于 '{project}': {e}")
        else:
            print(f"  [信息] 未找到 non-sec.json 文件于 '{project}'。跳过。")

    # 转换为列表并排序以便于查看
    sorted_cves = sorted(list(all_non_sec_cves))

    # 写入最终的聚合文件
    output_file = base_path / 'aggregated_non_sec_cves.json'
    print(f"\n[*] non-sec CVE 聚合完成，正在将结果写入: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        # 输出为 JSON 数组格式
        json.dump(sorted_cves, f, indent=4)

    print("[*] non-sec CVE 聚合任务完成！")


if __name__ == '__main__':
    # aggregate_and_filter()
    aggregate_non_sec_cves()