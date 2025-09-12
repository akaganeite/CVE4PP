import csv
import re
import argparse
import os
import json
from collections import defaultdict

def parse_csv_file(file_path):
    """
    解析生成结果的CSV文件
    
    返回:
        list: 包含每次任务元组的列表，每个元组格式为 (cve_id, vul_func_name, status)
    """
    tasks = []
    try:
        with open(file_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get('CVE_ID')
                func_name = row.get('func_name')
                status = row.get('status')
                if cve_id and func_name and status:
                    tasks.append((cve_id, func_name, status))
    except FileNotFoundError:
        print(f"警告: 文件未找到 -> {file_path}")
    except Exception as e:
        print(f"读取CSV文件 {file_path} 时出错: {e}")
    return tasks

def write_to_csv(output_path, tasks):
    """
    将任务结果写入CSV文件
    
    CSV格式:
        CVE_ID, func_name, status
    """
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["CVE_ID", "func_name", "status"])  # 写入表头
        
        for cve_id, func_name, status in tasks:
            writer.writerow([cve_id, func_name, status])

def write_pairs_to_json(output_path, pairs):
    """
    将 (CVE, function) 对以JSON格式写入文件
    
    参数:
        output_path (str): 输出文件路径
        pairs (set): (cve_id, func_name) 元组的集合
    """
    # 按CVE ID对函数进行分组
    data = defaultdict(list)
    for cve_id, func_name in pairs:
        data[cve_id].append(func_name)
    
    # 对每个CVE的函数列表进行排序
    for cve_id in data:
        data[cve_id].sort()

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4, sort_keys=True)

if __name__ == "__main__":
    # 设置命令行参数
    parser = argparse.ArgumentParser(description='从CSV解析Robin生成日志')
    parser.add_argument(
        "-proj", "--projects",
        nargs='*',
        default=["binutils", "curl", "ffmpeg", "freetype", "imagemagick", "libxml2", "openssl", "sqlite", "tcpdump", "openjpeg"],
        type=str,
        help="项目名称列表，用空格分隔"
    )
    args = parser.parse_args()
    
    all_tasks = []
    all_failed_pairs = set()
    all_successful_pairs = set()

    for project in args.projects:
        print(f"\n--- 处理项目: {project} ---")
        # 输入CSV文件路径
        input_csv_file = f"generation/{project}-gen.csv"

        # 解析CSV文件
        tasks = parse_csv_file(input_csv_file)
        if not tasks:
            continue # 如果文件不存在或为空，则跳过

        print(f"解析完成，共发现 {len(tasks)} 个生成任务")
        all_tasks.extend(tasks)
        
        # 收集失败和成功的 (CVE, function) 对
        for cve_id, func_name, status in tasks:
            if status == "fail":
                all_failed_pairs.add((cve_id, func_name))
            elif status == "success":
                all_successful_pairs.add((cve_id, func_name))

    # 写入所有失败的 (CVE, function) 对到JSON文件
    failed_json_output = "generation/all_failed_gen_pairs.json"
    write_pairs_to_json(failed_json_output, all_failed_pairs)
    print(f"\n所有失败的 (CVE, function) 对已写入: {failed_json_output}")

    # 写入所有成功的 (CVE, function) 对到JSON文件
    successful_json_output = "generation/all_successful_gen_pairs.json"
    write_pairs_to_json(successful_json_output, all_successful_pairs)
    print(f"所有成功的 (CVE, function) 对已写入: {successful_json_output}")
    
    # 统计信息
    success_count = sum(1 for t in all_tasks if t[2] == "success")
    failure_count = len(all_tasks) - success_count
    
    print("\n生成任务统计:")
    print(f"  总任务数: {len(all_tasks)}")
    print(f"  成功数: {success_count} ({success_count/len(all_tasks)*100:.1f}%)")
    print(f"  失败数: {failure_count} ({failure_count/len(all_tasks)*100:.1f}%)")
