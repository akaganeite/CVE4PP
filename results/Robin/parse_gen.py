import csv
import re
import argparse

def parse_log_file(file_path):
    """
    解析生成日志文件，提取每次生成任务的成功和失败情况
    
    返回:
        list: 包含每次任务元组的列表，每个元组格式为 (cve_id, vul_func_name, status)
              其中 status 为 "success" 或 "fail"
    """
    tasks = []  # 存储所有任务的结果
    current_cve = current_func = None
    
    with open(file_path, 'r') as f:
        for line in f:
            # 解析命令行获取CVE和函数名
            if '--mfi' in line and '--cve_id' in line and '--vul_func_name' in line:
                # 提取CVE ID和漏洞函数名
                match = re.search(r'--cve_id (\S+) .*?--vul_func_name (\S+)', line)
                if match:
                    current_cve, current_func = match.groups()
            
            # 检测成功或失败行
            elif 'ERROR - fail' in line:
                if current_cve and current_func:
                    tasks.append((current_cve, current_func, "fail"))
                    # 重置当前值
                    current_cve = current_func = None
            elif 'INFO - success' in line:
                if current_cve and current_func:
                    tasks.append((current_cve, current_func, "success"))
                    # 重置当前值
                    current_cve = current_func = None
    
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

def write_successful_cves(output_path, tasks,project):
    # 提取所有成功的组合
    successful_pairs = set()
    for cve_id, func_name, status in tasks:
        if status == "success":
            # 创建指定格式的字符串
            pair_str = f'"{cve_id}+{func_name}",'
            successful_pairs.add(pair_str)
    
    # 写入文件
    with open(output_path, 'a') as f:
        f.write(f"{project}:\n")
        # 排序以确保输出一致
        for pair in sorted(successful_pairs):
            f.write(pair + "\n")

if __name__ == "__main__":
    # 设置命令行参数
    parser = argparse.ArgumentParser(description='解析BinXray生成日志')
    parser.add_argument(
        "-proj", "--project",
        required=True,
        type=str,
        help="项目名称"
    )
    args = parser.parse_args()
    
    # 输入输出文件路径
    input_file = f"generation/{args.project}-gen.log"
    output_file = f"generation/{args.project}-gen.csv"
    success_output_file = "generation/stats"
    # 解析日志文件
    tasks = parse_log_file(input_file)
    print(f"解析完成，共发现 {len(tasks)} 个生成任务")
    
    # 写入CSV文件
    write_to_csv(output_file, tasks)
    print(f"结果已写入: {output_file}")

        # 写入成功的CVE-id+funcname文件
    num_successful = write_successful_cves(success_output_file, tasks,args.project)
    print(f"成功的CVE-id+funcname已写入: {success_output_file} ({num_successful}个)")
    
    # 统计信息
    success_count = sum(1 for t in tasks if t[2] == "success")
    failure_count = len(tasks) - success_count
    
    print("\n生成任务统计:")
    print(f"  总任务数: {len(tasks)}")
    print(f"  成功数: {success_count} ({success_count/len(tasks)*100:.1f}%)")
    print(f"  失败数: {failure_count} ({failure_count/len(tasks)*100:.1f}%)")
