import argparse
import csv
import re
from collections import defaultdict

TESTCASES={
    "binutils":613-20,
    "curl":340-7,
    "ffmpeg":192-17,
    "freetype":353-1,
    "imagemagick": 1027-6,
    "libxml2":510,
    "openssl":696-45,
    "sqlite":228-3,
    "tcpdump":1176-48,
    "openjpeg":104-7,
}

def parse_test_file(file_path):
    truth_dict = defaultdict(list)
    with open(file_path, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 4: 
                continue
            cve = parts[0]
            binary = parts[1].strip()
            func = parts[2].strip()
            truth = int(parts[3])
            project = binary.split('/')[3]  # 从路径提取项目名
            
            key = (cve, func)
            truth_dict[key].append((binary, truth, project))
    return truth_dict

def parse_result_file(file_path):
    result_dict = {}
    with open(file_path, 'r') as f:
        content = f.read().split('--------------------------------------------')
        for block in content:
            if not block.strip(): 
                continue
            cve = func = binary = None
            score = None
            
            lines = block.strip().split('\n')
            for line in lines:
                if line.startswith('CVE ID: '):
                    cve = line.split('CVE ID: ')[1].strip()
                elif line.startswith('Target Binary: '):
                    binary = line.split('Target Binary: ')[1].strip()
                elif line.startswith('Vulnerable Function Name: '):
                    func = line.split('Vulnerable Function Name: ')[1].strip()
                elif line.startswith('Overall Score is: '):
                    score_str = line.split('Overall Score is: ')[1].strip()
                    try:
                        score = float(score_str)
                    except ValueError:
                        continue
            
            if cve and func and binary is not None and score is not None:
                key = (cve, func, binary)
                result_dict[key] = score
    return result_dict

def parse_log_file(file_path):
    failed_versions = set()  # 使用集合存储唯一的三元组
    current_cve = current_func = current_binary = None
    
    with open(file_path, 'r') as f:
        for line in f:
            # 解析命令行获取目标二进制
            if '--detect' in line and '--cve_id' in line and '--target_bin' in line and '--vul_func_name' in line:
                # 改进的正则表达式提取所有必要信息
                match = re.search(r'--cve_id (\S+) --target_bin (\S+) --vul_func_name (\S+)', line)
                if match:
                    current_cve, current_binary, current_func = match.groups()
            
            # 检测ERROR行
            if 'ERROR - fail' in line:
                if current_cve and current_func and current_binary:
                    # 创建三元组作为唯一key
                    triple = (current_cve, current_func, current_binary)
                    failed_versions.add(triple)
    
    return failed_versions

def generate_report(truth_dict, result_dict, failed_versions_set, output_path):
    report_dict = defaultdict(lambda: {
        'succeed': 0,
        'target': 0,
        'false_positive': 0,
        'false_negative': 0,
        'failed_versions': []
    })
    
    # 准备项目名映射（每个CVE+func组合的项目名相同）
    project_map = {}
    for (cve, func), values in truth_dict.items():
        project_map[(cve, func)] = values[0][2]  # 取第一个项目的项目名
    
    # 处理每个ground truth条目
    for (cve, func), entries in truth_dict.items():
        key = (cve, func)
        report = report_dict[key]
        report['target'] = len(entries)  # 设置target值
        
        # 处理每个二进制版本
        for binary, truth, _ in entries:
            # 创建三元组用于失败版本检查
            triple = (cve, func, binary)
            
            # 检查是否是失败版本
            if triple in failed_versions_set:
                report['failed_versions'].append(binary)
                continue  # 跳过统计，因为是失败版本
            
            # 检查是否有测试结果
            result_key = triple  # 使用相同的三元组格式
            if result_key in result_dict:
                score = result_dict[result_key]
                
                # 检查是否匹配
                if (score > 0 and truth == 1) or (score <= 0 and truth == -1):
                    report['succeed'] += 1
                else:
                    if score > 0 and truth == -1:
                        report['false_positive'] += 1
                    elif score <= 0 and truth == 1:
                        report['false_negative'] += 1
    
    # 写入CSV
    with open(output_path, 'w', newline='') as f:
        fieldnames = ['project', 'CVE', 'func', 'succeed', 'target', 
                     'false_positive', 'false_negative', 'failed_versions']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for (cve, func), report in report_dict.items():
            row = {
                'project': project_map[(cve, func)],
                'CVE': cve,
                'func': func,
                'succeed': report['succeed'],
                'target': report['target'],
                'false_positive': report['false_positive'],
                'false_negative': report['false_negative'],
                'failed_versions': ";".join(report['failed_versions'])
            }
            writer.writerow(row)

def generate_accuracy_report(report_csv, accuracy_output,project):
    project_stats = defaultdict(lambda: {
        'total_succeed': 0,
        'total_target': 0,
        'total_fp': 0,
        'total_fn': 0
    })
    
    # 读取主报告CSV
    with open(report_csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            project = row['project']
            stats = project_stats[project]
            
            # 累加各项指标
            stats['total_succeed'] += int(row['succeed'])
            stats['total_target'] += int(row['target'])
            stats['total_fp'] += int(row['false_positive'])
            stats['total_fn'] += int(row['false_negative'])
 
    for project, stats in project_stats.items():
        total_succeed = stats['total_succeed']
        total_target = stats['total_target']
        total_errors = stats['total_fp'] + stats['total_fn']
        
        # 第一个准确率：成功检测数/总检测目标数
        accuracy_simple = total_succeed / total_target if total_target > 0 else 0
        
        # 第二个准确率：成功检测数/(成功数+假阳性+假阴性)
        accuracy_effective = 0
        denominator = total_succeed + total_errors
        if denominator > 0:
            accuracy_effective = total_succeed / denominator
        
        # 转换为百分比格式并保留两位小数
        accuracy_simple = f"{accuracy_simple:.2%}"
        accuracy_effective = f"{accuracy_effective:.2%}"
        # print("total_succeed:", total_succeed)
        ability = total_succeed/TESTCASES[project]
        print(project,":")
        print("ability:",f"{ability:.2%}"," ",total_succeed,"/",TESTCASES[project])
        print("accuracy:", accuracy_effective)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "-proj", "--project",
        required=True,
        type=str,
    )
    args = parser.parse_args()
    project = args.project
    # 输入文件（根据实际情况修改路径）
    test_file = f"../../../binaries/Robin/test-{project}"
    # result_file = "patch_detection_full.log"
    # log_file = "detectdetails.log"
    result_file = f"{project}-result.log"
    log_file = f"{project}-details.log"
    output_csv = f"{project}_result.csv"
    accuracy_csv = f"{project}_acc.csv"  # 新增准确率报告

    # 解析文件
    truth_data = parse_test_file(test_file)
    result_data = parse_result_file(result_file)
    
    # 解析日志并获取失败版本集合
    failed_versions_set = parse_log_file(log_file)
    
    # 生成主报告
    generate_report(truth_data, result_data, failed_versions_set, output_csv)
    print(f"主报告已生成至: {output_csv}")
    
    # 生成准确率统计报告
    generate_accuracy_report(output_csv, accuracy_csv,args.project)