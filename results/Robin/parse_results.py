import argparse
import csv
import re
import os
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
        'tp': 0,
        'tn': 0,
        'fp': 0,
        'fn': 0,
        'target': 0,
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
                s = binary
                first_dash = s.find('-')
                last_dash = s.rfind('-', 0, s.rfind('-'))
                current_version = s[first_dash + 1:last_dash]
                report['failed_versions'].append(current_version)
                continue  # 跳过统计，因为是失败版本
            
            # 检查是否有测试结果
            result_key = triple  # 使用相同的三元组格式
            if result_key in result_dict:
                score = result_dict[result_key]
                
                # 根据truth和score判断tp, tn, fp, fn
                if truth == 1:  # Ground truth is vulnerable
                    if score > 0:
                        report['tp'] += 1
                    else:
                        report['fn'] += 1
                elif truth == -1:  # Ground truth is patched
                    if score > 0:
                        report['fp'] += 1
                    else:
                        report['tn'] += 1
    
    # 写入CSV
    with open(output_path, 'w', newline='') as f:
        fieldnames = [
            'project', 'cve', 'funcname', 'succeed', 'tp', 'tn', 'fp', 'fn', 'target',
            'failed_versions', 'false_positive', 'false_negative'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for (cve, func), report in report_dict.items():
            false_positive_versions = []
            false_negative_versions = []
            for binary, truth, _ in truth_dict[(cve, func)]:
                s = binary
                first_dash = s.find('-')
                last_dash = s.rfind('-', 0, s.rfind('-'))
                current_version = s[first_dash + 1:last_dash]
                triple = (cve, func, binary)
                if triple in failed_versions_set:
                    continue
                if triple in result_dict:
                    score = result_dict[triple]
                    if truth == 1 and score <= 0:
                        false_negative_versions.append(current_version)
                    elif truth == -1 and score > 0:
                        false_positive_versions.append(current_version)
            
            row = {
                'project': project_map[(cve, func)],
                'cve': cve,
                'funcname': func,
                'succeed': report['tp'] + report['tn'],
                'tp': report['tp'],
                'tn': report['tn'],
                'fp': report['fp'],
                'fn': report['fn'],
                'target': report['target'],
                'failed_versions': ";".join(report['failed_versions']),
                'false_positive': ";".join(false_positive_versions),
                'false_negative': ";".join(false_negative_versions)
            }
            writer.writerow(row)

def aggregate_all_projects(projects, config):
    """
    聚合所有指定项目的统计数据并打印最终报告。
    """
    total_succeed_all = 0
    total_target_all = 0
    total_tp_all = 0
    total_tn_all = 0
    total_fp_all = 0
    total_fn_all = 0
    
    print("\n" + "="*20 + " 聚合所有项目统计 " + "="*20)

    for project in projects:
        report_csv = f"{config}/{project}_result.csv"
        if not os.path.exists(report_csv):
            print(f"警告: 未找到报告文件 {report_csv}，跳过聚合。")
            continue

        with open(report_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_succeed_all += int(row['succeed'])
                total_target_all += int(row['target'])
                total_tp_all += int(row['tp'])
                total_tn_all += int(row['tn'])
                total_fp_all += int(row['fp'])
                total_fn_all += int(row['fn'])

    if total_target_all == 0:
        print("没有可供聚合的数据。")
        return

    # 聚合准确率 (succeed/alltargets)
    accuracy_simple_all = total_succeed_all / total_target_all

    # 聚合有效准确率
    denominator_effective = total_tp_all + total_tn_all + total_fp_all + total_fn_all
    accuracy_effective_all = (total_tp_all + total_tn_all) / denominator_effective if denominator_effective > 0 else 0
    
    # 聚合 Precision, Recall, F1
    precision_all = total_tp_all / (total_tp_all + total_fp_all) if (total_tp_all + total_fp_all) > 0 else 0
    recall_all = total_tp_all / (total_tp_all + total_fn_all) if (total_tp_all + total_fn_all) > 0 else 0
    f1_score_all = 2 * (precision_all * recall_all) / (precision_all + recall_all) if (precision_all + recall_all) > 0 else 0

    print("--- 总体聚合报告 ---")
    print(f"Succeed/All Targets: {accuracy_simple_all:.2%} ({total_succeed_all}/{total_target_all})")
    print(f"Accuracy (effective): {accuracy_effective_all:.2%}")
    print(f"Precision: {precision_all:.2%}")
    print(f"Recall: {recall_all:.2%}")
    print(f"F1-Score: {f1_score_all:.2%}")
    print(f"TP: {total_tp_all}, TN: {total_tn_all}, FP: {total_fp_all}, FN: {total_fn_all}")


CONFIG = "gcc-o3"
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='解析Robin检测结果')
    parser.add_argument(
        "-p", "--projects",
        nargs="*",
        default=["binutils","curl","ffmpeg","freetype","imagemagick","libxml2","openssl","openjpeg","sqlite","tcpdump"],
        help="要解析结果的项目名称列表。默认为10个标准项目。"
    )
    args = parser.parse_args()
    
    for project in args.projects:
        print(f"\n{'='*20} 正在处理项目: {project} {'='*20}")
        # 输入文件（根据实际情况修改路径）
        test_file = f"../../../binaries/Robin/{project}/test-{project}-{CONFIG}"
        result_file = f"{CONFIG}/{project}-result.log"
        log_file = f"{CONFIG}/{project}-details.log"
        output_csv = f"{CONFIG}/{project}_result.csv"
        # 检查文件是否存在
        if not all(os.path.exists(f) for f in [test_file, result_file, log_file]):
            print(f"错误：项目 {project} 的一个或多个输入文件不存在，跳过。")
            continue

        # 解析文件
        truth_data = parse_test_file(test_file)
        result_data = parse_result_file(result_file)
        
        # 解析日志并获取失败版本集合
        failed_versions_set = parse_log_file(log_file)
        
        # 生成主报告
        generate_report(truth_data, result_data, failed_versions_set, output_csv)
        print(f"主报告已生成至: {output_csv}")
        
        # 生成准确率统计报
    # 在所有项目处理完毕后，进行聚合
    aggregate_all_projects(args.projects, CONFIG)