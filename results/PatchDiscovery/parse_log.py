#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
from collections import defaultdict
import argparse

def parse_log_file(log_file_path):
    """解析日志文件并提取CVE检测结果"""
    
    cve_results = {}
    current_cve = None
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # 检测CVE开始
        if line.startswith('[*] Detecting CVE:'):
            current_cve = line.split('CVE: ')[1]
            if current_cve not in cve_results:
                cve_results[current_cve] = {
                    'functions': defaultdict(list),
                    'target': current_cve,
                    'total_detections': 0,
                    'successful_detections': 0,
                    'failed_versions': [],
                    'false_positive': [],
                    'false_negative': []
                }
            continue
        
        # 检测函数检测结果
        if line.startswith('[*] Detection for target/') and current_cve:
            # 解析目标信息
            parts = line.split(',')
            if len(parts) >= 3:
                target_info = parts[0].split('target/')[1]
                function_name = parts[1]
                version_flag = parts[2]  # -1 for vulnerable, 1 for patched
                
                # 提取版本信息
                s=target_info
                first_dash = s.find('-')            
                last_dash = s.rfind('-', 0, s.rfind('-'))
                version = s[first_dash + 1:last_dash]
                # version = version_match.group(1)
                
                # 读取下一行的检测结果
                if i + 1 < len(lines):
                    result_line = lines[i + 1].strip()
                    if result_line.startswith('[*] Detection Result:'):
                        result = result_line.split('Detection Result:')[1].strip()
                        
                        # 判断结果类型
                        is_vulnerable = result.startswith('V')
                        is_patched = result.startswith('P')
                        
                        # 存储结果
                        cve_results[current_cve]['functions'][function_name].append({
                            'version': version,
                            'is_vulnerable': is_vulnerable,
                            'is_patched': is_patched,
                            'expected_vulnerable': version_flag == '-1',
                            'expected_patched': version_flag == '1',
                            'result': result
                        })
        
        # 检测函数未找到的情况
        elif line.startswith('[*] target function:') and current_cve:
            # 这种情况表示函数未找到，需要特殊处理
            pass
        
        # 检测失败决定的情况
        elif line.startswith('[*] Detection Result: fail to decide') and current_cve:
            # 这种情况表示检测失败
            pass
    
    return cve_results

def analyze_cve_results(cve_results):
    """分析CVE结果并生成CSV数据（以CVE为单位统计）"""
    csv_data = []
    total_tp_project, total_tn_project, total_fp_project, total_fn_project = 0, 0, 0, 0

    for cve, data in cve_results.items():
        # 1. 按版本重新组织数据
        results_by_version = defaultdict(list)
        for func_name, results_list in data['functions'].items():
            for result in results_list:
                result['function_name'] = func_name
                results_by_version[result['version']].append(result)

        # 2. 分析每个版本的结果
        succeed_versions = 0
        failed_versions_details = {
            'failed': [],
            'additional_error': [],
            'false_positive': [],
            'false_negative': []
        }
        tp_cve, tn_cve, fp_cve, fn_cve = 0, 0, 0, 0

        for version, version_results in results_by_version.items():
            is_version_correct = True
            has_fp = False
            has_fn = False
            has_error = False
            
            # 确定此版本的预期状态（易受攻击或已修补）
            # 假设同一版本的所有函数具有相同的预期状态
            expected_patched = any(r['expected_patched'] for r in version_results)
            expected_vulnerable = any(r['expected_vulnerable'] for r in version_results)

            for result in version_results:
                # 检查无法判定的情况
                if 'fail to decide' in result['result']:
                    has_error = True
                    is_version_correct = False
                    continue

                # 检查 FP 和 FN
                if result['expected_patched'] and result['is_vulnerable']:
                    has_fn = True # 预期已修补但检测为易受攻击 -> FN
                    is_version_correct = False
                if result['expected_vulnerable'] and result['is_patched']:
                    has_fp = True # 预期易受攻击但检测为已修补 -> FP
                    is_version_correct = False

            # 3. 更新统计信息
            if is_version_correct:
                succeed_versions += 1
                if expected_patched:
                    tp_cve += 1
                elif expected_vulnerable:
                    tn_cve += 1
            else:
                # 版本失败，确定原因
                if has_error:
                    failed_versions_details['additional_error'].append(version)
                if has_fp:
                    failed_versions_details['false_positive'].append(version)
                    fp_cve += 1
                if has_fn:
                    failed_versions_details['false_negative'].append(version)
                    fn_cve += 1
                
                # 如果既没有FP/FN也没有错误，但仍然不正确，则归入通用失败类别
                if not has_error and not has_fp and not has_fn:
                    failed_versions_details['failed'].append(version)


        total_versions = len(results_by_version)
        
        # 累加到项目总数
        total_tp_project += tp_cve
        total_tn_project += tn_cve
        total_fp_project += fp_cve
        total_fn_project += fn_cve

        csv_data.append({
            'cve': cve,
            'succeed': succeed_versions,
            'target': total_versions,
            'tp': tp_cve,
            'tn': tn_cve,
            'fp': fp_cve,
            'fn': fn_cve,
            'failed_versions': ';'.join(sorted(list(set(failed_versions_details['failed'])))),
            'additional_error': ';'.join(sorted(list(set(failed_versions_details['additional_error'])))),
            'false_positive': ';'.join(sorted(list(set(failed_versions_details['false_positive'])))),
            'false_negative': ';'.join(sorted(list(set(failed_versions_details['false_negative']))))
        })
        
    return csv_data, total_tp_project, total_tn_project, total_fp_project, total_fn_project

def write_csv(csv_data, output_file):
    """写入CSV文件"""
    
    fieldnames = [
        'cve', 'succeed', 'target', 'tp', 'tn', 'fp', 'fn', 
        'failed_versions', 'additional_error', 'false_positive', 'false_negative'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_data)

def calculate_overall_statistics(csv_data):
    """计算整体统计信息"""
    
    total_detections = sum(int(row['target']) for row in csv_data)
    total_successful = sum(int(row['succeed']) for row in csv_data)
    
    # 整体准确率
    overall_accuracy = (total_successful / total_detections * 100) if total_detections > 0 else 0

    failed = sum(1 for row in csv_data if row['failed_versions'])
    filtered = (total_successful/ (total_detections- failed))*100
    
    return {
        'total_detections': total_detections,
        'total_successful': total_successful,
        'overall_accuracy': overall_accuracy,
        'filtered': filtered
    }

def main():
    parser = argparse.ArgumentParser(description='解析PatchDiscovery检测结果')
    parser.add_argument(
        "--projects",
        default=["binutils","curl","freetype","ffmpeg","imagemagick","libxml2","openssl","openjpeg","sqlite","tcpdump"],
        nargs="*"
    )
    parser.add_argument(
        "-opt", "--optimization",
        type=str,
        help="优化级别 (如 o0, o1, o2, o3)"
    )
    parser.add_argument(
        "-compiler", "--compiler",
        type=str,
        help="编译器 (如 gcc, clang)"
    )
    
    args = parser.parse_args()
    projects = args.projects

    # 初始化所有项目的总计数器
    all_projects_tp = 0
    all_projects_tn = 0
    all_projects_fp = 0
    all_projects_fn = 0
    all_projects_target = 0
    processed_projects_count = 0

    for project in projects:
        # 根据是否指定opt和compiler参数来决定文件名
        if args.optimization and args.compiler:
            dir_path = f"{args.compiler}-{args.optimization}"
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            log_file = os.path.join(dir_path, f"{project}-test.log")
            output_file = os.path.join(dir_path, f"{project}-cve.csv")
        else:
            log_file = f"{project}-test.log"
            output_file = f"{project}-cve.csv"

        if not os.path.exists(log_file):
            print(f"警告：输入文件 {log_file} 不存在，跳过项目 {project}")
            continue

        print(f"======== 处理项目: {project} ========")
        print(f"正在解析日志文件: {log_file}")
        cve_results = parse_log_file(log_file)
        
        print(f"正在分析CVE结果...")
        csv_data, total_tp, total_tn, total_fp, total_fn = analyze_cve_results(cve_results)
        
        print(f"正在写入CSV文件: {output_file}")
        write_csv(csv_data, output_file)
        
        print(f"完成！共处理了 {len(csv_data)} 个CVE")
        
        # 计算并打印当前项目的整体统计信息
        stats = calculate_overall_statistics(csv_data)
        
        print(f"\n--- {project} 整体统计信息 ---")
        print(f"总检测版本数量: {stats['total_detections']}")
        print(f"成功检测版本数量: {stats['total_successful']}")
        print(f"整体准确率: {stats['overall_accuracy']:.2f}%")
        print(f"排除failed的准确率: {stats['filtered']:.2f}%\n")

                # 累加到总计数器
        all_projects_tp += total_tp
        all_projects_tn += total_tn
        all_projects_fp += total_fp
        all_projects_fn += total_fn
        all_projects_target += stats['total_detections']
        processed_projects_count += 1

    # 在所有项目处理完毕后，打印聚合结果
    if processed_projects_count > 0:
        print("========================================")
        print("======== 所有项目聚合结果 (Macro) ========")
        print("========================================")
        
        # 计算宏观平均指标
        total_classified = all_projects_tp + all_projects_tn + all_projects_fp + all_projects_fn
        macro_accuracy = (all_projects_tp + all_projects_tn) / total_classified if total_classified > 0 else 0
        macro_precision = all_projects_tp / (all_projects_tp + all_projects_fp) if (all_projects_tp + all_projects_fp) > 0 else 0
        macro_recall = all_projects_tp / (all_projects_tp + all_projects_fn) if (all_projects_tp + all_projects_fn) > 0 else 0
        macro_f1 = 2 * (macro_precision * macro_recall) / (macro_precision + macro_recall) if (macro_precision + macro_recall) > 0 else 0
        effectiveness = (all_projects_tp + all_projects_tn) / all_projects_target if all_projects_target > 0 else 0
        print(f"effectiveness:{all_projects_tp + all_projects_tn}/{all_projects_target}={effectiveness:.4f}")
        print(f"TP: {all_projects_tp}, TN: {all_projects_tn}, FP: {all_projects_fp}, FN: {all_projects_fn}")
        print(f"整体准确率 (Accuracy): {macro_accuracy:.4f}")
        print(f"整体精确率 (Precision): {macro_precision:.4f}")
        print(f"整体召回率 (Recall): {macro_recall:.4f}")
        print(f"整体F1分数 (F1-Score): {macro_f1:.4f}")


if __name__ == "__main__":
    main()