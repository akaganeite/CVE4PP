#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    """分析CVE结果并生成CSV数据（以CVE+version为单位统计）"""
    
    csv_data = []
    
    for cve, data in cve_results.items():
        # 1. 收集所有出现过的version
        version_set = set()
        for function_name, results in data['functions'].items():
            for result in results:
                version_set.add(result['version'])

        total_versions = len(version_set)
        succeed_versions = 0
        failed_versions = []
        false_positive = []
        false_negative = []

        for version in version_set:
            all_correct = True
            version_false_positive = False
            version_false_negative = False
            for function_name, results in data['functions'].items():
                found = False
                for result in results:
                    if result['version'] == version:
                        found = True
                        expected_vulnerable = result['expected_vulnerable']
                        expected_patched = result['expected_patched']
                        is_vulnerable = result['is_vulnerable']
                        is_patched = result['is_patched']
                        # 判断是否正确
                        if not ((expected_vulnerable and is_vulnerable) or (expected_patched and is_patched)):
                            all_correct = False
                        # 判断假阳性
                        if expected_vulnerable and is_patched:
                            version_false_positive = True
                        # 判断假阴性
                        if expected_patched and is_vulnerable:
                            version_false_negative = True
                        break
                if not found:
                    all_correct = False
            if all_correct:
                succeed_versions += 1
            else:
                # 只在不是假阳性也不是假阴性的情况下，才加入 failed_versions
                if not version_false_positive and not version_false_negative:
                    failed_versions.append(version)
            if version_false_positive:
                false_positive.append(version)
            if version_false_negative:
                false_negative.append(version)

        accuracy = (succeed_versions / total_versions * 100) if total_versions > 0 else 0

        csv_data.append({
            'cve': cve,
            'succeed': succeed_versions,
            'target': total_versions,
            'accuracy': f"{accuracy:.2f}%",
            'failed_versions': ';'.join(failed_versions) if failed_versions else '',
            'false_positive': ';'.join(false_positive) if false_positive else '',
            'false_negative': ';'.join(false_negative) if false_negative else ''
        })
    
    return csv_data

def write_csv(csv_data, output_file):
    """写入CSV文件"""
    
    fieldnames = ['cve', 'succeed', 'target', 'accuracy', 'failed_versions', 'false_positive', 'false_negative']
    
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
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "-proj", "--project",
        required=True,
        type=str,
    )
    args = parser.parse_args()
    project  = args.project

    log_file = f"{project}-test.log"
    output_file = f"{project}-cve.csv"
    
    print(f"正在解析日志文件: {log_file}")
    cve_results = parse_log_file(log_file)
    
    print(f"正在分析CVE结果...")
    csv_data = analyze_cve_results(cve_results)
    
    print(f"正在写入CSV文件: {output_file}")
    write_csv(csv_data, output_file)
    
    print(f"完成！共处理了 {len(csv_data)} 个CVE")
    
    # 计算整体统计信息
    stats = calculate_overall_statistics(csv_data)
    
    print(f"\n=== 整体统计信息 ===")
    print(f"总检测数量: {stats['total_detections']}")
    print(f"成功检测数量: {stats['total_successful']}")
    print(f"整体准确率: {stats['overall_accuracy']:.2f}%")
    print(f"排除failed的准确率: {stats['filtered']:.2f}%")

if __name__ == "__main__":
    main() 