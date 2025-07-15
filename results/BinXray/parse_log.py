#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import csv
import argparse
import json
from collections import defaultdict
import os

def load_correction_data(project_name):
    """加载correction.json文件"""
    correction_file = f"../../testset/{project_name}/correction.json"
    try:
        with open(correction_file, 'r', encoding='utf-8') as f:
            correction_data = json.load(f)
        print(f"成功加载correction数据: {correction_file}")
        return correction_data
    except FileNotFoundError:
        print(f"警告：correction文件不存在: {correction_file}")
        return {}
    except json.JSONDecodeError as e:
        print(f"错误：correction文件格式错误: {e}")
        return {}

def parse_log_file(log_file_path):
    """解析BinXray日志文件，按CVE+version+func统计检测结果"""
    cve_results = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    current_cve = None
    current_func = None
    current_version = None
    current_ground_truth = None
    with open(log_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith('[*] Detecting CVE:'):
            current_cve = line.split('CVE:')[1].strip()
            continue
        if line.startswith('[*] Detection for') and current_cve:
            parts = line.split(',')
            if len(parts) >= 3:
                s = parts[0]
                first_dash = s.find('-')
                last_dash = s.rfind('-', 0, s.rfind('-'))
                current_version = s[first_dash + 1:last_dash]
                current_func = parts[1]
                current_ground_truth = int(parts[2])
            continue
        if line.startswith('[*] Detection Result:') and current_cve and current_version and current_func is not None:
            result_str = line.split('Detection Result:')[1].strip()
            is_vulnerable = result_str.startswith('V')
            is_patched = result_str.startswith('P')
            expected_vulnerable = current_ground_truth == -1
            expected_patched = current_ground_truth == 1
            cve_results[current_cve][current_version][current_func] = {
                'is_vulnerable': is_vulnerable,
                'is_patched': is_patched,
                'expected_vulnerable': expected_vulnerable,
                'expected_patched': expected_patched,
                'result': result_str
            }
            continue
        if line.startswith('target function:') and 'not found' in line and current_cve and current_version and current_func is not None:
            cve_results[current_cve][current_version][current_func] = {
                'not_found': True
            }
            continue
        if line.startswith('[*] Detection Result: fail to decide') and current_cve and current_version and current_func is not None:
            cve_results[current_cve][current_version][current_func] = {
                'fail_to_decide': True
            }
            continue
    return cve_results

def apply_corrections(cve_results, correction_data):
    """应用correction.json修正假阴性等"""
    corrections_applied = 0
    for cve in cve_results:
        for version in cve_results[cve]:
            for func, fdata in cve_results[cve][version].items():
                if fdata.get('expected_patched') and fdata.get('is_vulnerable'):
                    if version in correction_data:
                        version_data = correction_data[version]
                        if isinstance(version_data, list):
                            for item in version_data:
                                if isinstance(item, dict) and cve in item:
                                    if item[cve].get('result') == 'wrong':
                                        fdata['correction'] = True
                                        corrections_applied += 1
                                        break
                        elif isinstance(version_data, dict) and cve in version_data:
                            if version_data[cve].get('result') == 'wrong':
                                fdata['correction'] = True
                                corrections_applied += 1
    print(f"总共应用了 {corrections_applied} 个修正")

def analyze_cve_results(cve_results):
    """分析CVE结果并生成CSV数据（以CVE为单位统计）"""
    csv_data = []
    for cve, version_dict in cve_results.items():
        # 收集所有出现过的version
        version_set = set(version_dict.keys())
        total_versions = len(version_set)
        succeed_versions = 0
        failed_versions = []
        false_positive = []
        false_negative = []
        for version in version_set:
            all_correct = True
            version_false_positive = False
            version_false_negative = False
            for func, fdata in version_dict[version].items():
                if fdata.get('correction'):
                    continue
                if fdata.get('not_found') or fdata.get('fail_to_decide'):
                    all_correct = False
                    continue
                expected_vulnerable = fdata.get('expected_vulnerable')
                expected_patched = fdata.get('expected_patched')
                is_vulnerable = fdata.get('is_vulnerable')
                is_patched = fdata.get('is_patched')
                if not ((expected_vulnerable and is_vulnerable) or (expected_patched and is_patched)):
                    all_correct = False
                if expected_vulnerable and is_patched:
                    version_false_positive = True
                if expected_patched and is_vulnerable:
                    version_false_negative = True
            if all_correct:
                succeed_versions += 1
            else:
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
    overall_accuracy = (total_successful / total_detections * 100) if total_detections > 0 else 0
    failed = sum(len(row['failed_versions'].split(';')) for row in csv_data if row['failed_versions'])
    filtered = (total_successful / (total_detections - failed)) * 100 if (total_detections - failed) > 0 else 0
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
    project = args.project
    log_file = f"{project}-test.log"
    output_file = f"{project}-cve.csv"
    print(f"正在解析日志文件: {log_file}")
    cve_results = parse_log_file(log_file)
    print(f"正在加载correction.json...")
    correction_data = load_correction_data(project)
    if correction_data:
        apply_corrections(cve_results, correction_data)
    print(f"正在分析CVE结果...")
    csv_data = analyze_cve_results(cve_results)
    print(f"正在写入CSV文件: {output_file}")
    write_csv(csv_data, output_file)
    print(f"完成！共处理了 {len(csv_data)} 个CVE")
    stats = calculate_overall_statistics(csv_data)
    print(f"\n=== 整体统计信息 ===")
    print(f"总检测数量: {stats['total_detections']}")
    print(f"成功检测数量: {stats['total_successful']}")
    print(f"整体准确率: {stats['overall_accuracy']:.2f}%")
    print(f"排除failed的准确率: {stats['filtered']:.2f}%")

if __name__ == "__main__":
    main() 