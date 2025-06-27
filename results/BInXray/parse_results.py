#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import csv
import sys
from collections import defaultdict
import os

def parse_binxray_results(input_file, output_file):
    """
    解析BinXray检测结果文件
    
    Args:
        input_file: 输入文件名
        output_file: 输出CSV文件名
        project_name: 项目名称（如curl, binutils等）
    """
    
    # 存储结果的字典，格式: {(cve, funcname): {results}}
    def new_result():
        return {
            'succeed': 0,
            'false_positive': [],
            'false_negative': [],
            'failed_versions': [],
            'too_much_diff': [],
            'cant_tell': [],
            'no_diff': [],
            'func_not_found': [],
            'targets': 0
        }
    results = defaultdict(new_result)
    
    current_cve = None
    current_func = None
    current_version = None
    current_ground_truth = None
    
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 找到检测开始的位置
    start_idx = 0
    for i, line in enumerate(lines):
        if "Detect o0 Binaries." in line:
            start_idx = i
            break
    
    # 从检测开始位置解析
    for idx, line in enumerate(lines[start_idx:]):
        line = line.strip()
        
        # 解析CVE行
        if line.startswith("[*] Detecting CVE:"):
            current_cve = line.split("CVE:")[1].strip()
            continue
        
        # 解析Detection for行
        if line.startswith("[*] Detection for"):
            # 格式: [*] Detection for /binaries/target/curl/curl-7.51.0-o0-curl,allocate_conn,-1
            parts = line.split(',')
            if len(parts) >= 3:
                # 提取版本号 - 使用动态项目名称
                version_pattern = rf'-([^-]+)-o0-'
                version_match = re.search(version_pattern, parts[0])
                if version_match:
                    current_version = version_match.group(1)
                
                # 提取函数名
                current_func = parts[1]
                
                # 提取真值
                current_ground_truth = int(parts[2])
                continue
        
        # 检查是否是函数未找到的情况（在Detection for行之后立即出现）
        if line.startswith("target function:") and "not found" in line:
            key = (current_cve, current_func)
            results[key]['targets'] += 1
            results[key]['func_not_found'].append(current_version)
            continue
        
        # 解析Detection Result行
        if line.startswith("[*] Detection Result:"):
            result_parts = line.split("Detection Result:")[1].strip()
            key = (current_cve, current_func)
            # 检查是否是明确的V或P结果
            if result_parts.startswith("V") or result_parts.startswith("P"):
                detection_result = result_parts[0]  # V 或 P
                is_correct = False
                if current_ground_truth == -1 and detection_result == "V":
                    is_correct = True
                elif current_ground_truth == 1 and detection_result == "P":
                    is_correct = True
                results[key]['targets'] += 1
                if is_correct:
                    results[key]['succeed'] += 1
                else:
                    if current_ground_truth == -1 and detection_result == "P":
                        results[key]['false_positive'].append(current_version)
                    elif current_ground_truth == 1 and detection_result == "V":
                        results[key]['false_negative'].append(current_version)
            else:
                # 处理不明确的结果
                if "NA too much diff" in line:
                    results[key]['too_much_diff'].append(current_version)
                elif "C can't tell" in line:
                    results[key]['cant_tell'].append(current_version)
                elif "N VP no diff" in line:
                    results[key]['no_diff'].append(current_version)
                else:
                    results[key]['failed_versions'].append(current_version)
                results[key]['targets'] += 1
    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE', 'funcname', 'succeed', 'false_positive', 'false_negative', 'failed_versions', 'too_much_diff', 'cant_tell', 'no_diff', 'func_not_found', 'targets']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for (cve, funcname), stats in results.items():
            writer.writerow({
                'CVE': cve,
                'funcname': funcname,
                'succeed': stats['succeed'],
                'false_positive': ';'.join(stats['false_positive']) if stats['false_positive'] else '',
                'false_negative': ';'.join(stats['false_negative']) if stats['false_negative'] else '',
                'failed_versions': ';'.join(stats['failed_versions']) if stats['failed_versions'] else '',
                'too_much_diff': ';'.join(stats['too_much_diff']) if stats['too_much_diff'] else '',
                'cant_tell': ';'.join(stats['cant_tell']) if stats['cant_tell'] else '',
                'no_diff': ';'.join(stats['no_diff']) if stats['no_diff'] else '',
                'func_not_found': ';'.join(stats['func_not_found']) if stats['func_not_found'] else '',
                'targets': stats['targets']
            })
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE-函数组合")

def calc_accuracy(csv_path):
    total_succeed = 0
    total_targets = 0
    total_func_not_found = 0
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            succeed = int(row['succeed']) if row['succeed'] else 0
            targets = int(row['targets']) if row['targets'] else 0
            func_not_found = 0
            if row['func_not_found']:
                # 可能是分号分隔的多个版本
                func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0
            total_succeed += succeed
            total_targets += targets
            total_func_not_found += func_not_found
    acc1 = total_succeed / total_targets if total_targets else 0
    acc2 = total_succeed / (total_targets - total_func_not_found) if (total_targets - total_func_not_found) else 0
    return acc1, acc2, total_succeed, total_targets, total_func_not_found

def main():
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument('input_file', help='输入文件名')
    parser.add_argument('output_file', help='输出文件名（必须以.csv结尾）')
    
    args = parser.parse_args()
    
    # 检查输出文件扩展名
    if not args.output_file.endswith('.csv'):
        print("错误：输出文件名必须以.csv结尾")
        sys.exit(1)
    
    # 检查输入文件是否存在
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            pass
    except FileNotFoundError:
        print(f"错误：输入文件 {args.input_file} 不存在")
        sys.exit(1)
    
    # 解析结果
    parse_binxray_results(args.input_file, args.output_file)

if __name__ == "__main__":
            
    # main() 
    # 批量计算准确率
    for fname in os.listdir('.'):
        if fname.endswith('_result.csv'):
            acc1, acc2, succeed, targets, func_not_found = calc_accuracy(fname)
            print(f'{fname}:')
            print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
            print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
            print()