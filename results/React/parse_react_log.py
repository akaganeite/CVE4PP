#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import csv
import sys
import json
from collections import defaultdict
import os

def load_correction_data(project_name):
    """
    加载correction.json文件
    
    Args:
        project_name: 项目名称
        
    Returns:
        dict: correction数据，格式为 {version: {cve: {result: "wrong"}}}
    """
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

def apply_corrections(results, correction_data):
    """
    应用correction数据到results中
    
    Args:
        results: 解析的结果数据
        correction_data: correction.json中的数据
    """
    corrections_applied = 0
    
    for cve, stats in results.items():
        # 检查false_negative中的版本
        corrected_versions = []
        for version in stats['false_negative']:
            # 检查correction_data中是否有对应的版本和CVE
            if version in correction_data:
                version_data = correction_data[version]
                
                # 处理版本数据可能是数组的情况
                if isinstance(version_data, list):
                    # 如果是数组，检查数组中的每个对象
                    for item in version_data:
                        if isinstance(item, dict) and cve in item:
                            if item[cve].get("result") == "wrong":
                                corrected_versions.append(version)
                                stats['targets'] -= 1
                                corrections_applied += 1
                                print(f"应用修正: CVE={cve}, 版本={version}")
                                break
                elif isinstance(version_data, dict) and cve in version_data:
                    # 检查result是否为"wrong"
                    if version_data[cve].get("result") == "wrong":
                        corrected_versions.append(version)
                        stats['targets'] -= 1
                        corrections_applied += 1
                        print(f"应用修正: CVE={cve}, 版本={version}")
        
        # 移除已修正的版本
        for version in corrected_versions:
            stats['false_negative'].remove(version)
    
    print(f"总共应用了 {corrections_applied} 个修正")

def parse_react_log(input_file, output_file, project_name):
    """
    解析React检测结果文件
    
    Args:
        input_file: 输入文件名
        output_file: 输出CSV文件名
        project_name: 项目名称
    """
    
    # 存储结果的字典，格式: {cve: {results}}
    def new_result():
        return {
            'succeed': 0,
            'failed': 0,
            'false_positive': [],
            'false_negative': [],
            'func_not_found': [],
            'targets': 0
        }
    results = defaultdict(new_result)
    
    current_cve = None
    current_version = None
    current_ground_truth = None
    current_test_result = None
    next_line_is_fail = False
    func_not_found_next = False
    
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # 检查是否是"function not found fail to determine"
        if line == "function not found fail to determine":
            func_not_found_next = True
            continue
        
        # 检查是否是"fail to determine"
        if line == "fail to determine":
            next_line_is_fail = True
            continue
        
        # 解析CVE行，格式: [CVE-2017-13710 binutils-2.29-o0-objdump vuln]  tested: vuln
        if line.startswith('[') and 'CVE-' in line and ']' in line:
            # 提取CVE ID
            cve_match = re.search(r'CVE-\d{4}-\d+', line)
            if cve_match:
                current_cve = cve_match.group(0)
            
            # 提取版本信息
            s = line.split(" ")[1]
            first_dash = s.find('-')            
            last_dash = s.rfind('-', 0, s.rfind('-'))
            current_version = s[first_dash + 1:last_dash]
            
            # 如果上一行为function not found fail to determine
            if func_not_found_next:
                key = current_cve
                results[key]['func_not_found'].append(current_version)
                results[key]['targets'] += 1
                func_not_found_next = False
                # 跳过后续判断
                current_version = None
                current_ground_truth = None
                current_test_result = None
                continue
            
            # 提取ground truth (vuln/patch)
            if 'vuln]' in line:
                current_ground_truth = 'vuln'
            elif 'patch]' in line:
                current_ground_truth = 'patch'
            
            # 提取测试结果
            if 'tested: vuln' in line:
                current_test_result = 'vuln'
            elif 'tested: patch' in line:
                current_test_result = 'patch'
            
            # 如果所有信息都完整，记录结果
            if current_cve and current_version and current_ground_truth and current_test_result:
                key = current_cve
                results[key]['targets'] += 1
                
                # 检查是否是fail to determine的情况
                if next_line_is_fail:
                    # 标记为failed，不计入false_positive或false_negative
                    results[key]['failed'] += 1
                    next_line_is_fail = False
                else:
                    # 判断是否正确
                    is_correct = (current_ground_truth == current_test_result)
                    
                    if is_correct:
                        results[key]['succeed'] += 1
                    else:
                        results[key]['failed'] += 1
                        if current_ground_truth == 'vuln' and current_test_result == 'patch':
                            results[key]['false_positive'].append(current_version)
                        elif current_ground_truth == 'patch' and current_test_result == 'vuln':
                            results[key]['false_negative'].append(current_version)
                
                # 重置当前变量
                current_version = None
                current_ground_truth = None
                current_test_result = None
    
    # 加载并应用correction数据
    correction_data = load_correction_data(project_name)
    if correction_data:
        apply_corrections(results, correction_data)
    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE', 'succeed', 'failed', 'false_positive', 'false_negative', 'func_not_found', 'targets']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for cve, stats in results.items():
            writer.writerow({
                'CVE': cve,
                'succeed': stats['succeed'],
                'failed': stats['failed'],
                'false_positive': ';'.join(stats['false_positive']) if stats['false_positive'] else '',
                'false_negative': ';'.join(stats['false_negative']) if stats['false_negative'] else '',
                'func_not_found': ';'.join(stats['func_not_found']) if stats['func_not_found'] else '',
                'targets': stats['targets']
            })
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE")

def calc_accuracy(csv_path):
    total_succeed = 0
    total_targets = 0
    total_failed = 0
    total_false_positive = 0
    total_false_negative = 0
    total_func_not_found = 0

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            succeed = int(row['succeed']) if row['succeed'] else 0
            failed = int(row['failed']) if row['failed'] else 0
            targets = int(row['targets']) if row['targets'] else 0
            
            false_positive = 0
            if row['false_positive']:
                false_positive = len(row['false_positive'].split(';')) if row['false_positive'] else 0
            
            false_negative = 0
            if row['false_negative']:
                false_negative = len(row['false_negative'].split(';')) if row['false_negative'] else 0
            
            func_not_found = 0
            if row['func_not_found']:
                func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0

            total_succeed += succeed
            total_failed += failed
            total_targets += targets
            total_false_positive += false_positive
            total_false_negative += false_negative
            total_func_not_found += func_not_found
    
    # 计算准确率
    acc1 = total_succeed / total_targets if total_targets else 0
    acc2 = total_succeed / (total_targets - total_func_not_found) if (total_targets - total_func_not_found) else 0

    # 只考虑false positive和false negative的准确率
    total_valid_targets = total_succeed + total_false_positive + total_false_negative
    acc3 = total_succeed / total_valid_targets if total_valid_targets else 0
    
    return acc1, acc2,acc3, total_succeed, total_targets, total_failed, total_valid_targets, total_func_not_found

def main():
    parser = argparse.ArgumentParser(description='解析React检测结果')
    parser.add_argument(
        "-proj", "--project",
        required=True,
        type=str,
        help="项目名称"
    )
    
    args = parser.parse_args()
    
    # 检查输出文件扩展名

    
    input_file = f"{args.project}-log.txt"
    output_file = f"{args.project}_result.csv"
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            pass
    except FileNotFoundError:
        print(f"错误：输入文件 {input_file} 不存在")
        sys.exit(1)
    
    # 解析结果
    parse_react_log(input_file,output_file, args.project)

if __name__ == "__main__":
    main()
    # 批量计算准确率
    for fname in os.listdir('.'):
        if fname.endswith('_result.csv'):
            acc1, acc2, acc3,succeed, targets, failed, valid_targets,func_not_found = calc_accuracy(fname)
            print(f'{fname}:')
            print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
            print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
            print(f'  succeed/valid_targets = {succeed}/{valid_targets} = {acc3:.4f} (只考虑FP/FN)')
            print()