#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import csv
import sys
from collections import defaultdict
import os
import json

def get_cve_functions_from_valid(project_name, cve_id):
    """
    从valid文件中获取指定CVE对应的函数列表
    
    Args:
        project_name: 项目名称
        cve_id: CVE编号
        
    Returns:
        list: 函数名列表
    """
    valid_file = f"../../testset/{project_name}/valid"
    functions = []
    
    try:
        with open(valid_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 5 and parts[0] == cve_id:
                    # 格式: CVE-ID 日期 commit-hash 二进制文件名 函数名列表
                    func_part = parts[4]  # 函数名部分
                    # 函数名可能用逗号分隔
                    func_list = func_part.split(',')
                    functions.extend(func_list)
        return functions
    except FileNotFoundError:
        print(f"警告：valid文件 {valid_file} 不存在")
        return []

PROJ =""

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

def apply_corrections(results, correction_data, is_cve_level=False):
    """
    应用correction数据到results中
    
    Args:
        results: 解析的结果数据
        correction_data: correction.json中的数据
        is_cve_level: 是否为CVE级别的结果（True为CVE级别，False为函数级别）
    """
    corrections_applied = 0
    
    if is_cve_level:
        # CVE级别的修正
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
    else:
        # 函数级别的修正（原有逻辑）
        for (cve, funcname), stats in results.items():
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
                                    print(f"应用修正: CVE={cve}, 版本={version}, 函数={funcname}")
                                    break
                    elif isinstance(version_data, dict) and cve in version_data:
                        # 检查result是否为"wrong"
                        if version_data[cve].get("result") == "wrong":
                            corrected_versions.append(version)
                            stats['targets'] -= 1
                            corrections_applied += 1
                            print(f"应用修正: CVE={cve}, 版本={version}, 函数={funcname}")
            
            # 移除已修正的版本
            for version in corrected_versions:
                stats['false_negative'].remove(version)
    
    print(f"总共应用了 {corrections_applied} 个修正")

def parse_binxray_results(input_file, output_file,project_name):
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
            'targets': 0,
            'no_sig': ''
        }
    results = defaultdict(new_result)
    
    current_cve = None
    current_func = None
    current_version = None
    current_ground_truth = None
    
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 从检测开始位置解析
    for idx, line in enumerate(lines):
        line = line.strip()
        
        # 跳过分隔线
        if line.startswith("---"):
            continue
            
        # 解析CVE行
        if line.startswith("Detecing CVE:"):
            current_cve = line.split("CVE:")[1].strip()
            continue
        
        # 处理"has no sigs, skip"的情况
        if "has no sigs, skip" in line:
            # 从行中提取CVE编号
            # 格式: CVE-2013-1944 has no sigs, skip
            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
            if cve_match:
                cve_id = cve_match.group(1)
                # 从valid文件中获取该CVE对应的函数
                functions = get_cve_functions_from_valid(project_name, cve_id)
                
                if functions:
                    # 为每个函数创建记录
                    for func in functions:
                        key = (cve_id, func)
                        results[key]['targets'] += 1
                        results[key]['no_sig'] = 'true'   # 标记
                        # 其他数据列保持为0
                        # print(f"处理has no sigs, skip: CVE={cve_id}, func={func}")
                else:
                    print(f"警告：在valid文件中未找到CVE {cve_id} 对应的函数")
            continue
        
        # 解析Detection for行
        if line.startswith("Detection for"):
            # 格式:Detection for: /home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/binutils/binutils-2.28-o0-readelf
            parts = line.split('/')
            s = parts[-1]
            first_dash = s.find('-')            
            last_dash = s.rfind('-', 0, s.rfind('-'))
            current_version = s[first_dash + 1:last_dash]
            continue
        
        # 检查是否是函数未找到的情况
        if line.startswith("no function"):
            # 格式: no function dict_keys(['print_gnu_build_attribute_name']) in target

            current_func = line.split("'")[1]
            print(f"func not found:{current_func}")
            key = (current_cve, current_func)
            results[key]['targets'] += 1
            results[key]['func_not_found'].append(current_version)
            continue
        
        # 解析Detection Result行
        if line.startswith("Result for"):
            # 格式: Result for print_gnu_build_attribute_name:vuln , truth is patch
            result_parts = line.split("Result for")[1].strip()
            func_result_part = result_parts.split(" , truth is")[0]
            current_func = func_result_part.split(":")[0]
            test_result = func_result_part.split(":")[1]
            current_ground_truth = result_parts.split("truth is ")[1]
            
            key = (current_cve, current_func)
            results[key]['targets'] += 1
            
            # 判断是否成功
            if test_result == current_ground_truth:
                results[key]['succeed'] += 1
            else:
                # 处理None结果
                if test_result == "None":
                    results[key]['failed_versions'].append(current_version)
                elif current_ground_truth == "patch" and test_result == "vuln":
                    results[key]['false_negative'].append(current_version)
                elif current_ground_truth == "vuln" and test_result == "patch":
                    results[key]['false_positive'].append(current_version)
                else:
                    # 处理其他情况
                    results[key]['failed_versions'].append(current_version)

    # 加载并应用correction数据
    correction_data = load_correction_data(project_name)
    if correction_data:
        apply_corrections(results, correction_data, is_cve_level=True)

    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE', 'funcname', 'succeed', 'false_positive', 'false_negative', 'failed_versions', 'func_not_found', 'targets', 'no_sig']  # 新增no_sig
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
                'func_not_found': ';'.join(stats['func_not_found']) if stats['func_not_found'] else '',
                'targets': stats['targets'],
                'no_sig': stats.get('no_sig', '')
            })
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE-函数组合")

def calc_accuracy(csv_path):
    total_succeed = 0
    total_targets = 0
    total_func_not_found = 0
    total_failed_versions = 0
    total_false_positive = 0
    total_false_negative = 0
    
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            succeed = int(row['succeed']) if row['succeed'] else 0
            targets = int(row['targets']) if row['targets'] else 0
            
            # 计算各种失败情况的数量
            func_not_found = 0
            if row['func_not_found']:
                func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0
            
            failed_versions = 0
            if row['failed_versions']:
                failed_versions = len(row['failed_versions'].split(';')) if row['failed_versions'] else 0
            
            false_positive = 0
            if row['false_positive']:
                false_positive = len(row['false_positive'].split(';')) if row['false_positive'] else 0
            
            false_negative = 0
            if row['false_negative']:
                false_negative = len(row['false_negative'].split(';')) if row['false_negative'] else 0
            
            total_succeed += succeed
            total_targets += targets
            total_func_not_found += func_not_found
            total_failed_versions += failed_versions
            total_false_positive += false_positive
            total_false_negative += false_negative
    
    # 计算各种准确率
    acc1 = total_succeed / total_targets if total_targets else 0
    acc2 = total_succeed / (total_targets - total_func_not_found) if (total_targets - total_func_not_found) else 0
    
    # 只考虑false positive和false negative的准确率
    # 总的有效目标数 = succeed + false_positive + false_negative
    total_valid_targets = total_succeed + total_false_positive + total_false_negative
    acc3 = total_succeed / total_valid_targets if total_valid_targets else 0
    
    return acc1, acc2, acc3, total_succeed, total_targets, total_func_not_found, total_valid_targets

def parse_cve_results(project_name):
    """
    解析CVE检测结果文件
    
    Args:
        project_name: 项目名称
    """
    input_file = f"{project_name}-cve.log"
    output_file = f"{project_name}-cve.csv"
    
    # 存储结果的字典，格式: {cve: {results}}
    def new_result():
        return {
            'succeed': 0,
            'false_positive': [],
            'false_negative': [],
            'failed_versions': [],
            'targets': 0,
            'no_sig': ''
        }
    results = defaultdict(new_result)
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"错误：输入文件 {input_file} 不存在")
        return
    
    for line in lines:
        line = line.strip()
        # print(line)
        if not line:
            continue
            
        # 处理TestJson开头的失败行
        if line.startswith("TestJson"):
            # 从TestJson行中提取CVE信息
            # 格式: TestJson(file='binutils-2.29-o0-objdump', cve='CVE-2017-14729', ...) is not valid
            cve_match = re.search(r"cve='([^']*)'", line)
            version_match = re.search(r"file='([^']*)'", line)
            if cve_match:
                cve = cve_match.group(1)
                bin = version_match.group(1)
                first_dash = bin.find('-')            
                last_dash = bin.rfind('-', 0, bin.rfind('-'))
                current_version = bin[first_dash + 1:last_dash]
                results[cve]['failed_versions'].append(current_version)
                results[cve]['targets'] += 1
                print(f"处理失败行: CVE={cve}")
            continue
        
        # 处理普通的CVE结果行
        # 格式: CVE-2017-14529 binutils-2.31-o0-objdump truth = patch result = vuln
        parts = line.split()
        if len(parts) >= 7 and parts[0].startswith("CVE-"):
            cve = parts[0]
            # 提取版本信息
            binary_name = parts[1]
            # 从binary_name中提取版本，格式: binutils-2.31-o0-objdump
            first_dash = binary_name.find('-')            
            last_dash = binary_name.rfind('-', 0, binary_name.rfind('-'))
            current_version = binary_name[first_dash + 1:last_dash]
            
            truth = parts[4]  # truth值
            result = parts[7]  # result值
            
            results[cve]['targets'] += 1
            
            # 判断是否成功
            if truth == result:
                results[cve]['succeed'] += 1
                print(f"处理成功行: CVE={cve}, 版本={current_version}, truth={truth}, result={result}")
            else:
                # 根据truth和result判断是false positive还是false negative
                if truth == "patch" and result == "vuln":
                    results[cve]['false_negative'].append(current_version)
                    print(f"处理false negative: CVE={cve}, 版本={current_version}, truth={truth}, result={result}")
                elif truth == "vuln" and result == "patch":
                    results[cve]['false_positive'].append(current_version)
                    print(f"处理false positive: CVE={cve}, 版本={current_version}, truth={truth}, result={result}")
                else:
                    # 处理其他情况，如None结果
                    results[cve]['failed_versions'].append(current_version)
                    print(f"处理失败行: CVE={cve}, 版本={current_version}, truth={truth}, result={result}")
        
        # 处理has no sigs, skip
        if "has no sigs, skip" in line:
            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
            if cve_match:
                cve = cve_match.group(1)
                results[cve]['targets'] += 1
                results[cve]['no_sig'] = 'true'
                print(f"parse_cve_results: 处理has no sigs, skip: CVE={cve}")
            continue
    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['cve', 'succeed', 'false_positive', 'false_negative', 'failed_versions', 'targets', 'no_sig']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for cve, stats in results.items():
            writer.writerow({
                'cve': cve,
                'succeed': stats['succeed'],
                'false_positive': ';'.join(stats['false_positive']) if stats['false_positive'] else '',
                'false_negative': ';'.join(stats['false_negative']) if stats['false_negative'] else '',
                'failed_versions': ';'.join(stats['failed_versions']) if stats['failed_versions'] else '',
                'targets': stats['targets'],
                'no_sig': stats.get('no_sig', '')
            })
    
    # 加载并应用correction数据
    correction_data = load_correction_data(project_name)
    if correction_data:
        apply_corrections(results, correction_data,is_cve_level=True)
    
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE")
    
    # 计算总体统计
    total_succeed = sum(stats['succeed'] for stats in results.values())
    total_false_positive = sum(len(stats['false_positive']) for stats in results.values())
    total_false_negative = sum(len(stats['false_negative']) for stats in results.values())
    total_failed_versions = sum(len(stats['failed_versions']) for stats in results.values())
    total_targets = sum(stats['targets'] for stats in results.values())
    valid_targets = total_succeed + total_false_positive + total_false_negative
    
    if total_targets > 0:
        accuracy = total_succeed / total_targets
        filtered_acc = total_succeed / valid_targets
        print(f"总体准确率: {total_succeed}/{total_targets} = {accuracy:.4f}")
        print(f"False Positive: {total_false_positive}, False Negative: {total_false_negative}, Failed Versions: {total_failed_versions}")
        print(f"filtered_acc:{total_succeed}/{total_succeed} + {total_false_positive} + {total_false_negative} = {filtered_acc:.4f}")

def main():
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "-proj", "--project",
        required=True,
        type=str,
    )
    parser.add_argument(
        "--mode",
        choices=["func", "cve"],
        default="func",
        help="解析模式：func为函数级别，cve为CVE级别"
    )
    
    args = parser.parse_args()
    PROJ = args.project
    
    if args.mode == "cve":
        # CVE级别解析
        parse_cve_results(args.project)
    else:
        # 函数级别解析
        output_file = f"{args.project}_result.csv"
        input_file = f"{args.project}-func.log"
        if not output_file.endswith('.csv'):
            print("错误：输出文件名必须以.csv结尾")
            sys.exit(1)
        
        # 检查输入文件是否存在
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                pass
        except FileNotFoundError:
            print(f"错误：输入文件 {input_file} 不存在")
            sys.exit(1)
        
        # 解析结果
        parse_binxray_results(input_file, output_file, args.project)

if __name__ == "__main__":
            
    main() 
    # 批量计算准确率
    for fname in os.listdir('.'):
        if fname.endswith('_result.csv'):
            acc1, acc2, acc3, succeed, targets, func_not_found, valid_targets = calc_accuracy(fname)
            print(f'{fname}:')
            print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
            print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
            print(f'  succeed/valid_targets = {succeed}/{valid_targets} = {acc3:.4f} (只考虑FP/FN)')
            print()