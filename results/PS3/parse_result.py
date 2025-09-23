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
                                    stats['fp'] -= 1 # 修正FP计数
                                    corrections_applied += 1
                                    print(f"应用修正: CVE={cve}, 版本={version}")
                                    break
                    elif isinstance(version_data, dict) and cve in version_data:
                        # 检查result是否为"wrong"
                        if version_data[cve].get("result") == "wrong":
                            corrected_versions.append(version)
                            stats['targets'] -= 1
                            stats['fp'] -= 1 # 修正FP计数
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
                                    stats['fp'] -= 1 # 修正FP计数
                                    corrections_applied += 1
                                    print(f"应用修正: CVE={cve}, 版本={version}, 函数={funcname}")
                                    break
                    elif isinstance(version_data, dict) and cve in version_data:
                        # 检查result是否为"wrong"
                        if version_data[cve].get("result") == "wrong":
                            corrected_versions.append(version)
                            stats['targets'] -= 1
                            stats['fp'] -= 1 # 修正FP计数
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
            'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
            'false_positive': [],
            'false_negative': [],
            'failed_versions': [],
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
                if current_ground_truth == "vuln":
                    results[key]['tp'] += 1
                else: # patch
                    results[key]['tn'] += 1
            else:
                # 处理None结果
                if test_result == "None":
                    results[key]['failed_versions'].append(current_version)
                elif current_ground_truth == "patch" and test_result == "vuln":
                    results[key]['fp'] += 1
                    results[key]['false_negative'].append(current_version) # 脚本原有的FN，即标准FP
                elif current_ground_truth == "vuln" and test_result == "patch":
                    results[key]['fn'] += 1
                    results[key]['false_positive'].append(current_version) # 脚本原有的FP，即标准FN
                else:
                    # 处理其他情况
                    results[key]['failed_versions'].append(current_version)

    # 加载并应用correction数据
    correction_data = load_correction_data(project_name)
    if correction_data:
        apply_corrections(results, correction_data, is_cve_level=False)

    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE', 'funcname', 'succeed', 'tp', 'tn', 'fp', 'fn', 'precision', 'recall', 'f1_score', 'false_positive', 'false_negative', 'failed_versions', 'func_not_found', 'targets', 'no_sig']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for (cve, funcname), stats in results.items():
            tp, tn, fp, fn = stats['tp'], stats['tn'], stats['fp'], stats['fn']
                    
            writer.writerow({
                'CVE': cve,
                'funcname': funcname,
                'succeed': tp + tn,
                'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
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
    total_tp, total_tn, total_fp, total_fn = 0, 0, 0, 0
    
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            targets = int(row['targets']) if row['targets'] else 0
            
            func_not_found = 0
            if row['func_not_found']:
                func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0
            
            total_targets += targets
            total_func_not_found += func_not_found
            total_tp += int(row['tp'])
            total_tn += int(row['tn'])
            total_fp += int(row['fp'])
            total_fn += int(row['fn'])

    total_succeed = total_tp + total_tn
    
    # 计算各种准确率
    acc1 = total_succeed / total_targets if total_targets else 0
    acc2 = total_succeed / (total_targets - total_func_not_found) if (total_targets - total_func_not_found) else 0
    
    # 只考虑false positive和false negative的准确率
    total_valid_targets = total_tp + total_tn + total_fp + total_fn
    acc3 = total_succeed / total_valid_targets if total_valid_targets else 0
    
    return acc1, acc2, acc3, total_succeed, total_targets, total_func_not_found, total_valid_targets, total_tp, total_tn, total_fp, total_fn


def parse_cve_results(project_name):
    """
    解析CVE检测结果文件
    
    Args:
        project_name: 项目名称
    """
    input_file = f"{CONFIG}/{project_name}-cve.log"
    output_file = f"{CONFIG}/{project_name}-cve.csv"
    
    # 存储结果的字典，格式: {cve: {results}}
    def new_result():
        return {
            'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
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
        if not line:
            continue
            
        # 处理TestJson开头的失败行
        if line.startswith("TestJson"):
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
            continue
        
        # 处理普通的CVE结果行
        parts = line.split()
        if len(parts) >= 7 and parts[0].startswith("CVE-"):
            cve = parts[0]
            binary_name = parts[1]
            first_dash = binary_name.find('-')            
            last_dash = binary_name.rfind('-', 0, binary_name.rfind('-'))
            current_version = binary_name[first_dash + 1:last_dash]
            
            truth = parts[4]
            result = parts[7]
            
            results[cve]['targets'] += 1
            
            if truth == result:
                if truth == "vuln":
                    results[cve]['tp'] += 1
                else: # patch
                    results[cve]['tn'] += 1
            else:
                if truth == "patch" and result == "vuln":
                    results[cve]['fp'] += 1
                    results[cve]['false_negative'].append(current_version)
                elif truth == "vuln" and result == "patch":
                    results[cve]['fn'] += 1
                    results[cve]['false_positive'].append(current_version)
                else:
                    results[cve]['failed_versions'].append(current_version)
        
        # 处理has no sigs, skip
        if "has no sigs, skip" in line:
            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
            if cve_match:
                cve = cve_match.group(1)
                results[cve]['targets'] += 1
                results[cve]['no_sig'] = 'true'
            continue
    
    # 加载并应用correction数据
    correction_data = load_correction_data(project_name)
    if correction_data:
        apply_corrections(results, correction_data,is_cve_level=True)

    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['cve', 'succeed', 'tp', 'tn', 'fp', 'fn','false_positive', 'false_negative', 'failed_versions', 'targets', 'no_sig']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for cve, stats in results.items():
            tp, tn, fp, fn = stats['tp'], stats['tn'], stats['fp'], stats['fn']
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            writer.writerow({
                'cve': cve,
                'succeed': tp + tn,
                'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                'false_positive': ';'.join(stats['false_positive']) if stats['false_positive'] else '',
                'false_negative': ';'.join(stats['false_negative']) if stats['false_negative'] else '',
                'failed_versions': ';'.join(stats['failed_versions']) if stats['failed_versions'] else '',
                'targets': stats['targets'],
                'no_sig': stats.get('no_sig', '')
            })
    
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE")
    
    # 计算总体统计
    total_tp = sum(stats['tp'] for stats in results.values())
    total_tn = sum(stats['tn'] for stats in results.values())
    total_fp = sum(stats['fp'] for stats in results.values())
    total_fn = sum(stats['fn'] for stats in results.values())
    total_succeed = total_tp + total_tn
    total_targets = sum(stats['targets'] for stats in results.values())
    total_failed = sum(len(stats['failed_versions']) for stats in results.values())
    
    if total_targets > 0:
        accuracy = total_succeed / total_targets
        accuracy_exclude_failed = total_succeed / (total_succeed+total_fp+total_fn)
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"--- {project_name} 总体统计 ---")
        print(f"TP: {total_tp}, TN: {total_tn}, FP: {total_fp}, FN: {total_fn}")
        print(f"总体准确率 (Accuracy): {accuracy:.4f}")
        print(f"Acc: {accuracy_exclude_failed:.4f}")
        print(f"精确率 (Precision): {precision:.4f}")
        print(f"召回率 (Recall): {recall:.4f}")
        print(f"F1分数 (F1-Score): {f1_score:.4f}")

CONFIG = ""

def aggregate_all_projects_accuracy(config_dir, mode):
    """
    聚合指定目录下所有项目的准确率
    """
    print("-" * 50)
    print(f"开始聚合计算目录 '{config_dir}' 下所有项目的 {mode} 级别准确率...")
    
    total_tp_all, total_tn_all, total_fp_all, total_fn_all = 0, 0, 0, 0
    project_count = 0
    
    if not os.path.isdir(config_dir):
        print(f"错误：配置目录 '{config_dir}' 不存在。")
        return

    if mode == 'func':
        total_succeed_all = 0
        total_targets_all = 0
        total_func_not_found_all = 0
        total_valid_targets_all = 0
        file_suffix = '_result.csv'
        
        for fname in os.listdir(config_dir):
            if fname.endswith(file_suffix):
                project_count += 1
                csv_path = os.path.join(config_dir, fname)
                acc1, acc2, acc3, succeed, targets, func_not_found, valid_targets, tp, tn, fp, fn = calc_accuracy(csv_path)
                
                total_succeed_all += succeed
                total_targets_all += targets
                total_func_not_found_all += func_not_found
                total_valid_targets_all += valid_targets
                total_tp_all += tp
                total_tn_all += tn
                total_fp_all += fp
                total_fn_all += fn
                
                print(f'{fname}:')
                print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
                print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
                print(f'  succeed/valid_targets = {succeed}/{valid_targets} = {acc3:.4f} (只考虑TP/TN/FP/FN)')
                print()
    
    elif mode == 'cve':
        file_suffix = '-cve.csv'
        total_failed_all = 0
        total_targets_all = 0
        total_succeed_all = 0
        for fname in os.listdir(config_dir):
            if fname.endswith(file_suffix):
                project_count += 1
                csv_path = os.path.join(config_dir, fname)
                with open(csv_path, newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        total_tp_all += int(row['tp'])
                        total_tn_all += int(row['tn'])
                        total_fp_all += int(row['fp'])
                        total_fn_all += int(row['fn'])
                        total_succeed_all += int(row['succeed'])
                        total_targets_all += int(row['targets'])
                        total_failed_all += len(row['failed_versions'].split(';')) if row['failed_versions'] else 0

        # 计算排除failed的准确率
        acc_exclude_failed = total_succeed_all / (total_targets_all - total_failed_all) if (total_targets_all - total_failed_all) > 0 else 0
        print(f'  succeed/(targets-failed) = {total_succeed_all}/({total_targets_all}-{total_failed_all}) = {acc_exclude_failed:.4f}')
    
    if project_count > 0:
        # 基于聚合数据计算总准确率和F1等指标
        total_classified = total_tp_all + total_tn_all + total_fp_all + total_fn_all
        macro_accuracy = (total_tp_all + total_tn_all) / total_classified if total_classified > 0 else 0
        macro_precision = total_tp_all / (total_tp_all + total_fp_all) if (total_tp_all + total_fp_all) > 0 else 0
        macro_recall = total_tp_all / (total_tp_all + total_fn_all) if (total_tp_all + total_fn_all) > 0 else 0
        macro_f1 = 2 * (macro_precision * macro_recall) / (macro_precision + macro_recall) if (macro_precision + macro_recall) > 0 else 0
        
        print("-" * 50)
        print(f"所有项目的聚合结果 (Macro Average for {mode} mode):")
        print(f"  TP: {total_tp_all}, TN: {total_tn_all}, FP: {total_fp_all}, FN: {total_fn_all}")
        print(f'  整体准确率 (Accuracy): {macro_accuracy:.4f}')
        print(f'  整体精确率 (Precision): {macro_precision:.4f}')
        print(f'  整体召回率 (Recall): {macro_recall:.4f}')
        print(f'  整体F1分数 (F1-Score): {macro_f1:.4f}')
        print("-" * 50)

        if mode == 'func':
            agg_acc1 = total_succeed_all / total_targets_all if total_targets_all > 0 else 0
            agg_acc2 = total_succeed_all / (total_targets_all - total_func_not_found_all) if (total_targets_all - total_func_not_found_all) > 0 else 0
            print("聚合准确率 (按原方式计算):")
            print(f'  succeed/targets = {total_succeed_all}/{total_targets_all} = {agg_acc1:.4f}')
            print(f'  succeed/(targets-func_not_found) = {total_succeed_all}/({total_targets_all}-{total_func_not_found_all}) = {agg_acc2:.4f}')
    else:
        print(f"在目录 '{config_dir}' 中未找到 *{file_suffix} 文件进行聚合计算。")


def main():
    global CONFIG
    global PROJ
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "-p", "--projects",
        nargs="*",
        default=["binutils","curl","freetype","ffmpeg","imagemagick","libxml2","openssl","openjpeg","sqlite","tcpdump"],
        help="要解析结果的项目名称列表。默认为10个标准项目。"
    )
    parser.add_argument(
        "--mode",
        choices=["func", "cve"],
        default="func",
        help="解析模式：func为函数级别，cve为CVE级别"
    )
    parser.add_argument(
        "--compiler",
        default="gcc",
        type=str,
        help="编译器名称 (例如: gcc, clang)"
    )
    parser.add_argument(
        "--opt",
        default="o2",
        type=str,
        help="编译优化级别 (例如: o0, o2, os)"
    )
    
    args = parser.parse_args()
    
    # 根据参数构建CONFIG目录
    CONFIG = f"{args.compiler}-{args.opt}"
    print(f"当前配置目录: {CONFIG}")

    # 确保目录存在
    os.makedirs(CONFIG, exist_ok=True)

    # 遍历所有指定的项目进行解析
    for project in args.projects:
        PROJ = project
        print(f"\n{'='*20} 正在处理项目: {project} {'='*20}")
        
        if args.mode == "cve":
            # CVE级别解析
            print(f"--- 开始解析 {project} 的 CVE 级别结果 ---")
            parse_cve_results(project)
        else:
            # 函数级别解析
            print(f"--- 开始解析 {project} 的函数级别结果 ---")
            output_file = f"{CONFIG}/{project}_result.csv"
            input_file = f"{CONFIG}/{project}-func.log"
            
            # 检查输入文件是否存在
            if not os.path.exists(input_file):
                print(f"警告：输入文件 {input_file} 不存在，跳过项目 {project}")
                continue
            
            # 解析结果
            parse_binxray_results(input_file, output_file, project)
    
    # 在所有项目解析完成后，执行一次聚合计算
    aggregate_all_projects_accuracy(CONFIG, args.mode)


if __name__ == "__main__":
    main()
