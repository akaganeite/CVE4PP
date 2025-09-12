#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import csv
import sys
import json
from collections import defaultdict
import os



def load_correct_cves(log_file="correct-cves.log"):
    """
    从指定的日志文件中加载所有正确的CVE列表。
    """
    if not os.path.exists(log_file):
        print(f"错误: correct-cves.log 文件未找到: {log_file}")
        return set()
    
    with open(log_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 使用正则表达式查找所有 "CVE-..." 格式的字符串
    cve_list = re.findall(r'"(CVE-\d{4}-\d+)"', content)
    print(f"从 {log_file} 中成功加载 {len(cve_list)} 个目标 CVE。")
    return set(cve_list)

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
            'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
            'failed': 0,
            'false_positive': [], # Standard FN (vuln -> patch)
            'false_negative': [], # Standard FP (patch -> vuln)
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
                        if current_ground_truth == 'vuln':
                            results[key]['tp'] += 1
                        else: # patch
                            results[key]['tn'] += 1
                    else:
                        if current_ground_truth == 'vuln' and current_test_result == 'patch':
                            results[key]['fp'] += 1 # FN
                            results[key]['false_positive'].append(current_version)
                        elif current_ground_truth == 'patch' and current_test_result == 'vuln':
                            results[key]['fn'] += 1 # FP
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
        fieldnames = ['cve', 'succeed', 'tp', 'tn', 'fp', 'fn', 'precision', 'recall', 'f1_score', 'failed_versions', 'false_positive', 'false_negative', 'func_not_found', 'target']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for cve, stats in results.items():
            tp, tn, fp, fn = stats['tp'], stats['tn'], stats['fp'], stats['fn']
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            writer.writerow({
                'cve': cve,
                'succeed': stats['tp'] + stats['tn'],
                'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                'precision': f"{precision:.4f}",
                'recall': f"{recall:.4f}",
                'f1_score': f"{f1_score:.4f}",
                'failed_versions': stats['failed'],
                'false_positive': ';'.join(stats['false_positive']) if stats['false_positive'] else '',
                'false_negative': ';'.join(stats['false_negative']) if stats['false_negative'] else '',
                'func_not_found': ';'.join(stats['func_not_found']) if stats['func_not_found'] else '',
                'target': stats['targets']
            })
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE")

def calc_accuracy(csv_path):
    total_succeed = 0
    total_targets = 0
    total_failed = 0
    total_tp, total_tn, total_fp, total_fn = 0, 0, 0, 0
    total_func_not_found = 0

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            targets = int(row['target']) if row['target'] else 0
            failed = int(row['failed_versions']) if row['failed_versions'] else 0
            
            total_tp += int(row['tp'])
            total_tn += int(row['tn'])
            total_fp += int(row['fp'])
            total_fn += int(row['fn'])
            
            func_not_found = 0
            if row['func_not_found']:
                func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0

            total_failed += failed
            total_targets += targets
            total_func_not_found += func_not_found
    
    total_succeed = total_tp + total_tn
    
    # 计算准确率
    acc1 = total_succeed / total_targets if total_targets else 0
    acc2 = total_succeed / (total_targets - total_func_not_found) if (total_targets - total_func_not_found) else 0

    # 只考虑false positive和false negative的准确率
    total_valid_targets = total_tp + total_tn + total_fp + total_fn
    acc3 = total_succeed / total_valid_targets if total_valid_targets else 0
    
    return acc1, acc2, acc3, total_succeed, total_targets, total_failed, total_valid_targets, total_func_not_found, total_tp, total_tn, total_fp, total_fn

CONFIG = ""

def aggregate_all_projects_accuracy(config_dir):
    """
    聚合指定目录下所有项目的准确率
    """
    print("-" * 50)
    print(f"开始聚合计算目录 '{config_dir}' 下所有项目的准确率...")
    
    total_succeed_all = 0
    total_targets_all = 0
    total_failed_all = 0
    total_valid_targets_all = 0
    total_func_not_found_all = 0
    total_tp_all, total_tn_all, total_fp_all, total_fn_all = 0, 0, 0, 0
    
    project_count = 0
    
    if not os.path.isdir(config_dir):
        print(f"错误：配置目录 '{config_dir}' 不存在。")
        return

    for fname in os.listdir(config_dir):
        if fname.endswith('_result.csv'):
            project_count += 1
            csv_path = os.path.join(config_dir, fname)
            acc1, acc2, acc3, succeed, targets, failed, valid_targets, func_not_found, tp, tn, fp, fn = calc_accuracy(csv_path)
            
            total_succeed_all += succeed
            total_targets_all += targets
            total_failed_all += failed
            total_valid_targets_all += valid_targets
            total_func_not_found_all += func_not_found
            total_tp_all += tp
            total_tn_all += tn
            total_fp_all += fp
            total_fn_all += fn
            
            print(f'{fname}:')
            print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
            print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
            print(f'  succeed/valid_targets = {succeed}/{valid_targets} = {acc3:.4f} (只考虑TP/TN/FP/FN)')
            print()

    if project_count > 0:
        # 基于聚合数据计算总准确率
        agg_acc1 = total_succeed_all / total_targets_all if total_targets_all > 0 else 0
        agg_acc2 = total_succeed_all / (total_targets_all - total_func_not_found_all) if (total_targets_all - total_func_not_found_all) > 0 else 0
        agg_acc3 = total_succeed_all / total_valid_targets_all if total_valid_targets_all > 0 else 0
        
        # 计算宏观平均指标
        macro_precision = total_tp_all / (total_tp_all + total_fp_all) if (total_tp_all + total_fp_all) > 0 else 0
        macro_recall = total_tp_all / (total_tp_all + total_fn_all) if (total_tp_all + total_fn_all) > 0 else 0
        macro_f1 = 2 * (macro_precision * macro_recall) / (macro_precision + macro_recall) if (macro_precision + macro_recall) > 0 else 0

        print("-" * 50)
        print("所有项目的聚合统计:")
        print(f"  TP: {total_tp_all}, TN: {total_tn_all}, FP: {total_fp_all}, FN: {total_fn_all}")
        print(f"  精确率 (Precision): {macro_precision:.4f}")
        print(f"  召回率 (Recall): {macro_recall:.4f}")
        print(f"  F1-Score: {macro_f1:.4f}")
        print("-" * 20)
        print("所有项目的聚合准确率:")
        print(f'  succeed/targets = {total_succeed_all}/{total_targets_all} = {agg_acc1:.4f}')
        print(f'  succeed/(targets-func_not_found) = {total_succeed_all}/({total_targets_all}-{total_func_not_found_all}) = {agg_acc2:.4f}')
        print(f'  succeed/valid_targets = {total_succeed_all}/{total_valid_targets_all} = {agg_acc3:.4f} (只考虑TP/TN/FP/FN)')
    else:
        print(f"在目录 '{config_dir}' 中未找到 *_result.csv 文件进行聚合计算。")

def analyze_correct_cves(config_dir="gcc-o0"):
    """
    读取correct-cves.log中的所有CVE,在指定配置目录的每个csv文件中搜索这些CVE的数据，
    并统计出一个聚合结果。
    """
    print("-" * 50)
    print(f"开始分析 correct-cves.log 在 '{config_dir}' 目录下的表现...")
    
    correct_cves = load_correct_cves()
    if not correct_cves:
        return

    total_succeed_correct = 0
    total_targets_correct = 0
    total_failed_correct = 0
    total_tp_correct, total_tn_correct, total_fp_correct, total_fn_correct = 0, 0, 0, 0
    total_func_not_found_correct = 0
    
    found_cves_count = 0

    if not os.path.isdir(config_dir):
        print(f"错误：结果目录 '{config_dir}' 不存在。")
        return

    for fname in os.listdir(config_dir):
        if fname.endswith('_result.csv'):
            csv_path = os.path.join(config_dir, fname)
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['cve'] in correct_cves:
                        found_cves_count += 1
                        total_succeed_correct += int(row['succeed']) if row['succeed'] else 0
                        total_targets_correct += int(row['target']) if row['target'] else 0
                        total_failed_correct += int(row['failed_versions']) if row['failed_versions'] else 0
                        total_tp_correct += int(row['tp'])
                        total_tn_correct += int(row['tn'])
                        total_fp_correct += int(row['fp'])
                        total_fn_correct += int(row['fn'])
                        total_func_not_found_correct += len(row['func_not_found'].split(';')) if row['func_not_found'] else 0

    if found_cves_count > 0:
        total_valid_targets_correct = total_tp_correct + total_tn_correct + total_fp_correct + total_fn_correct
        
        acc1 = total_succeed_correct / total_targets_correct if total_targets_correct > 0 else 0
        acc2 = total_succeed_correct / (total_targets_correct - total_func_not_found_correct) if (total_targets_correct - total_func_not_found_correct) > 0 else 0
        acc3 = total_succeed_correct / total_valid_targets_correct if total_valid_targets_correct > 0 else 0

        # 计算宏观平均指标
        macro_precision = total_tp_correct / (total_tp_correct + total_fp_correct) if (total_tp_correct + total_fp_correct) > 0 else 0
        macro_recall = total_tp_correct / (total_tp_correct + total_fn_correct) if (total_tp_correct + total_fn_correct) > 0 else 0
        macro_f1 = 2 * (macro_precision * macro_recall) / (macro_precision + macro_recall) if (macro_precision + macro_recall) > 0 else 0

        print("-" * 50)
        print("Correct-CVES 聚合统计结果:")
        print(f"  总共匹配到 {found_cves_count} 条CVE记录。")
        print(f"  TP: {total_tp_correct}, TN: {total_tn_correct}, FP: {total_fp_correct}, FN: {total_fn_correct}")
        print(f"  Succeed: {total_succeed_correct}")
        print(f"  Targets: {total_targets_correct}")
        print(f"  Failed: {total_failed_correct}")
        print(f"  Func Not Found: {total_func_not_found_correct}")
        print("-" * 20)
        print("Correct-CVES 评估指标:")
        print(f"  精确率 (Precision): {macro_precision:.4f}")
        print(f"  召回率 (Recall): {macro_recall:.4f}")
        print(f"  F1-Score: {macro_f1:.4f}")
        print("-" * 20)
        print("Correct-CVES 聚合准确率:")
        print(f'  succeed/targets = {total_succeed_correct}/{total_targets_correct} = {acc1:.4f}')
        print(f'  succeed/(targets-func_not_found) = {total_succeed_correct}/({total_targets_correct}-{total_func_not_found_correct}) = {acc2:.4f}')
        print(f'  succeed/valid_targets = {total_succeed_correct}/{total_valid_targets_correct} = {acc3:.4f} (只考虑TP/TN/FP/FN)')
    else:
        print(f"在 '{config_dir}' 目录的CSV文件中未找到任何 'correct-cves.log' 中列出的CVE。")


def main():
    global CONFIG
    parser = argparse.ArgumentParser(description='解析React检测结果')
    parser.add_argument(
        "-p", "--projects",
        nargs="*",
        default=["binutils","curl","freetype","ffmpeg","imagemagick","libxml2","openssl","openjpeg","sqlite","tcpdump"],
        help="要解析结果的项目名称列表。默认为10个标准项目。"
    )
    parser.add_argument(
        "--compiler",
        default="gcc",
        type=str,
        help="编译器名称 (例如: gcc, clang)"
    )
    parser.add_argument(
        "--opt",
        default="o1",
        type=str,
        help="编译优化级别 (例如: o0, o2, os)"
    )
    parser.add_argument(
        "--evo",
        action="store_true",
        help="是否为Evolution模式"
    )
    parser.add_argument(
        "--analyze-correct",
        action="store_true",
        help="分析correct-cves.log中指定的CVE在gcc-o0目录下的表现"
    )
    args = parser.parse_args()
    
    # 根据参数构建CONFIG目录
    CONFIG = f"{args.compiler}-{args.opt}"
    print(f"当前配置目录: {CONFIG}")

    # 遍历所有指定的项目进行解析
    for project in args.projects:
        print(f"\n{'='*20} 正在处理项目: {project} {'='*20}")
        if args.evo:
            input_file = f"Evolution/{project}-evo.log"
            output_file = f"Evolution/{project}_evo.csv"
            os.makedirs("Evolution", exist_ok=True)
        else:
            input_file = f"{CONFIG}/{project}-log.txt"
            output_file = f"{CONFIG}/{project}_result.csv"
            os.makedirs(CONFIG, exist_ok=True)

        if not os.path.exists(input_file):
            print(f"警告：输入文件 {input_file} 不存在，跳过项目 {project}")
            continue
        
        # 解析结果
        parse_react_log(input_file, output_file, project)
    
    # 在所有项目解析完成后，执行一次聚合计算
    if not args.evo and not args.analyze_correct:
        aggregate_all_projects_accuracy(CONFIG)
    
    # 分析correct-cves
    if args.analyze_correct:
        analyze_correct_cves()


if __name__ == "__main__":
    main()