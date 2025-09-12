#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import csv
import sys
import json
from collections import defaultdict
import os
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

def apply_corrections(results, correction_data):
    """
    应用correction数据到results中
    
    Args:
        results: 解析的结果数据
        correction_data: correction.json中的数据
    """
    corrections_applied = 0
    
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

def parse_binxray_results(input_file, output_file, project_name):
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
            'tp': 0,
            'tn': 0,
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
                # if PROJ == "openssl":
                #     # version_pattern = r'/(openssl-[^-]+-[^-]+)-o0-'
                #     version_pattern = rf"{project}-(OpenSSL_[\w.]+(?:-pre\d+)?)-o0"
                # else:
                #     version_pattern = rf"-([^-]+)-o0-"
                # version_match = re.search(version_pattern, parts[0])
                # if version_match:
                #     current_version = version_match.group(1)
                s=parts[0]
                first_dash = s.find('-')            
                last_dash = s.rfind('-', 0, s.rfind('-'))
                current_version = s[first_dash + 1:last_dash]
                # print(current_version)
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
                
                results[key]['targets'] += 1
                # ground_truth: 1 (patched), -1 (vulnerable)
                # detection_result: 'P' (patched), 'V' (vulnerable)
                if current_ground_truth == 1: # Patched
                    if detection_result == 'P':
                        results[key]['tp'] += 1
                        results[key]['succeed'] += 1
                    else: # 'V'
                        results[key]['false_negative'].append(current_version)
                elif current_ground_truth == -1: # Vulnerable
                    if detection_result == 'V':
                        results[key]['tn'] += 1
                        results[key]['succeed'] += 1
                    else: # 'P'
                        results[key]['false_positive'].append(current_version)
            else:
                # 处理不明确的结果
                if "NA too much diff" in line:
                    results[key]['too_much_diff'].append(current_version)
                elif "C can't tell" in line:
                    results[key]['cant_tell'].append(current_version)
                elif "N VP no diff" in line:
                    # 需求：no_diff 按检测结果 V 处理
                    detection_result = 'V'
                    results[key]['targets'] += 1
                    if current_ground_truth == -1:
                        results[key]['tn'] += 1
                        results[key]['succeed'] += 1
                    elif current_ground_truth == 1:
                        results[key]['false_negative'].append(current_version)
                    # 仍记录在 no_diff 方便追踪
                    results[key]['no_diff'].append(current_version)
                    continue  # 已完成计数，避免再次 targets +=1
                else:
                    results[key]['failed_versions'].append(current_version)
                results[key]['targets'] += 1
    
    # 加载并应用correction数据
    correction_data = load_correction_data(project_name)
    if correction_data:
        apply_corrections(results, correction_data)
    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['cve', 'funcname', 'succeed', 'tp', 'tn', 'false_positive', 'false_negative', 'failed_versions', 'too_much_diff', 'cant_tell', 'no_diff', 'func_not_found', 'targets']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for (cve, funcname), stats in results.items():
            writer.writerow({
                'cve': cve,
                'funcname': funcname,
                'succeed': stats['succeed'],
                'tp': stats['tp'],
                'tn': stats['tn'],
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
    total_failed_versions = 0
    total_too_much_diff = 0
    total_cant_tell = 0
    total_no_diff = 0
    total_fp = 0
    total_fn = 0
    total_tp = 0
    total_tn = 0
    
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            succeed = int(row['succeed']) if row['succeed'] else 0
            targets = int(row['targets']) if row['targets'] else 0
            tp = int(row['tp']) if row['tp'] else 0
            tn = int(row['tn']) if row['tn'] else 0
            
            # 计算各种失败情况的数量
            func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0
            failed_versions = len(row['failed_versions'].split(';')) if row['failed_versions'] else 0
            too_much_diff = len(row['too_much_diff'].split(';')) if row['too_much_diff'] else 0
            cant_tell = len(row['cant_tell'].split(';')) if row['cant_tell'] else 0
            no_diff = len(row['no_diff'].split(';')) if row['no_diff'] else 0
            fp = len(row['false_positive'].split(';')) if row['false_positive'] else 0
            fn = len(row['false_negative'].split(';')) if row['false_negative'] else 0
            
            total_succeed += succeed
            total_targets += targets
            total_tp += tp
            total_tn += tn
            total_func_not_found += func_not_found
            total_failed_versions += failed_versions
            total_too_much_diff += too_much_diff
            total_cant_tell += cant_tell
            total_no_diff += no_diff
            total_fp += fp
            total_fn += fn
    
    # 计算 Accuracy, Precision, Recall, F1-score
    accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return accuracy, precision, recall, f1_score, total_tp, total_tn, total_fp, total_fn

def main():
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "--projects",
        default=["binutils","curl","freetype","ffmpeg","imagemagick","libxml2","openssl","openjpeg","sqlite","tcpdump"],
        nargs="*"
    )
    parser.add_argument(
        "-opt", "--optimization",
        type=str,
        help="优化级别 (如 O0, O1, O2, O3)"
    )
    parser.add_argument(
        "-compiler", "--compiler",
        type=str,
        help="编译器 (如 gcc, clang)"
    )
    
    args = parser.parse_args()
    projects = args.projects
    for proj in projects:
        PROJ = proj
        # 根据是否指定opt参数来决定文件名
        if args.optimization:
            output_file = f"{args.compiler}-{args.optimization}/{PROJ}_result.csv"
            input_file = f"{args.compiler}-{args.optimization}/{PROJ}-test.log"
        else:
            output_file = f"{PROJ}_result.csv"
            input_file = f"{PROJ}-test.log"
        
        # 检查输出文件扩展名
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
        parse_binxray_results(input_file, output_file, PROJ)
            # 批量计算准确率
    all_projects_count = 0
    
    total_tp_all = 0
    total_tn_all = 0
    total_fp_all = 0
    total_fn_all = 0

    opt_dir = f'{args.compiler}-{args.optimization}'
    for fname in os.listdir(opt_dir):
        if fname.endswith('_result.csv'):
            acc, precision, recall, f1, tp, tn, fp, fn = calc_accuracy(os.path.join(opt_dir, fname))
            print(f'{fname}:')
            print(f'  TP={tp}, TN={tn}, FP={fp}, FN={fn}')
            print(f'  Accuracy  (TP+TN)/(TP+TN+FP+FN) = {tp+tn}/({tp+tn+fp+fn}) = {acc:.4f}')
            print(f'  Precision (TP/(TP+FP))          = {tp}/({tp+fp}) = {precision:.4f}')
            print(f'  Recall    (TP/(TP+FN))          = {tp}/({tp+fn}) = {recall:.4f}')
            print(f'  F1-Score  (2*P*R/(P+R))         = {f1:.4f}')
            print()
            
            total_tp_all += tp
            total_tn_all += tn
            total_fp_all += fp
            total_fn_all += fn
            all_projects_count += 1
    
    if all_projects_count > 0:
        # 基于所有项目的TP, TN, FP, FN总和来计算宏观平均指标
        total_succeed_all = total_tp_all + total_tn_all
        total_all = total_tp_all + total_tn_all + total_fp_all + total_fn_all
        
        macro_accuracy = total_succeed_all / total_all if total_all > 0 else 0
        macro_precision = total_tp_all / (total_tp_all + total_fp_all) if (total_tp_all + total_fp_all) > 0 else 0
        macro_recall = total_tp_all / (total_tp_all + total_fn_all) if (total_tp_all + total_fn_all) > 0 else 0
        macro_f1 = 2 * (macro_precision * macro_recall) / (macro_precision + macro_recall) if (macro_precision + macro_recall) > 0 else 0

        print("所有项目的总体指标 (Macro Average):")
        print(f'  Total TP={total_tp_all}, TN={total_tn_all}, FP={total_fp_all}, FN={total_fn_all}')
        print(f'  Accuracy  = {total_succeed_all}/{total_all} = {macro_accuracy:.4f}')
        print(f'  Precision = {total_tp_all}/({total_tp_all+total_fp_all}) = {macro_precision:.4f}')
        print(f'  Recall    = {total_tp_all}/({total_tp_all+total_fn_all}) = {macro_recall:.4f}')
        print(f'  F1-Score  = {macro_f1:.4f}')

if __name__ == "__main__":
            
    main()
