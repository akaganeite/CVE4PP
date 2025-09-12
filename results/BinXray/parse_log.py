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
            # 标准化文本，便于识别 additional error 类型
            norm = result_str.lower().replace(' ', '_')
            is_vulnerable = result_str.upper().startswith('V')
            is_patched = result_str.upper().startswith('P')
            expected_vulnerable = current_ground_truth == -1
            expected_patched = current_ground_truth == 1
            # 识别三类 additional error
            no_diff = ('no_diff' in norm) or ('no-diff' in norm)
            cant_tell = ('can\'t_tell' in norm) or ('fail_to_decide' in norm)
            too_much_diff = ('too_much_diff' in norm) or ('too-much-diff' in norm)
            fail_to_decide = ('fail_to_decide' in norm)
            # 需求：no_diff 视为 Vulnerable，不算 additional error
            if no_diff:
                is_vulnerable = True
                is_patched = False
            cve_results[current_cve][current_version][current_func] = {
                'is_vulnerable': is_vulnerable,
                'is_patched': is_patched,
                'expected_vulnerable': expected_vulnerable,
                'expected_patched': expected_patched,
                'result': result_str,
                'no_diff': no_diff,            # 仍保留标记，但不再当 additional error
                'cant_tell': cant_tell,
                'too_much_diff': too_much_diff,
                'fail_to_decide': fail_to_decide,
            }
            continue
        if line.startswith('target function:') and 'not found' in line and current_cve and current_version and current_func is not None:
            cve_results[current_cve][current_version][current_func] = {
                'not_found': True
            }
            continue
        if line.startswith('[*] Detection Result: fail to decide') and current_cve and current_version and current_func is not None:
            # 保底：标记为 cant_tell 以便计入 additional error
            cve_results[current_cve][current_version][current_func] = {
                'fail_to_decide': True,
                'cant_tell': True
            }
            continue
    return cve_results

def apply_corrections(cve_results, correction_data):
    """应用correction.json修正假阴性等"""
    corrections_applied = 0
    for cve in cve_results:
        for version in cve_results[cve]:
            for func, fdata in cve_results[cve][version].items():
                # 检查是否为假阴性 (FN)
                if fdata.get('expected_patched') and fdata.get('is_vulnerable'):
                    # 如果这个FN是由no_diff规则造成的，则不应用修正，让它被计为FN
                    if fdata.get('no_diff'):
                        continue
                    
                    # 仅对非no_diff造成的FN应用修正
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
    # 用于统计整个项目的TP/TN/FP/FN
    total_tp_project, total_tn_project, total_fp_project, total_fn_project = 0, 0, 0, 0

    for cve, version_dict in cve_results.items():
        # 收集所有出现过的version
        version_set = set(version_dict.keys())
        total_versions = 0  # 按需统计：若该version所有函数均not_found，则不计入
        succeed_versions = 0
        failed_versions = []
        additional_error = []
        false_positive = []
        false_negative = []
        
        # 用于统计当前CVE的TP/TN/FP/FN
        tp_cve, tn_cve, fp_cve, fn_cve = 0, 0, 0, 0

        for version in version_set:
            # 过滤掉 not_found 与 correction 的函数，不计入统计
            evaluated_funcs = []
            for func, fdata in version_dict[version].items():
                if fdata.get('not_found'):
                    continue
                if fdata.get('correction'):
                    continue
                evaluated_funcs.append((func, fdata))

            # 若该 version 全部函数都不计（要么 not_found 要么 correction），则跳过该 version
            if not evaluated_funcs:
                continue

            total_versions += 1
            all_correct = True
            version_false_positive = False
            version_false_negative = False
            version_additional_error = False

            # 版本级别的TP/TN判断
            is_version_tp = True
            is_version_tn = True
            has_patched_expectation = False
            has_vulnerable_expectation = False

            for func, fdata in evaluated_funcs:
                # additional error（去掉 no_diff）
                if fdata.get('fail_to_decide') or fdata.get('cant_tell') or fdata.get('too_much_diff'):
                    version_additional_error = True
                    is_version_tp = False
                    is_version_tn = False

                expected_vulnerable = fdata.get('expected_vulnerable')
                expected_patched = fdata.get('expected_patched')
                is_vulnerable = fdata.get('is_vulnerable')
                is_patched = fdata.get('is_patched')

                if expected_patched:
                    has_patched_expectation = True
                    if not is_patched:
                        is_version_tp = False # 不是TP
                    if is_vulnerable:
                        version_false_negative = True # 存在FN
                
                if expected_vulnerable:
                    has_vulnerable_expectation = True
                    if not is_vulnerable:
                        is_version_tn = False # 不是TN
                    if is_patched:
                        version_false_positive = True # 存在FP

            # 根据版本中所有函数的综合结果来更新CVE级别的统计
            if version_additional_error or version_false_positive or version_false_negative:
                # 任何错误都会使版本级别的TP/TN判断无效
                is_version_tp = False
                is_version_tn = False
            
            # 一个版本要么是Vulnerable(TN)，要么是Patched(TP)，不能混杂
            if has_patched_expectation and has_vulnerable_expectation:
                is_version_tp = False
                is_version_tn = False

            if is_version_tp and has_patched_expectation:
                tp_cve += 1
            elif is_version_tn and has_vulnerable_expectation:
                tn_cve += 1
            else:
                # 如果不是版本级别的TP或TN，则根据错误类型进行分类
                if version_false_positive:
                    fp_cve += 1
                if version_false_negative:
                    fn_cve += 1

            # 重新判断 all_correct
            # 只有当版本中没有任何FP, FN或additional_error时，才算成功
            all_correct = not (version_false_positive or version_false_negative or version_additional_error)

            if all_correct:
                succeed_versions += 1
            else:
                # 根据错误类型分类
                if version_additional_error:
                    additional_error.append(version)
                # 注意：一个版本可能同时是FP和FN（如果涉及多个函数）
                if version_false_positive:
                    false_positive.append(version)
                if version_false_negative:
                    false_negative.append(version)
                # 如果一个版本既不是succeed，也没有被归类到任何错误中，这是不期望的
                # 但为了健壮性，可以保留一个分类
                if not version_additional_error and not version_false_positive and not version_false_negative:
                    failed_versions.append(version)

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
            'failed_versions': ';'.join(failed_versions) if failed_versions else '',
            'additional_error': ';'.join(list(set(additional_error))) if additional_error else '',
            'false_positive': ';'.join(list(set(false_positive))) if false_positive else '',
            'false_negative': ';'.join(list(set(false_negative))) if false_negative else ''
        })
    return csv_data, total_tp_project, total_tn_project, total_fp_project, total_fn_project

def write_csv(csv_data, output_file):
    """写入CSV文件"""
    fieldnames = ['cve', 'succeed', 'target', 'tp', 'tn', 'fp', 'fn', 'failed_versions', 'additional_error', 'false_positive', 'false_negative']
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_data)

def calculate_overall_statistics(csv_data, total_tp, total_tn, total_fp, total_fn):
    """计算整体统计信息"""
    total_detections = sum(int(row['target']) for row in csv_data)
    total_successful = sum(int(row['succeed']) for row in csv_data)
    
    # 使用精确的TP/TN/FP/FN计算宏观指标
    total_classified = total_tp + total_tn + total_fp + total_fn
    accuracy = (total_tp + total_tn) / total_classified if total_classified > 0 else 0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        'total_detections': total_detections,
        'total_successful': total_successful,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'total_tp': total_tp,
        'total_tn': total_tn,
        'total_fp': total_fp,
        'total_fn': total_fn
    }

def main():
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "--projects",
        default=["binutils","curl","freetype","ffmpeg","imagemagick","libxml2","openssl","openjpeg","sqlite","tcpdump"],
        nargs="*"
    )
    args = parser.parse_args()
    projects = args.projects

    # 初始化所有项目的总计数器
    all_projects_tp = 0
    all_projects_tn = 0
    all_projects_fp = 0
    all_projects_fn = 0
    processed_projects_count = 0
    all_targets = 0

    for project in projects:
        log_file = f"gcc-o3/{project}-test.log"
        output_file = f"gcc-o3/{project}-cve.csv"
        # print(f"正在解析日志文件: {log_file}")
        cve_results = parse_log_file(log_file)
        # print(f"正在加载correction.json...")
        correction_data = load_correction_data(project)
        if correction_data:
            apply_corrections(cve_results, correction_data)
        # print(f"正在分析CVE结果...")
        csv_data, tp, tn, fp, fn = analyze_cve_results(cve_results)
        # print(f"正在写入CSV文件: {output_file}")
        write_csv(csv_data, output_file)
        # print(f"完成！共处理了 {len(csv_data)} 个CVE")
        stats = calculate_overall_statistics(csv_data, tp, tn, fp, fn)
        
        print(f"--- {project} 整体统计信息 ---")
        print(f"TP: {stats['total_tp']}, TN: {stats['total_tn']}, FP: {stats['total_fp']}, FN: {stats['total_fn']}")
        print(f"Accuracy:  {stats['accuracy']:.4f}")
        print(f"Precision: {stats['precision']:.4f}")
        print(f"Recall:    {stats['recall']:.4f}")
        print(f"F1-Score:  {stats['f1_score']:.4f}\n")

        # 累加到总计数器
        all_projects_tp += stats['total_tp']
        all_projects_tn += stats['total_tn']
        all_projects_fp += stats['total_fp']
        all_projects_fn += stats['total_fn']
        all_targets += stats['total_detections']
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
        effectiveness = (all_projects_tp + all_projects_tn) / all_targets if all_targets > 0 else 0
        print(f"effectiveness:({all_projects_tp} + {all_projects_tn})/{all_targets}={effectiveness:.4f}")
        print(f"TP: {all_projects_tp}, TN: {all_projects_tn}, FP: {all_projects_fp}, FN: {all_projects_fn}")
        print(f"整体准确率 (Accuracy): {macro_accuracy:.4f}")
        print(f"整体精确率 (Precision): {macro_precision:.4f}")
        print(f"整体召回率 (Recall): {macro_recall:.4f}")
        print(f"整体F1分数 (F1-Score): {macro_f1:.4f}")
        


if __name__ == "__main__":
    main()