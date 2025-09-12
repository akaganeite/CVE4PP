#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import csv
import sys
import json
from collections import defaultdict
import os

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
            
            s = line.split(" ")[1]
            dash_positions = [i for i, char in enumerate(s) if char == '-']  # 找到所有破折号的位置

            if len(dash_positions) >= 2:  # 确保至少有两个破折号
                second_last_dash = dash_positions[-2]  # 倒数第二个破折号的位置
                last_dash = dash_positions[-1]         # 最后一个破折号的位置
                current_version = s[second_last_dash + 1:last_dash]
            else:
                current_version = ""  # 如果没有足够破折号，返回空字符串
            
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
                        # results[key]['failed'] += 1
                        if current_ground_truth == 'vuln' and current_test_result == 'patch':
                            results[key]['false_positive'].append(current_version)
                        elif current_ground_truth == 'patch' and current_test_result == 'vuln':
                            results[key]['false_negative'].append(current_version)
                # if not results[key]['failed']:
                #     results[key]['failed'] =0
                # 重置当前变
                current_version = None
                current_ground_truth = None
                current_test_result = None

    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE', 'succeed', 'failed', 'false_positive', 'false_negative', 'func_not_found', 'target']
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
                'target': stats['targets']
            })
    print(f"解析完成，结果已保存到 {output_file}")
    print(f"总共处理了 {len(results)} 个CVE")

def calc_accuracy(csv_path):
    cve_unique = [
    "CVE-2016-10506",
    "CVE-2017-14164",
    "CVE-2014-3572",
    "CVE-2015-0206",
    "CVE-2015-1789",
    "CVE-2016-2109",
    "CVE-2016-10065",
    "CVE-2017-14174",
    "CVE-2017-12896",
    "CVE-2017-12992",
    "CVE-2017-12995",
    "CVE-2017-13002",
    "CVE-2017-13003",
    "CVE-2017-13030",
    "CVE-2017-13031",
    "CVE-2017-13035",
    "CVE-2017-13039",
    "CVE-2017-13050",
    "CVE-2017-13052",
    "CVE-2017-13053",
    "CVE-2017-13687",
    "CVE-2017-13690",
    "CVE-2017-13725",
    "CVE-2013-0338",
    "CVE-2015-7500",
    "CVE-2015-7941",
    "CVE-2015-8241",
    "CVE-2017-5130"
    ]
    total_succeed = 0
    total_targets = 0
    total_failed = 0
    total_false_positive = 0
    total_false_negative = 0
    total_func_not_found = 0

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # if not row.get('CVE'):
            #     continue
            # CVE = row['CVE']
            # if CVE not in cve_unique:
            #     continue
            succeed = int(row['succeed']) if row['succeed'] else 0
            failed = int(row['failed']) if row['failed'] else 0
            targets = int(row['target']) if row['target'] else 0
            
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

def _load_aftercommits_for_project(project, dataset_dir):
    """
    读取 Evo_{project}_aftercommits.log -> {cve: [short_commit1..short_commit4]}
    """
    path = os.path.join(dataset_dir, f"Evo_{project}_aftercommits.log")
    mapping = {}
    if not os.path.exists(path):
        return mapping
    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            parts = line.split(' ', 1)
            if len(parts) != 2:
                continue
            cve = parts[0].strip()
            commits = [c.strip()[:12] for c in parts[1].split(',') if c.strip()]
            mapping[cve] = commits[:4]
    return mapping

def parse_react_log_records(input_file, project_name):
    """
    解析 React evo 日志，返回逐条记录:
      [{'project','cve','commit_str','label'}]，其中 label 为 'P', 'V'(FN) 或 'F'(Fail)
    跳过 'function not found fail to determine'。
    """
    records = []
    current_cve = None
    current_version = None
    next_line_is_fail = False
    func_not_found_next = False

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line == "function not found fail to determine":
            func_not_found_next = True
            continue
        if line == "fail to determine":
            next_line_is_fail = True
            continue

        if line.startswith('[') and 'CVE-' in line and ']' in line:
            # 提取 CVE
            m = re.search(r'CVE-\d{4}-\d+', line)
            current_cve = m.group(0) if m else None

            # 提取 commit/版本字符串
            s = line.split(" ")[1]
            dash_positions = [i for i, ch in enumerate(s) if ch == '-']
            if len(dash_positions) >= 2:
                second_last_dash = dash_positions[-2]
                last_dash = dash_positions[-1]
                current_version = s[second_last_dash + 1:last_dash]
            else:
                current_version = ""

            # 跳过 not found
            if func_not_found_next:
                func_not_found_next = False
                current_version = None
                continue

            # 测试结果 -> P/V/F
            label = None
            if next_line_is_fail:
                label = 'F'
                next_line_is_fail = False
            elif 'tested: patch' in line:
                label = 'P'
            elif 'tested: vuln' in line:
                label = 'V'

            if project_name and current_cve and current_version and label:
                records.append({
                    'project': project_name,
                    'cve': current_cve,
                    'commit_str': current_version,
                    'label': label
                })
            current_version = None
            continue

    return records

def aggregate_evo_all(records, dataset_dir):
    """
    将记录按 aftercommits 匹配到 EVO1~EVO4，输出聚合统计:
      {1:{'total','patch','vuln','fail'}, 2:{...}, ...}
    """
    stats = {1: {'total': 0, 'patch': 0, 'fn': 0, 'fail': 0},
             2: {'total': 0, 'patch': 0, 'fn': 0, 'fail': 0},
             3: {'total': 0, 'patch': 0, 'fn': 0, 'fail': 0},
             4: {'total': 0, 'patch': 0, 'fn': 0, 'fail': 0}}

    # 按项目缓存 aftercommits
    projects = sorted({r['project'] for r in records})
    after_map = {p: _load_aftercommits_for_project(p, dataset_dir) for p in projects}

    for r in records:
        proj = r['project']
        cve = r['cve']
        commit_str = r['commit_str'] or ''
        cve_commits = after_map.get(proj, {}).get(cve)
        if not cve_commits:
            continue
        stage = None
        for idx, shortc in enumerate(cve_commits, start=1):
            if not shortc:
                continue
            if commit_str.startswith(shortc) or shortc.startswith(commit_str):
                stage = idx
                break
        if stage is None:
            continue
        stats[stage]['total'] += 1
        if r['label'] == 'P':
            stats[stage]['patch'] += 1
        elif r['label'] == 'V':
            stats[stage]['fn'] += 1
        elif r['label'] == 'F':
            stats[stage]['fail'] += 1

    return stats

def print_evo_all(stats, header="ALL PROJECTS (REACT)"):
    print("\n" + "-" * 60)
    print(header)
    print("-" * 60)
    for stage in range(1, 5):
        t = stats[stage]['total']
        p = stats[stage]['patch']
        fn = stats[stage]['fn']
        fail = stats[stage]['fail']
        # 准确率分母现在是 total - fail
        valid_total = t - fail
        acc = (p / valid_total) if valid_total > 0 else 0.0
        print(f"EVO{stage}:")
        print(f"  Total functions tested: {t}")
        print(f"  Functions detected as patch (Correct): {p}")
        print(f"  Functions detected as vulnerability (FN): {fn}")
        print(f"  Functions failed to determine (Fail): {fail}")
        print(f"  Overall accuracy (Correct / (Total - Fail)): {acc:.4f}")
        print(f" Overall FNRate (FN / (Total)): {(fn / t):.4f}" if t > 0 else "  Overall FNRate: N/A")
        print(f" Overall FailRate (Fail / Total): {(fail / t):.4f}" if t > 0 else "  Overall FailRate: N/A")

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
        
    input_file = f"{args.project}-evo.log"
    output_file = f"{args.project}_evo.csv"

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
        if fname.endswith('_evo.csv'):
            acc1, acc2, acc3,succeed, targets, failed, valid_targets,func_not_found = calc_accuracy(fname)
            print(f'{fname}:')
            print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
            print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
            print(f'  succeed/valid_targets = {succeed}/{valid_targets} = {acc3:.4f} (只考虑FP/FN)')
            print()

    # 新增：汇总所有项目的 EVO1~EVO4 数据（若对应 evo 日志存在且可解析）
    dataset_dir = '/home/zhangxb/patch/related-works/CVE-Dataset/PatchEvolution/dataset'
    projects = ["imagemagick","libxml2","openjpeg","tcpdump"]
    all_records = []
    for proj in projects:
        evo_log = f"{proj}-evo.log"
        if os.path.exists(evo_log):
            all_records.extend(parse_react_log_records(evo_log, proj))
    if all_records:
        stats = aggregate_evo_all(all_records, dataset_dir)
        print_evo_all(stats)
        # 新增：按项目分别输出 EVO1~EVO4 分类统计
        for proj in projects:
            proj_records = [r for r in all_records if r['project'] == proj]
            if not proj_records:
                continue
            proj_stats = aggregate_evo_all(proj_records, dataset_dir)
            print_evo_all(proj_stats, header=f"PROJECT {proj} (REACT)")