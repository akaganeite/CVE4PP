#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
from collections import defaultdict

def parse_evo_log(log_file):
    """解析evolution log文件，提取检测结果"""
    results = defaultdict(lambda: defaultdict(dict))
    
    with open(log_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 按CVE分割
    cve_sections = re.split(r'\[\*\] --+\n\[\*\] Detecting CVE: (CVE-\d{4}-\d+)', content)[1:]
    
    for i in range(0, len(cve_sections), 2):
        cve_id = cve_sections[i]
        section_content = cve_sections[i + 1]
        
        # 提取检测结果，同时检查是否为"not found"
        lines = section_content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('[*] Detection for'):
                # 提取detection信息
                match = re.search(r'/([^/]+?)-([^,]+),([^,]+),\d+$', line)
                if match and i + 1 < len(lines):
                    project, commit_hash, function = match.groups()
                    next_line = lines[i + 1].strip()
                    
                    # 检查下一行是否是"not found"
                    if "target function:" in next_line and "not found" in next_line:
                        # 跳过not found的情况
                        i += 2
                        continue
                    elif next_line.startswith('[*] Detection Result:'):
                        result = next_line.replace('[*] Detection Result:', '').strip()
                        # 判断是否为patch (P开头) 还是vulnerability (V开头)
                        is_patch = result.startswith('P')
                        results[cve_id][commit_hash][function] = is_patch
                        i += 2
                        continue
            i += 1
    
    return results

def parse_aftercommits_log(log_file):
    """解析aftercommits log文件，获取每个CVE的evolution commits"""
    cve_commits = {}
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(' ', 1)
            if len(parts) != 2:
                continue
            
            cve_id = parts[0]
            commits = parts[1].split(',')
            # 清理commit hash (移除可能的后缀)
            commits = [commit.strip()[:12] for commit in commits]  # 取前12位
            cve_commits[cve_id] = commits
    
    return cve_commits

def calculate_accuracy(evo_results, aftercommits, project):
    """计算每个evolution阶段的准确率"""
    # 存储每个stage的总体统计数据
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
    evo_stats = {1: {'correct': 0, 'total': 0, 'fn': 0}, 
                 2: {'correct': 0, 'total': 0, 'fn': 0},
                 3: {'correct': 0, 'total': 0, 'fn': 0}, 
                 4: {'correct': 0, 'total': 0, 'fn': 0}}
    
    for cve_id, commits in aftercommits.items():
        if cve_id not in cve_unique:
            continue

        if cve_id not in evo_results:
            print(f"Warning: CVE {cve_id} not found in evolution results")
            continue
        
        cve_results = evo_results[cve_id]
        
        for evo_stage, commit_hash in enumerate(commits, 1):
            if evo_stage > 4:
                break
            
            # 查找匹配的commit (可能需要模糊匹配)
            found_commit = None
            for result_commit in cve_results.keys():
                if commit_hash in result_commit or result_commit in commit_hash:
                    found_commit = result_commit
                    break
            
            if found_commit is None:
                print(f"Warning: Commit {commit_hash} for {cve_id} EVO{evo_stage} not found in results")
                continue
            
            # 获取该commit的所有函数检测结果
            functions_results = cve_results[found_commit]
            if not functions_results:
                continue
            
            # 统计该commit的检测结果
            for function, is_patch in functions_results.items():
                evo_stats[evo_stage]['total'] += 1
                if is_patch:
                    evo_stats[evo_stage]['correct'] += 1
                else:
                    evo_stats[evo_stage]['fn'] += 1
            
            # 输出详细信息
            correct_count = sum(1 for is_patch in functions_results.values() if is_patch)
            total_count = len(functions_results)
            print(f"{cve_id} EVO{evo_stage} ({commit_hash}): {correct_count}/{total_count} functions detected as patch")
    
    return evo_stats

def main():
    projects = ["imagemagick", "libxml2", "openjpeg", "openssl", "tcpdump"]
    # 全局累计器
    overall_stats = {1: {'correct': 0, 'total': 0, 'fn': 0},
                     2: {'correct': 0, 'total': 0, 'fn': 0},
                     3: {'correct': 0, 'total': 0, 'fn': 0},
                     4: {'correct': 0, 'total': 0, 'fn': 0}}

    for project in projects:
        evo_log_file = f"{project}-evo.log"
        aftercommits_log_file = f"/home/zhangxb/patch/related-works/CVE-Dataset/PatchEvolution/dataset/Evo_{project}_aftercommits.log"

        # 检查文件是否存在
        if not os.path.exists(evo_log_file):
            print(f"Error: Evolution log file not found: {evo_log_file}")
            continue
        if not os.path.exists(aftercommits_log_file):
            print(f"Error: Aftercommits log file not found: {aftercommits_log_file}")
            continue

        print(f"Parsing evolution results for project: {project}")
        print(f"Evolution log: {evo_log_file}")
        print(f"Aftercommits log: {aftercommits_log_file}")
        print("-" * 60)

        # 解析文件
        evo_results = parse_evo_log(evo_log_file)
        aftercommits = parse_aftercommits_log(aftercommits_log_file)

        print(f"Found {len(evo_results)} CVEs in evolution results")
        print(f"Found {len(aftercommits)} CVEs in aftercommits")
        print("-" * 60)

        # 计算准确率
        evo_stats = calculate_accuracy(evo_results, aftercommits, project)

        # 累加到overall_stats
        for evo_stage in range(1, 5):
            overall_stats[evo_stage]['correct'] += evo_stats[evo_stage]['correct']
            overall_stats[evo_stage]['total'] += evo_stats[evo_stage]['total']
            overall_stats[evo_stage]['fn'] += evo_stats[evo_stage]['fn']

        # 输出单项目结果
        print("\n" + "=" * 60)
        print(f"EVOLUTION ACCURACY RESULTS ({project})")
        print("=" * 60)
        for evo_stage in range(1, 5):
            stats = evo_stats[evo_stage]
            if stats['total'] > 0:
                accuracy = stats['correct'] / stats['total']
                print(f"EVO{evo_stage}-ACC: {accuracy:.4f} ({stats['correct']}/{stats['total']} functions correctly detected as patch)")
            else:
                print(f"EVO{evo_stage}-ACC: No data available")

        print("\n" + "-" * 60)
        print("DETAILED STATISTICS")
        print("-" * 60)
        for evo_stage in range(1, 5):
            stats = evo_stats[evo_stage]
            if stats['total'] > 0:
                accuracy = stats['correct'] / stats['total']
                vulnerability_count = stats['fn']
                print(f"EVO{evo_stage}:")
                print(f"  Total functions tested: {stats['total']}")
                print(f"  Functions detected as patch: {stats['correct']}")
                print(f"  Functions detected as vulnerability (FN): {vulnerability_count}")
                print(f"  Overall accuracy: {accuracy:.4f}")
                print(f"  Overall FNRate: {vulnerability_count / stats['total']:.4f}")
                print()

    # 输出全局总体结果
    print("\n" + "=" * 60)
    print("EVOLUTION ACCURACY RESULTS (ALL PROJECTS)")
    print("=" * 60)
    for evo_stage in range(1, 5):
        stats = overall_stats[evo_stage]
        if stats['total'] > 0:
            accuracy = stats['correct'] / stats['total']
            print(f"ALL-EVO{evo_stage}-ACC: {accuracy:.4f} ({stats['correct']}/{stats['total']} functions correctly detected as patch)")
        else:
            print(f"ALL-EVO{evo_stage}-ACC: No data available")

    print("\n" + "-" * 60)
    print("ALL PROJECTS DETAILED STATISTICS")
    print("-" * 60)
    for evo_stage in range(1, 5):
        stats = overall_stats[evo_stage]
        if stats['total'] > 0:
            accuracy = stats['correct'] / stats['total']
            vulnerability_count = stats['fn']
            print(f"ALL-EVO{evo_stage}:")
            print(f"  Total functions tested: {stats['total']}")
            print(f"  Functions detected as patch: {stats['correct']}")
            print(f"  Functions detected as vulnerability (FN): {vulnerability_count}")
            print(f"  Overall accuracy: {accuracy:.4f}")
            print(f"  Overall FNRate: {vulnerability_count / stats['total']:.4f}")
            print()

if __name__ == "__main__":
    main()
