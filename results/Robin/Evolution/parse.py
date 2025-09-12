#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import csv
from collections import defaultdict

def parse_results(results_path):
    """
    解析 Robin Evolution 的 results.txt：
      - 提取 cve、project、commit(12位)、binary、func、score
      - score > 0 标记为 'P' (patch)，score < 0 标记为 'V' (vuln)，score == 0 标记为 'C'
    """
    entries = []
    current = {}
    # 提取 project：/PatchEvolution/<project>/
    proj_re = re.compile(r'/PatchEvolution/([^/]+)/')
    # 提取 commit：basename: CVE-YYYY-NNNN-<commit>-<prog>
    commit_re = re.compile(r'CVE-\d{4}-\d+-([0-9a-fA-F]+)-[A-Za-z0-9._-]+$')

    with open(results_path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("CVE ID:"):
                # 开启新块
                if current:
                    entries.append(current)
                    current = {}
                current['cve'] = line.split(":", 1)[1].strip()
            elif line.startswith("Target Binary:"):
                binary = line.split(":", 1)[1].strip()
                current['binary'] = binary
                # project
                mproj = proj_re.search(binary)
                if mproj:
                    current['project'] = mproj.group(1)
                # commit (12位)
                base = os.path.basename(binary)
                mcommit = commit_re.search(base)
                if mcommit:
                    current['commit'] = mcommit.group(1)[:12]
            elif line.startswith("Vulnerable Function Name:"):
                current['func'] = line.split(":", 1)[1].strip()
            elif line.startswith("Overall Score is:"):
                s = line.split(":", 1)[1].strip()
                try:
                    score = float(s)
                except Exception:
                    score = None
                current['score'] = score
                if score is None:
                    current['label'] = 'C'
                else:
                    if score > 0:
                        current['label'] = 'P'
                    elif score < 0:
                        current['label'] = 'V'
                    else:
                        current['label'] = 'C'
            elif line.startswith('---'):
                if current:
                    entries.append(current)
                    current = {}
        # 最后一块
        if current:
            entries.append(current)
    return entries

def write_csv(entries, output_csv):
    # 增加 stage 字段
    fields = ['cve', 'project', 'commit', 'func', 'score', 'label', 'stage', 'binary']
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in entries:
            w.writerow({
                'cve': e.get('cve', ''),
                'project': e.get('project', ''),
                'commit': e.get('commit', ''),
                'func': e.get('func', ''),
                'score': e.get('score', ''),
                'label': e.get('label', ''),
                'stage': e.get('stage', ''),
                'binary': e.get('binary', ''),
            })

def _load_aftercommits_for_project(project, dataset_dir):
    """
    读取 /.../dataset/Evo_{project}_aftercommits.log
    返回 {cve: [short_commit1..short_commit4]}
    """
    path = os.path.join(dataset_dir, f"Evo_{project}_aftercommits.log")
    mapping = {}
    if not os.path.exists(path):
        print(f"Warning: aftercommits not found for project {project}: {path}")
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

def _attach_stage_and_calculate_stats(entries, dataset_dir):
    """
    为 entries 增加 stage 字段，并统计每个阶段的数据。
    新规则:
    - P: 成功识别为 Patch
    - V: 错误识别为 Vuln (即 FN)
    - C: 无法判断
    - Fail: CVE在results.txt中有记录，但部分commit缺失
    - 完全忽略: CVE在aftercommits.log中，但在results.txt中无任何记录
    """
    # 初始统计字典
    stats = {
        1: {'targets': 0, 'P': 0, 'V': 0, 'C': 0, 'Fail': 0},
        2: {'targets': 0, 'P': 0, 'V': 0, 'C': 0, 'Fail': 0},
        3: {'targets': 0, 'P': 0, 'V': 0, 'C': 0, 'Fail': 0},
        4: {'targets': 0, 'P': 0, 'V': 0, 'C': 0, 'Fail': 0}
    }

    # 按 project 缓存 aftercommits
    projects = sorted({e.get('project') for e in entries if e.get('project')})
    after_map = {p: _load_aftercommits_for_project(p, dataset_dir) for p in projects}

    # 创建一个更高效的查找结构: {cve -> {commit_prefix -> entry}}
    cve_to_results_map = defaultdict(dict)
    for e in entries:
        cve = e.get('cve')
        commit = e.get('commit')
        if cve and commit:
            cve_to_results_map[cve][commit] = e

    # 遍历基准 (aftercommits)，而不是遍历结果
    for proj, cve_map in after_map.items():
        for cve, commit_list_from_log in cve_map.items():
            
            # 规则1: 如果CVE在results.txt中完全不存在，则忽略
            if cve not in cve_to_results_map:
                continue

            # 获取该CVE在results.txt中的所有结果
            results_for_this_cve = cve_to_results_map[cve]

            # 遍历log中的每个commit阶段
            for stage, commit_short in enumerate(commit_list_from_log, start=1):
                if not commit_short:
                    continue

                # 只要CVE在results.txt中出现过，其所有log中的commit都应计入targets
                stats[stage]['targets'] += 1
                
                # 在该CVE的结果中查找匹配的commit
                found_entry = results_for_this_cve.get(commit_short)

                if found_entry:
                    # 找到了结果，进行分类
                    label = found_entry.get('label', 'C')
                    if label in ('P', 'V', 'C'):
                        stats[stage][label] += 1
                    else:
                        stats[stage]['C'] += 1
                    # 回填 stage 到 entry 中
                    found_entry['stage'] = stage
                else:
                    # 规则2: 未找到commit，但CVE本身存在于results.txt中，计为 Fail
                    stats[stage]['Fail'] += 1
    return stats

def main():
    parser = argparse.ArgumentParser(description="解析 Robin Evolution 的 results.txt，并按分数正负输出 P/V 标记")
    parser.add_argument('--input', default='results.txt', help='results.txt 路径')
    parser.add_argument('--output', default='robin-evo-results.csv', help='输出CSV路径')
    parser.add_argument('--dataset-dir', default='/home/zhangxb/patch/related-works/CVE-Dataset/PatchEvolution/dataset',
                        help='Evo_{project}_aftercommits.log 所在目录')
    args = parser.parse_args()

    entries = parse_results(args.input)

    # 打印单条结果（可选，用于调试）
    # for e in entries:
    #     lbl = e.get('label', 'C')
    #     print(f"{e.get('cve','')} {e.get('project','')} {e.get('commit','')}: {e.get('func','')} -> {lbl} (score={e.get('score','')})")

    # 计算 EVO1~EVO4 阶段数据
    stage_stats = _attach_stage_and_calculate_stats(entries, args.dataset_dir)

    print("\n" + "=" * 80)
    print("EVOLUTION SUMMARY (Robin)")
    print("  - P: Succeed (Correctly identified as Patched)")
    print("  - FN (V): False Negative (Incorrectly identified as Vulnerable)")
    print("  - C: Zero/Unknown Score")
    print("  - Fail: Entry missing in results.txt but present in aftercommits.log")
    print("=" * 80)
    
    total_stats = {'targets': 0, 'P': 0, 'V': 0, 'C': 0, 'Fail': 0}

    for stage in range(1, 5):
        s = stage_stats[stage]
        for key in total_stats:
            total_stats[key] += s.get(key, 0)

        if s['targets'] > 0:
            succeed_rate = s['P'] / s['targets']
            fn_rate = s['V'] / s['targets']
            fail_rate = s['Fail'] / s['targets']
            print(f"EVO{stage}: targets={s['targets']:<4} | P={s['P']:<4} | FN(V)={s['V']:<4} | C={s['C']:<4} | Fail={s['Fail']:<4} "
                  f" (Succeed Rate={succeed_rate:.2%}, FN Rate={fn_rate:.2%}, Fail Rate={fail_rate:.2%})")
        else:
            print(f"EVO{stage}: No data available")

    print("-" * 80)
    # 输出总计
    if total_stats['targets'] > 0:
        succeed_rate = total_stats['P'] / total_stats['targets']
        fn_rate = total_stats['V'] / total_stats['targets']
        fail_rate = total_stats['Fail'] / total_stats['targets']
        print(f"TOTAL : targets={total_stats['targets']:<4} | P={total_stats['P']:<4} | FN(V)={total_stats['V']:<4} | "
              f"C={total_stats['C']:<4} | Fail={total_stats['Fail']:<4} "
              f" (Succeed Rate={succeed_rate:.2%}, FN Rate={fn_rate:.2%}, Fail Rate={fail_rate:.2%})")

    # 写出 CSV（含 stage）
    write_csv(entries, args.output)
    print(f"\n已写出CSV: {args.output}")

if __name__ == '__main__':
    main()
