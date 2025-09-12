#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
from collections import defaultdict

def _new_func_stat():
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
    }

def parse_evo_log(log_file):
    """
    解析 BinXray 风格的 evolution 日志（参考 BinXray/parse_results.py）为:
      results[cve][commit_short][func] -> 统计字典
    日志关键行示例:
      [*] Detecting CVE: CVE-2017-XXXX
      [*] Detection for /.../<project>-<commit>-<prog>,<func>,<truth>
      target function: ... not found
      [*] Detection Result: P... / V... / NA too much diff / C can't tell / N VP no diff / ...
    """
    results = defaultdict(lambda: defaultdict(dict))

    current_cve = None
    current_commit = None
    current_func = None
    current_truth = None

    # 新增：正则从basename提取commit
    commit_re = re.compile(r'CVE-\d{4}-\d+-([0-9a-fA-F]+)-[A-Za-z0-9._-]+$')

    with open(log_file, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            if line.startswith("[*] Detecting CVE:"):
                current_cve = line.split("CVE:")[-1].strip()
                current_commit = None
                current_func = None
                current_truth = None
                continue

            if line.startswith("[*] Detection for"):
                # 兼容形如：
                # [*] Detection for /.../CVE-YYYY-NNNN-<commit>-prog,func,truth
                parts = line.split(',')
                if len(parts) >= 3:
                    # 去掉前缀，获得纯路径
                    path_str = line.split("Detection for", 1)[1].strip()
                    # 取路径末端basename
                    base = os.path.basename(parts[0].split("Detection for", 1)[-1].strip())
                    m = commit_re.search(base)
                    current_commit = m.group(1)[:12] if m else None

                    current_func = parts[1].strip()
                    try:
                        # 末尾truth可能为",1"
                        current_truth = int(parts[2].strip())
                    except Exception:
                        current_truth = None
                continue

            if line.startswith("target function:") and "not found" in line:
                if current_cve and current_commit and current_func:
                    func_stat = results[current_cve][current_commit].setdefault(current_func, _new_func_stat())
                    func_stat['targets'] += 1
                    func_stat['func_not_found'].append(current_commit)
                continue

            if line.startswith("[*] Detection Result:"):
                if not (current_cve and current_commit and current_func):
                    continue
                func_stat = results[current_cve][current_commit].setdefault(current_func, _new_func_stat())
                payload = line.split("Detection Result:", 1)[1].strip()

                # 明确的V/P结果（可能带“,1”尾巴）
                if payload.startswith("V") or payload.startswith("P"):
                    detection = payload[0]  # 'V' or 'P'
                    is_correct = False
                    if current_truth is not None:
                        if current_truth == -1 and detection == 'V':
                            is_correct = True
                        elif current_truth == 1 and detection == 'P':
                            is_correct = True

                    func_stat['targets'] += 1
                    if is_correct:
                        func_stat['succeed'] += 1
                    else:
                        if current_truth == -1 and detection == 'P':
                            func_stat['false_positive'].append(current_commit)
                        elif current_truth == 1 and detection == 'V':
                            func_stat['false_negative'].append(current_commit)
                        else:
                            func_stat['failed_versions'].append(current_commit)
                else:
                    # 其他非明确结果（可能带“,1”尾巴）
                    if "NA too much diff" in payload:
                        func_stat['too_much_diff'].append(current_commit)
                    elif "C can't tell" in payload:
                        func_stat['cant_tell'].append(current_commit)
                    elif "N VP no diff" in payload:
                        func_stat['no_diff'].append(current_commit)
                    else:
                        func_stat['failed_versions'].append(current_commit)
                    func_stat['targets'] += 1
                continue

    return results

def parse_aftercommits_log(log_file):
    """
    解析 Evo_{project}_aftercommits.log:
      CVE-XXXX-YYYY <commit1>,<commit2>,<commit3>,<commit4>
    返回 {cve: [short_commit1..short_commit4]}
    """
    cve_commits = {}
    with open(log_file, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            parts = line.split(' ', 1)
            if len(parts) != 2:
                continue
            cve = parts[0].strip()
            commits = [c.strip()[:12] for c in parts[1].split(',') if c.strip()]
            cve_commits[cve] = commits
    return cve_commits

def calculate_accuracy(evo_results, aftercommits):
    cve_target = [
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
    "CVE-2017-极0",
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
    """
    计算每个阶段的准确率（按函数粒度）:
      - 分母: targets（包括not found/各类NA）
      - 分子: succeed（预测与truth一致）
    另外给出:
      - acc2: succeed / (targets - func_not_found)
      - acc3: succeed / (succeed + FP + FN)
    """
    stage_stats = {
        1: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
        2: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
        3: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
        4: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
    }

    for cve, commits in aftercommits.items():
        if cve not in cve_target:
            continue
        if cve not in evo_results:
            print(f"Warning: CVE {cve} not found in evolution results")
            continue
        cve_map = evo_results[cve]

        for stage, short_commit in enumerate(commits[:4], 1):
            # 匹配commit
            matched_commit = None
            for real_commit in cve_map.keys():
                if short_commit in real_commit or real_commit.startswith(short_commit):
                    matched_commit = real_commit
                    break
            if not matched_commit:
                print(f"Warning: Commit {short_commit} for {cve} EVO{stage} not found in results")
                continue

            func_map = cve_map.get(matched_commit, {})
            if not func_map:
                continue

            # 汇总该commit的函数结果
            commit_succeed = 0
            commit_targets = 0
            for _, stat in func_map.items():
                commit_succeed += stat['succeed']
                commit_targets += stat['targets']
                stage_stats[stage]['func_not_found'] += len(stat['func_not_found'])
                stage_stats[stage]['fp'] += len(stat['false_positive'])
                stage_stats[stage]['fn'] += len(stat['false_negative'])
                # 新增：累计 cant_tell 与 too_much_diff
                stage_stats[stage]['cant_tell'] += len(stat['cant_tell'])
                stage_stats[stage]['too_much_diff'] += len(stat['too_much_diff'])
                stage_stats[stage]['failed_versions'] += len(stat['failed_versions'])
                stage_stats[stage]['no_diff'] += len(stat['no_diff'])

            stage_stats[stage]['succeed'] += commit_succeed
            stage_stats[stage]['targets'] += commit_targets

            print(f"{cve} EVO{stage} ({short_commit}): {commit_succeed}/{commit_targets} functions correct")

    return stage_stats

def main():
    projects=["imagemagick","libxml2","openjpeg","openssl","tcpdump"]
    # 新增：全局累计器
    overall_stats = {
        1: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
        2: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
        3: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
        4: {'succeed': 0, 'targets': 0, 'func_not_found': 0, 'fp': 0, 'fn': 0, 'cant_tell': 0, 'too_much_diff': 0, 'failed_versions': 0, 'no_diff': 0},
    }
    for project in projects:
        evo_log_file = f"{project}-evo.log"
        aftercommits_log_file = f"/home/zhangxb/patch/related-works/CVE-Dataset/PatchEvolution/dataset/Evo_{project}_aftercommits.log"

        if not os.path.exists(evo_log_file):
            print(f"Error: Evolution log file not found: {evo_log_file}")
            return
        if not os.path.exists(aftercommits_log_file):
            print(f"Error: Aftercommits log file not found: {aftercommits_log_file}")
            return

        print(f"Parsing evolution results for project: {project}")
        print(f"Evolution log: {evo_log_file}")
        print(f"Aftercommits log: {aftercommits_log_file}")
        print("-" * 60)

        evo_results = parse_evo_log(evo_log_file)
        aftercommits = parse_aftercommits_log(aftercommits_log_file)

        print(f"Found {len(evo_results)} CVEs in evolution results")
        print(f"Found {len(aftercommits)} CVEs in aftercommits")
        print("-" * 60)

        stats = calculate_accuracy(evo_results, aftercommits)

        # 新增：累计到 overall_stats
        for stage in range(1, 5):
            overall_stats[stage]['succeed'] += stats[stage]['succeed']
            overall_stats[stage]['targets'] += stats[stage]['targets']
            overall_stats[stage]['func_not_found'] += stats[stage]['func_not_found']
            overall_stats[stage]['fp'] += stats[stage]['fp']
            overall_stats[stage]['fn'] += stats[stage]['fn']
            overall_stats[stage]['cant_tell'] += stats[stage]['cant_tell']
            overall_stats[stage]['too_much_diff'] += stats[stage]['too_much_diff']
            overall_stats[stage]['failed_versions'] += stats[stage]['failed_versions']
            overall_stats[stage]['no_diff'] += stats[stage]['no_diff']

        print("\n" + "=" * 60)
        print("EVOLUTION ACCURACY RESULTS (BinXray)")
        print("=" * 60)
        for stage in range(1, 5):
            s = stats[stage]
            if s['targets'] > 0:
                acc1 = s['succeed'] / s['targets']
                denom2 = (s['targets'] - s['func_not_found'])
                acc2 = s['succeed'] / denom2 if denom2 > 0 else 0
                denom3 = s['succeed'] + s['fp'] + s['fn']
                acc3 = s['succeed'] / denom3 if denom3 > 0 else 0
                # 新增：ACC4 = succeed / (targets + FP + FN + cant_tell + too_much_diff)
                denom4 = s['succeed'] + s['fp'] + s['fn'] + s['cant_tell'] + s['too_much_diff']
                acc4 = s['succeed'] / denom4 if denom4 > 0 else 0
                print(f"EVO{stage}-ACC1 (succeed/targets): {acc1:.4f} ({s['succeed']}/{s['targets']})")
                print(f"EVO{stage}-ACC2 (succeed/(targets-func_not_found)): {acc2:.4f} ({s['succeed']}/({s['targets']}-{s['func_not_found']}))")
                print(f"EVO{stage}-ACC3 (succeed/(succeed+FP+FN)): {acc3:.4f} ({s['succeed']}/{s['succeed']}+{s['fp']}+{s['fn']})")
                print(f"EVO{stage}-ACC4 (succeed/(succeed+FP+FN+cant_tell+too_much_diff)): {acc4:.4f} ({s['succeed']}/{s['succeed']}+{s['fp']}+{s['fn']}+{s['cant_tell']}+{s['too_much_diff']})")
            else:
                print(f"EVO{stage}-ACC: No data available")

        print("\n" + "-" * 60)
        print("DETAILED STATISTICS")
        print("-" * 60)
        for stage in range(1, 5):
            s = stats[stage]
            if s['targets'] > 0:
                fail_count = s['failed_versions'] + s['too_much_diff'] + s['cant_tell'] + s['no_diff']
                print(f"EVO{stage}:")
                print(f"  Total targets: {s['targets']}")
                print(f"  Succeed: {s['succeed']}")
                print(f"  Func not found: {s['func_not_found']}")
                print(f"  False positive: {s['fp']}")
                print(f"  False negative (FN): {s['fn']}")
                print(f"  Fail (fv+tmd+ct+nd): {fail_count}")
                print()

    # 新增：所有项目合并后的总体输出
    print("\n" + "=" * 60)
    print("EVOLUTION ACCURACY RESULTS (ALL PROJECTS)")
    print("=" * 60)
    for stage in range(1, 5):
        s = overall_stats[stage]
        if s['targets'] > 0:
            acc1 = s['succeed'] / s['targets']
            denom2 = (s['targets'] - s['func_not_found'])
            acc2 = s['succeed'] / denom2 if denom2 > 0 else 0
            denom3 = s['succeed'] + s['fp'] + s['fn']
            acc3 = s['succeed'] / denom3 if denom3 > 0 else 0
            denom4 = s['succeed'] + s['fp'] + s['fn'] + s['cant_tell'] + s['too_much_diff']
            acc4 = s['succeed'] / denom4 if denom4 > 0 else 0
            print(f"ALL-EVO{stage}-ACC1: {acc1:.4f} ({s['succeed']}/{s['targets']})")
            print(f"ALL-EVO{stage}-ACC2: {acc2:.4f} ({s['succeed']}/({s['targets']}-{s['func_not_found']}))")
            print(f"ALL-EVO{stage}-ACC3: {acc3:.4f} ({s['succeed']}/{s['succeed']}+{s['fp']}+{s['fn']})")
            print(f"ALL-EVO{stage}-ACC4: {acc4:.4f} ({s['succeed']}/{s['succeed']}+{s['fp']}+{s['fn']}+{s['cant_tell']}+{s['too_much_diff']})")
        else:
            print(f"ALL-EVO{stage}-ACC: No data available")

    print("\n" + "-" * 60)
    print("ALL PROJECTS DETAILED STATISTICS")
    print("-" * 60)
    for stage in range(1, 5):
        s = overall_stats[stage]
        if s['targets'] > 0:
            fail_count = s['failed_versions'] + s['too_much_diff'] + s['cant_tell'] + s['no_diff']
            print(f"ALL-EVO{stage}:")
            print(f"  Total targets: {s['targets']}")
            print(f"  Succeed: {s['succeed']}")
            print(f"  Func not found: {s['func_not_found']}")
            print(f"  False positive: {s['fp']}")
            print(f"  False negative (FN): {s['fn']}")
            print(f"  Fail (fv+tmd+ct+nd): {fail_count}")
            print(f" FNRATE: {s['fn']/(s['fn']+s['succeed']):.4f} ({s['fn']}/{s['targets']})")
            print(f"FAILEDRATE: {fail_count/(s['targets']):.4f} ({fail_count}/{s['targets']})")

            print()


main()