#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
from collections import defaultdict

def parse_evo_log(log_file):
    """
    解析 PS3 的 tcpdump-func.log 风格的演化日志。
    期望的片段格式示例：
      ------------------------------------------
      Detecing CVE:CVE-2017-12893
      Detection for: /.../tcpdump/CVE-2017-12893-3a7639e545c0-tcpdump
      Result for name_len:patch , truth is patch
      ...
    返回:
      dict: { cve_id: { commit_hash: { function_name: is_patch(bool) } } }
    """
    results = defaultdict(lambda: defaultdict(dict))
    current_cve = None
    current_commit = None

    # 从 Detection for 路径末尾提取 commit 的正则：
    # 末段形如: CVE-YYYY-NNNN-<commit>-<prog>
    commit_pat = re.compile(r'(CVE-\d{4}-\d+)-([0-9a-fA-F]+)-[A-Za-z0-9._-]+$')

    with open(log_file, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            # 解析 CVE
            if line.startswith("Detecing CVE:"):
                # 例如: Detecing CVE:CVE-2017-12893
                current_cve = line.split("Detecing CVE:")[-1].strip()
                current_commit = None
                continue

            # 解析 Detection for，提取 commit
            if line.startswith("Detection for:"):
                # 取路径最后一段
                path = line.split("Detection for:", 1)[1].strip()
                base = os.path.basename(path)
                m = commit_pat.search(base)
                if m:
                    # cve_id_from_path = m.group(1)  # 如需校验，可使用
                    current_commit = m.group(2)[:12]  # 后续匹配使用短 commit
                else:
                    current_commit = None
                continue

            # 过滤掉与结果无关的提示
            if ("fail to determine" in line) or line.startswith("NotImplementedError") or line.startswith("no function"):
                # results[current_cve][current_commit][func_name] = 'none'
                continue
            # 解析结果行
            if line.startswith("Result for"):
                # 形如: Result for <func>:<label> , truth is <...>
                try:
                    payload = line.split("Result for", 1)[1].strip()
                    func_and_label, _, _truth = payload.partition(" , truth is")
                    func_name, _, label = func_and_label.partition(":")
                    func_name = func_name.strip()
                    label = label.strip().lower()  # patch / vuln / none

                    if current_cve and current_commit and func_name:
                        # is_patch = (label == "patch")
                        # # 将有结果的函数（包括 none/vuln）都计入分母
                        # results[current_cve][current_commit][func_name] = is_patch
                        # 直接存储标签，而不是布尔值
                        results[current_cve][current_commit][func_name] = label
                except Exception:
                    # 容错，跳过异常行
                    pass

    return results

def parse_evo_cve_log(log_file):
    """
    解析 {project}-cve.log（参考parse_result的CVE模式）
    行格式示例：
      CVE-2017-12893 CVE-2017-12893-3a7639e545c0-tcpdump truth = patch result = patch
      TestJson(file='CVE-2017-12894-d8bf24c8743e-tcpdump', cve='CVE-2017-12894', ...) is not valid
    返回:
      dict: { cve_id: { commit_short: is_patch(bool) } }
    """
    results = defaultdict(dict)
    commit_pat = re.compile(r'(CVE-\d{4}-\d+)-([0-9a-fA-F]+)-[A-Za-z0-9._-]+$')
    truth_result_pat = re.compile(r'truth\s*=\s*(\w+)\s+result\s*=\s*(\w+)', re.IGNORECASE)

    with open(log_file, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            # 有效结果行
            if line.startswith("CVE-"):
                parts = line.split()
                if len(parts) >= 2:
                    cve_id = parts[0]
                    file_id = parts[1]
                    m = commit_pat.search(file_id)
                    if not m:
                        continue
                    commit_short = m.group(2)[:12]
                    m2 = truth_result_pat.search(line)
                    if not m2:
                        continue
                    # truth = m2.group(1).lower()  # 如需使用可保留
                    result_label = m2.group(2).lower()
                    is_patch = (result_label == 'patch')
                    results[cve_id][commit_short] = is_patch
                continue

            # TestJson无效行：计入total但不算正确
            if line.startswith("TestJson("):
                m_file = re.search(r"file='([^']+)'", line)
                m_cve = re.search(r"cve='([^']+)'", line)
                if m_file and m_cve:
                    file_id = m_file.group(1)
                    cve_id = m_cve.group(1)
                    m = commit_pat.search(file_id)
                    if m:
                        commit_short = m.group(2)[:12]
                        # 视为非patch
                        results[cve_id][commit_short] = False
                continue

    return results

def parse_aftercommits_log(log_file):
    """
    解析Evo_{project}_aftercommits.log，格式:
      CVE-XXXX-YYYY <commit1>,<commit2>,<commit3>,<commit4>
    返回:
      dict: { cve_id: [commit1, commit2, commit3, commit4] }（取前4个，commit hash取前12位做匹配）
    """
    cve_commits = {}
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            parts = s.split(' ', 1)
            if len(parts) != 2:
                continue
            cve_id = parts[0]
            commits = [c.strip()[:12] for c in parts[1].split(',') if c.strip()]
            cve_commits[cve_id] = commits
    return cve_commits

def calculate_accuracy(evo_results, aftercommits):
    """
    计算每个EVO阶段的准确率（按函数粒度聚合）:
      - 分母: 某阶段对应commit下解析到的函数总数
      - 分子: 其中被判定为patch的函数数量
    返回:
      dict: { stage(1..4): {'correct': int, 'total': int} }
    """
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
    evo_stats = {1: {'correct': 0, 'total': 0, 'fn': 0, 'fail': 0},
                 2: {'correct': 0, 'total': 0, 'fn': 0, 'fail': 0},
                 3: {'correct': 0, 'total': 0, 'fn': 0, 'fail': 0},
                 4: {'correct': 0, 'total': 0, 'fn': 0, 'fail': 0}}

    for cve_id, commits in aftercommits.items():
        if cve_id not in cve_unique:
            continue
        if cve_id not in evo_results:
            print(f"Warning: CVE {cve_id} not found in evolution results")
            continue
        cve_results = evo_results[cve_id]

        for stage, short_commit in enumerate(commits[:4], 1):
            # 在cve_results里模糊匹配commit（包含关系）
            matched_commit = None
            for real_commit in cve_results.keys():
                if short_commit in real_commit or real_commit.startswith(short_commit):
                    matched_commit = real_commit
                    break
            if not matched_commit:
                print(f"Warning: Commit {short_commit} for {cve_id} EVO{stage} not found in results")
                continue

            functions_map = cve_results.get(matched_commit, {})
            if not functions_map:
                continue

            # correct = sum(1 for v in functions_map.values() if v)
            # total = len(functions_map)
            # evo_stats[stage]['correct'] += correct
            # evo_stats[stage]['total'] += total
            # print(f"{cve_id} EVO{stage} ({short_commit}): {correct}/{total} functions detected as patch")

            stage_stats = {'correct': 0, 'total': 0, 'fn': 0, 'fail': 0}
            for label in functions_map.values():
                stage_stats['total'] += 1
                if label == 'patch':
                    stage_stats['correct'] += 1
                elif label == 'vuln':
                    stage_stats['fn'] += 1
                elif label == 'none':
                    stage_stats['fail'] += 1
            
            evo_stats[stage]['correct'] += stage_stats['correct']
            evo_stats[stage]['total'] += stage_stats['total']
            evo_stats[stage]['fn'] += stage_stats['fn']
            evo_stats[stage]['fail'] += stage_stats['fail']

            print(f"{cve_id} EVO{stage} ({short_commit}): "
                  f"Correct={stage_stats['correct']}, FN={stage_stats['fn']}, "
                  f"Fail={stage_stats['fail']}, Total={stage_stats['total']}")

    return evo_stats

def calculate_accuracy_cve(evo_cve_results, aftercommits):
    """
    基于CVE级别结果计算每个EVO阶段准确率：
      - 分母：该阶段commit条目数
      - 分子：其中result=patch的条目数
    """
    evo_stats = {1: {'correct': 0, 'total': 0},
                 2: {'correct': 0, 'total': 0},
                 3: {'correct': 0, 'total': 0},
                 4: {'correct': 0, 'total': 0}}

    for cve_id, commits in aftercommits.items():
        if cve_id not in evo_cve_results:
            print(f"Warning: CVE {cve_id} not found in CVE-level results")
            continue
        cve_map = evo_cve_results[cve_id]

        for stage, short_commit in enumerate(commits[:4], 1):
            # 匹配commit（12位短hash优先）
            matched_commit = None
            for real_commit in cve_map.keys():
                if short_commit in real_commit or real_commit.startswith(short_commit):
                    matched_commit = real_commit
                    break
            if not matched_commit:
                print(f"Warning: Commit {short_commit} for {cve_id} EVO{stage} not found in CVE-level results")
                continue

            evo_stats[stage]['total'] += 1
            if cve_map.get(matched_commit, False):
                evo_stats[stage]['correct'] += 1

            print(f"{cve_id} EVO{stage} ({short_commit}): "
                  f"{1 if cve_map.get(matched_commit, False) else 0}/1 commits detected as patch")

    return evo_stats

def main():
    parser = argparse.ArgumentParser(description='Parse PS3 patch evolution accuracy (reference: PatchDiscovery)')
    # parser.add_argument('-proj', '--project', required=True, help='Project name (e.g., tcpdump)')
    parser.add_argument('-proj', '--projects', nargs='*', default=["tcpdump", "imagemagick", "libxml2", "openjpeg", "openssl"], help='Project names to analyze.')
    parser.add_argument('--mode', choices=['func', 'cve'], default='func', help='解析模式：func(函数级)，cve(CVE级)')
    args = parser.parse_args()

    # 初始化全局聚合统计
    if args.mode == 'cve':
        overall_stats = {i: {'correct': 0, 'total': 0} for i in range(1, 5)}
    else:
        overall_stats = {i: {'correct': 0, 'total': 0, 'fn': 0, 'fail': 0} for i in range(1, 5)}

    for project in args.projects:
        print("\n" + "#" * 70)
        print(f"# Processing project: {project}")
        print("#" * 70)

        aftercommits_log_file = f"/home/zhangxb/patch/related-works/CVE-Dataset/PatchEvolution/dataset/Evo_{project}_aftercommits.log"

        if not os.path.exists(aftercommits_log_file):
            print(f"Error: Aftercommits log file not found for {project}: {aftercommits_log_file}")
            continue

        if args.mode == 'cve':
            evo_log_file = f"{project}-cve.log"
            if not os.path.exists(evo_log_file):
                print(f"Error: CVE log file not found for {project}: {evo_log_file}")
                continue

            print(f"Parsing CVE-level evolution results for project: {project}")
            print(f"CVE log: {evo_log_file}")
            print(f"Aftercommits log: {aftercommits_log_file}")
            print("-" * 60)

            evo_cve_results = parse_evo_cve_log(evo_log_file)
            aftercommits = parse_aftercommits_log(aftercommits_log_file)

            print(f"Found {len(evo_cve_results)} CVEs in CVE-level results")
            print(f"Found {len(aftercommits)} CVEs in aftercommits")
            print("-" * 60)

            evo_stats = calculate_accuracy_cve(evo_cve_results, aftercommits)

            # 累加到全局统计
            for stage in range(1, 5):
                overall_stats[stage]['correct'] += evo_stats[stage]['correct']
                overall_stats[stage]['total'] += evo_stats[stage]['total']

            print("\n" + "=" * 60)
            print(f"EVOLUTION ACCURACY RESULTS ({project} - CVE LEVEL)")
            print("=" * 60)
            for stage in range(1, 5):
                stats = evo_stats[stage]
                if stats['total'] > 0:
                    acc = stats['correct'] / stats['total']
                    print(f"EVO{stage}-ACC: {acc:.4f} ({stats['correct']}/{stats['total']} commits detected as patch)")
                else:
                    print(f"EVO{stage}-ACC: No data available")

        else: # func mode
            evo_log_file = f"{project}-func.log"  # 读取 tcpdump-func.log 风格文件
            if not os.path.exists(evo_log_file):
                print(f"Error: Function log file not found for {project}: {evo_log_file}")
                continue

            print(f"Parsing evolution results for project: {project}")
            print(f"Function log: {evo_log_file}")
            print(f"Aftercommits log: {aftercommits_log_file}")
            print("-" * 60)

            evo_results = parse_evo_log(evo_log_file)
            aftercommits = parse_aftercommits_log(aftercommits_log_file)

            print(f"Found {len(evo_results)} CVEs in evolution results")
            print(f"Found {len(aftercommits)} CVEs in aftercommits")
            print("-" * 60)

            evo_stats = calculate_accuracy(evo_results, aftercommits)

            # 累加到全局统计
            for stage in range(1, 5):
                overall_stats[stage]['correct'] += evo_stats[stage]['correct']
                overall_stats[stage]['total'] += evo_stats[stage]['total']
                overall_stats[stage]['fn'] += evo_stats[stage]['fn']
                overall_stats[stage]['fail'] += evo_stats[stage]['fail']

            print("\n" + "=" * 60)
            print(f"EVOLUTION ACCURACY RESULTS ({project})")
            print("=" * 60)
            for stage in range(1, 5):
                stats = evo_stats[stage]
                if stats['total'] > 0:
                    acc = stats['correct'] / stats['total']
                    print(f"EVO{stage}-ACC: {acc:.4f} ({stats['correct']}/{stats['total']} functions correctly detected as patch)")
                else:
                    print(f"EVO{stage}-ACC: No data available")

            print("\n" + "-" * 60)
            print(f"DETAILED STATISTICS ({project})")
            print("-" * 60)
            for stage in range(1, 5):
                stats = evo_stats[stage]
                if stats['total'] > 0:
                    acc = stats['correct'] / stats['total']
                    print(f"EVO{stage}:")
                    print(f"  Total functions tested: {stats['total']}")
                    print(f"  Functions detected as patch (Correct): {stats['correct']}")
                    print(f"  Functions detected as vulnerability (FN): {stats['fn']}")
                    print(f"  Functions failed to determine (Fail): {stats['fail']}")
                    print(f"  Overall accuracy: {acc:.4f}\n")

    # 输出所有项目的聚合结果
    print("\n" + "#" * 70)
    print("# Overall Aggregated Results for All Projects")
    print("#" * 70)

    if args.mode == 'cve':
        print("\n" + "=" * 60)
        print("OVERALL EVOLUTION ACCURACY RESULTS (CVE LEVEL)")
        print("=" * 60)
        for stage in range(1, 5):
            stats = overall_stats[stage]
            if stats['total'] > 0:
                acc = stats['correct'] / stats['total']
                print(f"EVO{stage}-ACC: {acc:.4f} ({stats['correct']}/{stats['total']} commits detected as patch)")
            else:
                print(f"EVO{stage}-ACC: No data available")
    else: # func mode
        print("\n" + "=" * 60)
        print("OVERALL EVOLUTION ACCURACY RESULTS (FUNCTION LEVEL)")
        print("=" * 60)
        for stage in range(1, 5):
            stats = overall_stats[stage]
            if stats['total'] > 0:
                acc = stats['correct'] / stats['total']
                print(f"EVO{stage}-ACC: {acc:.4f} ({stats['correct']}/{stats['total']} functions correctly detected as patch)")
            else:
                print(f"EVO{stage}-ACC: No data available")

        print("\n" + "-" * 60)
        print("OVERALL DETAILED STATISTICS (FUNCTION LEVEL)")
        print("-" * 60)
        for stage in range(1, 5):
            stats = overall_stats[stage]
            if stats['total'] > 0:
                acc = stats['correct'] / stats['total']
                print(f"EVO{stage}:")
                print(f"  Total functions tested: {stats['total']}")
                print(f"  Functions detected as patch (Correct): {stats['correct']}")
                print(f"  Functions detected as vulnerability (FN): {stats['fn']}")
                print(f"  Functions failed to determine (Fail): {stats['fail']}")
                print(f"  Overall accuracy: {acc:.4f}\n")
                print(f"  Overall FNRate: {stats['fn'] / stats['total']:.4f}\n")
                print(f"  Overall FailRate: {stats['fail'] / stats['total']:.4f}\n")


if __name__ == "__main__":
    main()