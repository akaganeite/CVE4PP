#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re

def parse_patchdiscovery_report(path):
    """
    解析 PatchDiscovery 报告文本，返回分阶段累计统计：
      stats = {
        1: {'total': int, 'patch': int, 'vuln': int},
        2: {...}, 3: {...}, 4: {...}
      }
    """
    stats = {1: {'total': 0, 'patch': 0, 'vuln': 0},
             2: {'total': 0, 'patch': 0, 'vuln': 0},
             3: {'total': 0, 'patch': 0, 'vuln': 0},
             4: {'total': 0, 'patch': 0, 'vuln': 0}}

    evo_re = re.compile(r'^EVO([1-4]):\s*$')
    total_re = re.compile(r'^\s*Total functions tested:\s*(\d+)\s*$')
    patch_re = re.compile(r'^\s*Functions detected as patch:\s*(\d+)\s*$')
    vuln_re = re.compile(r'^\s*Functions detected as vulnerability:\s*(\d+)\s*$')

    current_stage = None
    pending_block = {'total': None, 'patch': None, 'vuln': None}

    def flush_stage(stage, block):
        if stage is None:
            return
        t = block['total'] if block['total'] is not None else 0
        p = block['patch'] if block['patch'] is not None else 0
        v = block['vuln'] if block['vuln'] is not None else (t - p if t and p is not None else 0)
        stats[stage]['total'] += t
        stats[stage]['patch'] += p
        stats[stage]['vuln'] += v
        block['total'] = block['patch'] = block['vuln'] = None

    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.rstrip('\n')
            m_evo = evo_re.match(line.strip())
            if m_evo:
                # 新阶段开始，冲刷上一阶段的临时数据
                flush_stage(current_stage, pending_block)
                current_stage = int(m_evo.group(1))
                continue

            if current_stage is None:
                continue

            m_total = total_re.match(line)
            if m_total:
                pending_block['total'] = int(m_total.group(1))
                continue

            m_patch = patch_re.match(line)
            if m_patch:
                pending_block['patch'] = int(m_patch.group(1))
                continue

            m_vuln = vuln_re.match(line)
            if m_vuln:
                pending_block['vuln'] = int(m_vuln.group(1))
                continue

    # 处理文件末尾可能未冲刷的数据
    flush_stage(current_stage, pending_block)
    return stats

def print_overall(stats):
    print("------------------------------------------------------------")
    print("ALL PROJECTS (AGGREGATED)")
    print("------------------------------------------------------------")
    for stage in range(1, 5):
        t = stats[stage]['total']
        p = stats[stage]['patch']
        v = stats[stage]['vuln']
        acc = (p / t) if t > 0 else 0.0
        print(f"EVO{stage}:")
        print(f"  Total functions tested: {t}")
        print(f"  Functions detected as patch: {p}")
        print(f"  Functions detected as vulnerability: {v}")
        print(f"  Overall accuracy: {acc:.4f}\n")

def main():
    parser = argparse.ArgumentParser(description="汇总所有 project 的 EVO1~EVO4 指标（来自 PatchDiscovery 报告）")
    parser.add_argument('--input', default='/home/zhangxb/patch/related-works/CVE-Dataset/New/RQs/patchevolution/PatchDiscovery',
                        help='PatchDiscovery 报告文本路径')
    args = parser.parse_args()

    stats = parse_patchdiscovery_report(args.input)
    print_overall(stats)

if __name__ == "__main__":
    main()
