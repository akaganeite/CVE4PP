#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re

def parse_ps3_report(path):
    """
    解析 PS3 报告文本，返回分阶段累计统计：
      stats = {
        1: {'total': int, 'patch': int, 'vuln': int},
        2: {...}, 3: {...}, 4: {...}
      }
    仅统计函数粒度（Total/Patch/Vuln），忽略 ACC 行与 CVE 粒度统计。
    """
    stats = {1: {'total': 0, 'patch': 0, 'vuln': 0},
             2: {'total': 0, 'patch': 0, 'vuln': 0},
             3: {'total': 0, 'patch': 0, 'vuln': 0},
             4: {'total': 0, 'patch': 0, 'vuln': 0}}

    evo_re = re.compile(r'^\s*EVO([1-4]):\s*$')
    total_re = re.compile(r'^\s*Total functions tested:\s*(\d+)\s*$')
    patch_re = re.compile(r'^\s*Functions detected as patch:\s*(\d+)\s*$')
    vuln_re = re.compile(r'^\s*Functions detected as vulnerability:\s*(\d+)\s*$')
    acc_line_re = re.compile(r'^\s*EVO[1-4]-ACC:')  # 忽略
    sep_re = re.compile(r'^-+|^=+|\s*FUNC:\s*$|\s*CVE:\s*$')  # 分割或子块标题

    current_stage = None
    # 每个 EVO 块的暂存，遇到下一个 EVO 或分割线时冲刷
    pending = {'total': None, 'patch': None, 'vuln': None}

    def flush(stage, buf):
        if stage is None:
            buf['total'] = buf['patch'] = buf['vuln'] = None
            return
        t = int(buf['total']) if buf['total'] is not None else 0
        p = int(buf['patch']) if buf['patch'] is not None else 0
        v = int(buf['vuln']) if buf['vuln'] is not None else 0
        # 若缺失 vuln，则用 total - patch 兜底（与报告语义一致）
        if v == 0 and (buf['vuln'] is None) and t and (p is not None):
            v = t - p
        stats[stage]['total'] += t
        stats[stage]['patch'] += p
        stats[stage]['vuln'] += v
        buf['total'] = buf['patch'] = buf['vuln'] = None

    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.rstrip('\n')

            # 忽略 ACC 行
            if acc_line_re.match(line.strip()):
                continue

            # 分隔线或子块标题到来，尝试冲刷当前 EVO
            if sep_re.match(line.strip()):
                flush(current_stage, pending)
                current_stage = None
                continue

            m_evo = evo_re.match(line.strip())
            if m_evo:
                # 新 EVO 开始，先冲刷上一段
                flush(current_stage, pending)
                current_stage = int(m_evo.group(1))
                continue

            if current_stage is None:
                continue

            m_total = total_re.match(line)
            if m_total:
                pending['total'] = int(m_total.group(1))
                continue

            m_patch = patch_re.match(line)
            if m_patch:
                pending['patch'] = int(m_patch.group(1))
                continue

            m_vuln = vuln_re.match(line)
            if m_vuln:
                pending['vuln'] = int(m_vuln.group(1))
                continue

    # 文件结束，冲刷最后一段
    flush(current_stage, pending)
    return stats

def print_overall(stats):
    print("------------------------------------------------------------")
    print("ALL PROJECTS (AGGREGATED FROM PS3)")
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
    parser = argparse.ArgumentParser(description="汇总 PS3 报告的所有项目 EVO1~EVO4 函数级统计")
    parser.add_argument('--input', default='/home/zhangxb/patch/related-works/CVE-Dataset/New/RQs/patchevolution/PS3',
                        help='PS3 报告文本路径')
    args = parser.parse_args()

    stats = parse_ps3_report(args.input)
    print_overall(stats)

if __name__ == '__main__':
    main()
