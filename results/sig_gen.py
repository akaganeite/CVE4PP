#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统计各个 work (BinXray / PatchDiscovery / PS3 / Robin) 的 *_result.csv 里的失败情况。

规则回顾：
1. 所有目录路径形如: <base>/<Work>/gcc-o0/*_result.csv
2. 需要从每个 *_result.csv 中读取关键信息：
   - failed_versions : 失败用例总数 (整数)
   - targets         : 全部测试用例总数 (整数)
   - 可能出现的细分原因：no_sig, too_much_diff, cant_tell (都为整数或布尔/字符串 true)

分类规则：
  PS3:            将 no_sig 的那些失败计入 failed_gen，其余 failed_versions - no_sig 计入 failed_test。
  PatchDiscovery: 全部 failed_versions 计入 failed_gen。
  BinXray:        too_much_diff + cant_tell 计入 failed_test，其余 (failed_versions - 这两项) 计入 failed_gen。
  Robin:          全部 failed_versions 计入 failed_test。

	输出：
	  每个 work 一行摘要：work, targets, failed_versions, fail_all, failed_gen, failed_test, fail_gen, fail_test
  最后再输出一个 Overall 汇总。

CSV 格式的兼容性：
  1) 可能是简单的 key,value 行（无表头）。
  2) 也可能是带表头的一行或多行；若检测到表头包含 failed_versions / targets 则直接从第一行（或做聚合）提取。
  3) 若值是布尔字符串 ("true"/"false") 或空，则按需要转为 int；缺失键按 0 处理。

使用：
  python sig_gen.py [--base BASE_DIR] [--detail]
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List

WORKS = ["BinXray", "PatchDiscovery", "PS3", "React", "Robin"]


@dataclass
class FileStat:
    work: str
    file: Path
    targets: int = 0
    failed_versions: int = 0
    failed_gen: int = 0
    failed_test: int = 0
    no_sig: int = 0
    too_much_diff: int = 0
    cant_tell: int = 0
    fp: int = 0
    fn: int = 0

    def to_row(self) -> Dict[str, str]:
        fail_all = self.failed_versions / self.targets if self.targets else 0.0
        fail_gen = self.failed_gen / self.targets if self.targets else 0.0
        fail_test = self.failed_test / self.targets if self.targets else 0.0
        fp_rate = self.fp / self.targets if self.targets else 0.0
        fn_rate = self.fn / self.targets if self.targets else 0.0
        return {
            "work": self.work,
            "file": self.file.name,
            "targets": str(self.targets),
            "failed_versions": str(self.failed_versions),
            "fail_all": f"{fail_all:.4f}",
            "failed_gen": str(self.failed_gen),
            "failed_test": str(self.failed_test),
            "fail_gen": f"{fail_gen:.4f}",
            "fail_test": f"{fail_test:.4f}",
            "fp": str(self.fp),
            "fn": str(self.fn),
            "fp_rate": f"{fp_rate:.4f}",
            "fn_rate": f"{fn_rate:.4f}",
        }


@dataclass
class WorkAggregate:
    work: str
    targets: int = 0
    failed_versions: int = 0
    failed_gen: int = 0
    failed_test: int = 0
    no_sig: int = 0
    too_much_diff: int = 0
    cant_tell: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, fs: FileStat):
        self.targets += fs.targets
        self.failed_versions += fs.failed_versions
        self.failed_gen += fs.failed_gen
        self.failed_test += fs.failed_test
        self.no_sig += fs.no_sig
        self.too_much_diff += fs.too_much_diff
        self.cant_tell += fs.cant_tell
        self.fp += fs.fp
        self.fn += fs.fn

    def summary_row(self) -> Dict[str, str]:
        fail_all = self.failed_versions / self.targets if self.targets else 0.0
        fail_gen = self.failed_gen / self.targets if self.targets else 0.0
        fail_test = self.failed_test / self.targets if self.targets else 0.0
        fp_rate = self.fp / self.targets if self.targets else 0.0
        fn_rate = self.fn / self.targets if self.targets else 0.0
        return {
            "work": self.work,
            "targets": str(self.targets),
            "failed_versions": str(self.failed_versions),
            "fail_all": f"{fail_all:.4f}",
            "failed_gen": str(self.failed_gen),
            "failed_test": str(self.failed_test),
            "fail_gen": f"{fail_gen:.4f}",
            "fail_test": f"{fail_test:.4f}",
            "fp": str(self.fp),
            "fn": str(self.fn),
            "fp_rate": f"{fp_rate:.4f}",
            "fn_rate": f"{fn_rate:.4f}",
        }


def parse_key_value_csv(path: Path) -> Dict[str, int]:
    """解析 *_result.csv 文件，返回 key->int 值字典。

	尝试多种格式：
	  - 多行: key,value
	  - 含表头: header 行 + 数据行(s)
	若某值为布尔字符串 true/false 则转换为 1/0。
	"""
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return {}
    lines = [l for l in text.splitlines() if l.strip()]
    # 尝试检测表头
    first = lines[0].split(',')
    keys = [k.strip() for k in first]
    result: Dict[str, int] = {}

    def norm_val(v: str) -> int:
        v = v.strip().strip('\"').lower()
        if v in ("true", "yes"):  # 解释为 1
            return 1
        if v in ("false", "no", ""):  # 解释为 0
            return 0
        try:
            if "." in v:
                return int(float(v))
            return int(v)
        except ValueError:
            return 0

    if len(lines) > 1 and ("failed_versions" in keys or "targets" in keys or keys[0] == 'cve'):
        # 认为是表格型；交给专用解析
        return parse_table_file_from_text(lines)

    # 否则假设每行是 key,value
    for line in lines:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 2:
            k = parts[0]
            v = norm_val(parts[1])
            if k:
                result[k] = v
        # 新增fp/fn字段
        if len(parts) >= 2 and parts[0] in ('fp', 'fn'):
            result[parts[0]] = norm_val(parts[1])
        # 新增 false_positive/false_negative 字段解析
        if len(parts) >= 2 and parts[0] in ('false_positive', 'false_negative'):
            result[parts[0]] = parts[1]
    return result


def classify(work: str, data: Dict[str, int]) -> FileStat:
    fs = FileStat(work=work, file=Path(data.get('__file__', '')))
    fs.targets = data.get('targets', 0)
    fs.failed_versions = data.get('failed_versions', 0)
    fs.no_sig = data.get('no_sig', 0)
    fs.too_much_diff = data.get('too_much_diff', 0)
    fs.cant_tell = data.get('cant_tell', 0)
    fs.failed_gen_cves = data.get('failed_gen_cves', []) # 新增

    # 处理 fp/fn
    if work in ('BinXray', 'PatchDiscovery'):
        fp_field = data.get('false_positive', '')
        fn_field = data.get('false_negative', '')
        if isinstance(fp_field, int):
            fs.fp = fp_field
        else:
            fs.fp = len([v for v in str(fp_field).split(';') if v.strip()])
            print(f"Debug: {fs.file} fp_field='{fp_field}' => fp={fs.fp}")
        if isinstance(fn_field, int):
            fs.fn = fn_field
        else:
            fs.fn = len([v for v in str(fn_field).split(';') if v.strip()])
    else:
        fs.fp = data.get('fp', 0)
        fs.fn = data.get('fn', 0)

    if work == 'PS3':
        fs.failed_gen = fs.no_sig
        fs.failed_test = fs.failed_versions
        fs.failed_versions = fs.failed_gen + fs.failed_test
    elif work == 'PatchDiscovery':
        fs.failed_gen = fs.failed_versions
        fs.failed_test = 0
    elif work == 'BinXray':
        fs.failed_test = fs.too_much_diff + fs.cant_tell
        fs.failed_gen = fs.failed_versions
        fs.failed_versions = fs.failed_gen + fs.failed_test
    elif work in ('React', 'Robin'):
        fs.failed_gen = 0
        fs.failed_test = fs.failed_versions
    else:
        fs.failed_gen = 0
        fs.failed_test = fs.failed_versions
    return fs


def parse_table_file_from_text(lines: List[str]) -> Dict[str, int]:
    """从行列表解析表格型 *_result.csv。
    首行是 header。统计：targets, failed_versions, no_sig, too_much_diff, cant_tell，及区分 failed_versions_no_sig/with_sig。
	failed_versions 字段/或 failed 字段若包含版本列表(分号分隔)则按数量计；为空则记 0（不回推）。
	no_sig 为 true 时，把该行的失败数计入 failed_versions_no_sig。
    """
    head = [h.strip() for h in lines[0].split(',')]
    idx = {h: i for i, h in enumerate(head)}
    res: Dict[str, int] = {k: 0 for k in ['targets','failed_versions','no_sig','too_much_diff','cant_tell','failed_versions_no_sig','failed_versions_with_sig','fp','fn']}
    res['failed_gen_cves'] = [] # 新增

    def cell(row: List[str], name: str) -> str:
        if name not in idx:
            return ''
        i = idx[name]
        return row[i].strip() if i < len(row) else ''

    for line in lines[1:]:
        if not line.strip():
            continue
        row = [c for c in line.split(',')]
        target_val = cell(row,'targets') or cell(row,'target')
        if target_val.isdigit():
            res['targets'] += int(target_val)
        
        # 检查Robin的signature_generated
        is_sig_gen_false = False
        if 'signature_generated' in idx:
            if cell(row, 'signature_generated').lower() == 'false':
                is_sig_gen_false = True

        failed_field = cell(row,'failed_versions') or cell(row,'failed')
        failed_count = 0
        if failed_field:
            if failed_field.isdigit():
                failed_count = int(failed_field)
            else:
                parts = [p for p in failed_field.split(';') if p]
                failed_count = len(parts)
        res['failed_versions'] += failed_count

        if is_sig_gen_false:
            cve_id = cell(row, 'cve')
            if cve_id:
                res['failed_gen_cves'].append(cve_id)

        for name in ('too_much_diff','cant_tell','fp','fn'):
            val = cell(row,name)
            if val:
                if val.isdigit():
                    res[name] += int(val)
                else:
                    res[name] += len([p for p in val.split(';') if p])
        # 解析 false_positive/false_negative 字段
        for name in ('false_positive', 'false_negative'):
            val = cell(row, name)
            if val:
                res[name] = res.get(name, '')
                if res[name]:
                    res[name] += ';' + val
                else:
                    res[name] = val
        no_sig_val = cell(row,'no_sig').lower()
        if no_sig_val == 'true':
            res['no_sig'] += int(target_val)
            res['failed_versions_no_sig'] += failed_count if failed_count else 0
        else:
            res['failed_versions_with_sig'] += failed_count

    return res


def collect(base: Path, detail: bool = False) -> None:
    aggregates: Dict[str, WorkAggregate] = {w: WorkAggregate(work=w) for w in WORKS}
    detail_rows: List[FileStat] = []
    robin_failed_gen_cves = set() # 用于收集Robin的failed_gen CVE

    for work in WORKS:
        # 兼容：有的 work (如 PatchDiscovery) 的 *_result.csv 直接在其根目录
        work_dir_gcc = base / work / 'gcc-o0'
        if work_dir_gcc.is_dir():
            candidate_dirs = [work_dir_gcc]
        else:
            work_dir_root = base / work
            if not work_dir_root.is_dir():
                continue
            candidate_dirs = [work_dir_root]

        for dir_path in candidate_dirs:
            for csv_file in sorted(dir_path.glob('*_result.csv')):
                data = parse_key_value_csv(csv_file)
                data['__file__'] = str(csv_file)
                fs = classify(work, data)
                fs.file = csv_file
                # 删除下面两行，避免覆盖 classify 的 fp/fn
                # fs.fp = data.get('fp', 0)
                # fs.fn = data.get('fn', 0)
                aggregates[work].add(fs)
                if work == 'Robin' and fs.failed_gen_cves:
                    robin_failed_gen_cves.update(fs.failed_gen_cves)
                if detail:
                    detail_rows.append(fs)

    # 输出（Markdown + CSV 文件）
    header = [
        'work', 'targets', 'failed_versions', 'fail_all',
        'failed_gen', 'failed_test', 'fail_gen', 'fail_test', 'fp', 'fn', 'fp_rate', 'fn_rate'
    ]
    print('# 汇总')
    print('|' + '|'.join(header) + '|')
    print('|' + '|'.join(['---'] * len(header)) + '|')
    csv_lines = [','.join(header)]
    overall = WorkAggregate(work='Overall')
    for work in WORKS:
        agg = aggregates[work]
        if agg.targets == 0 and agg.failed_versions == 0:
            continue
        row = agg.summary_row()
        csv_line = ','.join(row[h] for h in header)
        csv_lines.append(csv_line)
        print('|' + '|'.join(row[h] for h in header) + '|')
        overall.add(FileStat(work=work, file=Path('-'), targets=agg.targets,
                      failed_versions=agg.failed_versions,
                      failed_gen=agg.failed_gen, failed_test=agg.failed_test,
                      no_sig=agg.no_sig, too_much_diff=agg.too_much_diff,
                      cant_tell=agg.cant_tell, fp=agg.fp, fn=agg.fn))
    if overall.targets:
        row = overall.summary_row()
        csv_line = ','.join(row[h] for h in header)
        csv_lines.append(csv_line)
        print('|' + '|'.join(row[h] for h in header) + '|')

    # 写 CSV 文件
    csv_path = base / 'sig_gen.csv'
    csv_path.write_text('\n'.join(csv_lines) + '\n', encoding='utf-8')
    print(f"\n已生成: {csv_path}")

    # 将Robin的failed_gen CVEs写入日志文件
    if robin_failed_gen_cves:
        log_path = base / 'robin_failed_gen_cves.log'
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write("[\n")
            for cve in sorted(list(robin_failed_gen_cves)):
                f.write(f"    \"{cve}\",\n")
            f.write("]\n")
        print(f"Robin failed_gen CVEs 已写入: {log_path}")

    if detail and detail_rows:
        print('\n# 文件级明细')
        d_header = ['work', 'file', 'targets', 'failed_versions', 'fail_all', 'failed_gen', 'failed_test', 'fail_gen', 'fail_test', 'fp', 'fn']
        print('|' + '|'.join(d_header) + '|')
        print('|' + '|'.join(['---'] * len(d_header)) + '|')
        for fs in detail_rows:
            r = fs.to_row()
            print('|' + '|'.join(r[h] for h in d_header) + '|')


def main():
    parser = argparse.ArgumentParser(description='统计各个 work 的失败概率并细分失败类型')
    parser.add_argument('--base', type=str, default='.', help='基准目录(包含各 work 子目录)')
    parser.add_argument('--detail', action='store_true', help='输出每个文件的详细信息')
    args = parser.parse_args()
    base = Path(args.base).resolve()
    collect(base, detail=args.detail)


if __name__ == '__main__':
    main()
