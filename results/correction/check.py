#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
读取 {project}_correction.json 并提取所有 CVE 号。

用法示例：
  python check.py -proj tcpdump
  python check.py -proj ffmpeg -o ffmpeg_cves.txt
  python check.py -proj tcpdump --base /path/to/correction

行为：
- 在 base 目录查找 ./{project}_correction.json；若未找到，继续在 ./correction/ 下尝试
- 递归遍历 JSON 的 key/value，匹配所有形如 CVE-YYYY-NNNN 的字符串
- 去重并按 (year, number) 排序输出（默认一行一个）；若指定 -o 则写入文件
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Set

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def collect_cves(obj: Any, acc: Set[str]) -> None:
    """从任意 JSON 结构中递归收集 CVE IDs 到 acc。"""
    if obj is None:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                acc.update(CVE_RE.findall(k))
            collect_cves(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            collect_cves(it, acc)
    elif isinstance(obj, str):
        acc.update(CVE_RE.findall(obj))
    # 其他类型忽略


def resolve_json_path(project: str, base: str | None) -> Path:
    """根据 project 与 base 解析 JSON 路径，支持在 base 与 base/correction 两处查找。"""
    if base:
        base_dir = Path(base).resolve()
    else:
        # 默认用脚本所在目录
        base_dir = Path(__file__).parent.resolve()

    cand1 = base_dir / f"{project}_correction.json"
    cand2 = base_dir / "correction" / f"{project}_correction.json"

    if cand1.exists():
        return cand1
    if cand2.exists():
        return cand2

    # 向上一级也尝试（兼容从 results 目录运行）
    parent = base_dir.parent
    cand3 = parent / "correction" / f"{project}_correction.json"
    if cand3.exists():
        return cand3

    return cand1  # 返回首选路径用于错误提示


def main() -> int:
    parser = argparse.ArgumentParser(description="提取 {project}_correction.json 中的 CVE 号")
    parser.add_argument("-proj", required=True, help="项目名，如 tcpdump / ffmpeg / freetype 等")
    parser.add_argument("-o", "--output", help="输出到文件（可选），默认打印到标准输出")
    parser.add_argument("--base", default=None, help="包含 *_correction.json 的目录，缺省为脚本所在目录；也会自动尝试 ./correction/")
    args = parser.parse_args()

    json_path = resolve_json_path(args.proj, args.base)

    if not json_path.exists():
        print(f"错误：未找到文件 {json_path}", file=sys.stderr)
        return 1

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"错误：读取或解析 JSON 失败：{e}", file=sys.stderr)
        return 1

    cves: Set[str] = set()
    collect_cves(data, cves)

    # 规范化排序（按年份和编号排序），退化为字典序
    def sort_key(cve: str):
        # CVE-YYYY-NNNN...
        try:
            parts = cve.split("-")
            year = int(parts[1])
            num = int(parts[2])
            return (year, num)
        except Exception:
            return (9999, 10**9, cve)

    sorted_cves = sorted(cves, key=sort_key)

    if args.output:
        out_path = Path(args.output).resolve()
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                for cve in sorted_cves:
                    f.write(cve + "\n")
            print(f"已写入 {len(sorted_cves)} 条 CVE 到 {out_path}")
        except Exception as e:
            print(f"错误：写入输出文件失败：{e}", file=sys.stderr)
            return 1
    else:
        for cve in sorted_cves:
            print(cve)

    return 0


if __name__ == "__main__":
    sys.exit(main())
