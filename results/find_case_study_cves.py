import csv
import os
import glob
import pandas as pd
from pathlib import Path

# 要进行案例研究的 CVE 列表
CVES_TO_FIND = [
    "CVE-2010-2500", "CVE-2010-2805", "CVE-2012-5669", "CVE-2013-0338",
    "CVE-2013-0339", "CVE-2013-1969", "CVE-2014-2241", "CVE-2014-3660",
    "CVE-2014-9658", "CVE-2014-9663", "CVE-2014-9746", "CVE-2015-3196",
    "CVE-2015-5312", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-8241",
    "CVE-2015-8317", "CVE-2015-8871", "CVE-2015-8895", "CVE-2015-8896",
    "CVE-2016-0702", "CVE-2016-0798", "CVE-2016-1833", "CVE-2016-1834",
    "CVE-2016-1840", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2108",
    "CVE-2016-2176", "CVE-2016-2177", "CVE-2016-4449", "CVE-2016-4658",
    "CVE-2016-7534", "CVE-2016-8617", "CVE-2016-8623", "CVE-2016-8624",
    "CVE-2016-8625", "CVE-2016-9586", "CVE-2017-12894", "CVE-2017-12897",
    "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-13029", "CVE-2017-13040",
    "CVE-2017-13043", "CVE-2017-13046", "CVE-2017-13689", "CVE-2017-13690",
    "CVE-2017-13725", "CVE-2017-14039", "CVE-2017-14151", "CVE-2017-14174",
    "CVE-2017-14729", "CVE-2017-14974", "CVE-2017-16828", "CVE-2017-16932",
    "CVE-2017-17080", "CVE-2017-17126", "CVE-2017-5130", "CVE-2017-7375",
    "CVE-2017-9040", "CVE-2017-9955", "CVE-2018-1000007", "CVE-2018-1000120",
    "CVE-2018-14470", "CVE-2018-14882", "CVE-2018-17358", "CVE-2018-20847",
    "CVE-2018-7643", "CVE-2019-14981", "CVE-2019-1543", "CVE-2019-1547",
    "CVE-2019-16711", "CVE-2019-17541", "CVE-2019-19646", "CVE-2019-19956",
    "CVE-2019-5435", "CVE-2020-11656", "CVE-2020-16590", "CVE-2020-22024",
    "CVE-2020-22030", "CVE-2020-22036", "CVE-2020-22044", "CVE-2020-25663",
    "CVE-2020-25667", "CVE-2020-25675", "CVE-2020-25676", "CVE-2020-27750",
    "CVE-2020-27765", "CVE-2020-27769", "CVE-2020-27829", "CVE-2020-7595",
    "CVE-2020-8169", "CVE-2021-20311", "CVE-2021-20312", "CVE-2021-20313",
    "CVE-2021-3574", "CVE-2021-3962", "CVE-2021-4044", "CVE-2022-0284",
    "CVE-2022-1343", "CVE-2022-23308", "CVE-2022-29824", "CVE-2022-3602",
    "CVE-2022-3786", "CVE-2022-46908", "CVE-2022-48541", "CVE-2023-0216",
    "CVE-2023-1579", "CVE-2023-2650", "CVE-2023-34152", "CVE-2024-0727"
]

# 要搜索的 work 列表
WORKS = ['PS3', 'Robin', 'React', 'BinXray', 'PatchDiscovery']

def find_and_calculate_accuracy():
    """
    查找所有 work 中的 CVE 结果，并在内存中聚合数据以计算总体准确率。
    """
    print("开始查找指定的 CVEs 并计算准确率...")
    
    # 用于存储每个 work 的总 succeed 和 total
    # e.g. {'PS3': {'succeed': 10, 'target': 15}, ...}
    work_totals = {work: {'succeed': 0, 'target': 0} for work in WORKS}
    
    # 记录已处理的 CVE，避免在多个文件中重复计算同一个 CVE
    processed_cves = {work: set() for work in WORKS}

    # 遍历所有 work
    for work in WORKS:
        # 构造搜索路径 (相对于当前脚本所在目录)
        if work == 'React':
            search_path = f"./{work}/gcc-o0/*_result.csv"
        else:
            search_path = f"./{work}/gcc-o0/*-cve.csv"

        csv_files = glob.glob(search_path)
        
        if not csv_files:
            print(f"在 {work} 中没有找到 CSV 文件，路径: {search_path}")
            continue
            
        print(f"--- 正在处理 {work} ---")

        # 遍历找到的每个 CSV 文件
        for csv_path in csv_files:
            try:
                with open(csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        cve_id = row.get('cve', '').strip()
                        
                        # 检查 CVE 是否在目标列表且尚未被处理
                        if cve_id in CVES_TO_FIND and cve_id not in processed_cves[work]:
                            try:
                                succeed = int(row.get('succeed', 0) or 0)
                                target = int(row.get('target', 1) or 1)
                                if succeed == 0 and target == 1:
                                    continue
                                # 累加 succeed 和 target
                                work_totals[work]['succeed'] += succeed
                                work_totals[work]['target'] += target
                                
                                # 标记此 CVE 已处理
                                processed_cves[work].add(cve_id)
                                print(f"  找到 CVE: {cve_id} -> succeed/target: {succeed}/{target}")

                            except (ValueError, TypeError):
                                print(f"    警告: 在文件 {csv_path} 的 CVE {cve_id} 行中跳过无效的 succeed/target 值。")

            except Exception as e:
                print(f"读取或处理文件 {csv_path} 时出错: {e}")

    # 计算并打印最终的准确率
    print("\n" + "="*45)
    print("每个工作的总体准确率 (succeed / target):")
    print("="*45)

    for work, totals in work_totals.items():
        total_succeed = totals['succeed']
        total_target = totals['target']

        if total_target > 0:
            accuracy = (total_succeed / total_target) * 100
            print(f"{work:<15} | 准确率: {accuracy:.2f}% ({total_succeed}/{total_target})")
        else:
            print(f"{work:<15} | 未找到该工作的有效数据。")
    
    print("="*45)
    print("\n计算完成。")


if __name__ == "__main__":
    find_and_calculate_accuracy()
