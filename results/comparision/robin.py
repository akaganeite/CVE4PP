import os
import csv
from collections import defaultdict

def load_robin_cves(robin_dir):
    """
    加载Robin的所有result.csv，返回所有CVE集合和每个CVE的结果
    """
    cve_set = set()
    robin_results = {}
    for fname in os.listdir(robin_dir):
        if fname.endswith('_result.csv'):
            fpath = os.path.join(robin_dir, fname)
            with open(fpath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve = row.get('cve', '').strip()
                    if cve:
                        cve_set.add(cve)
                        # Robin的false_positive/false_negative直接转int
                        fp_val = row.get('false_positive', '').strip()
                        fn_val = row.get('false_negative', '').strip()
                        try:
                            fp_count = int(fp_val) if fp_val else 0
                        except Exception:
                            fp_count = 0
                        try:
                            fn_count = int(fn_val) if fn_val else 0
                        except Exception:
                            fn_count = 0
                        robin_results[cve] = {
                            'succeed': int(row.get('succeed', 0) or 0),
                            'target': int(row.get('target', 1) or 1),
                            'false_positive': fp_count,
                            'false_negative': fn_count
                        }
    return cve_set, robin_results

def load_work_results(work_dir, cve_set):
    """
    加载某个work下所有-cve.csv，返回CVE结果（只统计Robin中出现的CVE）
    """
    results = {}
    for fname in os.listdir(work_dir):
        # React读取_result.csv，其它work读取-cve.csv
        if (work_dir.endswith('React/gcc-o0') and fname.endswith('_result.csv')) or \
           (not work_dir.endswith('React/gcc-o0') and fname.endswith('-cve.csv')):
            fpath = os.path.join(work_dir, fname)
            with open(fpath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve = row.get('cve', '').strip()
                    if cve and cve in cve_set:
                        fp_val = row.get('false_positive', '').strip()
                        fn_val = row.get('false_negative', '').strip()
                        if fp_val:
                            fp_count = len(fp_val.split(';'))
                        else:
                            fp_count = 0
                        if fn_val:
                            fn_count = len(fn_val.split(';'))
                        else:
                            fn_count = 0
                        results[cve] = {
                            'succeed': int(row.get('succeed', 0) or 0),
                            'target': int(row.get('target', 1) or 1),
                            'false_positive': fp_count,
                            'false_negative': fn_count
                        }
    return results

def calc_accuracy(results):
    """
    计算准确率
    """
    total_succeed = 0
    total_target = 0
    total_fp_fn = 0
    for v in results.values():
        total_succeed += v['succeed']
        total_target += v['target']
        total_fp_fn += v['false_positive'] + v['false_negative']
    acc1 = total_succeed / total_target if total_target > 0 else 0
    acc2 = total_succeed / (total_succeed + total_fp_fn) if (total_succeed + total_fp_fn) > 0 else 0
    return acc1, acc2, len(results)

def main():
    robin_dir = '../Robin/gcc-o0/'
    works = ['PatchDiscovery', 'BinXray', 'PS3','React']
    work_dirs = {w: os.path.join('..', w, 'gcc-o0') for w in works}

    # 1. Robin的CVE全集
    cve_set, robin_results = load_robin_cves(robin_dir)
    print(f'Robin CVE数量: {len(cve_set)}')
    acc1, acc2, n = calc_accuracy(robin_results)
    print(f'Robin: matched={n}, accuracy_succeed_target={acc1:.4f}, accuracy_succeed_fp_fn={acc2:.4f}')

    # 2. 其它work
    for w in works:
        work_dir = work_dirs[w]
        work_results = load_work_results(work_dir, cve_set)
        acc1, acc2, n = calc_accuracy(work_results)
        print(f'{w}: matched={n}, accuracy_succeed_target={acc1:.4f}, accuracy_succeed_fp_fn={acc2:.4f}')

if __name__ == '__main__':
    main()
