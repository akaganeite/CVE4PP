import re
import json
import csv
from collections import defaultdict

PROJECTS = [
    "binutils","curl","ffmpeg","freetype","imagemagick",
    "libxml2","openssl","openjpeg","sqlite","tcpdump"
]

def extract_version(binary_path):
    s = binary_path
    first_dash = s.find('-')
    last_dash = s.rfind('-', 0, s.rfind('-'))
    return s[first_dash + 1:last_dash]

def load_ground_truth(json_path):
    with open(json_path, 'r') as f:
        data = json.load(f)
    ground_truth_dict = {}
    for cve, info in data.items():
        for v in info.get('vuln', []):
            ground_truth_dict[(cve, v)] = 'vuln'
        for v in info.get('patch', []):
            ground_truth_dict[(cve, v)] = 'patch'
    return ground_truth_dict

def parse_details_log(details_log_path):
    """返回 set((cve, func, version)) 作为 fail 检测集合"""
    fail_set = set()
    last_cve, last_func, last_version = None, None, None
    with open(details_log_path, 'r') as f:
        for line in f:
            if 'cmd:' in line:
                m = re.search(r'--cve_id (\S+) --target_bin (\S+) --vul_func_name (\S+)', line)
                if m:
                    last_cve, last_bin, last_func = m.groups()
                    last_version = extract_version(last_bin)
            elif 'ERROR - fail' in line:
                # 只有遇到fail时才用最近的cmd缓存
                if last_cve and last_func and last_version:
                    fail_set.add((last_cve, last_func, last_version))
    return fail_set

def parse_log(log_path, ground_truth_dict, fail_set):
    cve_version_func_results = defaultdict(lambda: defaultdict(lambda: defaultdict(str)))
    with open(log_path, 'r') as f:
        lines = f.readlines()

    current_cve = None
    current_binary = None
    current_func = None
    current_score = None

    for line in lines:
        if line.startswith('CVE ID:'):
            current_cve = line.strip().split(':', 1)[1].strip()
        elif line.startswith('Target Binary:'):
            current_binary = line.strip().split(':', 1)[1].strip()
            current_version = extract_version(current_binary)
        elif line.startswith('Vulnerable Function Name:'):
            current_func = line.strip().split(':', 1)[1].strip()
        elif line.startswith('Overall Score is:'):
            score_str = line.strip().split(':', 1)[1].strip()
            try:
                current_score = float(score_str)
            except:
                current_score = None
            if current_cve and current_func and current_version:
                gt = ground_truth_dict.get((current_cve, current_version), None)
                if gt is None or current_score is None:
                    continue
                if gt == 'vuln':
                    if current_score < 0:
                        cve_version_func_results[current_cve][current_version][current_func] = 'tn'
                    else:
                        cve_version_func_results[current_cve][current_version][current_func] = 'fp'
                elif gt == 'patch':
                    if current_score > 0:
                        cve_version_func_results[current_cve][current_version][current_func] = 'tp'
                    else:
                        cve_version_func_results[current_cve][current_version][current_func] = 'fn'
            current_func = None
            current_score = None

    # 把 fail_set 里的所有 (cve, func, version) 补充进结果
    for cve, func, version in fail_set:
        cve_version_func_results[cve][version][func] = 'fail'

    # 聚合为CVE粒度
    cve_stats = {}
    for cve, version_dict in cve_version_func_results.items():
        tp, tn, fp, fn, fail = 0, 0, 0, 0, 0
        for version, func_results in version_dict.items():
            labels = list(func_results.values())
            if 'fail' in labels:
                fail += 1
            elif 'fp' in labels:
                fp += 1
            elif 'fn' in labels:
                fn += 1
            elif labels and all(l == 'tp' for l in labels):
                tp += 1
            elif labels and all(l == 'tn' for l in labels):
                tn += 1
        cve_stats[cve] = {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn, 'fail': fail, 'target': len(version_dict)}
    return cve_stats, cve_version_func_results

def print_project_stats(project, cve_stats):
    total_tp = sum(stats['tp'] for stats in cve_stats.values())
    total_tn = sum(stats['tn'] for stats in cve_stats.values())
    total_fp = sum(stats['fp'] for stats in cve_stats.values())
    total_fn = sum(stats['fn'] for stats in cve_stats.values())
    total_fail = sum(stats['fail'] for stats in cve_stats.values())
    total_target = sum(stats['target'] for stats in cve_stats.values())
    total_succeed = total_tp + total_tn

    accuracy = total_succeed / total_target if total_target > 0 else 0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n--- {project} 聚合统计 ---")
    print(f"TP={total_tp} TN={total_tn} FP={total_fp} FN={total_fn} FAIL={total_fail} Target={total_target}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1_score:.4f}")

    return total_tp, total_tn, total_fp, total_fn, total_fail, total_target

def main():
    all_tp, all_tn, all_fp, all_fn, all_fail, all_target = 0, 0, 0, 0, 0, 0
    for project in PROJECTS:
        json_path = f"../../testset/{project}/testset.json"
        log_path = f"./gcc-o0/{project}-result.log"
        details_log_path = f"./gcc-o0/{project}-details.log"
        try:
            ground_truth_dict = load_ground_truth(json_path)
        except Exception as e:
            print(f"{project}: ground truth 加载失败: {e}")
            continue
        try:
            fail_set = parse_details_log(details_log_path)
        except Exception as e:
            print(f"{project}: details.log解析失败: {e}")
            fail_set = set()
        try:
            cve_stats, cve_version_func_results = parse_log(log_path, ground_truth_dict, fail_set)
        except Exception as e:
            print(f"{project}: result.log解析失败: {e}")
            continue
        tp, tn, fp, fn, fail, target = print_project_stats(project, cve_stats)
        all_tp += tp
        all_tn += tn
        all_fp += fp
        all_fn += fn
        all_fail += fail
        all_target += target

        # 写入csv
        output_csv = f"./gcc-o3/{project}-cve.csv"
        with open(output_csv, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['cve','target','tp','tn','fp','fn','failed','succeed','failed_versions'])
            for cve, stats in cve_stats.items():
                # 收集所有 failed 的版本号
                failed_versions = []
                version_func_results = cve_version_func_results.get(cve, {})
                for version, func_results in version_func_results.items():
                    if 'fail' in func_results.values():
                        failed_versions.append(version)
                writer.writerow([
                    cve,
                    stats['target'],
                    stats['tp'],
                    stats['tn'],
                    stats['fp'],
                    stats['fn'],
                    stats['fail'],
                    stats['tp'] + stats['tn'],
                    ";".join(sorted(failed_versions))
                ])

    # 总体聚合统计
    all_succeed = all_tp + all_tn
    accuracy = all_succeed / all_target if all_target > 0 else 0
    precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0
    recall = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n=== 所有项目总体聚合统计 ===")
    print(f"TP={all_tp} TN={all_tn} FP={all_fp} FN={all_fn} FAIL={all_fail} Target={all_target}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1_score:.4f}")

if __name__ == "__main__":
    main()