import os
import csv
import argparse

def extract_cve(row):
    """大小写不敏感获取 CVE 列"""
    for k, v in row.items():
        if k and k.lower() == 'cve':
            return (v or '').strip()
    return ''

def get_binxray_negatives(filepath):
    """BinXray: 只要 false_negative / too_much_diff / cant_tell 任一列非空即计入该 CVE"""
    neg_cves = set()
    all_cves = set()
    if not os.path.exists(filepath):
        return neg_cves, all_cves
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = extract_cve(row)
            if not cve:
                continue
            all_cves.add(cve)
            if any(row.get(col, '').strip() for col in ['too_much_diff', 'cant_tell','failed_versions','false_negative']):
            # if any(row.get(col, '').strip() for col in ['false_negative']):
                neg_cves.add(cve)
    return neg_cves, all_cves

def get_React_negatives(filepath):
    """React: failed_versions 数值 != 0 或 false_negative 非空则计入 CVE"""
    neg_cves = set()
    all_cves = set()
    if not os.path.exists(filepath):
        return neg_cves, all_cves
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = extract_cve(row)
            if not cve:
                continue
            all_cves.add(cve)
            fv = str(row.get('failed_versions', '')).strip()
            # fv =''
            fn = str(row.get('false_negative', '')).strip()
            fp = str(row.get('false_positive', '')).strip()
            # failed_versions: 仅当不为空且不等于 "0" 才算
            if ((fv != '' and fv != '0') or fn != '' or fp != ''):
                neg_cves.add(cve)
    return neg_cves, all_cves

def get_other_negatives(filepath):
    """PatchDiscovery 等：false_negative 或 failed_versions 任一列非空即计入 CVE"""
    neg_cves = set()
    all_cves = set()
    if not os.path.exists(filepath):
        return neg_cves, all_cves
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = extract_cve(row)
            if not cve:
                continue
            all_cves.add(cve)
            if any(row.get(col, '').strip() for col in ['false_negative','failed_versions']):
            # if any(row.get(col, '').strip() for col in ['false_negative']):
                neg_cves.add(cve)
    return neg_cves, all_cves

def get_ps3_negatives(filepath):
    """PS3: failed_versions / false_negative 任一非空 或 no_sig == true 即计入 CVE"""
    neg_cves = set()
    all_cves = set()
    if not os.path.exists(filepath):
        return neg_cves, all_cves
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = extract_cve(row)
            if not cve:
                continue
            all_cves.add(cve)
            no_sig_flag = str(row.get('no_sig', '')).strip().lower() == 'true'
            # no_sig_flag =False
            if no_sig_flag or any(row.get(col, '').strip() for col in ['false_positive','false_negative','failed_versions']):
                neg_cves.add(cve)
    return neg_cves, all_cves

PROJECTS = [
    'binutils', 'curl', 'ffmpeg', 'freetype', 'imagemagick',
    'libxml2', 'openjpeg', 'openssl', 'sqlite', 'tcpdump'
]

def process_project(project_name, dirs):
    """处理单项目，返回 (intersection_set, union_set, per_source_neg_sets, per_source_all_sets)."""
    per_source_neg_sets = []
    per_source_all_sets = []
    for d, func in dirs:
        filename = f'gcc-o0/{project_name}_result.csv'
        filepath = os.path.join(d, filename)
        neg_sets, all_sets = func(filepath)
        per_source_neg_sets.append(neg_sets)
        per_source_all_sets.append(all_sets)

    intersection = set.intersection(*per_source_neg_sets) if per_source_neg_sets else set()
    union_all = set().union(*per_source_neg_sets) if per_source_neg_sets else set()
    return intersection, union_all, per_source_neg_sets, per_source_all_sets

def main():
    parser = argparse.ArgumentParser(description='统计多项目 CVE 交/并集')
    parser.add_argument('-proj', default='all', help='指定 project 名称；默认 all (全部10个)；可用逗号分隔多个')
    args = parser.parse_args()
    proj_arg = args.proj.strip()
    if proj_arg.lower() == 'all' or proj_arg == '':
        target_projects = PROJECTS
    else:
        target_projects = [p.strip() for p in proj_arg.split(',') if p.strip()]

    dirs = [
        ('BinXray', get_binxray_negatives),
        ('PatchDiscovery', get_other_negatives),
        ('PS3', get_ps3_negatives),
        ('React', get_React_negatives),
        # ('Robin',get_other_negatives)
    ]

    summary_rows = []  # (project, |inter|, |union|, ratio)
    aggregated_neg_sets = [set() for _ in dirs]  # 每来源跨项目聚合的负例
    aggregated_all_sets = [set() for _ in dirs]  # 每来源跨项目聚合的全部CVE
    project_intersections = []  # 保存各项目交集集合

    for project in target_projects:
        inter_set, union_set, per_source_neg_sets, per_source_all_sets = process_project(project, dirs)
        project_intersections.append(inter_set)
        for i, s in enumerate(per_source_neg_sets):
            aggregated_neg_sets[i].update(s)
        for i, s in enumerate(per_source_all_sets):
            aggregated_all_sets[i].update(s)
        ratio = (len(inter_set) / len(union_set)) if union_set else 0.0
        summary_rows.append((project, len(inter_set), len(union_set), ratio))

        print(f"=== Project: {project} ===")
        print(f"交集数量: {len(inter_set)}  并集数量: {len(union_set)}  交/并: {ratio:.4f}")
        if inter_set:
            for cve in sorted(inter_set):
                print(cve)
        print()

    # 按来源聚合的全局交/并集
    if aggregated_neg_sets:
        global_intersection_sources = set.intersection(*aggregated_neg_sets)
        global_union_sources = set().union(*aggregated_neg_sets)
    else:
        global_intersection_sources = set()
        global_union_sources = set()
    global_ratio_sources = (len(global_intersection_sources) / len(global_union_sources)) if global_union_sources else 0.0

    # 各项目交集集合之间的并集与交集
    if project_intersections:
        inter_union_across_projects = set().union(*project_intersections)
        inter_intersection_across_projects = set.intersection(*project_intersections)
    else:
        inter_union_across_projects = set()
        inter_intersection_across_projects = set()

    print("===== 汇总 (逐项目) =====")
    print("Project\tInter\tUnion\tInter/Union")
    for row in summary_rows:
        print(f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]:.4f}")

    print("\n===== 全部项目聚合 (按来源) =====")
    print(f"全局交集(来源) 数量: {len(global_intersection_sources)}")
    print(f"全局并集(来源) 数量: {len(global_union_sources)}")
    print(f"全局交/并 比例: {global_ratio_sources:.4f}")

    # 新增：全局交集(来源)数量 / 每个来源全部CVE数量
    print("\n全局交集(来源)数量 / 每个来源全部CVE数量：")
    for i, (src, _) in enumerate(dirs):
        total = len(aggregated_neg_sets[i])
        ratio = (len(global_intersection_sources) / total) if total else 0.0
        print(f"{src}: {len(global_intersection_sources)}/{total} = {ratio:.4f}")


    print("\n===== 跨项目交集集合统计 =====")
    print(f"所有项目交集集合的并集大小: {len(inter_union_across_projects)}")

    print("\n===== 各来源全部CVE及独有CVE =====")
    for i, (src, _) in enumerate(dirs):
        all_neg_cves = aggregated_neg_sets[i]
        # print(f"\n{src} 全部CVE数量: {len(all_cves)}")
        # print(f"{src} 全部CVE列表:")
        # for cve in sorted(all_cves):
        #     print(cve)
        # 计算独有CVE
        others = set().union(*(aggregated_neg_sets[j] for j in range(len(dirs)) if j != i))
        unique_cves = all_neg_cves - others
        print(f"{src} 独有CVE数量: {len(unique_cves)}")
        if unique_cves:
            print(f"{src} 独有CVE列表:")
            for cve in sorted(unique_cves):
                print(cve)

    print("\n===== 只有该工作没有检出负例的 CVE =====")
    for i, (src, _) in enumerate(dirs):
        neg_i = aggregated_neg_sets[i]
        all_i = aggregated_all_sets[i]
        other_negs = [aggregated_neg_sets[j] for j in range(len(dirs)) if j != i]

        if not other_negs:
            continue

        intersection_of_others = set.intersection(*other_negs)
        
        # 候选者：在其他工具中都是负例，且在当前工具中不是负例
        candidates = intersection_of_others - neg_i
        
        # 最终结果：候选者必须在当前工具的记录中存在
        only_this_work_is_clean = candidates.intersection(all_i)

        print(f"\n--- {src} ---")
        print(f"数量: {len(only_this_work_is_clean)}")
        if only_this_work_is_clean:
            print("列表:")
            for cve in sorted(only_this_work_is_clean):
                print(cve)

main()