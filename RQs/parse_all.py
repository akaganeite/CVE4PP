import json
import pickle
import re

# 读取cves.txt
with open('cves.txt', 'r', encoding='utf-8') as f:
    cve_list = [line.strip() for line in f if line.strip()]

# 读取cluster.json，收集所有CVE
with open('failed_patch_clustering/cluster.json', 'r', encoding='utf-8') as f:
    cluster_data = json.load(f)
cluster_cves = set()
for items in cluster_data.values():
    for item in items:
        cluster_cves.add(item['CVE'])

# 去除cluster.json中的CVE
filtered_cve_list = [cve for cve in cve_list if cve not in cluster_cves]
filtered_cve_list = cve_list
# 后续分析都用 filtered_cve_list 替换 cve_list
# 读取pattern.json
with open('pattern_analysis/pattern.json', 'r', encoding='utf-8') as f:
    pattern_data = json.load(f)

# 读取cwe_refined.json
with open('cwe_analysis/cwe_refined.json', 'r', encoding='utf-8') as f:
    cwe_data = json.load(f)

# --- 新增：加载大小数据 ---
def load_size_data(pkl_path):
    try:
        with open(pkl_path, 'rb') as f:
            return pickle.load(f)
    except (FileNotFoundError, pickle.UnpicklingError) as e:
        print(f"Error loading {pkl_path}: {e}")
        return None

patch_size_data = load_size_data('size_analysis/cve_patch_size.pkl')
function_size_data = load_size_data('size_analysis/cve_function_binary_size.pkl')

# --- 新增：分类函数 ---
def categorize_patch_size(total_lines):
    if total_lines == 0:
        return "0"
    elif total_lines <= 3:
        return "1-3"
    elif total_lines <= 8:
        return "4-8"
    elif total_lines <= 20:
        return "9-20"
    else:
        return ">20"

def categorize_function_size(basic_blocks):
    if basic_blocks <= 0: return "not_found_or_zero"
    if basic_blocks <= 26: return "1-26"
    if basic_blocks <= 63: return "27-63"
    if basic_blocks <= 159: return "64-159"
    return ">159"

# --- 新增：统计大小分布 ---
# 统计 patch size
patch_size_count = {}
if patch_size_data:
    patch_size_map = {item['cve_id']: item['total_changed_lines'] for item in patch_size_data}
    for cve in filtered_cve_list:
        if cve in patch_size_map:
            size = patch_size_map[cve]
            category = categorize_patch_size(size)
            patch_size_count[category] = patch_size_count.get(category, 0) + 1
        else:
            patch_size_count['not_found'] = patch_size_count.get('not_found', 0) + 1

# 统计 function size
function_size_count = {}
if function_size_data:
    function_size_map = {}
    for item in function_size_data:
        function_size_map.setdefault(item['cve_id'], []).append(item['basic_blocks'])
    
    for cve in filtered_cve_list:
        if cve in function_size_map:
            sizes = function_size_map[cve]
            for size in sizes:
                category = categorize_function_size(size)
                function_size_count[category] = function_size_count.get(category, 0) + 1
        else:
            # 注意：函数大小是基于函数的，一个CVE可能没有对应的函数大小记录
            pass

# 统计pattern分布
pattern_count = {}
pattern_cve_map = {}
for cve in filtered_cve_list:
    if cve in pattern_data:
        patterns = pattern_data[cve]
        for p in patterns:
            pattern_count[p] = pattern_count.get(p, 0) + 1
            pattern_cve_map.setdefault(p, []).append(cve)
    else:
        pattern_count['not_found'] = pattern_count.get('not_found', 0) + 1
        pattern_cve_map.setdefault('not_found', []).append(cve)

# 统计cwe分布
cwe_count = {}
cwe_cve_map = {}
for cve in filtered_cve_list:
    found = False
    for cwe, cves in cwe_data.items():
        if cve in cves:
            cwe_count[cwe] = cwe_count.get(cwe, 0) + 1
            cwe_cve_map.setdefault(cwe, []).append(cve)
            found = True
    if not found:
        cwe_count['not_found'] = cwe_count.get('not_found', 0) + 1
        cwe_cve_map.setdefault('not_found', []).append(cve)

# --- 新增：聚合类别和Pattern数量统计 ---
# 1. 聚合类别定义
aggregate_categories = {
    "Input_Sanitization": {1, 2},
    "Data_Structure": {3, 4, 5},
    "Function_Changes": {6, 7, 8, 9}
}

# 2. 初始化新统计的计数器
# 专属聚合类别统计
exclusive_category_count = {
    "Input_Sanitization_Only": 0,
    "Data_Structure_Only": 0,
    "Function_Changes_Only": 0
}
# 细分Pattern数量统计
pattern_number_count = {
    "1_pattern": 0,
    "2_patterns": 0,
    "3_or_more_patterns": 0
}

# 3. 遍历CVE进行统计
for cve in filtered_cve_list:
    if cve in pattern_data:
        patterns = set(pattern_data[cve])  # 使用集合确保pattern唯一
        num_patterns = len(patterns)

        # 统计细分pattern数量
        if num_patterns == 1:
            pattern_number_count["1_pattern"] += 1
        elif num_patterns == 2:
            pattern_number_count["2_patterns"] += 1
        elif num_patterns >= 3:
            pattern_number_count["3_or_more_patterns"] += 1

        # 统计专属聚合类别
        cve_agg_categories = set()
        for p in patterns:
            if p in aggregate_categories["Input_Sanitization"]:
                cve_agg_categories.add("Input_Sanitization")
            elif p in aggregate_categories["Data_Structure"]:
                cve_agg_categories.add("Data_Structure")
            elif p in aggregate_categories["Function_Changes"]:
                cve_agg_categories.add("Function_Changes")
        
        if len(cve_agg_categories) == 1:
            # 如果只涉及一个聚合类别
            category = list(cve_agg_categories)[0]
            exclusive_category_count[f"{category}_Only"] += 1


pattern_categories = {
    1: "add input sanitization checks",
    2: "change input sanitization checks", 
    3: "add data structures",
    4: "change data structure definitions",
    5: "change data structure references",
    6: "change function parameters",
    7: "add or change function calls",
    8: "add functions",
    9: "change functions"
}

print("=== pattern.json 分布 ===")
for p in sorted(pattern_count, key=lambda x: (isinstance(x, int), x)):
    if isinstance(p, int) and p in pattern_categories:
        desc = pattern_categories[p]
        print(f"Pattern {p} ({desc}): {pattern_count[p]} 个")
    elif p == 'not_found':
        print(f"Pattern not_found: {pattern_count[p]} 个")
    else:
        print(f"Pattern {p}: {pattern_count[p]} 个")

print("\n=== cwe_refined.json 分布 ===")
for cwe in sorted(cwe_count):
    print(f"{cwe}: {cwe_count[cwe]} 个")
    # print("  " + ", ".join(cwe_cve_map[cwe]))

# --- 新增：打印专属聚合类别统计 ---
print("\n=== 专属聚合类别分布 (CVE只属于某一类) ===")
print(f"只属于 Input Sanitization: {exclusive_category_count['Input_Sanitization_Only']} 个")
print(f"只属于 Data Structure: {exclusive_category_count['Data_Structure_Only']} 个")
print(f"只属于 Function Changes: {exclusive_category_count['Function_Changes_Only']} 个")

# --- 新增：打印细分Pattern数量统计 ---
print("\n=== 细分Pattern数量分布 ===")
print(f"包含 1 个Pattern的CVE: {pattern_number_count['1_pattern']} 个")
print(f"包含 2 个Pattern的CVE: {pattern_number_count['2_patterns']} 个")
print(f"包含 3个及以上Pattern的CVE: {pattern_number_count['3_or_more_patterns']} 个")


# --- 新增：打印大小统计结果 ---
print("\n=== Patch Size 分布 ===")
if patch_size_count:
    patch_order = ["0", "1-3", "4-8", "9-20", ">20", "not_found"]
    for category in patch_order:
        if category in patch_size_count:
            print(f"{category}: {patch_size_count[category]} 个")
else:
    print("未找到 Patch size 数据或统计失败。")

print("\n=== Function Size (Basic Blocks) 分布 ===")
if function_size_count:
    func_order = ["1-26", "27-63", "64-159", ">159", "not_found_or_zero"]
    for category in func_order:
        if category in function_size_count:
            print(f"{category}: {function_size_count[category]} 个")
else:
    print("未找到 Function size 数据或统计失败。")

# --- 新增：non-sec CVE 分析 ---
def analyze_non_sec_cves(cve_list_to_check):
    """
    读取 aggregated_non_sec.jsonl，找出与 cve_list_to_check 重叠的 CVE。
    """
    non_sec_cves = set()
    try:
        with open('aggregated_non_sec.jsonl', 'r', encoding='utf-8') as f:
            content = f.read()
            # 使用正则表达式从格式不正确的JSON中提取所有CVE
            non_sec_cves = set(re.findall(r'"(CVE-\d{4}-\d{4,})"', content))
        print(f"\n从 aggregated_non_sec.jsonl 中加载了 {len(non_sec_cves)} 个唯一的CVE。")
    except FileNotFoundError:
        print("\n警告: aggregated_non_sec.jsonl 文件未找到。")
        return

    main_cve_set = set(cve_list_to_check)
    
    # 找出交集
    common_cves = sorted(list(main_cve_set.intersection(non_sec_cves)))
    
    print("\n" + "="*80)
    print("在 aggregated_non_sec.jsonl 中找到的CVE分析")
    print("="*80)
    print(f"总共有 {len(common_cves)} 个CVE同时存在于主分析列表和 aggregated_non_sec.jsonl 中。")
    
    if common_cves:
        print("它们是:")
        # 打印列表
        print(common_cves)

# 调用新增的分析函数
analyze_non_sec_cves(filtered_cve_list)