import json
import pickle

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
    if total_lines <= 5: return "1-5"
    if total_lines <= 10: return "6-10"
    if total_lines <= 20: return "11-20"
    if total_lines <= 50: return "21-50"
    return ">50"

def categorize_function_size(basic_blocks):
    if basic_blocks <= 10: return "1-10"
    if basic_blocks <= 20: return "11-20"
    if basic_blocks <= 50: return "21-50"
    if basic_blocks <= 100: return "51-100"
    return ">100"

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

# --- 新增：打印大小统计结果 ---
print("\n=== Patch Size 分布 ===")
if patch_size_count:
    patch_order = ["1-5", "6-10", "11-20", "21-50", ">50", "not_found"]
    for category in patch_order:
        if category in patch_size_count:
            print(f"{category}: {patch_size_count[category]} 个")
else:
    print("未找到 Patch size 数据或统计失败。")

print("\n=== Function Size (Basic Blocks) 分布 ===")
if function_size_count:
    func_order = ["1-10", "11-20", "21-50", "51-100", ">100"]
    for category in func_order:
        if category in function_size_count:
            print(f"{category}: {function_size_count[category]} 个")
else:
    print("未找到 Function size 数据或统计失败。")