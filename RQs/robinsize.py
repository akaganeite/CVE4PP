import json
import pickle
import os
from collections import defaultdict

WHITE_LIST = [
    "CVE-2021-20176",
    "CVE-2020-20446",
    "CVE-2016-4797",
    "CVE-2020-27763",
    "CVE-2020-27756",
    "CVE-2020-27750",
    "CVE-2020-20453",
    "CVE-2021-20309",
    "CVE-2021-20244",
    "CVE-2017-15025",
    "CVE-2019-11472",
    "CVE-2021-20246",
    "CVE-2020-27765",
    "CVE-2020-27560",
    "CVE-2020-20448",
    "CVE-2020-27760",
    "CVE-2016-10506",
    "CVE-2019-14981",
    "CVE-2021-20311",
    "CVE-2021-20310"
]

def load_failed_functions(json_path):
    """
    从JSON文件中加载生成失败的CVE-函数对。
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"成功加载失败函数数据: {json_path} ({len(data)} 个CVE)")
        return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"读取 {json_path} 文件时出错: {e}")
        return {}

def load_function_size_data(pkl_path):
    """
    从pickle文件中加载函数大小数据。
    """
    try:
        with open(pkl_path, 'rb') as f:
            data = pickle.load(f)
        print(f"成功加载函数大小数据: {pkl_path} ({len(data)} 条记录)")
        return data
    except (FileNotFoundError, pickle.UnpicklingError) as e:
        print(f"读取 {pkl_path} 文件时出错: {e}")
        return None

def categorize_function_size(basic_blocks):
    """
    根据基本块数量对函数大小进行分类。
    """
    if basic_blocks <= 0: return "not_found_or_zero"
    if basic_blocks <= 26: return "1-26"
    if basic_blocks <= 63: return "27-63"
    if basic_blocks <= 159: return "64-159"
    return ">159"

def main():
    """
    主函数，执行分析和统计。
    """
    # --- 1. 加载数据 ---
    failed_functions_data = load_failed_functions('all_failed_gen_pairs.json')
    function_size_data = load_function_size_data('size_analysis/cve_function_binary_size.pkl')

    if not failed_functions_data or not function_size_data:
        print("缺少必要的数据文件，无法继续分析。")
        return

    # --- 2. 数据处理 ---
    # 将函数大小数据转换为 (cve, func) -> size 的映射
    function_size_map = {}
    for item in function_size_data:
        key = (item['cve_id'], item['function'])
        function_size_map[key] = item.get('basic_blocks', 0)

    # --- 3. 分类与统计 ---
    failed_function_size_count = defaultdict(int)
    total_failed_functions = 0
    
    # 遍历所有生成失败的函数
    for cve, funcs in failed_functions_data.items():
        if cve not in WHITE_LIST:
            continue
        for func in funcs:
            total_failed_functions += 1
            key = (cve, func)
            
            # 查找函数大小并分类
            size = function_size_map.get(key, 0)
            category = categorize_function_size(size)
            failed_function_size_count[category] += 1

    # --- 4. 输出结果 ---
    print("\n" + "="*50)
    print("生成失败的函数大小分布")
    print("="*50)
    
    if total_failed_functions > 0:
        # 定义输出顺序
        size_order = ["1-26", "27-63", "64-159", ">159", "not_found_or_zero"]

        print(f"总计失败函数数量: {total_failed_functions}\n")
        
        for category in size_order:
            count = failed_function_size_count[category]
            percentage = (count / total_failed_functions) * 100
            print(f"{category:<20}: {count:<5} 个 ({percentage:.2f}%)")
    else:
        print("没有找到生成失败的函数记录。")

if __name__ == "__main__":
    main()