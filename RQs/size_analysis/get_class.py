import pickle
import pandas as pd
import os

def load_pkl_data(file_path):
    """
    从pickle文件中加载数据。
    """
    if not os.path.exists(file_path):
        print(f"错误: 文件未找到 -> {file_path}")
        return None
    
    try:
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
        print(f"成功加载数据: {file_path} ({len(data)} 条记录)")
        return data
    except Exception as e:
        print(f"加载文件 {file_path} 时出错: {e}")
        return None

def analyze_and_suggest_boundaries(data, size_key, analysis_name):
    """
    分析数据并使用四分位数建议分类标准。
    """
    if not data:
        print(f"{analysis_name}: 无数据可分析。")
        return

    # 提取所有有效的（大于0）尺寸数据
    sizes = [item.get(size_key, 0) for item in data if item.get(size_key, 0) > 0]
    
    if not sizes:
        print(f"{analysis_name}: 没有找到有效的尺寸数据（>0）。")
        return

    # 使用pandas计算描述性统计和四分位数
    size_series = pd.Series(sizes)
    description = size_series.describe(percentiles=[.25, .5, .75])
    
    q1 = description['25%']
    median = description['50%']
    q3 = description['75%']
    
    print("\n" + "="*50)
    print(f"{analysis_name} 分析")
    print("="*50)
    print("描述性统计:")
    print(description)
    
    print("\n建议的分类边界:")
    print(f" - 25% (Q1): {q1:.2f}")
    print(f" - 50% (中位数): {median:.2f}")
    print(f" - 75% (Q3): {q3:.2f}")
    
    print("\n可能的分类方案:")
    print(f"  - 方案 A (基于中位数): [1 - {median:.0f}], [> {median:.0f}]")
    print(f"  - 方案 B (基于四分位数): [1 - {q1:.0f}], [{q1+1:.0f} - {q3:.0f}], [> {q3:.0f}]")
    print(f"  - 方案 C (更细粒度): [1 - {q1:.0f}], [{q1+1:.0f} - {median:.0f}], [{median+1:.0f} - {q3:.0f}], [> {q3:.0f}]")
    print("="*50)


def main():
    """
    主函数，加载数据并进行分析。
    """
    # 定义文件路径
    function_size_pkl = 'cve_function_binary_size.pkl'
    patch_size_pkl = 'cve_patch_size.pkl'
    
    # 分析函数大小
    function_data = load_pkl_data(function_size_pkl)
    if function_data:
        analyze_and_suggest_boundaries(
            data=function_data, 
            size_key='basic_blocks', 
            analysis_name="函数大小 (基本块数量)"
        )
        
    # 分析补丁大小
    patch_data = load_pkl_data(patch_size_pkl)
    if patch_data:
        analyze_and_suggest_boundaries(
            data=patch_data, 
            size_key='total_changed_lines', 
            analysis_name="补丁大小 (总修改行数)"
        )

if __name__ == "__main__":
    main()