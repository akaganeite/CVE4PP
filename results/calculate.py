import pandas as pd
from pathlib import Path

def calculate_overall_accuracy():
    """
    读取 trivial.csv 文件并计算每个工作的总体准确率。
    """
    csv_path = Path(__file__).parent / 'trivial.csv'
    
    if not csv_path.exists():
        print(f"错误: 未找到文件 '{csv_path}'")
        return

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"读取 CSV 文件时出错: {e}")
        return

    # 要计算准确率的列
    works = ['PS3', 'Robin', 'React', 'BinXray', 'PatchDiscovery']
    
    print("每个工作的总体准确率:")
    print("-" * 30)

    for work in works:
        if work not in df.columns:
            print(f"警告: 在 CSV 文件中找不到列 '{work}'")
            continue

        total_correct = 0
        total_possible = 0

        # 遍历该列中的每个值
        for value in df[work].dropna(): # dropna() 会忽略空值
            try:
                # 将 "x/y" 格式的字符串分割
                parts = str(value).split('/')
                if len(parts) == 2:
                    correct = int(parts[0])
                    possible = int(parts[1])
                    
                    total_correct += correct
                    total_possible += possible
            except (ValueError, IndexError):
                print(f"警告: 在列 '{work}' 中跳过无效格式的值: '{value}'")

        # 计算准确率
        if total_possible > 0:
            accuracy = (total_correct / total_possible) * 100
            print(f"{work:<15} | 准确率: {accuracy:.2f}% ({total_correct}/{total_possible})")
        else:
            print(f"{work:<15} | 无有效数据可供计算")
            
    print("-" * 30)

if __name__ == '__main__':
    calculate_overall_accuracy()