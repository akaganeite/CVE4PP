import os

def load_details_file(filepath):
    """
    加载 details 文件并将其解析为字典。
    
    Args:
        filepath (str): 文件路径。
        
    Returns:
        dict: 一个字典，键是 CVE 标识符，值是函数名的集合。
    """
    data = {}
    if not os.path.exists(filepath):
        print(f"错误: 文件未找到 '{filepath}'")
        return data
        
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            cve_id = parts[0]
            
            # 检查是否存在函数列表
            if len(parts) > 2:
                # 函数列表是最后一个元素
                functions = set(parts[-1].split(','))
            else:
                functions = set()
            
            data[cve_id] = functions
            
    return data

def compare_files(file1_path, file2_path):
    """
    比较两个 details 文件并报告差异。
    
    Args:
        file1_path (str): 第一个文件 (例如 'details') 的路径。
        file2_path (str): 第二个文件 (例如 'details_refined') 的路径。
    """
    print(f"--- 正在比较 '{file1_path}' (旧) 和 '{file2_path}' (新) ---\n")
    
    data1 = load_details_file(file1_path)
    data2 = load_details_file(file2_path)
    
    if not data1 or not data2:
        print("因文件加载失败，无法进行比较。")
        return

    all_cves = sorted(set(data1.keys()) | set(data2.keys()))
    
    differences_found = 0
    
    for cve_id in all_cves:
        funcs1 = data1.get(cve_id, set())
        funcs2 = data2.get(cve_id, set())
        
        if funcs1 == funcs2:
            continue
            
        differences_found += 1
        print(f"[*] CVE: {cve_id}")
        
        removed_funcs = funcs1 - funcs2
        if removed_funcs:
            print(f"  [-] Removed ({len(removed_funcs)}): {', '.join(sorted(list(removed_funcs)))}")
            
        added_funcs = funcs2 - funcs1
        if added_funcs:
            print(f"  [+] Added ({len(added_funcs)}): {', '.join(sorted(list(added_funcs)))}")
            
        print("-" * 20)
        
    print("\n--- 总结 ---")
    if differences_found > 0:
        print(f"在 {len(all_cves)} 个 CVE 中，共发现 {differences_found} 个存在差异。")
    else:
        print("两个文件之间没有发现任何差异。")

if __name__ == "__main__":
    # 假设文件在当前目录下
    details_file = "./tcpdump/details"
    details_refined_file = "./tcpdump/details_refined"
    
    compare_files(details_file, details_refined_file)