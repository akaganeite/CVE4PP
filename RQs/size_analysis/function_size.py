import os
import re
import csv
import pickle
from collections import defaultdict
import angr

def extract_cve_commit_functions_from_valid(valid_file_path):
    """
    从valid文件中提取CVE号、commit hash和函数名
    """
    cve_data = {}
    
    try:
        with open(valid_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and line.startswith('CVE-'):
                    # 解析格式: CVE-YYYY-NNNN YYYY-MM-DD commit_hash tool function_names
                    parts = line.split()
                    if len(parts) >= 5:
                        cve_id = parts[0]
                        commit_hash = parts[2]
                        # 函数名从第5个元素开始（索引4），可能有多个，用逗号分隔
                        functions_str = ' '.join(parts[4:])  # 合并所有函数名部分
                        # 按逗号分隔函数名
                        function_names = [name.strip() for name in functions_str.split(',') if name.strip()]
                        cve_data[cve_id] = {
                            'commit': commit_hash,
                            'functions': function_names
                        }
    
    except Exception as e:
        print(f"读取文件 {valid_file_path} 时出错: {e}")
    
    return cve_data

def extract_cve_from_binary_filename(filename):
    """
    从二进制文件名中提取CVE号
    文件名格式: CVE-YYYY-NNNN-patch-commit_hash-tool
    """
    pattern = r'(CVE-\d{4}-\d{4,7})'
    match = re.search(pattern, filename)
    return match.group(1) if match else None

def analyze_binary_functions(binary_path, function_names):
    """
    使用angr分析二进制文件中指定函数的基本块数量
    返回字典: {function_name: basic_blocks_count}
    """
    function_sizes = {}
    
    try:
        print(f"    加载二进制文件: {os.path.basename(binary_path)}")
        # 使用angr加载二进制文件
        project = angr.Project(binary_path, auto_load_libs=False)
        
        # 查找每个目标函数的符号和地址范围
        for func_name in function_names:
            function_sizes[func_name] = 0
            
            # 在符号表中查找函数
            symbol = project.loader.find_symbol(func_name)
            if symbol:
                func_addr = symbol.rebased_addr
                func_size = symbol.size if symbol.size > 0 else 0x1000  # 默认4KB
                func_end_addr = func_addr + func_size
                
                print(f"      找到函数符号 {func_name}: 0x{func_addr:x} - 0x{func_end_addr:x} (大小: {func_size} 字节)")
                
                # 为该函数的地址范围生成CFG
                try:
                    print(f"      为函数 {func_name} 生成CFG...")
                    # 使用regions参数代替deprecated的start/end参数
                    cfg = project.analyses.CFGFast(
                        regions=[(func_addr, func_end_addr)],
                        normalize=True
                    )
                    
                    # 在生成的CFG中查找函数
                    if func_addr in cfg.functions:
                        function = cfg.functions[func_addr]
                        # 修复: 将生成器转换为列表再计算长度
                        basic_blocks_count = len(list(function.blocks))
                        function_sizes[func_name] = basic_blocks_count
                        print(f"      函数 {func_name}: {basic_blocks_count} 个基本块")
                    else:
                        print(f"      函数 {func_name}: CFG中未找到函数对象")
                        
                except Exception as cfg_error:
                    print(f"      为函数 {func_name} 生成CFG失败: {cfg_error}")
                    # 回退方案：生成全局CFG再查找
                    try:
                        print(f"      尝试全局CFG方案...")
                        global_cfg = project.analyses.CFGFast()
                        if func_addr in global_cfg.functions:
                            function = global_cfg.functions[func_addr]
                            # 修复: 将生成器转换为列表再计算长度
                            basic_blocks_count = len(list(function.blocks))
                            function_sizes[func_name] = basic_blocks_count
                            print(f"      函数 {func_name}: {basic_blocks_count} 个基本块 (全局CFG)")
                        else:
                            print(f"      函数 {func_name}: 全局CFG中也未找到")
                    except Exception as global_cfg_error:
                        print(f"      全局CFG也失败: {global_cfg_error}")
            else:
                print(f"      函数 {func_name}: 未找到符号，尝试名称匹配...")
                # 尝试通过名称匹配查找函数
                found = False
                try:
                    # 生成全局CFG用于名称匹配
                    cfg = project.analyses.CFGFast()
                    for addr, function in cfg.functions.items():
                        if function.name == func_name:
                            # 修复: 将生成器转换为列表再计算长度
                            basic_blocks_count = len(list(function.blocks))
                            function_sizes[func_name] = basic_blocks_count
                            print(f"      函数 {func_name}: {basic_blocks_count} 个基本块 (名称匹配)")
                            found = True
                            break
                    
                    if not found:
                        print(f"      函数 {func_name}: 名称匹配也未找到")
                        
                except Exception as match_error:
                    print(f"      名称匹配失败: {match_error}")
    
    except Exception as e:
        print(f"    分析二进制文件失败: {e}")
        # 初始化所有函数为0
        for func_name in function_names:
            function_sizes[func_name] = 0
    
    return function_sizes

def collect_cve_function_binary_size():
    """
    收集CVE-函数-二进制大小的映射关系
    """
    testset_dir = "../../testset"
    binaries_dir = "../../../binaries/reference"
    results = []
    
    if not os.path.exists(testset_dir):
        print(f"目录 {testset_dir} 不存在")
        return []
    
    if not os.path.exists(binaries_dir):
        print(f"目录 {binaries_dir} 不存在")
        return []
    
    # 遍历testset目录下的每个项目目录
    for project_name in os.listdir(testset_dir):
        project_path = os.path.join(testset_dir, project_name)
        
        if not os.path.isdir(project_path):
            continue
            
        valid_file_path = os.path.join(project_path, "valid")
        
        if not os.path.exists(valid_file_path):
            print(f"项目 {project_name} 中没有找到valid文件")
            continue
        
        print(f"处理项目: {project_name}")
        
        # 提取CVE、commit和函数映射
        cve_data = extract_cve_commit_functions_from_valid(valid_file_path)
        print(f"  找到 {len(cve_data)} 个CVE记录")
        
        # 对应的二进制文件目录
        binary_project_dir = os.path.join(binaries_dir, project_name)
        
        if not os.path.exists(binary_project_dir):
            print(f"  二进制目录不存在: {binary_project_dir}")
            continue
        
        # 查找包含patch的二进制文件
        binary_files = []
        for filename in os.listdir(binary_project_dir):
            if 'patch' in filename and 'i64' not in filename and os.path.isfile(os.path.join(binary_project_dir, filename)):
                binary_files.append(filename)
        
        print(f"  找到 {len(binary_files)} 个patch二进制文件")
        
        # 处理每个二进制文件
        for binary_filename in binary_files:
            # 从文件名提取CVE号
            cve_id = extract_cve_from_binary_filename(binary_filename)
            
            if cve_id and cve_id in cve_data:
                function_names = cve_data[cve_id]['functions']
                commit_hash = cve_data[cve_id]['commit']
                
                binary_path = os.path.join(binary_project_dir, binary_filename)
                
                print(f"  分析 {cve_id} 的二进制文件: {binary_filename}")
                
                # 使用angr分析函数大小
                function_sizes = analyze_binary_functions(binary_path, function_names)
                
                # 为每个函数添加记录
                for func_name, size in function_sizes.items():
                    results.append({
                        'project': project_name,
                        'cve_id': cve_id,
                        'commit': commit_hash,
                        'function': func_name,
                        'basic_blocks': size,
                        'binary_file': binary_filename
                    })
                    
                    if size > 0:
                        print(f"    {cve_id} - {func_name}: {size} 个基本块")
            else:
                if cve_id:
                    print(f"  跳过 {binary_filename}: CVE {cve_id} 不在valid文件中")
                else:
                    print(f"  跳过 {binary_filename}: 无法提取CVE号")
    
    return results

def save_results_to_csv(results, output_file="cve_function_binary_size.csv"):
    """
    将二进制分析结果保存为CSV文件
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['project', 'cve_id', 'commit', 'function', 'basic_blocks', 'binary_file']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        
        print(f"二进制分析CSV结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存二进制分析CSV文件失败: {e}")

def save_results_to_pkl(results, output_file="cve_function_binary_size.pkl"):
    """
    将二进制分析结果保存为pickle文件
    """
    try:
        with open(output_file, 'wb') as f:
            pickle.dump(results, f)
        
        print(f"二进制分析PKL结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存二进制分析pickle文件失败: {e}")

def print_statistics(results):
    """
    打印二进制分析统计信息
    """
    if not results:
        print("没有收集到二进制分析数据")
        return
    
    # 过滤出有效的记录（basic_blocks > 0）
    valid_results = [r for r in results if r['basic_blocks'] > 0]
    
    total_records = len(results)
    valid_records = len(valid_results)
    total_projects = len(set(r['project'] for r in results))
    total_cves = len(set(r['cve_id'] for r in results))
    total_functions = len(set(r['function'] for r in results))
    
    if valid_records > 0:
        total_blocks = sum(r['basic_blocks'] for r in valid_results)
        avg_blocks = total_blocks / valid_records
        max_blocks = max(r['basic_blocks'] for r in valid_results)
        min_blocks = min(r['basic_blocks'] for r in valid_results)
    else:
        total_blocks = avg_blocks = max_blocks = min_blocks = 0
    
    print(f"\n二进制分析统计信息:")
    print(f"  总记录数: {total_records}")
    print(f"  有效记录数: {valid_records}")
    print(f"  成功率: {valid_records/total_records*100:.1f}%" if total_records > 0 else "  成功率: 0%")
    print(f"  涉及项目: {total_projects}")
    print(f"  涉及CVE: {total_cves}")
    print(f"  涉及函数: {total_functions}")
    print(f"  总基本块数: {total_blocks}")
    print(f"  平均基本块数: {avg_blocks:.2f}")
    print(f"  最大基本块数: {max_blocks}")
    print(f"  最小基本块数: {min_blocks}")
    
    # 按基本块数量分布统计
    if valid_results:
        print(f"\n基本块数量分布:")
        size_ranges = [(1, 5), (6, 10), (11, 20), (21, 50), (51, 100), (101, float('inf'))]
        for min_size, max_size in size_ranges:
            count = len([r for r in valid_results if min_size <= r['basic_blocks'] <= max_size])
            if max_size == float('inf'):
                print(f"  {min_size}+ 个基本块: {count} 个函数")
            else:
                print(f"  {min_size}-{max_size} 个基本块: {count} 个函数")

def main():
    """
    主函数
    """
    print("开始收集CVE-函数-二进制大小关系...")
    
    # 收集二进制数据
    results = collect_cve_function_binary_size()
    
    if not results:
        print("没有收集到任何数据")
        return
    
    # 打印统计信息
    print_statistics(results)
    
    # 保存结果
    save_results_to_csv(results)
    save_results_to_pkl(results)
    
    return results

if __name__ == "__main__":
    binary_data = main()
    
    # 示例：显示前几条记录
    if binary_data:
        print("\n示例记录:")
        valid_records = [r for r in binary_data if r['basic_blocks'] > 0]
        for i, record in enumerate(valid_records[:5]):
            print(f"  {record['cve_id']} - {record['function']}: {record['basic_blocks']} 个基本块")
        
        if len(valid_records) == 0:
            print("  没有找到有效的函数分析结果")
