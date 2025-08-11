import os
import re
import csv
import pickle
from collections import defaultdict
from unidiff import PatchSet

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
                        # 函数名从第5个元素开始（索引4），可能有多个
                        function_names = parts[4:]
                        cve_data[cve_id] = {
                            'commit': commit_hash,
                            'functions': function_names
                        }
    
    except Exception as e:
        print(f"读取文件 {valid_file_path} 时出错: {e}")
    
    return cve_data

def is_c_file(filename):
    """
    判断是否为C/C++源文件
    """
    c_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
    return any(filename.lower().endswith(ext) for ext in c_extensions)

def extract_patch_statistics(diff_file_path):
    """
    使用unidiff解析diff文件，统计C文件的修改行数
    返回字典: {'total_added': int, 'total_removed': int, 'total_changed': int, 'c_files': list}
    """
    try:
        patch = PatchSet.from_filename(diff_file_path, encoding='utf-8')
        
        total_added = 0
        total_removed = 0
        c_files_info = []
        
        for patched_file in patch:
            # 只统计C/C++文件
            if is_c_file(patched_file.path):
                file_added = patched_file.added
                file_removed = patched_file.removed
                
                total_added += file_added
                total_removed += file_removed
                
                c_files_info.append({
                    'file_path': patched_file.path,
                    'added': file_added,
                    'removed': file_removed,
                    'total': file_added + file_removed,
                    'is_added_file': patched_file.is_added_file,
                    'is_removed_file': patched_file.is_removed_file,
                    'is_modified_file': patched_file.is_modified_file
                })
        
        return {
            'total_added': total_added,
            'total_removed': total_removed,
            'total_changed': total_added + total_removed,
            'c_files': c_files_info,
            'c_files_count': len(c_files_info)
        }
        
    except Exception as e:
        print(f"使用unidiff解析文件失败: {e}")
        return {
            'total_added': 0,
            'total_removed': 0,
            'total_changed': 0,
            'c_files': [],
            'c_files_count': 0
        }

def collect_cve_patch_size():
    """
    收集CVE-补丁大小的映射关系
    """
    testset_dir = "../../testset"
    diff_base_dir = "../../Diff"
    results = []
    
    if not os.path.exists(testset_dir):
        print(f"目录 {testset_dir} 不存在")
        return []
    
    if not os.path.exists(diff_base_dir):
        print(f"目录 {diff_base_dir} 不存在")
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
        
        # 对应的diff目录
        diff_project_dir = os.path.join(diff_base_dir, project_name, "diff_files")
        
        if not os.path.exists(diff_project_dir):
            print(f"  diff目录不存在: {diff_project_dir}")
            continue
        
        # 处理每个CVE
        for cve_id, cve_info in cve_data.items():
            commit_hash = cve_info['commit']
            function_names = cve_info['functions']
            
            # 构建diff文件名
            diff_filename = f"{project_name}_{cve_id}_{commit_hash}.diff"
            diff_file_path = os.path.join(diff_project_dir, diff_filename)
            
            if os.path.exists(diff_file_path):
                print(f"  解析 {cve_id} 的diff文件...")
                # 使用unidiff解析统计
                patch_stats = extract_patch_statistics(diff_file_path)
                
                if patch_stats['total_changed'] > 0:
                    # 添加总体记录
                    results.append({
                        'project': project_name,
                        'cve_id': cve_id,
                        'commit': commit_hash,
                        'functions': ','.join(function_names),
                        'c_files_count': patch_stats['c_files_count'],
                        'total_added_lines': patch_stats['total_added'],
                        'total_removed_lines': patch_stats['total_removed'],
                        'total_changed_lines': patch_stats['total_changed'],
                        'file_details': patch_stats['c_files']
                    })
                    
                    print(f"    {cve_id}: {patch_stats['c_files_count']} 个C文件, "
                          f"+{patch_stats['total_added']} -{patch_stats['total_removed']} "
                          f"(总计{patch_stats['total_changed']}行)")
                    
                    # 打印详细的文件信息
                    for file_info in patch_stats['c_files']:
                        print(f"      {file_info['file_path']}: "
                              f"+{file_info['added']} -{file_info['removed']}")
                else:
                    print(f"    {cve_id}: 没有C文件修改")
            else:
                print(f"  {cve_id}: diff文件不存在 - {diff_filename}")
    
    return results

def save_results_to_csv(results, output_file="cve_patch_size.csv"):
    """
    将结果保存为CSV文件
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['project', 'cve_id', 'commit', 'functions', 'c_files_count', 
                         'total_added_lines', 'total_removed_lines', 'total_changed_lines']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in results:
                # 不包含file_details字段，因为它是复杂的嵌套结构
                csv_row = {k: v for k, v in row.items() if k != 'file_details'}
                writer.writerow(csv_row)
        
        print(f"CSV结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存CSV文件失败: {e}")

def save_detailed_csv(results, output_file="cve_patch_size.csv"):
    """
    将详细的文件级别结果保存为CSV文件
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['project', 'cve_id', 'commit', 'file_path', 
                         'file_added_lines', 'file_removed_lines', 'file_total_lines',
                         'is_added_file', 'is_removed_file', 'is_modified_file']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in results:
                for file_info in row['file_details']:
                    detailed_row = {
                        'project': row['project'],
                        'cve_id': row['cve_id'],
                        'commit': row['commit'],
                        'file_path': file_info['file_path'],
                        'file_added_lines': file_info['added'],
                        'file_removed_lines': file_info['removed'],
                        'file_total_lines': file_info['total'],
                        'is_added_file': file_info['is_added_file'],
                        'is_removed_file': file_info['is_removed_file'],
                        'is_modified_file': file_info['is_modified_file']
                    }
                    writer.writerow(detailed_row)
        
        print(f"详细CSV结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存详细CSV文件失败: {e}")

def save_results_to_pkl(results, output_file="cve_patch_size.pkl"):
    """
    将结果保存为pickle文件
    """
    try:
        with open(output_file, 'wb') as f:
            pickle.dump(results, f)
        
        print(f"PKL结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存pickle文件失败: {e}")

def print_statistics(results):
    """
    打印统计信息
    """
    if not results:
        print("没有收集到数据")
        return
    
    total_records = len(results)
    total_projects = len(set(r['project'] for r in results))
    total_cves = len(set(r['cve_id'] for r in results))
    
    total_c_files = sum(r['c_files_count'] for r in results)
    total_added = sum(r['total_added_lines'] for r in results)
    total_removed = sum(r['total_removed_lines'] for r in results)
    total_changes = sum(r['total_changed_lines'] for r in results)
    
    avg_patch_size = total_changes / total_records if total_records > 0 else 0
    avg_files_per_cve = total_c_files / total_records if total_records > 0 else 0
    
    print(f"\n统计信息:")
    print(f"  总记录数: {total_records}")
    print(f"  涉及项目: {total_projects}")
    print(f"  涉及CVE: {total_cves}")
    print(f"  总C文件数: {total_c_files}")
    print(f"  总添加行数: {total_added}")
    print(f"  总删除行数: {total_removed}")
    print(f"  总修改行数: {total_changes}")
    print(f"  平均补丁大小: {avg_patch_size:.2f} 行/CVE")
    print(f"  平均文件数: {avg_files_per_cve:.2f} 文件/CVE")

def main():
    """
    主函数
    """
    print("开始收集CVE-补丁大小关系...")
    
    # 收集数据
    results = collect_cve_patch_size()
    
    if not results:
        print("没有收集到任何数据")
        return
    
    # 打印统计信息
    print_statistics(results)
    
    # 保存结果
    save_results_to_csv(results)
    save_detailed_csv(results)
    save_results_to_pkl(results)
    
    return results


if __name__ == "__main__":
    patch_size_data = main()
    
    # 示例：显示前几条记录
    if patch_size_data:
        print("\n示例记录:")
        for i, record in enumerate(patch_size_data[:5]):
            print(f"  {record['cve_id']}: {record['total_changed_lines']} 行修改, "
                  f"{record['c_files_count']} 个C文件")