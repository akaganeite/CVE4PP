import os
import re
import pickle
from collections import defaultdict

def extract_cve_commit_from_valid(valid_file_path):
    """
    从valid文件中提取CVE号和对应的commit hash
    """
    cve_commit_mapping = {}
    
    try:
        with open(valid_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and line.startswith('CVE-'):
                    # 解析格式: CVE-YYYY-NNNN YYYY-MM-DD commit_hash tool function_names
                    parts = line.split()
                    if len(parts) >= 3:
                        cve_id = parts[0]
                        commit_hash = parts[2]
                        cve_commit_mapping[cve_id] = commit_hash
    
    except Exception as e:
        print(f"读取文件 {valid_file_path} 时出错: {e}")
    
    return cve_commit_mapping

def load_diff_file(diff_file_path):
    """
    加载diff文件内容
    """
    try:
        with open(diff_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"读取diff文件 {diff_file_path} 失败: {e}")
        return ""

def collect_cve_diff_mapping():
    """
    收集CVE到diff文件内容的映射关系
    """
    testset_dir = "../testset"
    diff_base_dir = "../Diff"
    cve_diff_mapping = {}
    
    if not os.path.exists(testset_dir):
        print(f"目录 {testset_dir} 不存在")
        return {}
    
    if not os.path.exists(diff_base_dir):
        print(f"目录 {diff_base_dir} 不存在")
        return {}
    
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
        
        # 提取CVE和commit映射
        cve_commit_mapping = extract_cve_commit_from_valid(valid_file_path)
        print(f"  找到 {len(cve_commit_mapping)} 个CVE-commit映射")
        
        # 对应的diff目录
        diff_project_dir = os.path.join(diff_base_dir, project_name, "diff_files")
        
        if not os.path.exists(diff_project_dir):
            print(f"  diff目录不存在: {diff_project_dir}")
            continue
        
        # 查找每个CVE对应的diff文件
        for cve_id, commit_hash in cve_commit_mapping.items():
            # 构建diff文件名格式: CVE-YYYY-NNNN-commit_hash.diff
            diff_filename = f"{project_name}_{cve_id}_{commit_hash}.diff"
            diff_file_path = os.path.join(diff_project_dir, diff_filename)
            
            if os.path.exists(diff_file_path):
                diff_content = load_diff_file(diff_file_path)
                if diff_content:
                    cve_diff_mapping[cve_id] = diff_content
                    print(f"  {cve_id}: 加载diff文件成功 ({len(diff_content)} 字符)")
                else:
                    print(f"  {cve_id}: diff文件为空")
            else:
                print(f"  {cve_id}: diff文件不存在 - {diff_filename}")
    
    return cve_diff_mapping

def save_diff_mapping_to_pkl(cve_diff_mapping, output_file="cve_diff_mapping.pkl"):
    """
    将CVE-diff映射保存为pickle文件
    """
    try:
        with open(output_file, 'wb') as f:
            pickle.dump(cve_diff_mapping, f)
        
        print(f"CVE-diff映射已保存到: {output_file}")
    except Exception as e:
        print(f"保存pickle文件失败: {e}")

def main():
    """
    主函数
    """
    print("开始收集CVE到diff文件的映射...")
    
    # 收集映射
    cve_diff_mapping = collect_cve_diff_mapping()
    
    print(f"\n总共收集到 {len(cve_diff_mapping)} 个CVE的diff文件")
    
    # 打印统计信息
    total_size = sum(len(content) for content in cve_diff_mapping.values())
    print(f"总diff内容大小: {total_size} 字符")
    
    # 保存为pickle文件
    save_diff_mapping_to_pkl(cve_diff_mapping)
    
    return cve_diff_mapping

if __name__ == "__main__":
    diff_mapping = main()
    
    # 示例：打印前几个CVE的diff内容长度
    print("\n示例CVE diff长度:")
    for i, (cve_id, diff_content) in enumerate(diff_mapping.items()):
        if i >= 5:  # 只显示前5个
            break
        print(f"  {cve_id}: {len(diff_content)} 字符")
