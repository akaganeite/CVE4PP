import json
import os
import re
import requests
import time
from collections import defaultdict

"""
发现的父子关系:
  CWE-476 -> CWE-754
  CWE-125 -> CWE-119
  CWE-787 -> CWE-119
  CWE-835 -> CWE-834
  CWE-770 -> CWE-400
  CWE-295 -> CWE-287
  CWE-203 -> CWE-200
  CWE-772 -> CWE-404
  CWE-434 -> CWE-669
  CWE-681 -> CWE-704
  CWE-459 -> CWE-404
  CWE-617 -> CWE-670
  CWE-319 -> CWE-311
  CWE-502 -> CWE-913
  CWE-611 -> CWE-610

开始合并CWE数据...
合并 CWE-476 到父节点 CWE-754
合并 CWE-125 到父节点 CWE-119
合并 CWE-787 到父节点 CWE-119
合并 CWE-770 到父节点 CWE-400
合并 CWE-295 到父节点 CWE-287
合并 CWE-203 到父节点 CWE-200
合并 CWE-319 到父节点 CWE-311
"""


def extract_cve_from_valid_file(valid_file_path):
    """
    从valid文件中提取CVE号
    """
    cve_list = []
    try:
        with open(valid_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # 使用正则表达式匹配CVE格式: CVE-YYYY-NNNN
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cves = re.findall(cve_pattern, content)
            cve_list.extend(cves)
    except Exception as e:
        print(f"读取文件 {valid_file_path} 时出错: {e}")
    
    return list(set(cve_list))  # 去重

def load_rawdata_json(project_name):
    """
    加载对应项目的rawdata JSON文件
    """
    rawdata_path = f"rawdata/{project_name}_raw.json"
    try:
        with open(rawdata_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"读取rawdata文件 {rawdata_path} 时出错: {e}")
        return None

def collect_cve_cwe_mapping():
    """
    收集CVE到CWE的映射关系
    """
    testset_dir = "testset"
    cwe_to_cve_mapping = defaultdict(list)
    
    if not os.path.exists(testset_dir):
        print(f"目录 {testset_dir} 不存在")
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
        
        # 提取CVE号
        cve_list = extract_cve_from_valid_file(valid_file_path)
        print(f"  找到 {len(cve_list)} 个CVE")
        
        # 加载对应的rawdata文件
        rawdata = load_rawdata_json(project_name)
        if rawdata is None:
            continue
        
        # 查询每个CVE对应的CWE
        for cve in cve_list:
            found = False
            for entry in rawdata:
                if entry.get('id') == cve:
                    primary_cwe = entry.get('cwe')
                    for cwe in primary_cwe:
                        cwe_to_cve_mapping[cwe].append(cve)
                        print(f"  {cve} -> {cwe}")
                        found = True
                        break
            
            if not found:
                print(f"  警告: 未找到 {cve} 的CWE信息")
    
    return dict(cwe_to_cve_mapping)

def get_cwe_info(cwe_id):
    """
    从MITRE API获取CWE信息
    """
    try:
        # 提取数字部分
        cwe_num = cwe_id.replace("CWE-", "")
        url = f"https://cwe-api.mitre.org/api/v1/cwe/{cwe_num}"
        response = requests.get(url)
        time.sleep(0.1)  # 避免请求过快
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"获取 {cwe_id} 信息失败: {response.status_code}")
            return None
    except Exception as e:
        print(f"请求 {cwe_id} 时出错: {e}")
        return None

def get_cwe_parents(cwe_id, visited=None):
    """
    递归查找CWE的父节点，直到找到class_weakness类型的父节点
    """
    if visited is None:
        visited = set()
    
    # 防止循环引用
    if cwe_id in visited:
        return None
    
    visited.add(cwe_id)
    
    try:
        cwe_num = cwe_id.replace("CWE-", "")
        url = f"https://cwe-api.mitre.org/api/v1/cwe/{cwe_num}/parents?view=1000"
        response = requests.get(url)
        time.sleep(0.1)  # 避免请求过快
        
        if response.status_code == 200:
            parents = response.json()
            
            # 首先查找直接的class_weakness父节点
            for parent in parents:
                if parent.get("Type") == "class_weakness":
                    return f"CWE-{parent['ID']}"
            
            # 如果没有找到class_weakness，递归查找每个父节点
            for parent in parents:
                parent_id = f"CWE-{parent['ID']}"
                if parent.get("Type") in ["base_weakness", "variant_weakness"]:
                    # 递归查找这个父节点的class_weakness祖先
                    class_ancestor = get_cwe_parents(parent_id, visited.copy())
                    if class_ancestor:
                        return class_ancestor
            
            return None
        else:
            print(f"获取 {cwe_id} 父节点失败: {response.status_code}")
            return None
    except Exception as e:
        print(f"请求 {cwe_id} 父节点时出错: {e}")
        return None

def refine_cwe_mapping(input_file="cwe_mapping.json"):
    """
    优化CWE映射，将base_weakness合并到其class_weakness父节点
    """
    # 读取现有的CWE映射
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            cwe_mapping = json.load(f)
    except Exception as e:
        print(f"读取文件 {input_file} 失败: {e}")
        return {}
    
    refined_mapping = defaultdict(list)
    parent_child_relations = {}
    
    print("开始分析CWE类型和父子关系...")
    
    # 首先分析所有CWE的类型
    cwe_types = {}
    for cwe_id in cwe_mapping.keys():
        if cwe_id.startswith("CWE-"):
            print(f"查询 {cwe_id} 的类型...")
            cwe_info = get_cwe_info(cwe_id)
            if cwe_info and len(cwe_info) > 0:
                cwe_types[cwe_id] = cwe_info[0].get("Type", "unknown")
                print(f"  {cwe_id}: {cwe_types[cwe_id]}")
    
    # 对于base_weakness和variant_weakness类型的CWE，查找其class_weakness父节点
    non_class_weaknesses = [cwe for cwe, type_info in cwe_types.items() 
                           if type_info in ["base_weakness", "variant_weakness"]]
    
    for cwe in non_class_weaknesses:
        print(f"递归查找 {cwe} 的class_weakness父节点...")
        class_parent = get_cwe_parents(cwe)
        if class_parent:
            parent_child_relations[cwe] = class_parent
            print(f"  {cwe} -> {class_parent}")
        else:
            print(f"  未找到 {cwe} 的class_weakness父节点")
    
    # 开始合并数据
    print("\n开始合并CWE数据...")
    
    for cwe_id, cves in cwe_mapping.items():
        if cwe_id in parent_child_relations:
            # 这是一个base_weakness，需要合并到父节点
            parent_cwe = parent_child_relations[cwe_id]
            if parent_cwe in cwe_mapping:
                print(f"合并 {cwe_id} 到父节点 {parent_cwe}")
                refined_mapping[parent_cwe].extend(cves)
                refined_mapping[parent_cwe].extend(cwe_mapping[parent_cwe])
            else:
                # 父节点不在现有映射中，保持原样
                refined_mapping[cwe_id].extend(cves)
        else:
            # 不是base_weakness或没有找到父节点，直接复制
            if cwe_id not in [parent_child_relations[child] for child in parent_child_relations if parent_child_relations[child] in cwe_mapping]:
                refined_mapping[cwe_id].extend(cves)
    
    # 去重并排序
    for cwe_id in refined_mapping:
        refined_mapping[cwe_id] = list(set(refined_mapping[cwe_id]))
    
    # 按CVE数量排序
    sorted_refined = dict(sorted(refined_mapping.items(), key=lambda x: len(x[1]), reverse=True))
    
    # 输出父子关系信息
    if parent_child_relations:
        print("\n发现的父子关系:")
        for child, parent in parent_child_relations.items():
            print(f"  {child} -> {parent}")
    
    return sorted_refined

def main():
    """
    主函数
    """
    print("开始收集CVE到CWE的映射关系...")
    
    cwe_mapping = collect_cve_cwe_mapping()
    
    # 按CVE数量从多到少排序
    sorted_cwe_mapping = dict(sorted(cwe_mapping.items(), key=lambda x: len(x[1]), reverse=True))
    
    # 输出结果到JSON文件
    output_file = "cwe_mapping.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sorted_cwe_mapping, f, indent=2, ensure_ascii=False)
        
        print(f"\n结果已保存到 {output_file}")
        print(f"总共收集到 {len(sorted_cwe_mapping)} 个CWE分类")
        
        # 打印统计信息
        for cwe, cves in sorted_cwe_mapping.items():
            print(f"{cwe}: {len(cves)} 个CVE")
    except Exception as e:
        print(f"保存结果时出错: {e}")
        return
    
    # 执行refine功能
    print("\n" + "="*50)
    print("开始执行CWE映射优化...")
    
    refined_mapping = refine_cwe_mapping(output_file)
    
    # 输出优化后的结果
    refined_output_file = "cwe_refined.json"
    try:
        with open(refined_output_file, 'w', encoding='utf-8') as f:
            json.dump(refined_mapping, f, indent=2, ensure_ascii=False)
        
        print(f"\n优化后的结果已保存到 {refined_output_file}")
        print(f"优化后共有 {len(refined_mapping)} 个CWE分类")
        
        # 打印优化后的统计信息
        print("\n优化后的统计信息:")
        for cwe, cves in refined_mapping.items():
            print(f"{cwe}: {len(cves)} 个CVE")
            
    except Exception as e:
        print(f"保存优化结果时出错: {e}")

if __name__ == "__main__":
    main()
