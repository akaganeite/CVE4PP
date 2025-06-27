import json
import argparse
import glob
from collections import defaultdict

def process_cwe_clustering(program_name):
    # 读取原始数据
    with open(f"./cveinfo/{program_name}/{program_name}_parsed.json", 'r') as f:
        cve_data = json.load(f)
    
    # 创建自动初始值的聚类字典
    cwe_clusters = defaultdict(list)
    
    # 遍历每个CVE条目
    for entry in cve_data:
        cve_id = entry["id"]
        cwe_list = entry.get("cwe", [])
        
        # 处理无CWE分类的情况
        if not cwe_list:
            cwe_list = ["CWE-UNKNOWN"]
        
        # 将CVE添加到对应的CWE分类
        for cwe in cwe_list:
            cwe_clusters[cwe].append(cve_id)
    
    # 转换为标准字典并排序
    sorted_clusters = {
        cwe: sorted(cves) 
        for cwe, cves in sorted(cwe_clusters.items())
    }
    
    # 生成输出文件名
    output_filename = f"./cveinfo/{program_name}_CWE.json"
    
    # 保存结果
    with open(output_filename, 'w') as f:
        json.dump(sorted_clusters, f, indent=2, ensure_ascii=False)
    
    print(f"生成文件: {output_filename}")
    print(f"聚类统计: { {k: len(v) for k, v in sorted_clusters.items()} }")


def merge_cwe_data():
    # 初始化合并字典
    merged = defaultdict(list)
    
    # 查找所有_CWE.json文件
    for cwe_file in glob.glob("./cveinfo/*/*_CWE.json"):
        with open(cwe_file, 'r') as f:
            data = json.load(f)
            for cwe_id, cves in data.items():
                merged[cwe_id].extend(cves)
    
    # 按CVE数量降序排序
    sorted_cwes = sorted(merged.items(), 
                        key=lambda x: len(x[1]), 
                        reverse=True)
    #去掉sorted_cwes中key为"NVD-CWE-Other"的元素
    sorted_cwes = [(k, v) for k, v in sorted_cwes if k != "NVD-CWE-Other"]
    # 转换为有序字典
    ordered_result = {k: v for k, v in sorted_cwes}
    
    # 保存结果
    with open("./CWE_all.json", 'w') as f:
        json.dump(ordered_result, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CWE分类聚类工具')
    parser.add_argument('-p', '--program',  help='程序名称')
    parser.add_argument('-m', '--merge',  action='store_true',help='合并所有CWE数据')
    args = parser.parse_args()
    if args.merge:
        merge_cwe_data()
    elif args.program:   
        process_cwe_clustering(args.program)