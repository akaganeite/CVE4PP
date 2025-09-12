import json
import csv
import os
import pickle
from collections import defaultdict

def load_function_size_data():
    """
    加载函数基本块大小数据
    """
    pkl_path = '../../RQs/size_analysis/cve_function_binary_size.pkl'
    try:
        with open(pkl_path, 'rb') as f:
            data = pickle.load(f)
        print(f"加载函数大小数据: {len(data)} 条记录")
        return data
    except Exception as e:
        print(f"读取函数大小PKL文件失败: {e}")
        return []

def load_patch_size_data():
    """
    加载补丁大小数据
    """
    pkl_path = '../../RQs/size_analysis/cve_patch_size.pkl'
    try:
        with open(pkl_path, 'rb') as f:
            data = pickle.load(f)
        print(f"加载补丁大小数据: {len(data)} 条记录")
        print(data[1])
        return data
    except Exception as e:
        print(f"读取补丁大小PKL文件失败: {e}")
        return []

def categorize_function_size(basic_blocks):
    """
    将函数基本块数量按步长40分类
    """
    # if basic_blocks == 0:
    #     return "0"
    # elif basic_blocks <= 40:
    #     return "1-40"
    # elif basic_blocks <= 80:
    #     return "41-80"
    # elif basic_blocks <= 120:
    #     return "81-120"
    # elif basic_blocks <= 160:
    #     return "121-160"
    # elif basic_blocks <= 200:
    #     return "161-200"
    # else:
    #     return ">200"
    if basic_blocks == 0:
        return "0"
    elif basic_blocks <= 26:
        return "1-26"
    elif basic_blocks <= 63:
        return "27-63"
    elif basic_blocks <= 159:
        return "64-159"
    else:
        return ">159"

def categorize_patch_size(total_lines):
    """
    将补丁修改行数按步长10分类
    """
    # if total_lines == 0:
    #     return "0"
    # elif total_lines <= 5:
    #     return "1-5"
    # elif total_lines <= 10:
    #     return "6-10"
    # elif total_lines <= 20:
    #     return "11-20"
    # elif total_lines <= 30:
    #     return "21-30"
    # elif total_lines <= 40:
    #     return "31-40"
    # elif total_lines <= 50:
    #     return "41-50"
    # elif total_lines <= 60:
    #     return "51-60"
    # elif total_lines <= 70:
    #     return "61-70"
    # elif total_lines <= 80:
    #     return "71-80"
    # else:
    #     return ">80"
    # if total_lines == 0:
    #     return "0"
    # elif total_lines <= 20:
    #     return "1-20"
    # elif total_lines <= 40:
    #     return "21-40"
    # elif total_lines <= 60:
    #     return "41-60"
    # elif total_lines <= 80:
    #     return "61-80"
    # else:
    #     return ">80"
    if total_lines == 0:
        return "0"
    elif total_lines <= 3:
        return "1-3"
    elif total_lines <= 8:
        return "4-8"
    elif total_lines <= 20:
        return "9-20"
    else :
        return ">20"

def load_function_results_csv(work, project):
    """
    加载函数级别结果CSV（{project}_results.csv）
    返回CVE-函数级别的结果字典
    """
    csv_path = f"../{work}/gcc-o0/{project}_result.csv"
    results = {}
    
    if not os.path.exists(csv_path):
        print(f"文件不存在: {csv_path}")
        return results
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row_orig in reader:
                row = {k.lower() if k else k: v for k, v in row_orig.items()}
                cve_id = row.get('cve', '').strip()
                func_name = row.get('funcname', '').strip()
                
                if cve_id and func_name:
                    try:
                        # 处理false_positive和false_negative
                        if work == "Robin" or work == "PS3":
                            fp_value = int(row.get('fp', 0))
                            fn_value = int(row.get('fn', 0))
                        else:
                            fp_value = row.get('false_positive', '').strip()
                            fn_value = row.get('false_negative', '').strip()
                            if fp_value and ';' in fp_value:
                                fp_value = len(fp_value.split(';'))
                            elif fp_value:  
                                fp_value = 1
                            else:
                                fp_value = 0
                                
                            if fn_value and ';' in fn_value:
                                fn_value = len(fn_value.split(';'))
                            elif fn_value:
                                fn_value = 1
                            else:
                                fn_value = 0
                               
                        # 构建CVE-函数的键
                        key = f"{cve_id}-{func_name}"
                        results[key] = {
                            'cve_id': cve_id,
                            'func_name': func_name,
                            'succeed': int(row.get('succeed', 0) or 0),
                            'target': int(row.get('targets', row.get('target', 1)) or 1),
                            'false_positive': fp_value,
                            'false_negative': fn_value,
                        }
                    except ValueError as ve:
                        print(f"数据转换错误 {csv_path} 行 {cve_id}-{func_name}: {ve}")
    except Exception as e:
        print(f"读取CSV文件 {csv_path} 失败: {e}")
    
    return results

def load_patch_results_csv(work, project):
    """
    加载补丁级别结果CSV（{project}-cve.csv）
    """
    csv_path = f"../{work}/gcc-o0/{project}-cve.csv"
    if work == 'React':
        csv_path = f"../{work}/gcc-o0/{project}_result.csv"
    results = {}
    
    if not os.path.exists(csv_path):
        print(f"文件不存在: {csv_path}")
        return results
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row_orig in reader:
                row = {k.lower() if k else k: v for k, v in row_orig.items()}
                cve_id = row.get('cve', '').strip()
                if cve_id:
                    try:
                        # 处理false_positive和false_negative
                        fp_value = int(row.get('fp', 0))
                        fn_value = int(row.get('fn', 0))


                        
                        
                        results[cve_id] = {
                            'succeed': int(row.get('succeed', 0) or 0),
                            'target': int(row.get('target', 1) or 1),
                            'false_positive': fp_value,
                            'false_negative': fn_value,
                            'signature_generated': False,
                        }
                        if work == "Robin":
                            hassig=row.get('signature_generated', 'False').strip().lower() == 'true'
                            results[cve_id]['signature_generated'] = hassig
                    except ValueError as ve:
                        print(f"数据转换错误 {csv_path} 行 {cve_id}: {ve}")
    except Exception as e:
        print(f"读取CSV文件 {csv_path} 失败: {e}")
    
    return results

def analyze_function_size_accuracy(function_data, works, projects):
    """
    分析函数大小对准确率的影响
    """
    # 按CVE-函数组织数据
    cve_function_sizes = {}
    for record in function_data:
        if record['basic_blocks'] > 0:  # 只考虑成功分析的函数
            key = f"{record['cve_id']}-{record['function']}"
            cve_function_sizes[key] = {
                'cve_id': record['cve_id'],
                'function': record['function'],
                'basic_blocks': record['basic_blocks'],
                'category': categorize_function_size(record['basic_blocks'])
            }
    
    print(f"有效函数大小记录: {len(cve_function_sizes)}")
    
    results = {}
    for work in works:
        results[work] = defaultdict(lambda: {
            'total_succeed': 0, 'total_target': 0, 'total_fp_fn': 0, 'count': 0
        })
        
        print(f"\n处理工作 {work} 的函数大小分析")
        
        # 收集所有项目的函数级别结果
        all_function_results = {}
        for project in projects:
            project_results = load_function_results_csv(work, project)
            all_function_results.update(project_results)
            print(f"  {project}: {len(project_results)} 个函数结果")
        
        # 按函数大小分类统计
        for key, func_data in cve_function_sizes.items():
            category = func_data['category']
            
            # 直接使用相同的key进行匹配
            if key in all_function_results:
                result = all_function_results[key]
                results[work][category]['total_succeed'] += result['succeed']
                results[work][category]['total_target'] += result['target']
                results[work][category]['total_fp_fn'] += (
                    result['false_positive'] + result['false_negative']
                )
                results[work][category]['count'] += 1
        
        # 计算准确率
        for category in results[work]:
            data = results[work][category]
            if data['total_target'] > 0:
                data['accuracy1'] = data['total_succeed'] / data['total_target']
            else:
                data['accuracy1'] = 0
            
            total_attempts = data['total_succeed'] + data['total_fp_fn']
            if total_attempts > 0:
                data['accuracy2'] = data['total_succeed'] / total_attempts
            else:
                data['accuracy2'] = 0
            
            print(f"  {category}: {data['count']} 个函数, 准确率1: {data['accuracy1']:.3f}, 准确率2: {data['accuracy2']:.3f}")
    
    return results

def analyze_patch_size_accuracy(patch_data, works, projects):
    """
    分析补丁大小对准确率的影响
    """
    # 按CVE组织补丁大小数据
    cve_patch_sizes = {}
    for record in patch_data:
        if record['total_changed_lines'] > 0:
            cve_id = record['cve_id']
            cve_patch_sizes[cve_id] = {
                'total_lines': record['total_changed_lines'],
                'category': categorize_patch_size(record['total_changed_lines'])
            }
    
    print(f"有效补丁大小记录: {len(cve_patch_sizes)}")
    
    results = {}
    for work in works:
        results[work] = defaultdict(lambda: {
            'total_succeed': 0, 'total_target': 0, 'total_fp_fn': 0, 'count': 0
        })
        
        print(f"\n处理工作 {work} 的补丁大小分析")
        
        # 收集所有项目的结果
        all_results = {}
        for project in projects:
            project_results = load_patch_results_csv(work, project)
            all_results.update(project_results)
            print(f"  {project}: {len(project_results)} 个CVE结果")
        
        # 按补丁大小分类统计
        for cve_id, patch_data in cve_patch_sizes.items():
            category = patch_data['category']
            
            if cve_id in all_results:
                result = all_results[cve_id]
                results[work][category]['total_succeed'] += result['succeed']
                if work =="Robin":
                    if result['signature_generated'] == True :
                        results[work][category]['total_target'] += result['target']
                else:
                    results[work][category]['total_target'] += result['target']
                results[work][category]['total_fp_fn'] += (
                    result['false_positive'] + result['false_negative']
                )
                results[work][category]['count'] += 1
        
        # 计算准确率
        for category in results[work]:
            data = results[work][category]
            if data['total_target'] > 0:
                data['accuracy1'] = data['total_succeed'] / data['total_target']
            else:
                data['accuracy1'] = 0
            
            total_attempts = data['total_succeed'] + data['total_fp_fn']
            if total_attempts > 0:
                data['accuracy2'] = data['total_succeed'] / total_attempts
            else:
                data['accuracy2'] = 0
            
            print(f"  {category}: {data['count']} 个补丁, 准确率1: {data['accuracy1']:.3f}, 准确率2: {data['accuracy2']:.3f}")
    
    return results

def save_function_analysis_to_csv(results, output_file):
    """
    保存函数大小分析结果到CSV
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Work', 'Function_Size_Category', 'Count', 'Total_Succeed', 
                'Total_Target', 'Total_FP_FN', 'Accuracy_Succeed_Target', 'Accuracy_Succeed_FP_FN'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # 定义分类顺序
            # categories = ["0", "1-40", "41-80", "81-120", "121-160", "161-200", ">200"]
            categories = ["0", "1-26", "27-63", "64-159", ">159"]
            for work, work_results in results.items():
                for category in categories:
                    if category in work_results:
                        data = work_results[category]
                        writer.writerow({
                            'Work': work,
                            'Function_Size_Category': category,
                            'Count': data['count'],
                            'Total_Succeed': data['total_succeed'],
                            'Total_Target': data['total_target'],
                            'Total_FP_FN': data['total_fp_fn'],
                            'Accuracy_Succeed_Target': f"{data['accuracy1']:.4f}",
                            'Accuracy_Succeed_FP_FN': f"{data['accuracy2']:.4f}"
                        })
        
        print(f"函数大小分析结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存函数分析CSV文件失败: {e}")

def save_patch_analysis_to_csv(results, output_file):
    """
    保存补丁大小分析结果到CSV
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Work', 'Patch_Size_Category', 'Count', 'Total_Succeed', 
                'Total_Target', 'Total_FP_FN', 'Accuracy_Succeed_Target', 'Accuracy_Succeed_FP_FN'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # 定义分类顺序
            # categories = ["0", "1-10", "11-20", "21-30", "31-40", "41-50", 
            #              "51-60", "61-70", "71-80", ">80"]
            # categories = ["0", "1-5", "6-10","11-20", "21-30", "31-40", "41-50", 
            #              "51-60", "61-70", "71-80", ">80"]
            # categories = ["0", "1-20", "21-40", "41-60", "61-80",">80"]
            categories = ["0", "1-3", "4-8", "9-20", ">20"]
            
            for work, work_results in results.items():
                for category in categories:
                    if category in work_results:
                        data = work_results[category]
                        writer.writerow({
                            'Work': work,
                            'Patch_Size_Category': category,
                            'Count': data['count'],
                            'Total_Succeed': data['total_succeed'],
                            'Total_Target': data['total_target'],
                            'Total_FP_FN': data['total_fp_fn'],
                            'Accuracy_Succeed_Target': f"{data['accuracy1']:.4f}",
                            'Accuracy_Succeed_FP_FN': f"{data['accuracy2']:.4f}"
                        })
        
        print(f"补丁大小分析结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存补丁分析CSV文件失败: {e}")

def print_summary(function_results, patch_results):
    """
    打印汇总信息
    """
    print("\n" + "="*80)
    print("大小分析汇总")
    print("="*80)
    
    print("\n函数大小分析:")
    print("-" * 80)
    for work in function_results:
        print(f"\n工作: {work}")
        print(f"{'大小分类':<15} {'数量':<8} {'成功':<8} {'目标':<8} {'准确率1':<10} {'准确率2':<10}")
        print("-" * 60)
        
        # categories = ["0", "1-40", "41-80", "81-120", "121-160", "161-200", ">200"]
        categories = ["0", "1-26", "27-63", "64-159", ">159"]
        for category in categories:
            if category in function_results[work]:
                data = function_results[work][category]
                print(f"{category:<15} {data['count']:<8} {data['total_succeed']:<8} "
                      f"{data['total_target']:<8} {data['accuracy1']:<10.3f} {data['accuracy2']:<10.3f}")
    
    print("\n\n补丁大小分析:")
    print("-" * 80)
    for work in patch_results:
        print(f"\n工作: {work}")
        print(f"{'大小分类':<15} {'数量':<8} {'成功':<8} {'目标':<8} {'准确率1':<10} {'准确率2':<10}")
        print("-" * 60)
        
        # categories = ["0", "1-10", "11-20", "21-30", "31-40", "41-50", 
        #              "51-60", "61-70", "71-80", ">80"]
        # categories = ["0", "1-20", "21-40", "41-60", "61-80",">80"]
        categories = ["0", "1-3", "4-8", "9-20", ">20"]
        # categories = ["0", "1-5", "6-10","11-20", "21-30", "31-40", "41-50", 
                        #  "51-60", "61-70", "71-80", ">80"]
        for category in categories:
            if category in patch_results[work]:
                data = patch_results[work][category]
                print(f"{category:<15} {data['count']:<8} {data['total_succeed']:<8} "
                      f"{data['total_target']:<8} {data['accuracy1']:<10.3f} {data['accuracy2']:<10.3f}")

def main():
    """
    主函数
    """
    print("开始大小分析...")
    
    # 配置
    works = ['PS3','BinXray','PatchDiscovery','React','Robin']
    projects = ['binutils','curl','ffmpeg','freetype','imagemagick','libxml2', 
                'openjpeg','openssl','sqlite', 'tcpdump']
    
    # 加载数据
    function_data = load_function_size_data()
    patch_data = load_patch_size_data()
    
    if not function_data:
        print("无法加载函数大小数据")
    
    if not patch_data:
        print("无法加载补丁大小数据")
    
    # 分析函数大小
    function_results = {}
    if function_data:
        function_results = analyze_function_size_accuracy(function_data, ['PS3', 'BinXray', 'PatchDiscovery','Robin'], projects)
        save_function_analysis_to_csv(function_results, 'function_size_analysis.csv')
    
    # 分析补丁大小
    patch_results = {}
    if patch_data:
        patch_results = analyze_patch_size_accuracy(patch_data, works, projects)
        save_patch_analysis_to_csv(patch_results, 'patch_size_analysis.csv')
    
    # 打印汇总
    print_summary(function_results, patch_results)

if __name__ == "__main__":
    main()
