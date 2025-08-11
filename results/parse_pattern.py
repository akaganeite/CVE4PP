import json
import csv
import os
from collections import defaultdict

def load_pattern_data():
    """
    加载pattern分类数据
    """
    try:
        with open('../pattern_analysis/pattern.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"读取pattern.json失败: {e}")
        return {}

def load_csv_results(work, project):
    """
    加载指定工作和项目的CSV结果
    """
    csv_path = f"{work}/{project}_result.csv"
    results = {}
    
    if not os.path.exists(csv_path):
        print(f"文件不存在: {csv_path}")
        return results
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get('CVE', '').strip()
                if cve_id:
                    try:
                        # 处理false_positive和false_negative，它们可能是版本号列表
                        fp_value = row.get('false_positive', '').strip()
                        fn_value = row.get('false_negative', '').strip()
                        
                        # 如果是版本号列表（包含分号），计算数量
                        if fp_value and ';' in fp_value:
                            fp_count = len(fp_value.split(';'))
                        elif fp_value:
                            fp_count = 1
                        else:
                            fp_count = 0
                            
                        if fn_value and ';' in fn_value:
                            fn_count = len(fn_value.split(';'))
                        elif fn_value:
                            fn_count = 1
                        else:
                            fn_count = 0
                        
                        # 如果是BinXray，还需要处理额外的字段
                        additional_count = 0
                        if work == 'BinXray':
                            for field in ['too_much_diff', 'cant_tell', 'no_diff']:
                                field_value = row.get(field, '').strip()
                                if field_value and ';' in field_value:
                                    additional_count += len(field_value.split(';'))
                                elif field_value:
                                    additional_count += 1
                        
                        results[cve_id] = {
                            'succeed': int(row.get('succeed', 0) or 0),
                            'target': int(row.get('targets', 1) or 1),
                            'false_positive': fp_count,
                            'false_negative': fn_count,
                            'additional_errors': additional_count
                        }
                    except ValueError as ve:
                        print(f"数据转换错误 {csv_path} 行 {cve_id}: {ve}")
                        results[cve_id] = {
                            'succeed': 0,
                            'target': 1,
                            'false_positive': 0,
                            'false_negative': 0,
                            'additional_errors': 0
                        }
    except Exception as e:
        print(f"读取CSV文件 {csv_path} 失败: {e}")
    
    return results

def calculate_pattern_accuracy(pattern_data, works, projects):
    """
    计算每个工作在每个模式分类下的准确率
    """
    results = {}
    
    # 定义模式分类
    pattern_categories = {
        1: "add input sanitization checks",
        2: "change input sanitization checks", 
        3: "add data structures",
        4: "change data structure definitions",
        5: "change data structure references",
        6: "change function parameters",
        7: "add or change function calls",
        8: "add functions",
        9: "change functions"
    }
    
    # 定义聚合类别
    aggregate_categories = {
        "Input_Sanitization": [1, 2],
        "Data_Structure": [3, 4, 5], 
        "Function_Changes": [6, 7, 8, 9]
    }
    
    for work in works:
        results[work] = {}
        print(f"\n处理工作: {work}")
        
        # 收集所有项目的结果
        all_project_results = {}
        for project in projects:
            project_results = load_csv_results(work, project)
            all_project_results.update(project_results)
            print(f"  {project}: 加载了 {len(project_results)} 个CVE结果")
        
        # 按模式分类计算准确率
        for pattern_id in range(1, 10):
            pattern_name = pattern_categories[pattern_id]
            
            total_succeed = 0
            total_target = 0
            total_fp_fn = 0
            matched_cves = 0
            
            # 找到包含该模式的CVE
            for cve_id, patterns in pattern_data.items():
                if pattern_id in patterns and cve_id in all_project_results:
                    matched_cves += 1
                    result = all_project_results[cve_id]
                    total_succeed += result['succeed']
                    total_target += result['target']
                    
                    # 对于BinXray，计算总错误数包括额外字段
                    if work == 'BinXray':
                        total_fp_fn += (result['false_positive'] + result['false_negative'] + 
                                      result['additional_errors'])
                    else:
                        total_fp_fn += result['false_positive'] + result['false_negative']
            
            if matched_cves > 0:
                # 计算两种准确率
                accuracy1 = total_succeed / total_target if total_target > 0 else 0
                
                if work == 'BinXray':
                    total_all_attempts = total_succeed + total_fp_fn
                    accuracy2 = total_succeed / total_all_attempts if total_all_attempts > 0 else 0
                else:
                    accuracy2 = total_succeed / (total_succeed + total_fp_fn) if (total_succeed + total_fp_fn) > 0 else 0
                
                results[work][f"Pattern_{pattern_id}"] = {
                    'pattern_name': pattern_name,
                    'matched_cves': matched_cves,
                    'total_succeed': total_succeed,
                    'total_target': total_target,
                    'total_fp_fn': total_fp_fn,
                    'accuracy_succeed_target': accuracy1,
                    'accuracy_succeed_fp_fn': accuracy2
                }
                
                print(f"  模式{pattern_id}: {matched_cves} CVEs, "
                      f"准确率1: {accuracy1:.3f}, 准确率2: {accuracy2:.3f}")
        
        # 计算聚合类别准确率
        for agg_name, pattern_list in aggregate_categories.items():
            total_succeed = 0
            total_target = 0
            total_fp_fn = 0
            matched_cves = 0
            processed_cves = set()
            
            # 找到包含任一聚合模式的CVE
            for cve_id, patterns in pattern_data.items():
                if any(p in patterns for p in pattern_list) and cve_id in all_project_results:
                    if cve_id not in processed_cves:
                        processed_cves.add(cve_id)
                        matched_cves += 1
                        result = all_project_results[cve_id]
                        total_succeed += result['succeed']
                        total_target += result['target']
                        
                        if work == 'BinXray':
                            total_fp_fn += (result['false_positive'] + result['false_negative'] + 
                                          result['additional_errors'])
                        else:
                            total_fp_fn += result['false_positive'] + result['false_negative']
            
            if matched_cves > 0:
                accuracy1 = total_succeed / total_target if total_target > 0 else 0
                
                if work == 'BinXray':
                    total_all_attempts = total_succeed + total_fp_fn
                    accuracy2 = total_succeed / total_all_attempts if total_all_attempts > 0 else 0
                else:
                    accuracy2 = total_succeed / (total_succeed + total_fp_fn) if (total_succeed + total_fp_fn) > 0 else 0
                
                results[work][agg_name] = {
                    'pattern_name': f"聚合类别: {agg_name}",
                    'matched_cves': matched_cves,
                    'total_succeed': total_succeed,
                    'total_target': total_target,
                    'total_fp_fn': total_fp_fn,
                    'accuracy_succeed_target': accuracy1,
                    'accuracy_succeed_fp_fn': accuracy2
                }
                
                print(f"  {agg_name}: {matched_cves} CVEs, "
                      f"准确率1: {accuracy1:.3f}, 准确率2: {accuracy2:.3f}")
    
    return results

def save_results_to_csv(results, output_file):
    """
    将结果保存为CSV文件
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Work', 'Pattern_Category', 'Pattern_Name', 'Matched_CVEs', 
                'Total_Succeed', 'Total_Target', 'Total_FP_FN',
                'Accuracy_Succeed_Target', 'Accuracy_Succeed_FP_FN'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for work, pattern_results in results.items():
                for pattern_id, metrics in pattern_results.items():
                    writer.writerow({
                        'Work': work,
                        'Pattern_Category': pattern_id,
                        'Pattern_Name': metrics['pattern_name'],
                        'Matched_CVEs': metrics['matched_cves'],
                        'Total_Succeed': metrics['total_succeed'],
                        'Total_Target': metrics['total_target'],
                        'Total_FP_FN': metrics['total_fp_fn'],
                        'Accuracy_Succeed_Target': f"{metrics['accuracy_succeed_target']:.4f}",
                        'Accuracy_Succeed_FP_FN': f"{metrics['accuracy_succeed_fp_fn']:.4f}"
                    })
        
        print(f"\n结果已保存到: {output_file}")
    except Exception as e:
        print(f"保存CSV文件失败: {e}")

def print_summary(results):
    """
    打印汇总信息
    """
    print("\n" + "="*80)
    print("模式分类准确率分析汇总")
    print("="*80)
    
    for work in results:
        print(f"\n工作: {work}")
        print("-" * 70)
        print(f"{'分类':<20} {'匹配CVE':<10} {'准确率1':<10} {'准确率2':<10}")
        print("-" * 70)
        
        # 按准确率1排序
        sorted_patterns = sorted(results[work].items(), 
                               key=lambda x: x[1]['accuracy_succeed_target'], 
                               reverse=True)
        
        for pattern_id, metrics in sorted_patterns:
            print(f"{pattern_id:<20} {metrics['matched_cves']:<10} "
                  f"{metrics['accuracy_succeed_target']:<10.3f} "
                  f"{metrics['accuracy_succeed_fp_fn']:<10.3f}")

def main():
    """
    主函数
    """
    print("开始分析模式分类准确率...")
    
    # 配置
    works = ['PS3', 'BinXray', 'PatchDiscovery', 'React']
    projects = ['curl', 'openssl', 'libxml2', 'sqlite', 'ffmpeg', 'binutils']
    
    # 加载模式数据
    pattern_data = load_pattern_data()
    if not pattern_data:
        print("无法加载模式数据，退出")
        return
    
    print(f"加载了 {len(pattern_data)} 个CVE的模式分类")
    print(f"工作列表: {works}")
    print(f"项目列表: {projects}")
    
    # 计算准确率
    results = calculate_pattern_accuracy(pattern_data, works, projects)
    
    # 保存结果
    save_results_to_csv(results, 'pattern_accuracy_analysis.csv')
    
    # 打印汇总
    print_summary(results)

if __name__ == "__main__":
    main()
