import json
import csv
import os
from collections import defaultdict

def load_cwe_refined():
    """
    加载CWE refined数据
    """
    try:
        with open('../cwe_refined.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"读取cwe_refined.json失败: {e}")
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
                            'target': int(row.get('targets', 1) or 1),  # 使用targets而不是target
                            'false_positive': fp_count,
                            'false_negative': fn_count,
                            'additional_errors': additional_count  # 仅BinXray使用
                        }
                    except ValueError as ve:
                        print(f"数据转换错误 {csv_path} 行 {cve_id}: {ve}")
                        # 使用默认值
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

def calculate_cwe_accuracy(cwe_refined, works, projects):
    """
    计算每个工作在每个CWE下的准确率
    """
    results = {}
    
    for work in works:
        results[work] = {}
        print(f"\n处理工作: {work}")
        
        # 收集所有项目的结果
        all_project_results = {}
        for project in projects:
            project_results = load_csv_results(work, project)
            all_project_results.update(project_results)
            print(f"  {project}: 加载了 {len(project_results)} 个CVE结果")
        
        # 按CWE分组计算准确率
        for cwe_id, cve_list in cwe_refined.items():
            if not cwe_id.startswith('CWE-'):
                continue
            
            # 只处理CVE数量大于10个的CWE
            if len(cve_list) <= 5:
                continue
                
            total_succeed = 0
            total_target = 0
            total_fp_fn = 0
            matched_cves = 0
            
            for cve in cve_list:
                if cve in all_project_results:
                    matched_cves += 1
                    result = all_project_results[cve]
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
                
                # 对于BinXray，ACC2 = succeed / (succeed + fp + fn + additional_errors)
                if work == 'BinXray':
                    total_all_attempts = total_succeed + total_fp_fn
                    accuracy2 = total_succeed / total_all_attempts if total_all_attempts > 0 else 0
                else:
                    accuracy2 = total_succeed / (total_succeed + total_fp_fn)

                results[work][cwe_id] = {
                    'matched_cves': matched_cves,
                    'total_cves': len(cve_list),
                    'total_succeed': total_succeed,
                    'total_target': total_target,
                    'total_fp_fn': total_fp_fn,
                    'accuracy_succeed_target': accuracy1,
                    'accuracy_succeed_fp_fn': accuracy2
                }
                
                print(f"  {cwe_id}: {matched_cves}/{len(cve_list)} CVEs, "
                      f"准确率1: {accuracy1:.3f}, 准确率2: {accuracy2:.3f}")
    
    return results

def save_results_to_csv(results, output_file):
    """
    将结果保存为CSV文件
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Work', 'CWE_ID', 'Matched_CVEs', 'Total_CVEs', 
                'Total_Succeed', 'Total_Target', 'Total_FP_FN',
                'Accuracy_Succeed_Target', 'Accuracy_Succeed_FP_FN'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for work, cwe_results in results.items():
                for cwe_id, metrics in cwe_results.items():
                    writer.writerow({
                        'Work': work,
                        'CWE_ID': cwe_id,
                        'Matched_CVEs': metrics['matched_cves'],
                        'Total_CVEs': metrics['total_cves'],
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
    print("CWE准确率分析汇总")
    print("="*80)
    
    for work in results:
        print(f"\n工作: {work}")
        print("-" * 60)
        print(f"{'CWE ID':<15} {'匹配CVE':<10} {'总CVE':<8} {'准确率1':<10} {'准确率2':<10}")
        print("-" * 60)
        
        # 按准确率1排序
        sorted_cwes = sorted(results[work].items(), 
                           key=lambda x: x[1]['accuracy_succeed_target'], 
                           reverse=True)
        
        for cwe_id, metrics in sorted_cwes:
            print(f"{cwe_id:<15} {metrics['matched_cves']:<10} "
                  f"{metrics['total_cves']:<8} "
                  f"{metrics['accuracy_succeed_target']:<10.3f} "
                  f"{metrics['accuracy_succeed_fp_fn']:<10.3f}")

def main():
    """
    主函数
    """
    print("开始分析CWE准确率...")
    
    # 配置 - 3个工作，6个项目
    works = ['PS3', 'BinXray', 'PatchDiscovery','React']
    projects = ['curl', 'openssl', 'libxml2', 'sqlite', 'ffmpeg', 'binutils']
    
    # 加载CWE refined数据
    cwe_refined = load_cwe_refined()
    if not cwe_refined:
        print("无法加载CWE数据，退出")
        return
    
    print(f"加载了 {len(cwe_refined)} 个CWE分类")
    print(f"工作列表: {works}")
    print(f"项目列表: {projects}")
    
    # 计算准确率
    results = calculate_cwe_accuracy(cwe_refined, works, projects)
    
    # 保存结果
    save_results_to_csv(results, 'cwe_accuracy_analysis.csv')
    
    # 打印汇总
    print_summary(results)

if __name__ == "__main__":
    main()
