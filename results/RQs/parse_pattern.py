import json
import csv
import os
from collections import defaultdict

def load_pattern_data():
    """
    加载pattern分类数据
    """
    try:
        with open('../../RQs/pattern_analysis/pattern.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"读取pattern.json失败: {e}")
        return {}

def load_csv_results(work, project):
    """
    加载指定工作和项目的CSV结果
    """
    csv_path = f"../{work}/gcc-o0/{project}-cve.csv"
    if work == "React":
        csv_path = f"../{work}/gcc-o0/{project}_result.csv"
    results = {}
    
    if not os.path.exists(csv_path):
        print(f"文件不存在: {csv_path}")
        return results
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row = {k.lower() if k else k: v for k, v in row.items()}
                cve_id = row.get('cve', '').strip()
                if cve_id:
                    try:
                        # 处理false_positive和false_negative，它们可能是版本号列表
                        fp_value = int(row.get('fp', 0))
                        fn_value = int(row.get('fn', 0))
                    
                        
                        # 如果是BinXray，还需要处理额外的字段
                        has_sig = False
                        if work == 'Robin':
                            has_sig = row.get('signature_generated', 'False').strip().lower() == 'true'

                        
                        results[cve_id] = {
                            'succeed': int(row.get('succeed', 0) or 0),
                            'target': int(row.get('target', 1) or 1),
                            'false_positive': fp_value,
                            'false_negative': fn_value,
                            'has_sig': has_sig
                        }
                    except ValueError as ve:
                        print(f"数据转换错误 {csv_path} 行 {cve_id}: {ve}")
                        results[cve_id] = {
                            'succeed': 0,
                            'target': 1,
                            'false_positive': 0,
                            'false_negative': 0,
                            'has_sig': False
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
                    result = all_project_results[cve_id]
                    total_succeed += result['succeed']                    
                    total_fp_fn += result['false_positive'] + result['false_negative']
                    
                    # 对于BinXray，计算总错误数包括额外字段
                    # if work == 'Robin':
                    #     if result['has_sig']:
                    #         total_target += result['target']
                    #         matched_cves += 1
                    # else:
                    total_target += result['target']
                    matched_cves += 1
            
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
                        result = all_project_results[cve_id]
                        total_succeed += result['succeed']
                        total_fp_fn += result['false_positive'] + result['false_negative']
                                            # 对于BinXray，计算总错误数包括额外字段
                        # if work == 'Robin':
                        #     if result['has_sig']:
                        #         total_target += result['target']
                        #         matched_cves += 1
                        # else:
                        total_target += result['target']
                        matched_cves += 1
            
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

def analyze_cve_pattern_category_count(pattern_data, works, projects):
    """
    统计CVE对应的聚合pattern类别数量分布，并输出各相关工作在该分类下的accuracy
    """
    # 1. 先加载所有项目的所有结果，方便查询
    all_works_results = {}
    for work in works:
        all_project_results = {}
        for project in projects:
            project_results = load_csv_results(work, project)
            all_project_results.update(project_results)
        all_works_results[work] = all_project_results

    # 2. 定义聚合类别
    aggregate_categories = {
        "Input_Sanitization": [1, 2],
        "Data_Structure": [3, 4, 5],
        "Function_Changes": [6, 7, 8, 9]
    }

    # 3. 将CVE按聚合pattern类别数量分类
    count_map = {1: [], 2: [], 3: []}
    for cve, patterns in pattern_data.items():
        involved_agg_categories = set()
        for p in patterns:
            if p in aggregate_categories["Input_Sanitization"]:
                involved_agg_categories.add("Input_Sanitization")
            elif p in aggregate_categories["Data_Structure"]:
                involved_agg_categories.add("Data_Structure")
            elif p in aggregate_categories["Function_Changes"]:
                involved_agg_categories.add("Function_Changes")
        
        n = len(involved_agg_categories)
        if n in count_map:
            count_map[n].append(cve)

    print("\n" + "="*80)
    print("CVE按聚合pattern类别数量分布：")
    print("="*80)

    # 4. 针对每个分类，重新计算准确率
    for k in [1, 2, 3]:
        category_cves = count_map[k]
        category_name = f"只涉及{k}个聚合类别"
        
        print(f"\n{category_name}的CVE数量: {len(category_cves)}")
        # print(f"CVE列表: {category_cves}")
        print("各相关工作在该分类下的accuracy：")

        for work in works:
            work_results = all_works_results[work]
            
            total_succeed = 0
            total_target = 0
            total_fp = 0
            total_fn = 0
            matched_cves_count = 0
            matched_cves_list = []
            
            # 只遍历属于当前分类的CVE
            for cve_id in category_cves:
                if cve_id in work_results:
                    result = work_results[cve_id]
                    total_succeed += result['succeed']
                    total_fp += result['false_positive']
                    total_fn += result['false_negative']
                    
                    # if work == 'Robin':
                    #     if result['has_sig']:
                    #         matched_cves_count += 1
                    #         total_target += result['target']
                    #         matched_cves_list.append(cve_id)

                    # else:
                    matched_cves_count += 1
                    total_target += result['target']
                    matched_cves_list.append(cve_id)


            # 计算准确率
            accuracy1 = total_succeed / total_target if total_target > 0 else 0
            accuracy2 = total_succeed / (total_succeed + total_fp + total_fn) if (total_succeed + total_fp + total_fn) > 0 else 0
            
            print(f"  {work}: matched_cves={matched_cves_count}, accuracy_succeed_target={accuracy1:.4f}, accuracy_succeed_fp_fn={accuracy2:.4f}")
            # if matched_cves_list:
            #     print(f"    Matched CVEs: {matched_cves_list}")

def analyze_exclusive_pattern_accuracy(pattern_data, works, projects):
    """
    分析只包含特定聚合类别模式的CVE的准确率
    """
    # 1. 加载所有项目的所有结果
    all_works_results = {}
    for work in works:
        all_project_results = {}
        for project in projects:
            project_results = load_csv_results(work, project)
            all_project_results.update(project_results)
        all_works_results[work] = all_project_results

    # 2. 定义聚合类别
    aggregate_categories = {
        "Input_Sanitization_Only": [1, 2],
        "Data_Structure_Only": [3, 4, 5],
        "Function_Changes_Only": [6, 7, 8, 9]
    }
    
    print("\n" + "="*80)
    print("专属模式类别准确率分析 (CVE只包含该类别的模式)")
    print("="*80)

    # 3. 遍历每个专属类别
    for category_name, pattern_list in aggregate_categories.items():
        exclusive_cves = []
        for cve_id, patterns in pattern_data.items():
            # 检查该CVE的所有模式是否都属于当前类别
            if all(p in pattern_list for p in patterns):
                exclusive_cves.append(cve_id)
        
        print(f"\n类别: {category_name}, 包含的CVE数量: {len(exclusive_cves)}")
        
        for work in works:
            work_results = all_works_results[work]
            
            total_succeed = 0
            total_target = 0
            total_fp = 0
            total_fn = 0
            matched_cves_count = 0
            
            for cve_id in exclusive_cves:
                if cve_id in work_results:
                    result = work_results[cve_id]
                    total_succeed += result['succeed']
                    total_fp += result['false_positive']
                    total_fn += result['false_negative']
                    
                    # if work == 'Robin' and not result['has_sig']:
                    #     continue # Robin跳过签名生成失败的
                    
                    total_target += result['target']
                    matched_cves_count += 1
            
            accuracy1 = total_succeed / total_target if total_target > 0 else 0
            accuracy2 = total_succeed / (total_succeed + total_fp + total_fn) if (total_succeed + total_fp + total_fn) > 0 else 0
            
            print(f"  {work}: matched_cves={matched_cves_count}, accuracy_succeed_target={accuracy1:.4f}, accuracy_succeed_fp_fn={accuracy2:.4f}")


def main():
    """
    主函数
    """
    print("开始分析模式分类准确率...")
    
    # 配置
    works = ['PS3', 'BinXray', 'PatchDiscovery', 'React','Robin']
    projects = ['imagemagick','tcpdump','freetype','openjpeg','curl', 'openssl', 'libxml2', 'sqlite', 'ffmpeg', 'binutils']
    
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
    
    # CVE模式类别数量分布分析
    analyze_cve_pattern_category_count(pattern_data, works, projects)

    # 专属模式类别分析
    analyze_exclusive_pattern_accuracy(pattern_data, works, projects)


if __name__ == "__main__":
    main()
