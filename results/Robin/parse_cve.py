import argparse
import pandas as pd
import os

def analyze_cve_accuracy(project):
    # 读取两个CSV文件
    gen_df = pd.read_csv(f'./generation/{project}-gen.csv')
    result_df = pd.read_csv(f'./{project}_result.csv')
    
    # 读取BinXray的CSV文件来获取target信息
    binxray_df = pd.read_csv(f'../PatchDiscovery/{project}-cve.csv')

    # 按CVE分组分析generation结果
    gen_by_cve = gen_df.groupby('CVE_ID')
    
    cve_results = []
    total_succeed = 0
    total_target = 0
    
    # 获取result.csv中所有的CVE作为参考
    result_cves = set(result_df['CVE'].unique())
    
    for cve_id, cve_group in gen_by_cve:
        # 检查该CVE的所有函数是否都是success
        all_success = all(cve_group['status'] == 'success')
        
        if not all_success:
            # 如果有任何函数失败，整个CVE失败
            # 从BinXray CSV中查找target数目
            binxray_row = binxray_df[binxray_df['cve'] == cve_id]
            target_value = binxray_row['target'].iloc[0] if not binxray_row.empty else 0
            
            cve_results.append({
                'CVE': cve_id,
                'succeed': 0,
                'target': target_value
            })
            total_succeed += 0
            total_target += target_value
            continue
        
        # 如果所有函数都成功生成，查找在result中的对应记录
        cve_functions = cve_group['func_name'].tolist()
        
        # 在result_df中查找匹配的记录
        matching_results = result_df[
            (result_df['CVE'] == cve_id) & 
            (result_df['func'].isin(cve_functions))
        ]
        
        if matching_results.empty:
            # 在result中找不到对应记录，视为失败
            # 从BinXray CSV中查找target数目
            binxray_row = binxray_df[binxray_df['cve'] == cve_id]
            target_value = binxray_row['target'].iloc[0] if not binxray_row.empty else 0
            
            cve_results.append({
                'CVE': cve_id,
                'succeed': 0,
                'target': target_value
            })
            total_succeed += 0
            total_target += target_value
            continue
        
        # 计算该CVE的succeed和target
        # 如果有多个函数，取最小的succeed值
        min_succeed = matching_results['succeed'].min()
        min_target = matching_results['target'].min()
        
        cve_results.append({
            'CVE': cve_id,
            'succeed': min_succeed,
            'target': min_target
        })
        total_succeed += min_succeed
        total_target += min_target
    
    # 计算总体准确率 (succeed总数/target总数)
    accuracy = total_succeed / total_target if total_target > 0 else 0
    
    # 计算基于result.csv中CVE的准确率
    # 只考虑存在于result.csv中的CVE
    result_cve_results = [item for item in cve_results if item['CVE'] in result_cves]
    result_total_succeed = sum(item['succeed'] for item in result_cve_results)
    result_total_target = sum(item['target'] for item in result_cve_results)
    result_accuracy = result_total_succeed / result_total_target if result_total_target > 0 else 0
    
    # 创建结果DataFrame
    results_df = pd.DataFrame(cve_results)
    
    # 保存到CSV文件
    output_path = f'./{project}-cve.csv'
    results_df.to_csv(output_path, index=False)
    
    # 打印结果
    print(f"{project}-cve:")
    print(f"{total_succeed}/{total_target}={accuracy*100:.2f}%")
    print(f"{result_total_succeed}/{result_total_target}={result_accuracy*100:.2f}%")
    
    return accuracy, result_accuracy, results_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='解析BinXray检测结果')
    parser.add_argument(
        "-proj", "--project",
        required=True,
        type=str,
    )
    args = parser.parse_args()
    project = args.project
    analyze_cve_accuracy(project)
