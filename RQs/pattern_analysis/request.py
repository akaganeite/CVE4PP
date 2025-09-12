import requests
import pickle
import json
import os
import time

API_KEY = 'sk-71BQX5ne88mBeP3gBdA5Ea6b519d498dB548261e3f265c38'
BASE_URL = "https://api.gpt.ge/v1/"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

def load_existing_results():
    """
    加载已有的结果文件
    """
    pattern_results = {}
    detail_results = {}
    
    # 加载pattern.json
    if os.path.exists('pattern.json'):
        try:
            with open('pattern.json', 'r', encoding='utf-8') as f:
                pattern_results = json.load(f)
            print(f"加载了已有的pattern.json ({len(pattern_results)} 个CVE)")
        except Exception as e:
            print(f"加载pattern.json失败: {e}")
    
    # 加载pattern_details.json
    if os.path.exists('pattern_details.json'):
        try:
            with open('pattern_details.json', 'r', encoding='utf-8') as f:
                detail_results = json.load(f)
            print(f"加载了已有的pattern_details.json ({len(detail_results)} 个CVE)")
        except Exception as e:
            print(f"加载pattern_details.json失败: {e}")
    
    return pattern_results, detail_results

def load_data():
    """
    加载pickle文件和prompt模板
    """
    # 加载CVE-diff映射
    try:
        with open('cve_diff_mapping.pkl', 'rb') as f:
            cve_diff_mapping = pickle.load(f)
        print(f"加载了 {len(cve_diff_mapping)} 个CVE的diff数据")
    except Exception as e:
        print(f"加载pickle文件失败: {e}")
        return None, None
    
    # 加载prompt模板
    try:
        with open('prompt.txt', 'r', encoding='utf-8') as f:
            prompt_template = f.read()
        print("加载prompt模板成功")
    except Exception as e:
        print(f"加载prompt模板失败: {e}")
        return None, None
    
    return cve_diff_mapping, prompt_template

def filter_new_cves(cve_diff_mapping, existing_pattern_results):
    """
    筛选出需要处理的新CVE
    """
    existing_cves = set(existing_pattern_results.keys())
    all_cves = set(cve_diff_mapping.keys())
    new_cves = all_cves - existing_cves
    
    # 只保留新的CVE
    new_cve_diff_mapping = {cve: cve_diff_mapping[cve] for cve in new_cves}
    
    print(f"总CVE数量: {len(all_cves)}")
    print(f"已处理CVE数量: {len(existing_cves)}")
    print(f"新CVE数量: {len(new_cves)}")
    
    return new_cve_diff_mapping

def analyze_cve_diff(cve_id, diff_content, prompt_template):
    """
    分析单个CVE的diff文件
    """
    try:
        # 构建完整的prompt
        full_prompt = prompt_template + "\n" + diff_content
        
        response = requests.post(
            url=f"{BASE_URL}chat/completions",
            json={
                "model": "gpt-4o-all",
                "max_tokens": 4000,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": full_prompt}],
            },
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            response_content = result['choices'][0]['message']['content']
            print(response_content)
            
            # 去掉markdown代码块标记，提取JSON内容
            cleaned_content = response_content.strip()
            if cleaned_content.startswith('```json'):
                cleaned_content = cleaned_content[7:]  # 去掉开头的```json
            if cleaned_content.startswith('```'):
                cleaned_content = cleaned_content[3:]   # 去掉开头的```
            if cleaned_content.endswith('```'):
                cleaned_content = cleaned_content[:-3]  # 去掉结尾的```
            
            cleaned_content = cleaned_content.strip()
            
            # 尝试解析JSON响应
            try:
                parsed_result = json.loads(cleaned_content)
                print(f"✓ {cve_id}: 分析完成")
                return cve_id, parsed_result, True
            except json.JSONDecodeError as e:
                print(f"✗ {cve_id}: JSON解析失败 - {e}")
                print(f"清理后的内容: {cleaned_content[:200]}...")
                return cve_id, {"content": response_content, "result": []}, False
        else:
            print(f"✗ {cve_id}: 请求失败，状态码: {response.status_code}")
            return cve_id, None, False
    except Exception as e:
        print(f"✗ {cve_id}: 请求异常 - {e}")
        return cve_id, None, False

def process_new_cves(new_cve_diff_mapping, prompt_template):
    """
    处理新的CVE
    """
    if not new_cve_diff_mapping:
        print("没有新的CVE需要处理")
        return {}, {}
    
    new_pattern_results = {}  # CVE -> result数组
    new_detail_results = {}   # CVE -> {content, result}
    
    total_cves = len(new_cve_diff_mapping)
    processed = 0
    
    for cve_id, diff_content in new_cve_diff_mapping.items():
        processed += 1
        print(f"处理进度: {processed}/{total_cves} - {cve_id}")
        
        cve_id, parsed_result, success = analyze_cve_diff(cve_id, diff_content, prompt_template)
        
        if parsed_result:
            new_detail_results[cve_id] = parsed_result
            if success and 'result' in parsed_result:
                new_pattern_results[cve_id] = parsed_result['result']
            else:
                new_pattern_results[cve_id] = []
        
        # 在请求之间添加延迟，避免触发API限制
        time.sleep(1)
    
    return new_pattern_results, new_detail_results

def merge_and_save_results(existing_pattern_results, existing_detail_results, 
                          new_pattern_results, new_detail_results):
    """
    合并新旧结果并保存
    """
    # 合并结果
    merged_pattern_results = {**existing_pattern_results, **new_pattern_results}
    merged_detail_results = {**existing_detail_results, **new_detail_results}
    
    try:
        # 保存合并后的pattern.json
        with open('pattern.json', 'w', encoding='utf-8') as f:
            json.dump(merged_pattern_results, f, indent=2, ensure_ascii=False)
        print(f"✓ pattern.json 保存成功 (总计 {len(merged_pattern_results)} 个CVE, 新增 {len(new_pattern_results)} 个)")
        
        # 保存合并后的pattern_details.json
        with open('pattern_details.json', 'w', encoding='utf-8') as f:
            json.dump(merged_detail_results, f, indent=2, ensure_ascii=False)
        print(f"✓ pattern_details.json 保存成功 (总计 {len(merged_detail_results)} 个CVE, 新增 {len(new_detail_results)} 个)")
        
    except Exception as e:
        print(f"保存结果失败: {e}")

def main():
    """
    主函数
    """
    print("开始CVE Diff模式增量分析...")
    
    # 加载已有结果
    existing_pattern_results, existing_detail_results = load_existing_results()
    
    # 加载数据
    cve_diff_mapping, prompt_template = load_data()
    if not cve_diff_mapping or not prompt_template:
        print("数据加载失败，退出")
        return
    
    # 筛选出需要处理的新CVE
    new_cve_diff_mapping = filter_new_cves(cve_diff_mapping, existing_pattern_results)
    
    if not new_cve_diff_mapping:
        print("所有CVE都已处理完成，无需更新")
        return
    
    print(f"准备分析 {len(new_cve_diff_mapping)} 个新CVE")
    
    # 处理新的CVE
    new_pattern_results, new_detail_results = process_new_cves(new_cve_diff_mapping, prompt_template)
    
    # 合并并保存结果
    merge_and_save_results(existing_pattern_results, existing_detail_results,
                          new_pattern_results, new_detail_results)
    
    # 统计信息
    total_new_processed = len(new_detail_results)
    successful_new_parsed = len(new_pattern_results)
    total_cves = len(existing_pattern_results) + len(new_pattern_results)
    
    print(f"\n增量分析完成!")
    print(f"总CVE数量: {len(cve_diff_mapping)}")
    print(f"已完成CVE数量: {total_cves}")
    print(f"本次新处理: {total_new_processed}")
    print(f"本次成功解析: {successful_new_parsed}")
    if new_cve_diff_mapping:
        print(f"本次成功率: {successful_new_parsed/len(new_cve_diff_mapping)*100:.1f}%")

if __name__ == "__main__":
    main()