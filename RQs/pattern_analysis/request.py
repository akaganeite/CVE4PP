import asyncio
import aiohttp
import pickle
import json
import os

API_KEY = 'sk-71BQX5ne88mBeP3gBdA5Ea6b519d498dB548261e3f265c38'
BASE_URL = "https://api.gpt.ge/v1/"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

def load_data():
    """
    加载pickle文件和prompt模板
    """
    cve_diff_mapping_test ={}
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
    # first_key = next(iter(cve_diff_mapping))
    # first_value = cve_diff_mapping[first_key]
    # cve_diff_mapping_test[first_key] = first_value  
    return cve_diff_mapping, prompt_template

async def analyze_cve_diff(session, cve_id, diff_content, prompt_template):
    """
    分析单个CVE的diff文件
    """
    try:
        # 构建完整的prompt
        full_prompt = prompt_template + "\n" + diff_content
        
        async with session.post(
            url=f"{BASE_URL}chat/completions",
            json={
                "model": "gpt-4o-all",
                "max_tokens": 4000,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": full_prompt}],
            },
            headers=headers
        ) as response:
            if response.status == 200:
                result = await response.json()
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
                print(f"✗ {cve_id}: 请求失败，状态码: {response.status}")
                return cve_id, None, False
    except Exception as e:
        print(f"✗ {cve_id}: 请求异常 - {e}")
        return cve_id, None, False

async def process_all_cves(cve_diff_mapping, prompt_template):
    """
    处理所有CVE
    """
    pattern_results = {}  # CVE -> result数组
    detail_results = {}   # CVE -> {content, result}
    
    # 控制并发数量，避免API限制
    semaphore = asyncio.Semaphore(10)  # 同时最多10个请求
    
    async def process_single_cve(session, cve_id, diff_content):
        async with semaphore:
            return await analyze_cve_diff(session, cve_id, diff_content, prompt_template)
    
    async with aiohttp.ClientSession() as session:
        # 创建所有任务
        tasks = [
            process_single_cve(session, cve_id, diff_content)
            for cve_id, diff_content in cve_diff_mapping.items()
        ]
        
        # 批量处理，每次处理50个
        batch_size = 50
        total_tasks = len(tasks)
        
        for i in range(0, total_tasks, batch_size):
            batch = tasks[i:i + batch_size]
            print(f"处理批次 {i//batch_size + 1}/{(total_tasks + batch_size - 1)//batch_size}")
            
            # 执行当前批次
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            # 处理结果
            for result in batch_results:
                if isinstance(result, Exception):
                    print(f"批次处理异常: {result}")
                    continue
                
                cve_id, parsed_result, success = result
                if parsed_result:
                    detail_results[cve_id] = parsed_result
                    if success and 'result' in parsed_result:
                        pattern_results[cve_id] = parsed_result['result']
                    else:
                        pattern_results[cve_id] = []
            
            # 在批次之间添加延迟
            if i + batch_size < total_tasks:
                await asyncio.sleep(2)
    
    return pattern_results, detail_results

def save_results(pattern_results, detail_results):
    """
    保存结果到JSON文件
    """
    try:
        # 保存pattern.json
        with open('pattern.json', 'w', encoding='utf-8') as f:
            json.dump(pattern_results, f, indent=2, ensure_ascii=False)
        print(f"✓ pattern.json 保存成功 ({len(pattern_results)} 个CVE)")
        
        # 保存pattern_details.json
        with open('pattern_details.json', 'w', encoding='utf-8') as f:
            json.dump(detail_results, f, indent=2, ensure_ascii=False)
        print(f"✓ pattern_details.json 保存成功 ({len(detail_results)} 个CVE)")
        
    except Exception as e:
        print(f"保存结果失败: {e}")

async def main():
    """
    主函数
    """
    print("开始CVE Diff模式分析...")
    
    # 加载数据
    cve_diff_mapping, prompt_template = load_data()
    if not cve_diff_mapping or not prompt_template:
        print("数据加载失败，退出")
        return
    
    print(f"准备分析 {len(cve_diff_mapping)} 个CVE")
    
    # 处理所有CVE
    pattern_results, detail_results = await process_all_cves(cve_diff_mapping, prompt_template)
    
    # 保存结果
    save_results(pattern_results, detail_results)
    
    # 统计信息
    total_processed = len(detail_results)
    successful_parsed = len(pattern_results)
    
    print(f"\n分析完成!")
    print(f"总CVE数量: {len(cve_diff_mapping)}")
    print(f"成功处理: {total_processed}")
    print(f"成功解析: {successful_parsed}")
    print(f"成功率: {successful_parsed/len(cve_diff_mapping)*100:.1f}%")

if __name__ == "__main__":
    asyncio.run(main())