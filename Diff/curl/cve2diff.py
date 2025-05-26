import json
import requests
import subprocess
import os
import shlex
import time
import re

PROJECT="curl"

def get_git_commit_hashes_from_url(url: str) -> tuple[str | None, str | None]:
    introduced_hash = None
    fixed_hash = None

    try:
        # 发起 HTTP GET 请求，设置超时以防请求挂起
        response = requests.get(url, timeout=10)
        
        # 检查请求是否成功 (状态码 200-299)，如果不成功则抛出异常
        response.raise_for_status()

        # 解析响应内容为 JSON
        data = response.json()

        # 开始逐层查找数据
        # 1. 获取 'affected' 列表，如果不存在则返回空列表
        affected_list = data.get("affected", [])

        # 2. 遍历 'affected' 列表中的每个项目
        for affected_item in affected_list:
            # 3. 获取 'ranges' 列表
            ranges_list = affected_item.get("ranges", [])
            
            # 4. 遍历 'ranges' 列表中的每个项目
            for range_item in ranges_list:
                # 5. 检查 'type' 是否为 'GIT'
                if range_item.get("type") == "GIT":
                    # 6. 获取 'events' 列表
                    events_list = range_item.get("events", [])
                    
                    # 7. 遍历 'events' 列表查找哈希值
                    for event in events_list:
                        if "introduced" in event:
                            introduced_hash = event["introduced"]
                        if "fixed" in event:
                            fixed_hash = event["fixed"]
                    
                    # 8. 只要找到了一组 GIT 的哈希值，就立即返回
                    #    (假设每个 JSON 中只需要找第一组)
                    if introduced_hash or fixed_hash:
                        return introduced_hash, fixed_hash

    except requests.exceptions.RequestException as e:
        print(f"请求 URL 时发生网络错误: {e}")
        return None, None
    except requests.exceptions.JSONDecodeError:
        print(f"无法从 URL '{url}' 解码 JSON 数据。")
        return None, None
    except (KeyError, TypeError, AttributeError) as e:
        # 捕获因 JSON 结构不符或数据缺失导致的错误
        print(f"解析 JSON 数据结构时发生错误: {e}")
        return None, None

    # 如果遍历完所有都没有找到，返回 None
    print("未在数据中找到 'GIT' 类型的 'events' 哈希值。")
    return None, None




def download_commit_diff(cve_id, url,CWE_ID):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    intro_hash, git_hash = get_git_commit_hashes_from_url(url)
    GITHUB_URL = f"https://github.com/curl/curl/commit/{git_hash}.diff"
    try:
        # 创建保存目录
        os.makedirs(PROJECT, exist_ok=True)
        
        # 生成文件名（与原始逻辑一致）
        filename = f"{PROJECT}_{cve_id}_{git_hash[:7]}_{CWE_ID}.diff"

        # 方案1: 使用wget下载（推荐）
        cmd = f"wget -q --timeout=10 -O {shlex.quote(filename)} {shlex.quote(GITHUB_URL)}"
        
        # 方案2: 使用curl下载（备选）
        # cmd = f"curl -s -m 10 -o {shlex.quote(filename)} {shlex.quote(GITHUB_URL)}"
        
        # 执行命令（安全处理参数）
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            timeout=15,  # 总超时大于下载超时
            universal_newlines=True
        )
        
        # 验证文件是否下载成功
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"✅ Downloaded {git_hash[:7]} for {cve_id}")
            return True
            
        print(f"❌ Empty file: {git_hash[:7]} for {cve_id}")
        return False
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Download failed (code {e.returncode}): {git_hash[:7]}")
    except Exception as e:
        print(f"❌ System error: {str(e)}")
    
    return False

def process_cve_data(json_path, target_cves,CWE_ID):
    """处理CVE数据"""
    with open(json_path, "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    
    results = []
    
    for entry in cve_data:
        if entry["id"] in target_cves:
            print(f"\nProcessing {entry['id']}")
            url =f"https://curl.se/docs/{entry['id']}.json"
            if download_commit_diff(entry["id"], url,CWE_ID):
                results.append({
                    "cve": entry["id"],
                    "url": url,
                    "status": "success"
                })
            else:
                results.append({
                    "cve": entry["id"],
                    "url": url,
                    "status": "failed"
                })
            time.sleep(1)  # 防止请求过频
                
    return results

if __name__ == "__main__":
    # 配置参数
    JSON_FILE = f"../../cveinfo/{PROJECT}/{PROJECT}_filtered.json"
    with open("../../first_batch.json", "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    TARGET_CVES =[]
    for (key,value) in cve_data.items():
        print(f"\nProcessing {key} for {PROJECT}")
        #if entry["id"] not in TARGET_CVES:
        CWE_ID = key
        results = process_cve_data(JSON_FILE, value,CWE_ID)
    
        # 输出结果统计
        success = sum(1 for r in results if r["status"] == "success")
        print(f"\nTotal: {len(results)}, Success: {success}, Failed: {len(results)-success}")
        #TARGET_CVES.append(entry["id"])

    
    # 执行处理
    