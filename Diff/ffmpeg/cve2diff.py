import json
import requests
import subprocess
import os
import shlex
import time
import re

PROJECT="ffmpeg"



def extract_git_hash(url):
    """从URL中提取h=后的全部字符（不依赖参数解析）"""
    # 使用正则表达式匹配 h= 后的非分隔符内容
    match = re.search(r'commit/([^&;]+)', url)
    return match.group(1) if match else None



def download_commit_diff(cve_id, url,CWE_ID):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    GITHUB_URL = f"{url}.diff"
    git_hash = extract_git_hash(url)
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
            
            # 遍历所有引用链接
            URLs = []
            for ref in entry.get("references", []):
                if ref.startswith("https://github.com"):
                        URLs.append(ref)
                    
            # 去重后下载
            for url in list(set(URLs)):
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
    