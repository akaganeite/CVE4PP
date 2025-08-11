import json
import requests
import subprocess
import os
import shlex
import time
import re

PROJECT="tcpdump"
MODE = "chosen"



def download_commit_diff(cve_id, git_hash):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    GITHUB_URL = f"{git_hash}.diff"
    
    try:
        # 创建保存目录        
        # 生成文件名（与原始逻辑一致）
        hash = git_hash.split("/")[-1]  # 提取哈希值
        filename = f"./diff_files/{PROJECT}_{cve_id}_{hash[:12]}.diff"
        
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
            print(f"✅ Downloaded {git_hash[:12]} for {cve_id}")
            return True
            
        print(f"❌ Empty file: {git_hash[:12]} for {cve_id}")
        return False
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Download failed (code {e.returncode}): {git_hash[:12]}")
    except Exception as e:
        print(f"❌ System error: {str(e)}")
    
    return False

def process_cve_data(json_path, target_cves):
    """处理CVE数据"""
    with open(json_path, "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    
    results = []
    
    for entry in cve_data:
        if entry["id"] in target_cves:
            print(f"\nProcessing {entry['id']}")
            
            # 遍历所有引用链接
            hashes = []
            for ref in entry.get("references", []):
                if ref.startswith("https://github.com/the-tcpdump-group/tcpdump/commit/"):
                    hashes.append(ref)
                    
            # 去重后下载
            for git_hash in list(set(hashes)):
                if download_commit_diff(entry["id"], git_hash):
                    results.append({
                        "cve": entry["id"],
                        "hash": git_hash,
                        "status": "success"
                    })
                else:
                    results.append({
                        "cve": entry["id"],
                        "hash": git_hash,
                        "status": "failed"
                    })
                time.sleep(1)  # 防止请求过频
                
    return results

if __name__ == "__main__":
    # 配置参数
    JSON_FILE = f"../../cveinfo/{PROJECT}/{PROJECT}_parsed.json"
    with open(f"../../testset/{PROJECT}/{MODE}.txt", "r", encoding="utf-8") as f:
        cve_data = f.readlines()
    TARGET_CVES =[]
    for key in cve_data:
        key = key.strip()
        print(f"\nProcessing {key} for {PROJECT}")
        #if entry["id"] not in TARGET_CVES:
        results = process_cve_data(JSON_FILE, [key])
    
        # 输出结果统计
        print(f"\nResults for {key}: {results}")
        
        #TARGET_CVES.append(entry["id"])

    
    # 执行处理
    