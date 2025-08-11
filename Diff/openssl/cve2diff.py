import json
import requests
import subprocess
import os
import shlex
import time
import re

import urllib

PROJECT="openssl"
MODE = "append"


def extract_git_hash(url: str) -> str | None:
    """
    从URL中提取 git commit 哈希值。
    优先匹配 commit/HASH 格式，其次匹配查询参数 h=HASH。
    """
    
    # --- 关键修正：先对URL进行解码 ---
    # 这会将 "%3B" 转换成 ";"，使正则表达式可以正常工作
    try:
        decoded_url = urllib.parse.unquote(url)
    except Exception:
        # 如果解码失败，则在原始URL上尝试
        decoded_url = url

    # 规则 1: 匹配路径格式，例如 .../commit/<hash>
    # 你的第一个正则很好，我们让它更精确一点
    match = re.search(r'commit/([a-f0-9]{7,40})', decoded_url)
    if match:
        return match.group(1)

    # 规则 2: 匹配查询参数格式，例如 ...?h=<hash> 或 ...;h=<hash>
    # 你的第二个正则基本正确，现在它可以在解码后的URL上工作了
    # {7,40} 表示匹配7到40位，可以同时兼容长哈希和短哈希
    match = re.search(r'[?&;]h=([a-f0-9]{7,40})', decoded_url)
    if match:
        return match.group(1)
        
    # 如果以上规则都失败，返回 None
    return None



def download_commit_diff(cve_id, url):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    GITHUB_URL = f"{url}.diff"
    git_hash = extract_git_hash(url)
    if git_hash is None:
        print(f"❌ Invalid URL format for {cve_id}: {url}")
        return False
    print(f"🔍hash: {git_hash[:12]}")
    try:
        # 创建保存目录
        
        # 生成文件名（与原始逻辑一致）
        filename = f"./diff_files/{PROJECT}_{cve_id}_{git_hash[:12]}.diff"
        #如果filename存在就直接返回
        if os.path.exists(filename):
            print(f"✅ File already exists: {filename}")
            return True
        # 方案1: 使用wget下载（推荐）
        if GITHUB_URL.startswith("https://git.openssl.org/"):
            GITHUB_URL = f"https://github.com/openssl/openssl/commit/{git_hash}.diff"
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
            URLs = []
            for ref in entry.get("references", []):
                if ref.startswith("https://github.com/openssl/openssl/commit/"):
                        URLs.append(ref)
                if ref.startswith("https://git.openssl.org/gitweb/?p=openssl.git"):
                    URLs.append(ref)
                if ref.startswith("https://git.openssl.org/?p=openssl.git"):
                    URLs.append(ref)
            # 去重后下载
            for url in list(set(URLs)):
                if download_commit_diff(entry["id"], url):
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
    with open(f"../../testset/openssl/{MODE}.txt", "r", encoding="utf-8") as f:
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
    