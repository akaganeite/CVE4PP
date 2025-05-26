# <span id="hash-ci">
# https://github.com/search?q=repo%3Asqlite%2Fsqlite+cefc032473ac5ad244c0b6402c541b2f76c0c65a041bda03bfbe7c0e2c11fac2&type=commits
# "sha": 

import json
import requests
import subprocess
import os
import shlex
import time
import re
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time
PROJECT="sqlite"

def extract_git_hash(url):
    """从URL中提取h=后的全部字符（不依赖参数解析）"""
    # 使用正则表达式匹配 h= 后的非分隔符内容
    match = re.search(r'https://github.com/sqlite/sqlite/commit/([^&;]+)', url)
    return match.group(1) if match else None

def extract_sqlite_hash(html):
    pattern = r'<span\s+id="hash-ci"[^>]*>(.*?)</span>'
    match = re.search(pattern, html, re.DOTALL)
    
    if not match:
        return None
    content = match.group(1)
    cleaned = re.sub(r'<wbr\s*/?>', '', content, flags=re.IGNORECASE)  # 处理 <wbr> 或 <WBR />
    
    # 合并连续字符并验证格式
    merged_hash = re.sub(r'\s+', '', cleaned)  # 移除空格换行
    if re.fullmatch(r'[0-9a-fA-F]+', merged_hash):  # 验证十六进制格式
        return merged_hash.lower()  # 统一小写格式
    return None

def find_closed_commit_link(html_content: str) -> str | None:

    hashs = re.findall(r'"sha":\s*"([0-9a-f]{40})"', html_content)
    hashs = list(set(hashs))  # 去重
    print(f"找到的提交哈希: {hashs}")
    return hashs

def find_sqlite_url_from_post(post_url: str) -> str | None:
    """从SQLite论坛帖子中提取提交哈希"""
    response = requests.get(post_url)
    response.raise_for_status()  # 检查请求是否成功
    match= re.search(r'https://www.sqlite.org/src/info/([^&;]+)', response.text, re.DOTALL)
    if match:
        return f"https://www.sqlite.org/src/info/{match.group(1)}"
    else:
        print(f"❌ No URL links found in post: {post_url}")
        return None 


def download_commit_diff(cve_id, url,CWE_ID,hash=None):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    if hash is None:
        response = requests.get(url)
        sqlite_hash =extract_sqlite_hash(response.text)
        if not sqlite_hash:
            print(f"❌ No commit hash found for {cve_id} in {url}")
            return False
        git_search_url = f"https://github.com/search?q=repo%3Asqlite%2Fsqlite+{sqlite_hash}&type=commits"
        response = requests.get(git_search_url)
        git_hash = find_closed_commit_link(response.text)
        git_hash = git_hash[0]  # 取第一个匹配的哈希值
    else:
        git_hash = hash
    GITHUB_URL = f"https://github.com/sqlite/sqlite/commit/{git_hash}.diff"
    try:
        
        # 生成文件名（与原始逻辑一致）
        filename = f"{PROJECT}_{cve_id}_{git_hash[:7]}_{CWE_ID}.diff"

        # 方案1: 使用wget下载（推荐）
        cmd = f"wget -q --timeout=10 -O {shlex.quote(filename)} {shlex.quote(GITHUB_URL)}"
        
        # 方案2: 使用curl下载（备选）
        # cmd = f"curl -s -m 10 -o {shlex.quote(filename)} {shlex.quote(GITHUB_URL)}"

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
            hashes = []
            urls = []
            posts = []
            for ref in entry.get("references", []):
                if git_hash := extract_git_hash(ref):
                    hashes.append(git_hash)
                elif "src/info" in ref:
                    urls.append(ref)
                elif "https://www.sqlite.org/forum/forumpost/" in ref:
                    posts.append(ref)
            for git_hash in list(set(hashes)):
                print(f"Processing git hash: {git_hash}")
                if download_commit_diff(entry["id"], git_hash,CWE_ID,hash=git_hash):
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
                time.sleep(1)
            # process URLs
            if hashes is None or len(hashes) == 0:
                urls = list(set(urls))
                print(f"Processing URL: {urls}")
                for url in urls:
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
                time.sleep(1)  # 防止请求过频   \
            if len(hashes) == 0 and len(urls) == 0:
                posts = list(set(posts))
                print(f"Processing post: {posts}")
                if len(posts) == 0:
                    results.append({
                        "cve": entry["id"],
                        "status": "failed",
                    })
                for post in posts:
                    url = find_sqlite_url_from_post(post)
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