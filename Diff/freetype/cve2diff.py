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
PROJECT="freetype"
MODE = "chosen"
def extract_git_hash(url):
    """从URL中提取h=后的全部字符（不依赖参数解析）"""
    # 使用正则表达式匹配 h= 后的非分隔符内容
    return url.split("?id=")[-1]

def find_closed_commit_link(html_content: str) -> str | None:
    """
    从 HTML 文本中提取 /GNOME/libxml2/-/commit/ 后的哈希值
    返回格式：['487ee1d8711c6415218b373ef455fcd969d12399', ...]
    """
    # print(html_content)
    # href="/freetype/freetype/-/commit/cd02d359a6d0455e9d16b87bf9665961c4699538"
    hashs = re.findall(r'/freetype/freetype/-/commit/([0-9a-f]{40})', html_content)
    hashs = list(set(hashs))  # 去重
    print(f"找到的提交哈希: {hashs}")
    return hashs




def download_commit_diff(cve_id, url,hash=None):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    if hash is None:
        response = requests.get(url)
        git_hash =find_closed_commit_link(response.text)
        if not git_hash:
            print(f"❌ No commit hash found for {cve_id} in {url}")
            return False
        git_hash = git_hash[0]  # 取第一个匹配的哈希值
    else:
        git_hash = hash
    GITHUB_URL = f"https://github.com/freetype/freetype/commit/{git_hash}.diff"
    try:
        
        # 生成文件名（与原始逻辑一致）
        filename = f"diff_files/{PROJECT}_{cve_id}_{git_hash[:12]}.diff"

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
            hashes = []
            urls= []
            for ref in entry.get("references", []):
                if ref.startswith("http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/"):
                    hashes.append(extract_git_hash(ref))
                elif len(hashes)==0 and ref.startswith("https://gitlab.freedesktop.org/freetype/freetype"):
                    print(f"Processing issue link: {ref}")
                    response = requests.get(ref)
                    if hash_list := find_closed_commit_link(response.text):
                        # 将列表中的每个哈希值单独添加到hashes中
                        hashes.extend(hash_list)
            
            # 去重并处理每个哈希值
            unique_hashes = list(set(hashes))
            for git_hash in unique_hashes:
                print(f"Processing git hash: {git_hash}")
                if download_commit_diff(entry["id"], git_hash, hash=git_hash):
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
        success = sum(1 for r in results if r["status"] == "success")
        print(f"\nTotal: {len(results)}, Success: {success}, Failed: {len(results)-success}")