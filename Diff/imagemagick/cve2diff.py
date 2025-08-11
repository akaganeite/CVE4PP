import json
import requests
import subprocess
import os
import shlex
import time
import re
import logging
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time
PROJECT="imagemagick"
MODE = "chosen"

# 配置日志
log_filename = f"{PROJECT}_cve2diff_error.log"
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename, encoding='utf-8'),
        logging.StreamHandler()  # 同时输出到控制台
    ]
)
def extract_git_hash(url):
    """从URL中提取h=后的全部字符（不依赖参数解析）"""
    # 使用正则表达式匹配 h= 后的非分隔符内容
    match = re.search(r'/commit/([^&;]+)', url)
    return match.group(1) if match else None

def find_closed_commit_link(html_content: str) -> str | None:
    """
    从 HTML 文本中提取 /GNOME/imagemagick/-/commit/ 后的哈希值
    返回格式：['487ee1d8711c6415218b373ef455fcd969d12399', ...]
    """
    # print(html_content)
    hashs = re.findall(r'https://github.com/ImageMagick/ImageMagick/commit/([0-9a-f]{40})', html_content)
    hashs = list(set(hashs))  # 去重
    print(f"找到的提交哈希: {hashs}")
    return hashs




def download_commit_diff(cve_id, url,hash=None):
    """使用wget/curl下载GitHub提交的diff文件"""
    # 配置参数（根据实际情况调整）
    if hash is None:
        try:
            response = requests.get(url)
            git_hash =find_closed_commit_link(response.text)
            if not git_hash:
                error_msg = f"No commit hash found for {cve_id} in {url}"
                print(f"❌ {error_msg}")
                logging.error(f"CVE: {cve_id} - {error_msg}")
                return False
            git_hash = git_hash[0]  # 取第一个匹配的哈希值
        except Exception as e:
            error_msg = f"Failed to fetch URL {url} for {cve_id}: {str(e)}"
            print(f"❌ {error_msg}")
            logging.error(f"CVE: {cve_id} - {error_msg}")
            return False
    else:
        git_hash = hash
    GITHUB_URL = f"https://github.com/ImageMagick/ImageMagick/commit/{git_hash}.diff"
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
            logging.info(f"CVE: {cve_id} - Successfully downloaded diff for hash {git_hash[:12]}")
            return True
            
        error_msg = f"Empty file downloaded for {git_hash[:12]} from {GITHUB_URL}"
        print(f"❌ Empty file: {git_hash[:12]} for {cve_id}")
        logging.error(f"CVE: {cve_id} - {error_msg}")
        return False
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Download command failed with code {e.returncode}"
        print(f"❌ Download failed (code {e.returncode}): {git_hash[:12]}")
        logging.error(f"CVE: {cve_id} - Hash: {git_hash[:12]} - {error_msg}")
    except subprocess.TimeoutExpired:
        error_msg = f"Download timeout for hash {git_hash[:12]}"
        print(f"❌ Download timeout: {git_hash[:12]}")
        logging.error(f"CVE: {cve_id} - {error_msg}")
    except Exception as e:
        error_msg = f"System error during download: {str(e)}"
        print(f"❌ System error: {str(e)}")
        logging.error(f"CVE: {cve_id} - Hash: {git_hash[:12]} - {error_msg}")
    
    return False

def process_cve_data(json_path, target_cves):
    """处理CVE数据"""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            cve_data = json.load(f)
    except Exception as e:
        error_msg = f"Failed to load JSON file {json_path}: {str(e)}"
        print(f"❌ {error_msg}")
        logging.error(error_msg)
        return []
    
    results = []
    
    for entry in cve_data:
        if entry["id"] in target_cves:
            print(f"\nProcessing {entry['id']}")
            logging.info(f"Starting processing CVE: {entry['id']}")
            hashes = []
            urls= []
            try:
                for ref in entry.get("references", []):
                    if git_hash := extract_git_hash(ref):
                        hashes.append(git_hash)
                    elif len(hashes)==0 and ref.startswith("https://bugzilla.redhat.com/show_bug.cgi"):
                        print(f"Processing issue link: {ref}")
                        try:
                            response = requests.get(ref)
                            if hash_list := find_closed_commit_link(response.text):
                                # 将列表中的每个哈希值单独添加到hashes中
                                hashes.extend(hash_list)
                        except Exception as e:
                            error_msg = f"Failed to process bugzilla link {ref}: {str(e)}"
                            print(f"❌ {error_msg}")
                            logging.error(f"CVE: {entry['id']} - {error_msg}")
                
                # 去重并处理每个哈希值
                unique_hashes = list(set(hashes))
                if not unique_hashes:
                    error_msg = f"No git hashes found for CVE {entry['id']}"
                    logging.warning(f"CVE: {entry['id']} - {error_msg}")
                
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
            except Exception as e:
                error_msg = f"Error processing CVE {entry['id']}: {str(e)}"
                print(f"❌ {error_msg}")
                logging.error(error_msg)
                results.append({
                    "cve": entry["id"],
                    "hash": "unknown",
                    "status": "failed"
                })
            # process URLs       
    return results

if __name__ == "__main__":
    # 配置参数
    logging.info(f"Starting CVE processing for project: {PROJECT}")
    JSON_FILE = f"../../cveinfo/{PROJECT}/{PROJECT}_parsed.json"
    
    try:
        with open(f"../../testset/{PROJECT}/{MODE}.txt", "r", encoding="utf-8") as f:
            cve_data = f.readlines()
    except Exception as e:
        error_msg = f"Failed to load CVE list file: {str(e)}"
        print(f"❌ {error_msg}")
        logging.error(error_msg)
        exit(1)
    
    TARGET_CVES =[]
    total_success = 0
    total_failed = 0
    
    for key in cve_data:
        key = key.strip()
        if not key:  # 跳过空行
            continue
            
        print(f"\nProcessing {key} for {PROJECT}")
        logging.info(f"Processing {key} for {PROJECT}")
        
        try:
            results = process_cve_data(JSON_FILE, [key])
        
            # 输出结果统计
            success = sum(1 for r in results if r["status"] == "success")
            failed = len(results) - success
            total_success += success
            total_failed += failed
            
            print(f"\nTotal: {len(results)}, Success: {success}, Failed: {failed}")
            logging.info(f"CVE {key} processed - Total: {len(results)}, Success: {success}, Failed: {failed}")
            
        except Exception as e:
            error_msg = f"Critical error processing {key}: {str(e)}"
            print(f"❌ {error_msg}")
            logging.error(error_msg)
            total_failed += 1
    
    # 最终统计
    final_msg = f"Final statistics - Total Success: {total_success}, Total Failed: {total_failed}"
    print(f"\n{final_msg}")
    logging.info(final_msg)