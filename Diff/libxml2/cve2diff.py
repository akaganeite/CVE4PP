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
PROJECT="libxml2"

def extract_git_hash(url):
    """从URL中提取h=后的全部字符（不依赖参数解析）"""
    # 使用正则表达式匹配 h= 后的非分隔符内容
    match = re.search(r'-/commit/([^&;]+)', url)
    return match.group(1) if match else None

def find_closed_commit_link(html_content: str) -> str | None:
    """
    从 HTML 文本中提取 /GNOME/libxml2/-/commit/ 后的哈希值
    返回格式：['487ee1d8711c6415218b373ef455fcd969d12399', ...]
    """
    hashs = re.findall(r'/GNOME/libxml2/-/commit/([0-9a-f]{40})', html_content)
    hashs = list(set(hashs))  # 去重
    print(f"找到的提交哈希: {hashs}")
    return hashs




def download_commit_diff(cve_id, url,CWE_ID,hash=None):
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
    GITHUB_URL = f"https://gitlab.gnome.org/GNOME/libxml2/-/commit/{git_hash}.diff"
    try:
        
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
            hashes = []
            for ref in entry.get("references", []):
                if git_hash := extract_git_hash(ref):
                    hashes.append(git_hash)
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
                url = f"https://gitlab.gnome.org/GNOME/libxml2/-/commits/master?search={entry['id']}"
                print(f"Processing URL: {url}")
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

    
#     # 执行处理






# def get_dynamic_html(url: str) -> str | None:
#     """
#     使用 Selenium 访问 URL，执行 JS，并返回渲染后的 HTML。

#     Args:
#         url: 要访问的网页 URL。

#     Returns:
#         渲染后的 HTML 字符串，如果失败则返回 None。
#     """
#     # --- 设置 Chrome 选项 (可选，例如无头模式) ---
#     options = webdriver.ChromeOptions()
#     # options.add_argument('--headless')  # 开启无头模式 (不打开浏览器窗口)
#     options.add_argument('--no-sandbox')
#     options.add_argument('--disable-dev-shm-usage')
#     options.add_argument('user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"') # 设置 User-Agent

#     # --- 初始化 WebDriver (使用 webdriver-manager 自动管理) ---
#     driver = None
#     try:
#         print(f"正在启动浏览器并访问: {url}")
#         driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)

#         # --- 访问页面 ---
#         driver.get(url)

#         # --- 等待！这是关键步骤 ---
#         # 仅仅 driver.get() 是不够的，你需要等待 JS 执行完毕。
#         # 等待策略有很多种，最常用的是等待某个关键元素出现。
#         # 例如，等待一个 ID 为 'content' 的元素加载完成，最多等 15 秒。
#         print("页面加载中，等待动态内容...")
#         wait = WebDriverWait(driver, 15)
#         # 你需要根据实际网页情况，选择一个合适的元素来等待
#         # 如果不确定等什么，可以尝试等待 body 标签，或者干脆 sleep 一段时间 (不推荐)
#         wait.until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

#         # (可选) 如果页面有滚动加载，你可能需要模拟滚动
#         # driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
#         # time.sleep(3) # 等待滚动加载内容

#         # (可选) 如果有需要点击才能出现的内容，你需要模拟点击
#         # try:
#         #    button = wait.until(EC.element_to_be_clickable((By.ID, 'load-more-button')))
#         #    button.click()
#         #    time.sleep(3) # 等待点击后加载
#         # except Exception as e:
#         #    print(f"未能点击按钮或按钮不存在: {e}")

#         # --- 获取渲染后的 HTML ---
#         print("获取渲染后的 HTML...")
#         html_content = driver.page_source
#         return html_content

#     except Exception as e:
#         print(f"访问或处理页面时发生错误: {e}")
#         return None

#     finally:
#         # --- 关闭浏览器 ---
#         if driver:
#             print("关闭浏览器...")
#             driver.quit()


# target_url = "https://gitlab.gnome.org/GNOME/libxml2/-/issues/583" # 替换成你要爬取的、有动态内容的网站
# # 注意：很多网站有反爬措施，Selenium 也可能被检测到。

# dynamic_html = get_dynamic_html(target_url)

# if dynamic_html:
#     # print(dynamic_html) # 打印获取到的 F12 元素内容

#     # --- 你可以接着使用 BeautifulSoup 解析这个 HTML ---
#     print("\n使用 BeautifulSoup 解析获取到的 HTML...")
#     soup = BeautifulSoup(dynamic_html, 'html.parser')

#     # 例如，查找所有 h1 标签
#     h1_tags = soup.find_all('h1')
#     for h1 in h1_tags:
#         print(f"找到 H1: {h1.text.strip()}")

#     # 在这里执行你的具体解析逻辑...

# else:
#     print("未能获取动态 HTML 内容。")