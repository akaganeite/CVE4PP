import os
import re
import requests
import json
from datetime import datetime

# 配置项目到GitHub仓库的映射
REPO_MAP = {
    "binutils": "api.github.com/bminor/binutils-gdb",
    "curl": "api.github.com/curl/curl",
    "ffmpeg": "api.github.com/FFmpeg/FFmpeg",
    #"libxml2": "gitlab.gnome.org/GNOME/libxml2/-",
    "sqlite": "api.github.com/sqlite/sqlite",
    "openssl": "api.github.com/openssl/openssl",
}

def parse_diff_filename(filename):
    """解析diff文件名，返回(CVE-ID, commit_hash)"""
    pattern = r"^.*_CVE-(.+?)_([0-9a-f]{6,})_CWE-.*\.diff$"
    match = re.match(pattern, filename)
    if not match: 
        return None, None
    return f"CVE-{match.group(1)}", match.group(2)

def fetch_commit_date(repo, commit_hash):
    """通过GitHub API获取提交日期"""
    url = f"https://{repo}/commits/{commit_hash}"
    try:
        response = requests.get(url, headers={"Accept": "application/vnd.github.v3+json"})
        if response.status_code == 200:
            return response.json()["commit"]["committer"]["date"]
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
    return None

def extract_functions(diff_path):
    """从diff文件提取修改的函数列表"""
    func_pattern = r"@@\s*-\d+,\d+\s*\+\d+,\d+\s*@@\s*(.*?)\("
    functions = set()
    
    with open(diff_path, "r") as f:
        for line in f:
            match = re.search(func_pattern, line)
            if match:
                func = match.group(1).split()[-1]  # 提取最后一个单词作为函数名
                functions.add(func)
    return sorted(functions)

def generate_report(project_dir, entries):
    """生成项目目录的details文件"""
    with open(os.path.join(project_dir, "details"), "w") as f:
        for cve_id, date,funcs in entries:
            func_list = ",".join(funcs) if funcs else "N/A"
            f.write(f"{cve_id} {date} {func_list}\n")

def main():
    for root, dirs, files in os.walk("."):
        project = os.path.basename(root)
        if project not in REPO_MAP: continue
        
        repo = REPO_MAP[project]
        report_entries = []
        
        for file in files:
            if not file.endswith(".diff") or file == "cve2diff.py":
                continue
                
            # 解析文件名信息
            cve_id, commit_hash = parse_diff_filename(file)
            if not cve_id: continue
            
            # 获取提交日期
            commit_date = fetch_commit_date(repo, commit_hash)
            if not commit_date: continue
            date_str = datetime.fromisoformat(commit_date[:-1]).strftime("%Y-%m-%d")
            
            # 提取修改函数
            diff_path = os.path.join(root, file)
            functions = extract_functions(diff_path)
            print(date_str)
            report_entries.append( (cve_id+"_"+commit_hash,date_str, functions) )
        
        if report_entries:
            generate_report(root, report_entries)

if __name__ == "__main__":
    main()