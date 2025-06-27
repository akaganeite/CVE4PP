import os
import re
import requests
import json
from datetime import datetime
from unidiff import PatchSet
from typing import List, Tuple, Set, Optional, Dict

# 配置项目到GitHub仓库的映射
REPO_MAP = {
    # "binutils": "api.github.com/repos/bminor/binutils-gdb",
    # "curl": "api.github.com/repos/curl/curl",
    "ffmpeg": "api.github.com/repos/FFmpeg/FFmpeg",
    # "libxml2": "api.github.com/repos/GNOME/libxml2",
    # "sqlite": "api.github.com/repos/sqlite/sqlite",
    # "openssl": "api.github.com/repos/openssl/openssl",
}

def parse_diff_filename(filename):
    """解析diff文件名，返回(CVE-ID, commit_hash)"""
    pattern = r"^.*_CVE-(.+?)_([0-9a-f]{6,}).diff$"
    match = re.match(pattern, filename)
    if not match: 
        return None, None
    return f"CVE-{match.group(1)}", match.group(2)

def fetch_commit_date(repo, commit_hash, token=""):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}" if token else None
    }
    
    # 清理可能的路径错误
    repo = repo.replace("//", "/").replace(":/", "://").lstrip("/")
    url = f"https://{repo}/commits/{commit_hash}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # 处理速率限制 (403)
        if response.status_code == 403:
            reset_time = response.headers.get('X-RateLimit-Reset')
            if reset_time:
                reset_date = datetime.fromtimestamp(int(reset_time)).strftime('%Y-%m-%d %H:%M:%S')
                print(f"API 速率限制已触发，重置时间：{reset_date}")
            return None
            
        response.raise_for_status()
        return response.json()["commit"]["committer"]["date"][:11]  # 返回 YYYY-MM-DD
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print("认证失败，请检查 Token 权限")
        elif e.response.status_code == 404:
            print("资源未找到，请检查仓库路径和 commit hash")
        return None
    except Exception as e:
        print(f"请求异常: {str(e)}")
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

# Python 函数定义
PYTHON_FUNC_REGEX = re.compile(r"^\s*def\s+([a-zA-Z_][a-zA-Z_0-9]*)\s*\(")
# Python Hunk 头 (可以简化，或者用和上面一样的)
PYTHON_HUNK_REGEX = PYTHON_FUNC_REGEX 

# C 语言函数定义 (用于匹配 +/- 行，需要 { )
C_FUNC_REGEX = re.compile(
    r'^\s*'                          # 行首和可选空格
    r'(?:(?:static|inline|extern|const|volatile|struct|enum|union)\s+)*' # 可选关键字/类型前缀
    r'[\w\s\*&<>_:]+?'              # 返回类型 (非贪婪匹配)
    r'\s+'                           # 至少一个空格
    r'([a-zA-Z_]\w*)'                # 函数名 (捕获组 1)
    r'\s*'                           # 可选空格
    r'\('                            # 左括号
    r'[^)]*'                         # 参数 (简单匹配)
    r'\)'                            # 右括号
    r'\s*'                           # 可选空格
    r'\{',                           # 左大括号 (必须)
    re.MULTILINE 
)

# C 语言 Hunk 头识别 (更宽松，不需要 { )
# 它只查找看起来像 "标识符(" 的模式
C_HUNK_REGEX = re.compile(
    r'([a-zA-Z_]\w*)'                # 函数名 (捕获组 1)
    r'\s*'                           # 可选空格
    r'\('                            # 左括号
)

# 将语言和对应的正则表达式关联起来 (每种语言两个)
LANG_LINE_REGEX_MAP: Dict[str, re.Pattern] = {
    "python": PYTHON_FUNC_REGEX,
    "c": C_FUNC_REGEX,
}
LANG_HUNK_REGEX_MAP: Dict[str, re.Pattern] = {
    "python": PYTHON_HUNK_REGEX,
    "c": C_HUNK_REGEX, # <--- 使用新的 C Hunk 正则
}

# --- 辅助函数 ---

def extract_name(line: str, regex: re.Pattern) -> Optional[str]:
    """尝试从单行代码中提取函数/类名 (捕获组 1)。"""
    match = regex.match(line) # 使用 match 确保从行首开始匹配 (符合行正则的意图)
    if match:
        if match.groups():
            return match.group(1)
    return None

def extract_name_from_hunk_header(header: str, regex: re.Pattern) -> Optional[str]:
    """尝试从 hunk 的头部信息中提取函数/类名。"""
    lines = header.splitlines()
    if lines:
        for line in reversed(lines):
            cleaned_line = line.strip().split('@@')[-1].strip()
            # 对于 Hunk 头，我们用 search，因为它可能不从头开始
            match = regex.search(cleaned_line) 
            if match:
                if match.groups():
                    return match.group(1)
    return None

# --- 主解析函数 (修改版) ---

def parse_diff_functions_inclusive(
    diff_filepath: str, 
    language: str = "c"
) -> List[str]:
    """
    解析 diff 文件，识别所有新增、删除和修改迹象的函数，
    并返回一个合并去重后的列表。
    """
    all_added: Set[str] = set()
    all_deleted: Set[str] = set()
    all_modified: Set[str] = set()

    line_regex = LANG_LINE_REGEX_MAP.get(language)
    hunk_regex = LANG_HUNK_REGEX_MAP.get(language) # <--- 获取 Hunk 正则

    if not line_regex or not hunk_regex:
        raise ValueError(f"不支持的语言或未配置正则表达式: {language}")

    try:
        with open(diff_filepath, 'r', encoding='utf-8', errors='ignore') as f:
            diff_content = f.read()
            
        patch = PatchSet.from_string(diff_content)

    except FileNotFoundError:
        print(f"错误: 文件未找到 '{diff_filepath}'")
        return []
    except Exception as e:
        print(f"解析 Diff 内容时发生错误: {e}")
        return []

    for patched_file in patch:
        # 只处理 .c 文件
        is_c_file = patched_file.source_file.endswith('.c') or patched_file.target_file.endswith('.c')
        
        # 如果文件类型不匹配或者不是修改过的文件，则跳过
        if patched_file.is_modified_file and is_c_file:
            for hunk in patched_file:
                hunk_added: Set[str] = set()
                hunk_deleted: Set[str] = set()
                has_changes_in_hunk = False

                for line in hunk:
                    if line.is_added:
                        has_changes_in_hunk = True
                        name = extract_name(line.value.lstrip('+').rstrip(), line_regex)
                        if name: hunk_added.add(name)
                    elif line.is_removed:
                        has_changes_in_hunk = True
                        name = extract_name(line.value.lstrip('-').rstrip(), line_regex)
                        if name: hunk_deleted.add(name)
                
                all_added.update(hunk_added)
                all_deleted.update(hunk_deleted)

                signature_changed = hunk_added & hunk_deleted
                all_modified.update(signature_changed)

                # 使用 Hunk 正则解析 Hunk 头
                if has_changes_in_hunk:
                    hunk_func_name = extract_name_from_hunk_header(hunk.section_header, hunk_regex)
                    if hunk_func_name:
                         all_modified.add(hunk_func_name)

    return list(all_added | all_deleted | all_modified)

def generate_report(project_dir, entries):
    """生成项目目录的details文件"""
    with open(os.path.join(project_dir, "details"), "w") as f:
        # 在迭代前对 entries 进行排序
        # key=lambda entry: entry[0] 表示按每个条目(entry)的第一个元素(cve_id)排序
        for cve_id, date, funcs in sorted(entries, key=lambda entry: entry[0]):
            # funcs 去掉 while for if
            funcs = [func for func in funcs if func not in ("while", "for", "if","switch")]
            func_list = ",".join(funcs) if funcs else "N/A"
            f.write(f"{cve_id} {date} {func_list}\n")

def main():
    for root, dirs, files in os.walk("./ffmpeg/diff_files"):
        project = root.split(os.sep)[-2]  # 获取项目名
        print(project)
        if project not in REPO_MAP: continue
        
        repo = REPO_MAP[project]
        report_entries = []
        
        for file in files:
            if not file.endswith(".diff") or file == "cve2diff.py":
                continue
                
            # 解析文件名信息
            cve_id, commit_hash = parse_diff_filename(file)
            if not cve_id: continue
            print(f"Processing {file} in {root}...")
            # 获取提交日期
            commit_date = fetch_commit_date(repo, commit_hash)
            if not commit_date: continue
            date_str = datetime.fromisoformat(commit_date[:-1]).strftime("%Y-%m-%d")
            
            # 提取修改函数
            diff_path = os.path.join(root, file)
            functions = parse_diff_functions_inclusive(diff_path)
            print(date_str)
            report_entries.append( (cve_id+"_"+commit_hash,date_str, functions) )
        
        if report_entries:
            generate_report(root, report_entries)

if __name__ == "__main__":
    main()