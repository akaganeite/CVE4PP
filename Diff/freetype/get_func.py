#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
from typing import List

# 配置项目到本地仓库路径的映射
REPO_MAP = {
    "freetype": "/home/zhangxb/patch/related-works/CVE-Dataset/target/freetype",
}

def parse_diff_filename(filename):
    """解析diff文件名，返回(CVE-ID, commit_hash)"""
    # 支持多种命名格式
    patterns = [
        r"^.*_CVE-(.+?)_([0-9a-f]{6,}).diff$",
        r"^CVE-(.+?)_([0-9a-f]{6,}).diff$",
        r"^.*_([0-9a-f]{6,}).diff$"  # 如果没有CVE信息
    ]
    
    for pattern in patterns:
        match = re.match(pattern, filename)
        if match:
            if len(match.groups()) == 2:
                return f"CVE-{match.group(1)}", match.group(2)
            else:
                return "UNKNOWN", match.group(1)
    return None, None

def get_commit_info(repo_path, commit_hash):
    """从本地仓库获取commit信息"""
    try:
        # 获取commit日期
        date_cmd = ["git", "show", "-s", "--format=%ci", commit_hash]
        date_result = subprocess.run(date_cmd, cwd=repo_path, capture_output=True, text=True, check=True)
        commit_date = date_result.stdout.strip()[:10]  # 只要YYYY-MM-DD部分
        
        # 获取commit消息
        msg_cmd = ["git", "show", "-s", "--format=%B", commit_hash]
        msg_result = subprocess.run(msg_cmd, cwd=repo_path, capture_output=True, text=True, check=True)
        commit_msg = msg_result.stdout.strip()
        
        return commit_date, commit_msg
        
    except subprocess.CalledProcessError as e:
        print(f"获取commit信息失败 {commit_hash}: {e}")
        return None, None
    except Exception as e:
        print(f"处理commit {commit_hash} 时发生异常: {e}")
        return None, None

def parse_functions_from_commit_msg(commit_msg: str) -> List[str]:
    """从commit消息中解析修改的函数
    格式示例: (ft_smooth_render_generic): Don't allow
    """
    functions = set()
    
    # 匹配格式 (函数名): 描述
    pattern = r'\(([^)]+)\):'
    
    for line in commit_msg.split('\n'):
        line = line.strip()
        matches = re.findall(pattern, line)
        for match in matches:
            # 处理多个函数名，可能用逗号分隔
            func_names = [name.strip() for name in match.split(',')]
            for func_name in func_names:
                if func_name and func_name not in ("while", "for", "if", "switch", "else", "case", "return"):
                    functions.add(func_name)
    
    return sorted(list(functions))

def generate_report(project_dir, entries):
    """生成项目目录的details文件"""
    details_path = os.path.join(project_dir, "details")
    
    with open(details_path, "w", encoding="utf-8") as f:
        # 按CVE_ID排序
        for cve_commit, date, commit_msg, funcs in sorted(entries, key=lambda entry: entry[0]):
            func_list = ",".join(funcs) if funcs else "N/A"
            # 格式：CVE_commit date functions
            f.write(f"{cve_commit} {date} {func_list}\n")
    
    print(f"生成details文件: {details_path}")

def main():
    """主函数"""
    project_name = os.path.basename(os.getcwd())  # 获取当前目录名作为项目名
    
    if project_name not in REPO_MAP:
        print(f"错误: 项目 {project_name} 不在支持的项目列表中")
        print(f"支持的项目: {list(REPO_MAP.keys())}")
        return
    
    repo_path = REPO_MAP[project_name]
    
    if not os.path.exists(repo_path):
        print(f"错误: 仓库路径不存在 {repo_path}")
        return
    
    diff_files_dir = "./diff_files"
    if not os.path.exists(diff_files_dir):
        print(f"错误: diff_files 目录不存在")
        return
    
    print(f"处理项目: {project_name}")
    print(f"仓库路径: {repo_path}")
    print(f"diff文件目录: {diff_files_dir}")
    
    report_entries = []
    
    # 遍历diff_files目录中的所有.diff文件
    for file in os.listdir(diff_files_dir):
        if not file.endswith(".diff"):
            continue
            
        print(f"处理文件: {file}")
        
        # 解析文件名信息
        cve_id, commit_hash = parse_diff_filename(file)
        if not cve_id or not commit_hash:
            print(f"  跳过文件 {file}: 无法解析CVE ID或commit hash")
            continue
        
        print(f"  CVE: {cve_id}, Commit: {commit_hash}")
        
        # 获取commit信息
        commit_date, commit_msg = get_commit_info(repo_path, commit_hash)
        if not commit_date or not commit_msg:
            print(f"  跳过commit {commit_hash}: 无法获取commit信息")
            continue
        
        # 从commit消息中提取修改的函数
        functions = parse_functions_from_commit_msg(commit_msg)
        
        print(f"  日期: {commit_date}")
        print(f"  函数: {functions}")
        print(f"  消息: {commit_msg[:100]}...")  # 只显示前100个字符
        
        # 准备commit消息（移除换行符，保持单行格式）
        clean_commit_msg = " ".join(commit_msg.split())
        
        report_entries.append((f"{cve_id}_{commit_hash}", commit_date, clean_commit_msg, functions))
    
    if report_entries:
        generate_report(".", report_entries)
        print(f"\n完成! 处理了 {len(report_entries)} 个commit")
    else:
        print("没有找到有效的diff文件或commit信息")

if __name__ == "__main__":
    main()
