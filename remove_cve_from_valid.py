#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
删除New/testset/{project}/valid文件中在cve_compilation_issues.json中列出的CVE数据项
"""

import json
import os
import sys
from pathlib import Path

def load_cve_issues(json_file):
    """加载CVE编译问题JSON文件"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"错误: 找不到文件 {json_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"错误: JSON文件格式错误 - {e}")
        sys.exit(1)

def get_cves_to_remove(cve_issues):
    """从JSON数据中提取需要删除的CVE列表"""
    cves_to_remove = {}
    
    for project_data in cve_issues:
        project = project_data['project']
        failed_cves = project_data.get('failed', [])
        no_func_cves = project_data.get('no_func', [])
        
        # 合并failed和no_func中的CVE
        all_cves = failed_cves + no_func_cves
        if all_cves:
            cves_to_remove[project] = set(all_cves)
    
    return cves_to_remove

def read_valid_file(valid_file_path):
    """读取valid文件内容"""
    try:
        with open(valid_file_path, 'r', encoding='utf-8') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"警告: 找不到valid文件 {valid_file_path}")
        return []
    except Exception as e:
        print(f"错误: 读取文件 {valid_file_path} 时出错 - {e}")
        return []

def write_valid_file(valid_file_path, lines):
    """写入valid文件内容"""
    try:
        with open(valid_file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return True
    except Exception as e:
        print(f"错误: 写入文件 {valid_file_path} 时出错 - {e}")
        return False

def process_valid_file(project, valid_file_path, cves_to_remove):
    """处理单个项目的valid文件"""
    if project not in cves_to_remove:
        print(f"项目 {project} 没有需要删除的CVE")
        return
    
    print(f"处理项目: {project}")
    print(f"文件路径: {valid_file_path}")
    
    # 读取文件内容
    lines = read_valid_file(valid_file_path)
    if not lines:
        return
    
    # 统计原始行数
    original_count = len(lines)
    print(f"原始行数: {original_count}")
    
    # 过滤掉需要删除的CVE
    filtered_lines = []
    removed_count = 0
    
    for line in lines:
        line = line.strip()
        if not line:  # 跳过空行
            continue
            
        # 提取CVE ID（第一列）
        parts = line.split()
        if not parts:
            continue
            
        cve_id = parts[0]
        
        # 检查是否在删除列表中
        if cve_id in cves_to_remove[project]:
            print(f"  删除: {cve_id}")
            removed_count += 1
        else:
            filtered_lines.append(line + '\n')
    
    # 写入过滤后的内容
    if write_valid_file(valid_file_path, filtered_lines):
        print(f"成功处理 {project}: 删除了 {removed_count} 个CVE，保留 {len(filtered_lines)} 个CVE")
    else:
        print(f"处理 {project} 失败")

def main():
    """主函数"""
    # 获取脚本所在目录
    script_dir = Path(__file__).parent
    json_file = script_dir / "cve_compilation_issues.json"
    testset_dir = script_dir / "testset"
    
    print("开始处理CVE删除任务...")
    print(f"JSON文件: {json_file}")
    print(f"测试集目录: {testset_dir}")
    print("-" * 50)
    
    # 加载CVE问题数据
    cve_issues = load_cve_issues(json_file)
    print(f"加载了 {len(cve_issues)} 个项目的数据")
    
    # 提取需要删除的CVE
    cves_to_remove = get_cves_to_remove(cve_issues)
    print(f"需要处理 {len(cves_to_remove)} 个项目")
    
    # 处理每个项目
    for project in cves_to_remove:
        valid_file_path = testset_dir / project / "valid"
        
        if not valid_file_path.exists():
            print(f"警告: 项目 {project} 的valid文件不存在: {valid_file_path}")
            continue
        
        process_valid_file(project, valid_file_path, cves_to_remove)
        print("-" * 50)
    
    print("处理完成!")

if __name__ == "__main__":
    main() 

# 开始处理CVE删除任务...
# JSON文件: /home/zhangxb/patch/related-works/CVE-Dataset/New/cve_compilation_issues.json
# 测试集目录: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset
# --------------------------------------------------
# 加载了 6 个项目的数据
# 需要处理 6 个项目
# 处理项目: openssl
# 文件路径: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset/openssl/valid
# 原始行数: 54
#   删除: CVE-2021-3711
#   删除: CVE-2021-4160
#   删除: CVE-2022-1434
#   删除: CVE-2022-4203
#   删除: CVE-2023-0216
#   删除: CVE-2023-0217
# 成功处理 openssl: 删除了 6 个CVE，保留 48 个CVE
# --------------------------------------------------
# 处理项目: binutils
# 文件路径: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset/binutils/valid
# 原始行数: 59
# 成功处理 binutils: 删除了 0 个CVE，保留 59 个CVE
# --------------------------------------------------
# 处理项目: curl
# 文件路径: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset/curl/valid
# 原始行数: 38
# 成功处理 curl: 删除了 0 个CVE，保留 37 个CVE
# --------------------------------------------------
# 处理项目: sqlite
# 文件路径: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset/sqlite/valid
# 原始行数: 33
#   删除: CVE-2015-3416
#   删除: CVE-2017-10989
#   删除: CVE-2019-19603
#   删除: CVE-2020-13631
#   删除: CVE-2020-9327
# 成功处理 sqlite: 删除了 5 个CVE，保留 28 个CVE
# --------------------------------------------------
# 处理项目: libxml2
# 文件路径: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset/libxml2/valid
# 原始行数: 37
# 成功处理 libxml2: 删除了 0 个CVE，保留 37 个CVE
# --------------------------------------------------
# 处理项目: ffmpeg
# 文件路径: /home/zhangxb/patch/related-works/CVE-Dataset/New/testset/ffmpeg/valid
# 原始行数: 69
#   删除: CVE-2020-12284
#   删除: CVE-2020-20450
#   删除: CVE-2020-20451
#   删除: CVE-2020-21688
#   删除: CVE-2020-22016
#   删除: CVE-2020-22025
#   删除: CVE-2020-22032
#   删除: CVE-2021-30123
#   删除: CVE-2021-38114
#   删除: CVE-2021-38171
#   删除: CVE-2022-2566
#   删除: CVE-2022-3341
#   删除: CVE-2022-3964
#   删除: CVE-2022-3965
#   删除: CVE-2022-48434
#   删除: CVE-2023-47344
#   删除: CVE-2023-49502
#   删除: CVE-2024-28661
#   删除: CVE-2024-31582
#   删除: CVE-2024-36617
#   删除: CVE-2025-1816
# 成功处理 ffmpeg: 删除了 21 个CVE，保留 48 个CVE
# --------------------------------------------------
# 处理完成!