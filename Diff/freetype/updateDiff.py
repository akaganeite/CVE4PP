#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
from pathlib import Path
from datetime import datetime

# 配置参数
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DETAILS_FILE = os.path.join(CURRENT_DIR, "details")
DIFF_FILES_DIR = os.path.join(CURRENT_DIR, "diff_files")
LOG_DIR = "logs"

# 确保日志目录存在
os.makedirs(LOG_DIR, exist_ok=True)

def log_debug(msg):
    """记录调试信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {msg}"
    print(log_msg)

def log_error(msg):
    """记录错误信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] ERROR: {msg}"
    print(log_msg)

def parse_details_line(line):
    """解析details文件中的行"""
    parts = line.strip().split()
    if len(parts) < 3:
        return None, None, None, None
    
    cve_hash = parts[0]
    cve_id = cve_hash.split('_')[0]
    commit_hash = cve_hash.split('_')[1]
    date = parts[1]
    functions = parts[2].split(',')
    
    return cve_id, commit_hash, date, functions

def find_diff_file(cve_id, commit_hash, diff_files_dir):
    """查找CVE对应的diff文件"""
    diff_dir = Path(diff_files_dir)
    
    # 尝试不同的文件名模式
    possible_patterns = [
        f"freetype_{cve_id}_{commit_hash}.diff",
    ]
    
    for pattern in possible_patterns:
        diff_file = diff_dir / pattern
        if diff_file.exists():
            log_debug(f"找到diff文件: {diff_file}")
            return diff_file
    
    # 如果直接匹配不到，尝试模糊匹配
    for file_path in diff_dir.glob("*"):
        if file_path.is_file() and cve_id.lower() in file_path.name.lower():
            log_debug(f"通过模糊匹配找到diff文件: {file_path}")
            return file_path
    
    return None

def parse_changelog_entries(diff_content):
    """解析ChangeLog中的文件-函数映射关系"""
    lines = diff_content.split('\n')
    file_func_map = {}
    
    # 匹配ChangeLog中的条目模式: * src/path/file.c (function_name)
    changelog_pattern = re.compile(r'^\+?\s*\*\s+([^(]+)\s+\(([^)]+)\)')
    
    for line in lines:
        match = changelog_pattern.match(line)
        if match:
            file_path = match.group(1).strip()
            functions_str = match.group(2).strip()
            
            # 处理多个函数的情况，用逗号分隔
            functions = [f.strip() for f in functions_str.split(',')]
            
            # 标准化文件路径（去掉src/前缀，因为diff中通常不包含）
            if file_path.startswith('src/'):
                file_path = file_path[4:]
            
            file_func_map[file_path] = functions
            log_debug(f"ChangeLog映射: {file_path} -> {functions}")
    
    return file_func_map

def get_function_for_file(file_path, file_func_map):
    """根据文件路径获取对应的函数列表"""
    # 尝试直接匹配
    if file_path in file_func_map:
        return file_func_map[file_path]
    
    # 尝试部分匹配（文件名匹配）
    filename = os.path.basename(file_path)
    for mapped_path, functions in file_func_map.items():
        if os.path.basename(mapped_path) == filename:
            return functions
    
    # 尝试路径包含匹配
    for mapped_path, functions in file_func_map.items():
        if mapped_path in file_path or file_path in mapped_path:
            return functions
    
    return []

def update_hunk_headers_with_mapping(diff_content, file_func_map):
    """更新diff内容中的hunk headers，根据文件路径添加对应的函数名"""
    lines = diff_content.split('\n')
    updated_lines = []
    current_file = None
    
    # 匹配diff文件头: diff --git a/path b/path 或 --- a/格式
    file_header_pattern = re.compile(r'^(?:diff --git a/(.+) b/(.+)|--- a/(.+))')
    # hunk header的正则表达式: @@ -起始行,行数 +起始行,行数 @@
    hunk_pattern = re.compile(r'^@@\s*-(\d+),?(\d*)\s*\+(\d+),?(\d*)\s*@@(.*)$')
    
    for line in lines:
        # 检查是否是文件头
        file_match = file_header_pattern.match(line)
        if file_match:
            # 提取文件路径
            if file_match.group(1):  # diff --git格式
                current_file = file_match.group(2)  # 使用b/路径
            elif file_match.group(3):  # --- a/格式
                current_file = file_match.group(3)
            
            log_debug(f"检测到文件: {current_file}")
            updated_lines.append(line)
            continue
        
        # 检查是否是hunk header
        hunk_match = hunk_pattern.match(line)
        if hunk_match and current_file:
            # 提取现有的hunk header信息
            old_start = hunk_match.group(1)
            old_count = hunk_match.group(2) if hunk_match.group(2) else '1'
            new_start = hunk_match.group(3) 
            new_count = hunk_match.group(4) if hunk_match.group(4) else '1'
            existing_context = hunk_match.group(5).strip()
            
            # 获取该文件对应的函数
            functions = get_function_for_file(current_file, file_func_map)
            
            if functions:
                # 如果有多个函数，选择第一个（或者可以根据具体规则选择）
                func_name = functions[0]
                new_context = f" {func_name}()"
                
                # 如果已经有其他上下文信息，保留它
                if existing_context and not any(f"({f}" in existing_context or f"{f})" in existing_context for f in functions):
                    new_context = f" {existing_context} {func_name}()"
                elif any(f"({f}" in existing_context or f"{f})" in existing_context for f in functions):
                    # 如果已经包含函数信息，跳过
                    updated_lines.append(line)
                    continue
            else:
                # 如果没找到对应函数，保持原样
                new_context = f" {existing_context}" if existing_context else ""
            
            # 重新构建hunk header
            if old_count == '1':
                old_range = old_start
            else:
                old_range = f"{old_start},{old_count}"
                
            if new_count == '1':
                new_range = new_start  
            else:
                new_range = f"{new_start},{new_count}"
            
            updated_line = f"@@ -{old_range} +{new_range} @@{new_context}"
            updated_lines.append(updated_line)
            
            if functions:
                log_debug(f"更新hunk header: {line} -> {updated_line}")
        else:
            updated_lines.append(line)
    
    return '\n'.join(updated_lines)

def backup_file(file_path):
    """备份文件"""
    backup_path = f"{file_path}.backup"
    if not Path(backup_path).exists():
        with open(file_path, 'r', encoding='utf-8') as src:
            with open(backup_path, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        log_debug(f"创建备份文件: {backup_path}")
    else:
        log_debug(f"备份文件已存在: {backup_path}")

def process_cve_diff(cve_id, commit_hash, functions, diff_files_dir):
    """处理单个CVE的diff文件"""
    log_debug(f"处理CVE: {cve_id}, 函数: {', '.join(functions)}")
    
    # 查找对应的diff文件
    diff_file = find_diff_file(cve_id, commit_hash, diff_files_dir)
    if not diff_file:
        log_error(f"未找到CVE {cve_id} 对应的diff文件")
        return False
    
    try:
        # 读取原始diff内容
        with open(diff_file, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # 检查是否已经包含函数名信息（检查()格式）
        if re.search(r'@@.*\w+\(\)', original_content):
            log_debug(f"diff文件 {diff_file} 已包含函数名信息，跳过")
            return True
        
        # 备份原文件
        backup_file(diff_file)
        
        # 解析ChangeLog中的文件-函数映射关系
        file_func_map = parse_changelog_entries(original_content)
        
        if not file_func_map:
            log_error(f"未能从ChangeLog中解析出文件-函数映射关系")
            # 如果没有ChangeLog信息，尝试使用传统方法（所有函数应用到所有hunk）
            updated_content = update_hunk_headers(original_content, functions)
        else:
            # 使用解析出的映射关系更新hunk headers
            updated_content = update_hunk_headers_with_mapping(original_content, file_func_map)
        
        # 写回更新后的内容
        with open(diff_file, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        
        log_debug(f"成功更新diff文件: {diff_file}")
        return True
        
    except Exception as e:
        log_error(f"处理diff文件 {diff_file} 时发生错误: {str(e)}")
        return False

def update_hunk_headers(diff_content, functions):
    """传统方法：更新diff内容中的hunk headers，添加函数名信息（兼容旧逻辑）"""
    lines = diff_content.split('\n')
    updated_lines = []
    
    # hunk header的正则表达式: @@ -起始行,行数 +起始行,行数 @@
    hunk_pattern = re.compile(r'^@@\s*-(\d+),?(\d*)\s*\+(\d+),?(\d*)\s*@@(.*)$')
    
    for line in lines:
        match = hunk_pattern.match(line)
        if match:
            # 提取现有的hunk header信息
            old_start = match.group(1)
            old_count = match.group(2) if match.group(2) else '1'
            new_start = match.group(3) 
            new_count = match.group(4) if match.group(4) else '1'
            existing_context = match.group(5).strip()
            
            # 对于传统方法，只使用第一个函数
            func_name = functions[0] if functions else "unknown"
            new_context = f" {func_name}()"
            
            # 如果已经有上下文信息，保留它
            if existing_context and not (f"({func_name}" in existing_context or f"{func_name})" in existing_context):
                new_context = f" {existing_context} {func_name}()"
            elif f"({func_name}" in existing_context or f"{func_name})" in existing_context:
                # 如果已经包含函数信息，跳过
                updated_lines.append(line)
                continue
            
            # 重新构建hunk header
            if old_count == '1':
                old_range = old_start
            else:
                old_range = f"{old_start},{old_count}"
                
            if new_count == '1':
                new_range = new_start  
            else:
                new_range = f"{new_start},{new_count}"
            
            updated_line = f"@@ -{old_range} +{new_range} @@{new_context}"
            updated_lines.append(updated_line)
            log_debug(f"更新hunk header: {line} -> {updated_line}")
        else:
            updated_lines.append(line)
    
    return '\n'.join(updated_lines)

def main():
    """主函数"""
    log_debug("===== 开始更新diff文件中的hunk headers =====")
    
    # 检查必要文件和目录
    if not os.path.isfile(DETAILS_FILE):
        log_error(f"错误：details文件不存在 {DETAILS_FILE}")
        return
    
    if not os.path.isdir(DIFF_FILES_DIR):
        log_error(f"错误：diff文件目录不存在 {DIFF_FILES_DIR}")
        return
    
    success_count = 0
    error_count = 0
    processed_cves = set()
    
    # 处理每个CVE条目
    with open(DETAILS_FILE, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 解析details行
            cve_id, commit_hash, date, functions = parse_details_line(line)
            if not all([cve_id, commit_hash, functions]):
                log_error(f"第{line_num}行格式错误: {line}")
                error_count += 1
                continue
            
            # 如果这个CVE已经处理过，跳过
            if cve_id in processed_cves:
                log_debug(f"跳过已处理的CVE: {cve_id}")
                continue
            
            # 处理CVE对应的diff文件
            if process_cve_diff(cve_id, commit_hash, functions, DIFF_FILES_DIR):
                success_count += 1
            else:
                error_count += 1
            
            # 标记这个CVE已处理
            processed_cves.add(cve_id)
    
    log_debug("===== 处理完成 =====")
    log_debug(f"成功处理: {success_count} 个CVE")
    log_debug(f"处理失败: {error_count} 个CVE") 
    log_debug(f"总计处理: {len(processed_cves)} 个唯一CVE")
    
    if error_count == 0:
        log_debug("所有diff文件更新成功！")
    else:
        log_error(f"有 {error_count} 个CVE处理失败，请检查日志")

if __name__ == "__main__":
    main()
