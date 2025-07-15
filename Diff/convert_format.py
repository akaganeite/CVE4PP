#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
格式转换脚本：将valid文件格式转换为details文件格式

valid文件格式：CVE-ID 日期 commit_hash curl 函数名
details文件格式：CVE-ID_commit_hash 日期 函数名
"""

import os
import sys

def convert_valid_to_details(valid_file_path, output_file_path):
    """
    将valid文件格式转换为details文件格式
    
    Args:
        valid_file_path (str): valid文件的路径
        output_file_path (str): 输出文件的路径
    """
    try:
        with open(valid_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        converted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:  # 跳过空行
                continue
                
            # 解析valid文件格式：CVE-ID 日期 commit_hash curl 函数名
            parts = line.split()
            if len(parts) < 5:
                print(f"警告：跳过格式不正确的行: {line}")
                continue
            
            # 提取各个部分
            cve_id = parts[0]
            date = parts[1]
            commit_hash = parts[2]
            project = parts[3]  # 通常是 "curl"
            function_name = ' '.join(parts[4:])  # 函数名可能包含空格
            
            # 转换为details格式：CVE-ID_commit_hash 日期 函数名
            converted_line = f"{cve_id}_{commit_hash} {date} {project} {function_name}"
            converted_lines.append(converted_line)
        
        # 写入输出文件
        with open(output_file_path, 'w', encoding='utf-8') as f:
            for line in converted_lines:
                f.write(line + '\n')
        
        print(f"转换完成！")
        print(f"输入文件: {valid_file_path}")
        print(f"输出文件: {output_file_path}")
        print(f"转换了 {len(converted_lines)} 行数据")
        
    except FileNotFoundError:
        print(f"错误：找不到文件 {valid_file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"错误：转换过程中出现异常: {e}")
        sys.exit(1)

PROJECT = "openssl"
def main():
    """主函数"""
    # 设置文件路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    valid_file = os.path.join(script_dir, f"../testset/{PROJECT}/valid")
    output_file = f"{PROJECT}/diff_files/details_llvm"
    
    # 检查输入文件是否存在
    if not os.path.exists(valid_file):
        print(f"错误：找不到valid文件 {valid_file}")
        print("请确保文件路径正确")
        sys.exit(1)
    
    # 执行转换
    convert_valid_to_details(valid_file, output_file)

if __name__ == "__main__":
    main() 