#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import shutil
from pathlib import Path
import glob
from datetime import datetime
import multiprocessing

# 配置参数
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/ImageMagick"
DETAILS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/imagemagick/details"
REFERENCE_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/imagemagick"
LOG_DIR = "logs"
BUILD_DIR_PREFIX = os.path.join(REPO_DIR, "build")
# 日志文件名带时间戳
now_str = datetime.now().strftime("%Y%m%d_%H%M")
DEBUG_LOG = os.path.join(LOG_DIR, f"compile_reference_{now_str}.log")
ERROR_LOG = os.path.join(LOG_DIR, "compile_reference_error.log")

# 确保日志目录存在
os.makedirs(LOG_DIR, exist_ok=True)

def log_debug(msg):
    """记录调试信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {msg}"
    print(log_msg)
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def log_error(msg):
    """记录错误信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] ERROR: {msg}"
    print(log_msg)
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def log_failure(cve_id: str, commit_hash: str, error_type: str, error_details: str, binary_type: str) -> None:
    """记录失败信息到失败日志文件"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] CVE: {cve_id} | Commit: {commit_hash} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    log_error(log_message)
    with open("logs/failed_reference_imagemagick.log", "a", encoding="utf-8") as f:
        f.write(log_message + "\n")

def run_cmd(cmd, cwd=None, env=None, shell=False, log_file=None):
    """运行命令并记录日志"""
    try:
        with open(log_file, "a", encoding="utf-8") if log_file else open(os.devnull, "w") as logf:
            result = subprocess.run(cmd, cwd=cwd, env=env, shell=shell, check=True, 
                                  stdout=logf, stderr=logf, encoding="utf-8")
        log_debug(f"命令成功: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        return True
    except subprocess.CalledProcessError as e:
        err_msg = f"命令执行失败: {' '.join(cmd) if isinstance(cmd, list) else cmd}"
        log_error(err_msg)
        if log_file:
            log_error(f"详情见日志: {log_file}")
        return False

def check_functions_in_binary(binary_path, functions):
    """检查二进制文件是否包含所有指定函数"""
    try:
        result = subprocess.run(["nm", binary_path], capture_output=True, text=True, check=True)
        nm_output = result.stdout
        
        missing_funcs = []
        for func in functions:
            func = func.strip()
            if f" {func}$" not in nm_output and f" {func}\n" not in nm_output:
                missing_funcs.append(func)
        
        if missing_funcs:
            log_error(f"缺少函数: {', '.join(missing_funcs)} in {binary_path}")
            return False
        
        log_debug(f"所有函数都找到了: {', '.join(functions)} in {os.path.basename(binary_path)}")
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"nm 命令执行失败: {binary_path}")
        return False

def find_valid_imagemagick_binary(build_dir, functions):
    patterns = [
        # 常见的 .so 文件路径
        os.path.join(build_dir, "MagickCore", ".libs","*.so.*.*"),
        os.path.join(build_dir, "MagickWand", ".libs", "*.so.*.*"),
    ]
    validbins = []
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            with open(match, 'rb') as f:
                # 读取文件前 4 字节
                magic = f.read(4)
                # ELF 魔数: 0x7F 'E' 'L' 'F'
                if magic == b'\x7fELF':
                    log_debug(f"找到有效的 imagemagick 二进制文件: {match}")
                    if check_functions_in_binary(match, functions):
                        return match        
    log_error(f"未找到 imagemagick 二进制文件,目录: {build_dir}")
    return None

def compile_and_copy_imagemagick(git_checkout_ref, output_binary_names, destination_dir, details_line, functions):
    """编译和复制 imagemagick 二进制文件"""
    # 替换路径中的特殊字符
    sanitized_ref = git_checkout_ref.replace('/', '_')
    current_build_dir = f"{BUILD_DIR_PREFIX}-{sanitized_ref}"
    log_file = os.path.join(current_build_dir, "compile.log")
    
    log_debug("=" * 50)
    log_debug(f"开始处理 Git Ref: {git_checkout_ref}")
    log_debug(f"构建目录: {current_build_dir}")
    log_debug(f"日志文件: {log_file}")
    
    # 检查目标二进制是否已存在
    for name in output_binary_names:
        target_path = os.path.join(destination_dir, name)
        if os.path.isfile(target_path):
            log_debug(f"二进制文件 {target_path} 已存在，跳过编译")
            return True
    
    # 准备仓库：导航到仓库并存储当前状态
    if not os.path.isdir(REPO_DIR):
        log_error(f"仓库目录不存在: {REPO_DIR}")
        return False
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    # 检出指定的 git 引用
    log_debug(f"正在检出 {git_checkout_ref}...")
    if not run_cmd(["git", "checkout", git_checkout_ref], cwd=REPO_DIR, log_file=DEBUG_LOG):
        log_error(f"无法检出 {git_checkout_ref}")
        return False
    
    log_debug(f"已成功检出 {git_checkout_ref}")
    
    # 编译 imagemagick（如果可执行文件在其构建目录中不存在）
    valid_binary = None
    os.makedirs(current_build_dir, exist_ok=True)
    
    # 配置环境变量
    env = os.environ.copy()
    env["CFLAGS"] = "-g -O0"
    env["CXXFLAGS"] = "-g -O0"
    
    # 在构建目录中执行编译
    with open(log_file, "w", encoding="utf-8") as logf:
        logf.write(f"=== 开始配置 {git_checkout_ref} ===\n")
    
    # 执行 autogen.sh 配置
    configrue_cmd = [
        os.path.join(REPO_DIR, "configure"),
        f"CFLAGS={env['CFLAGS']}",
        f"CXXFLAGS={env['CXXFLAGS']}",
        "--disable-werrors",
        "--enable-shared",
        "--disable-install",
    ]
    
    if not run_cmd(configrue_cmd, cwd=current_build_dir, env=env, log_file=log_file):
        log_error(f"配置失败，详见 {log_file}")
        log_failure(details_line.split("_")[0], git_checkout_ref, "CONFIGURE_ERROR", 
                    f"配置失败，详见 {log_file}", "imagemagick")
        return False
    
    # 执行编译
    with open(log_file, "a", encoding="utf-8") as logf:
        logf.write(f"\n=== 开始编译 {git_checkout_ref} ===\n")
    
    nproc = multiprocessing.cpu_count()
    make_cmd = ["make","-j", str(nproc)]
    
    run_cmd(make_cmd, cwd=current_build_dir, env=env, log_file=log_file)
    
    log_debug("编译子任务完成")
    
    # 查找有效的二进制文件
    valid_binary = find_valid_imagemagick_binary(current_build_dir, functions)
    if not valid_binary:
        log_error(f"编译后未找到有效的 imagemagick 二进制文件，详情请查看 {log_file}")
        log_failure(details_line.split("_")[0], git_checkout_ref, "BINARY_NOT_FOUND", 
                    f"编译后未找到有效的 imagemagick 二进制文件", "imagemagick")
        return False
    
    log_debug(f"{git_checkout_ref} 编译成功")
    
    # 复制编译的二进制文件到最终目标
    if valid_binary and os.path.isfile(valid_binary):
        if "MagickCore" in valid_binary:
            target_path = os.path.join(destination_dir, f"{output_binary_names[0]}")
        elif "MagickWand" in valid_binary:
            target_path = os.path.join(destination_dir, f"{output_binary_names[1]}")
        log_debug(f"复制 {valid_binary} 到 {target_path}")
        os.makedirs(destination_dir, exist_ok=True)
        
        try:
            shutil.copy(valid_binary, target_path)
            log_debug("二进制文件复制成功")
            return True
        except Exception as e:
            log_error(f"复制 {valid_binary} 失败: {e}")
            log_failure(details_line.split("_")[0], git_checkout_ref, "COPY_ERROR", 
                       f"复制失败: {e}", "imagemagick")
            return False
    else:
        log_error(f"错误：某些函数未在二进制文件中找到")
        log_failure(details_line.split("_")[0], git_checkout_ref, "FUNCTION_NOT_FOUND", 
                   "某些函数未在二进制文件中找到", "imagemagick")
        return False

def parse_details_line(line):
    """解析details文件中的行"""
    parts = line.strip().split()
    if len(parts) < 3:
        return None, None, None, None
    
    # 解析CVE_CommitHash格式
    cve_hash_field = parts[0]
    if '_' not in cve_hash_field:
        return None, None, None, None
    
    cve_id = cve_hash_field.split('_')[0]
    commit_hash = '_'.join(cve_hash_field.split('_')[1:])  # 获取剩余部分作为commit_hash
    
    # 提取函数名（第三个字段开始）
    functions = []
    if len(parts) > 2:
        func_str = ' '.join(parts[2:])  # 合并所有剩余字段
        functions = [func.strip() for func in func_str.split(',') if func.strip()]
    
    return cve_id, commit_hash, functions, line

def main():
    """主函数"""
    log_debug("===== 开始处理 imagemagick CVE 参考二进制编译 =====")
    
    # 创建输出目录
    os.makedirs(REFERENCE_DIR, exist_ok=True)
    os.makedirs(BUILD_DIR_PREFIX, exist_ok=True)
    
    # 检查必要文件和目录
    if not os.path.isdir(REPO_DIR):
        log_error(f"错误：仓库目录不存在 {REPO_DIR}")
        return
    
    if not os.path.isfile(DETAILS_FILE):
        log_error(f"错误：details文件不存在 {DETAILS_FILE}")
        return
    
    # 处理每个CVE条目
    with open(DETAILS_FILE, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            # 解析details行
            cve_id, commit_hash, functions, original_line = parse_details_line(line)
            if not all([cve_id, commit_hash, functions]):
                log_error(f"第{line_num}行格式错误: {line}")
                continue
            
            log_debug("")  # 空行提高可读性
            log_debug(f">>> 处理 CVE: {cve_id}, 补丁 Commit: {commit_hash} <<<")
            log_debug(f"相关函数: {', '.join(functions)}")
            
            try:
                # 1. 编译补丁版本（commit_hash本身）
                short_commit_hash = commit_hash[:12]
                output_name_patches = [f"{cve_id}-patch-{short_commit_hash}-magickcore",f"{cve_id}-patch-{short_commit_hash}-magickwand"]

                if not compile_and_copy_imagemagick(commit_hash, output_name_patches, REFERENCE_DIR,
                                               original_line, functions):
                    log_error(f"编译 CVE {cve_id} 的补丁版本 ({commit_hash}) 失败")
                
                # 2. 编译漏洞版本（补丁提交的父提交）
                try:
                    result = subprocess.run(["git", "rev-parse", f"{commit_hash}~1"], 
                                          cwd=REPO_DIR, capture_output=True, text=True, check=True)
                    prev_commit_full = result.stdout.strip()
                    
                    if not prev_commit_full:
                        log_error(f"无法获取 {commit_hash} 的父提交")
                        continue
                    
                    short_prev_commit_hash = prev_commit_full[:12]
                    output_name_vulns = [f"{cve_id}-vuln-{short_prev_commit_hash}-magickcore", f"{cve_id}-vuln-{short_prev_commit_hash}-magickwand"]

                    log_debug(f"漏洞版本 (父提交): {prev_commit_full}")
                    if not compile_and_copy_imagemagick(prev_commit_full, output_name_vulns, REFERENCE_DIR,
                                                   original_line, functions):
                        log_error(f"编译 CVE {cve_id} 的漏洞版本 ({prev_commit_full}) 失败")
                        
                except subprocess.CalledProcessError:
                    log_error(f"无法获取 {commit_hash} 的父提交。跳过 {cve_id} 的漏洞版本")
                    continue
                
            except Exception as e:
                log_error(f"处理CVE {cve_id} 时发生异常: {str(e)}")
                log_failure(cve_id, commit_hash, "EXCEPTION", str(e), "all")
                continue
    
    # 清理工作区
    
    log_debug("")  # 空行
    log_debug("===== 所有处理完成 =====")
    log_debug(f"CVE 相关二进制文件应位于: {REFERENCE_DIR}")
    log_debug(f"编译日志和中间构建产物位于以 '{BUILD_DIR_PREFIX}-' 为前缀的各个目录中")

if __name__ == "__main__":
    main()
