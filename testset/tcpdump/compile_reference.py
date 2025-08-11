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
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/tcpdump"
CONFIG_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/tcpdump/details"
BINARIES_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/tcpdump"
LOG_DIR = "logs"

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

def log_failure(cve_id: str, version: str, error_type: str, error_details: str, binary_type: str) -> None:
    """记录失败信息到失败日志文件"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] CVE: {cve_id} | Version: {version} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    log_error(log_message)
    with open("logs/failed_reference_tcpdump", "a", encoding="utf-8") as f:
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
        
        for func in functions:
            if func not in nm_output:
                return False
        return True
    except subprocess.CalledProcessError:
        return False

def find_valid_binary(build_dir, functions):
    """找到包含所有函数的二进制文件"""
    # tcpdump 通常只有一个主要的二进制文件
    tcpdump_path = os.path.join(build_dir, "tcpdump")
    if os.path.isfile(tcpdump_path):
        if check_functions_in_binary(tcpdump_path, functions):
            log_debug(f"found all functions in tcpdump: {' '.join(functions)}")
            return tcpdump_path
    
    return None

def compile_version(commit_hash, version_type, cve_id, functions):
    """编译指定版本"""
    log_file = os.path.join(REPO_DIR, "compile.log")
    
    log_debug(f"处理 {version_type} 版本 ({commit_hash})")
    
    # 检查目标二进制是否已存在
    target_pattern = os.path.join(BINARIES_DIR, f"{cve_id}-{version_type}-{commit_hash}-*")
    existing_files = glob.glob(target_pattern)
    if existing_files:
        log_debug(f"目标二进制已存在，跳过编译: {existing_files[0]}")
        return True
    
    # 检查构建目录是否存在
    log_debug("开始编译...")
    
    # 配置环境变量
    env = os.environ.copy()
    env["CFLAGS"] = "-g3 -O0"
    env["CXXFLAGS"] = "-g3 -O0"
    
    # 执行配置
    configure_cmd = [
        os.path.join(REPO_DIR, "configure"),
        f"CFLAGS={env['CFLAGS']}",
        f"CXXFLAGS={env['CXXFLAGS']}"
    ]
    
    with open(log_file, "w", encoding="utf-8") as logf:
        logf.write("=== 开始配置 ===\n")
        with open(os.devnull, 'w') as devnull:
            proc = subprocess.run(configure_cmd, cwd=REPO_DIR, env=env, 
                                stdout=devnull, stderr=devnull)
        if proc.returncode != 0:
            log_error(f"configure 阶段失败，详见 {log_file}")
            log_failure(cve_id, commit_hash, "CONFIGURE_ERROR", 
                        f"configure 阶段失败，详见 {log_file}", version_type)
            return False
        
        logf.write("\n=== 开始编译 ===\n")
        nproc = multiprocessing.cpu_count()
        make_cmd = ["make", f"-j{nproc}"]
        with open(os.devnull, 'w') as devnull:
            proc = subprocess.run(make_cmd, cwd=REPO_DIR, env=env, 
                                stdout=devnull, stderr=devnull)
        if proc.returncode != 0:
            log_error(f"make 阶段失败，详见 {log_file}")
            log_failure(cve_id, commit_hash, "COMPILE_ERROR", 
                        f"make 阶段失败，详见 {log_file}", version_type)
            return False
    
    # 检查二进制文件是否存在
    tcpdump_path = os.path.join(REPO_DIR, "tcpdump")
    if not os.path.isfile(tcpdump_path):
        log_error(f"错误：tcpdump 二进制文件 {tcpdump_path} 不存在")
        log_failure(cve_id, commit_hash, "BINARY_NOT_FOUND", 
                   f"tcpdump 二进制文件 {tcpdump_path} 不存在", version_type)
        return False
    
    # 找到包含所有函数的二进制文件
    target_binary = find_valid_binary(REPO_DIR, functions)
    
    if target_binary:
        bin_name = os.path.basename(target_binary)
        log_debug(f"找到有效二进制: {bin_name}")
        target_path = os.path.join(BINARIES_DIR, f"{cve_id}-{version_type}-{commit_hash}-{bin_name}")
        shutil.copy(target_binary, target_path)
        return True
    else:
        log_error("未找到包含所有函数的二进制")
        log_failure(cve_id, commit_hash, "BINARY_NOT_FOUND", 
                   "未找到包含所有函数的二进制", version_type)
        return False

def parse_details_line(line):
    """解析details文件中的行"""
    parts = line.strip().split()
    if len(parts) < 3:
        return None, None, None, None
    
    # 解析CVE_CommitHash格式
    cve_hash = parts[0]
    if '_' not in cve_hash:
        return None, None, None, None
    
    cve_id = cve_hash.split('_')[0]
    commit_hash = cve_hash.split('_')[1]
    
    # 跳过日期，提取函数名
    functions = parts[2].split(',') if len(parts) > 2 else []
    functions = [func.strip() for func in functions if func.strip()]
    
    return cve_id, commit_hash, functions, cve_hash

def main():
    """主函数"""
    log_debug("===== 开始处理 tcpdump CVE 参考二进制编译 =====")
    
    # 创建输出目录
    os.makedirs(BINARIES_DIR, exist_ok=True)
    
    # 检查必要文件和目录
    if not os.path.isdir(REPO_DIR):
        log_error(f"错误：仓库目录不存在 {REPO_DIR}")
        return
    
    if not os.path.isfile(CONFIG_FILE):
        log_error(f"错误：配置文件不存在 {CONFIG_FILE}")
        return
    
    # 用于存储已处理的CVE
    processed_cves = set()
    
    # 处理每个CVE条目
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 解析details行
            cve_id, commit_hash, functions, cve_hash = parse_details_line(line)
            if not all([cve_id, commit_hash, functions]):
                log_error(f"第{line_num}行格式错误: {line}")
                continue
            
            # 如果这个CVE已经处理过，跳过
            if cve_id in processed_cves:
                log_debug(f"跳过已处理的CVE: {cve_id}")
                continue
            
            log_debug(f"处理: {cve_id} ({commit_hash})")
            log_debug(f"相关函数: {', '.join(functions)}")
            
            try:
                # 1. 检出并编译补丁版本（当前commit）
                if not run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG):
                    log_error(f"无法清理工作区")
                    continue
                
                if not run_cmd(["git", "checkout", commit_hash], cwd=REPO_DIR, log_file=DEBUG_LOG):
                    log_error(f"无法检出补丁commit {commit_hash}")
                    log_failure(cve_id, commit_hash, "CHECKOUT_ERROR", 
                               f"无法检出补丁commit {commit_hash}", "patch")
                    continue
                
                # 编译补丁版本
                if not compile_version(commit_hash, "patch", cve_id, functions):
                    log_error(f"补丁版本编译失败: {cve_id}")
                run_cmd(["make", "clean"], cwd=REPO_DIR, log_file=DEBUG_LOG)
                # 2. 检出并编译漏洞版本（上一个commit）
                try:
                    result = subprocess.run(["git", "rev-parse", f"{commit_hash}~1"], 
                                          cwd=REPO_DIR, capture_output=True, text=True, check=True)
                    prev_commit_full = result.stdout.strip()
                    prev_commit = prev_commit_full[:12]  # 截取前12位
                except subprocess.CalledProcessError:
                    log_error(f"无法获取上一个commit: {commit_hash}~1")
                    continue
                
                if not run_cmd(["git", "checkout", prev_commit], cwd=REPO_DIR, log_file=DEBUG_LOG):
                    log_error(f"无法检出漏洞commit {prev_commit}")
                    log_failure(cve_id, prev_commit, "CHECKOUT_ERROR", 
                               f"无法检出漏洞commit {prev_commit}", "vuln")
                    continue
                
                # 编译漏洞版本
                if not compile_version(prev_commit, "vuln", cve_id, functions):
                    log_error(f"漏洞版本编译失败: {cve_id}")
                
                # 标记这个CVE已处理
                processed_cves.add(cve_id)
                
            except Exception as e:
                log_error(f"处理CVE {cve_id} 时发生异常: {str(e)}")
                log_failure(cve_id, commit_hash, "EXCEPTION", str(e), "all")
                continue
    
    # 最后清理工作区
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    
    log_debug("===== 所有操作完成 =====")
    log_debug(f"结果保存在 {BINARIES_DIR}/")

if __name__ == "__main__":
    main()
