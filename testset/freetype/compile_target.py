#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import shutil
from pathlib import Path
import glob
from datetime import datetime
import multiprocessing

# 配置参数
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/freetype"
CONFIG_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/freetype/versions"
BINARIES_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/freetype"
LOG_DIR = "logs"

# 日志文件名带时间戳
now_str = datetime.now().strftime("%Y%m%d_%H%M")
DEBUG_LOG = os.path.join(LOG_DIR, f"compile_target_{now_str}.log")
ERROR_LOG = os.path.join(LOG_DIR, "compile_target_error.log")

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
    with open("logs/failed_target_freetype", "a", encoding="utf-8") as f:
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

def version_to_tag(version):
    """将版本号转换为tag格式: 2.9.1 -> VER-2-9-1"""
    if not version or version == "N/A":
        return None
    
    # 移除可能的前缀
    version = version.strip()
    
    # 处理已经是VER-格式的情况
    if version.startswith("VER-"):
        return version
    
    # 分割版本号
    parts = version.split('.')
    if len(parts) < 2:
        return None
    
    # 构建tag格式
    tag = "VER-" + "-".join(parts)
    return tag

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

def find_valid_binary(build_dir, functions=[]):
    """找到freetype共享库文件"""
    # freetype 通常生成 libfreetype.so
    patterns = [
        # freetype 的 .so 文件路径
        os.path.join(build_dir, "objs", ".libs", "*.so*"),
        os.path.join(build_dir, "builds", "unix", ".libs", "*.so*"),
        os.path.join(build_dir, ".libs", "*.so*"),
        # 也可能在这些位置
        os.path.join(build_dir, "objs", "libfreetype.so*"),
        os.path.join(build_dir, "builds", "unix", "libfreetype.so*"),
    ]
    
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            if os.path.isfile(match) and ('libfreetype' in os.path.basename(match) or match.endswith('.so')):
                # 优先选择 .so 文件
                if match.endswith(('.so', '.so.6', '.so.1')) or '.so.' in match:
                    log_debug(f"找到 freetype 共享库: {match}")
                    # 如果有functions要求，检查函数是否存在
                    if functions and not check_functions_in_binary(match, functions):
                        continue
                    return match
    
    log_error("未找到 freetype 的共享库文件")
    return None

def compile_version(tag, version, compiler="gcc", opt_level="O0"):
    """编译指定版本"""
    # 创建唯一的构建目录
    build_dir = REPO_DIR
    log_file = os.path.join(build_dir, "compile.log")
    
    log_debug(f"处理版本 (tag: {tag}, version: {version}, compiler: {compiler}, opt: {opt_level})")
    log_debug(f"构建目录: {build_dir}")
    
    # 检查目标二进制是否已存在
    target_pattern = os.path.join(BINARIES_DIR, f"freetype-{version}-{opt_level.lower()}-*")
    existing_files = glob.glob(target_pattern)
    if existing_files:
        log_debug(f"目标二进制已存在，跳过编译: {existing_files[0]}")
        return True
    
    # 创建构建目录
    os.makedirs(build_dir, exist_ok=True)
    log_debug("开始编译...")
    
    # 提前export环境变量
    env = os.environ.copy()
    env["CC"] = compiler
    env["CXX"] = compiler + "++" if compiler == "gcc" else "clang++"
    env["CFLAGS"] = f"-{opt_level} -g3 -pipe"
    env["CXXFLAGS"] = f"-{opt_level} -g3 -pipe"
    
    # 执行配置
    autogen_script = os.path.join(REPO_DIR, "autogen.sh")
    
    # 确保autogen.sh有执行权限
    if os.path.exists(autogen_script):
        os.chmod(autogen_script, 0o755)
    
    autogen_cmd = [autogen_script]
    configure_cmd = [
        "./configure",
        f"CFLAGS={env['CFLAGS']}",
        f"CXXFLAGS={env['CXXFLAGS']}",
        "--enable-freetype-config",
        "--with-harfbuzz=no",
        "--with-png=yes",
        "--with-zlib=yes",
        "--enable-static",
        "--enable-shared",
    ]
    
    with open(log_file, "w", encoding="utf-8") as logf:
        logf.write("=== 开始配置 ===\n")
        
        # 执行autogen.sh
        with open(os.devnull, 'w') as devnull:
            proc = subprocess.run(autogen_cmd, cwd=build_dir, env=env, 
                                stdout=devnull, stderr=devnull)
        if proc.returncode != 0:
            log_error(f"autogen.sh 阶段失败，详见 {log_file}")
            log_failure(version, tag, "AUTOGEN_ERROR", 
                        f"autogen.sh 阶段失败，详见 {log_file}", "target")
            return False
        
        # 执行configure
        with open(os.devnull, 'w') as devnull:
            proc = subprocess.run(configure_cmd, cwd=build_dir, env=env, 
                                stdout=devnull, stderr=devnull)
        if proc.returncode != 0:
            log_error(f"configure 阶段失败，详见 {log_file}")
            log_failure(version, tag, "CONFIGURE_ERROR", 
                        f"configure 阶段失败，详见 {log_file}", "target")
            return False
        
        logf.write("\n=== 开始编译 ===\n")
        nproc = multiprocessing.cpu_count()
        make_cmd = ["make", f"-j{nproc}"]
        with open(os.devnull, 'w') as devnull:
            proc = subprocess.run(make_cmd, cwd=build_dir, env=env, 
                                stdout=devnull, stderr=devnull)
        if proc.returncode != 0:
            log_error(f"make 阶段失败，详见 {log_file}")
            log_failure(version, tag, "COMPILE_ERROR", 
                        f"make 阶段失败，详见 {log_file}", "target")
            return False
    
    # 找到共享库文件
    target_binary = find_valid_binary(build_dir, [])
    
    if target_binary:
        bin_name = os.path.basename(target_binary)
        log_debug(f"找到有效二进制: {bin_name}")
        target_path = os.path.join(BINARIES_DIR, f"freetype-{version}-{opt_level.lower()}-freetype")
        shutil.copy(target_binary, target_path)
        return True
    else:
        log_error("未找到共享库文件")
        log_failure(version, tag, "BINARY_NOT_FOUND", 
                   "未找到共享库文件", "target")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="批量编译freetype指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()
    
    log_debug(f"===== 开始处理 freetype 版本 (编译器: {args.compiler}, 优化级别: {args.opt}) =====")
    
    # 创建输出目录
    os.makedirs(BINARIES_DIR, exist_ok=True)
    
    # 检查必要文件和目录
    if not os.path.isdir(REPO_DIR):
        log_error(f"错误：仓库目录不存在 {REPO_DIR}")
        return
    
    if not os.path.isfile(CONFIG_FILE):
        log_error(f"错误：版本文件不存在 {CONFIG_FILE}")
        return
    
    # 读取版本文件
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            version = line.strip()
            if not version or version.startswith('#'):
                continue
            
            log_debug(f"处理版本: {version}")
            
            # 转换版本号为tag格式
            target_tag = version_to_tag(version)
            if not target_tag:
                log_error(f"无法转换版本号 {version} 为tag格式")
                continue
            
            log_debug(f"目标版本: {version} -> {target_tag}")
            
            # 清理构建环境
            run_cmd(["make", "clean"], cwd=REPO_DIR)
            run_cmd(["rm", "-rf", "builds"], cwd=REPO_DIR)
            run_cmd(["rm", "-rf", "objs"], cwd=REPO_DIR)
            
            try:
                # 检出目标tag
                if not run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG):
                    log_error(f"无法清理工作区")
                    continue
                
                if not run_cmd(["git", "checkout", target_tag], cwd=REPO_DIR, log_file=DEBUG_LOG):
                    log_error(f"无法检出目标tag {target_tag}")
                    log_failure(version, target_tag, "CHECKOUT_ERROR", 
                               f"无法检出目标tag {target_tag}", "target")
                    continue
                
                # 编译目标版本
                if compile_version(target_tag, version, args.compiler, args.opt):
                    log_debug(f"版本编译成功: {version}")
                else:
                    log_error(f"版本编译失败: {version}")
                
            except Exception as e:
                log_error(f"处理版本 {version} 时发生异常: {str(e)}")
                log_failure(version, target_tag, "EXCEPTION", str(e), "target")
                continue
    
    # 最后清理工作区
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    
    log_debug("===== 所有操作完成 =====")
    log_debug(f"结果保存在 {BINARIES_DIR}/")

if __name__ == "__main__":
    main()
