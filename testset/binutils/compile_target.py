#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import shutil
from pathlib import Path
import sys
from datetime import datetime

REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb"
VERSIONS_FILE = "versions"
BINARIES_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/binutils"
BASE_BUILD_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/build"
LOG_DIR = "logs"

# 日志文件名带时间戳
now_str = datetime.now().strftime("%Y%m%d_%H%M")
DEBUG_LOG = os.path.join(LOG_DIR, f"compile_target_{now_str}.log")
ERROR_LOG = os.path.join(LOG_DIR, "compile_target_error.log")

os.makedirs(LOG_DIR, exist_ok=True)

def log_debug(msg):
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def log_error(msg):
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

readelf_versions = {
    "2.28","2.29","2.29.1", "2.30", "2.31", "2.31.1", "2.28", "2.28.1", "2.29", "2.35", "2.35.2", "2.35.1", "2.36.1", "2.37"
}
nm_versions = {
    "2.31", "2.32", "2.31.1", "2.33.1", "2.34", "2.35", "2.35.1", "2.34"
}

def log_failure(tag: str, error_type: str, error_details: str, binary_type: str) -> None:
    """Log failure information to the failed log file and error log."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] Tag: {tag} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    log_error(log_message)
    with open("logs/failed_target", "a", encoding="utf-8") as f:
        f.write(log_message)
        f.write("\n")

def run_cmd(cmd, cwd=None, env=None, shell=False, log_file=None):
    try:
        with open(log_file, "a", encoding="utf-8") if log_file else open(os.devnull, "w") as logf:
            result = subprocess.run(cmd, cwd=cwd, env=env, shell=shell, check=True, stdout=logf, stderr=logf, encoding="utf-8")
        log_debug(f"命令成功: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        return True
    except subprocess.CalledProcessError as e:
        err_msg = f"命令执行失败: {' '.join(cmd) if isinstance(cmd, list) else cmd}"
        log_error(err_msg)
        if log_file:
            log_error(f"详情见日志: {log_file}")
        return False

def compile_tag(input_tag, git_tag, compiler, opt_level):
    # if compiler == "clang":
    #     BINARIES_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target_clang/binutils"
    build_dir = f"{BASE_BUILD_DIR}-{git_tag}-{compiler}-{opt_level}"
    objdump_path = os.path.join(build_dir, "binutils/objdump")
    objdump_target = os.path.join(BINARIES_DIR, f"binutils-{input_tag}-{opt_level.lower()}-objdump")
    readelf_path = os.path.join(build_dir, "binutils/readelf")
    readelf_target = os.path.join(BINARIES_DIR, f"binutils-{input_tag}-{opt_level.lower()}-readelf")
    nm_target = os.path.join(BINARIES_DIR, f"binutils-{input_tag}-{opt_level.lower()}-nm")
    nm_path = os.path.join(build_dir, "binutils/nm-new")
    log_file = os.path.join(build_dir, "compile.log")
    need_readelf = input_tag in readelf_versions
    need_nm = input_tag in nm_versions

    log_debug(f"--- 处理 input tag: {input_tag} (Git tag: {git_tag}) ---")

    # 1. 检出tag
    if not os.path.isdir(REPO_DIR):
        log_error(f"错误：仓库目录不存在 {REPO_DIR}")
        log_failure(git_tag, "REPO_ACCESS_ERROR", f"仓库目录不存在 {REPO_DIR}", "all")
        return
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    if not run_cmd(["git", "checkout", git_tag], cwd=REPO_DIR, log_file=DEBUG_LOG):
        log_error(f"错误：无法检出 {git_tag}")
        log_failure(git_tag, "CHECKOUT_ERROR", f"无法检出 {git_tag}", "all")
        return

    # 2. 编译
    if not (os.path.isfile(objdump_target) and
            (not need_readelf or os.path.isfile(readelf_target)) and
            (not need_nm or os.path.isfile(nm_target))):
        log_debug("开始编译...")
        os.makedirs(build_dir, exist_ok=True)
        env = os.environ.copy()
        env["CC"] = compiler
        env["CXX"] = compiler + "++" if compiler == "gcc" else "clang++"
        env["CFLAGS"] = f"-{opt_level} -pipe"
        env["CXXFLAGS"] = f"-{opt_level} -pipe"

        configure_cmd = [
            os.path.join(REPO_DIR, "configure"),
            f"CFLAGS={env['CFLAGS']}",
            f"CXXFLAGS={env['CXXFLAGS']}",
            "--disable-werror"
        ]
        with open(log_file, "w", encoding="utf-8") as logf:
            logf.write("=== 开始配置 ===\n")
            proc = subprocess.run(configure_cmd, cwd=build_dir, env=env, stdout=logf, stderr=logf)
            if proc.returncode != 0:
                log_error(f"configure 阶段失败，详见 {log_file}")
                log_failure(git_tag, "CONFIGURE_ERROR", f"configure 阶段失败，详见 {log_file}", "all")
                return
            logf.write("\n=== 开始编译 ===\n")
            proc = subprocess.run(["make", "-j18", "all-binutils", "all-ld", "all-gas"], cwd=build_dir, env=env, stdout=logf, stderr=logf)
            if proc.returncode != 0:
                log_error(f"make 阶段失败，详见 {log_file}")
                log_failure(git_tag, "COMPILE_ERROR", f"make 阶段失败，详见 {log_file}", "all")
                return

        # 检查编译结果
        if not os.path.isfile(objdump_path):
            log_error(f"错误：编译失败或 {git_tag} 的 objdump 未找到。请检查 {log_file}")
            log_failure(git_tag, "BINARY_NOT_FOUND", f"objdump 未找到。请检查 {log_file}", "objdump")
            return
        if need_readelf and not os.path.isfile(readelf_path):
            log_error(f"错误：编译失败或 {git_tag} 的 readelf 未找到。请检查 {log_file}")
            log_failure(git_tag, "BINARY_NOT_FOUND", f"readelf 未找到。请检查 {log_file}", "readelf")
            return
        if need_nm and not os.path.isfile(nm_path):
            log_error(f"错误：编译失败或 {git_tag} 的 nm 未找到。请检查 {log_file}")
            log_failure(git_tag, "BINARY_NOT_FOUND", f"nm 未找到。请检查 {log_file}", "nm")
            return
        log_debug(f"{git_tag} 编译成功。")
    else:
        log_debug("所有需要的二进制文件已存在，跳过编译。")
        return

    # 3. 复制二进制文件
    log_debug(f"复制 objdump 到 {objdump_target}")
    shutil.copy(objdump_path, objdump_target)
    if need_readelf:
        log_debug(f"复制 readelf 到 {readelf_target}")
        shutil.copy(readelf_path, readelf_target)
    if need_nm:
        log_debug(f"复制 nm 到 {nm_target}")
        shutil.copy(nm_path, nm_target)

    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    log_debug(f"--- 完成处理 input tag: {input_tag} ---")

def main():
    parser = argparse.ArgumentParser(description="批量编译binutils指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()

    os.makedirs(BINARIES_DIR, exist_ok=True)
    if not os.path.isfile(VERSIONS_FILE):
        log_error(f"错误: {VERSIONS_FILE} 在当前目录未找到。")
        return

    log_debug("===== 开始处理 binutils 版本 (Tags) =====")
    with open(VERSIONS_FILE, "r") as vf:
        for line in vf:
            input_tag = line.strip().replace('\r', '')
            if not input_tag:
                continue
            git_tag = f"binutils-{input_tag.replace('.', '_')}"
            log_debug(f">>> 处理 Tag: {input_tag} (Git Tag: {git_tag}) <<<")
            compile_tag(input_tag, git_tag, args.compiler, args.opt)
    log_debug("===== 所有处理完成 =====")
    log_debug(f"二进制文件应位于: {BINARIES_DIR}")

if __name__ == "__main__":
    main()