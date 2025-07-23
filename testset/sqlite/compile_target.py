#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import shutil
from pathlib import Path
import sys
from datetime import datetime

# --- 配置 ---
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/sqlite"
VERSIONS_FILE = "versions"
BINARIES_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/sqlite"
BASE_BUILD_DIR = f"{REPO_DIR}/build_sqlite_versions"
LOG_DIR = "logs"

now_str = datetime.now().strftime("%Y%m%d_%H")
DEBUG_LOG = os.path.join(LOG_DIR, f"compile_target_{now_str}.log")
ERROR_LOG = os.path.join(LOG_DIR, "compile_target_error.log")

os.makedirs(LOG_DIR, exist_ok=True)

def log_debug(msg):
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def log_error(msg):
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def log_failure(tag: str, error_type: str, error_details: str) -> None:
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] Tag: {tag} | Type: {error_type} | Details: {error_details}"
    log_error(log_message)
    with open(os.path.join(LOG_DIR, "failed_target"), "a", encoding="utf-8") as f:
        f.write(log_message + "\n")

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
    sanitized_ref = git_tag.replace('/', '_')
    build_dir = f"{BASE_BUILD_DIR}-{sanitized_ref}"
    sqlite_executable = os.path.join(build_dir, ".libs/sqlite3")
    alt_sqlite_executable = os.path.join(build_dir, "sqlite3")
    output_name = f"sqlite-{input_tag}-{opt_level.lower()}-sqlite3"
    output_path = os.path.join(BINARIES_DIR, output_name)
    log_file = os.path.join(build_dir, "compile.log")

    log_debug(f"--- 处理 input tag: {input_tag} (Git tag: {git_tag}) ---")
    # 1. 检出tag
    if not os.path.isdir(REPO_DIR):
        log_error(f"错误：仓库目录不存在 {REPO_DIR}")
        log_failure(git_tag, "REPO_ACCESS_ERROR", f"仓库目录不存在 {REPO_DIR}")
        return
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    if not run_cmd(["git", "checkout", git_tag], cwd=REPO_DIR, log_file=DEBUG_LOG):
        log_error(f"错误：无法检出 {git_tag}")
        log_failure(git_tag, "CHECKOUT_ERROR", f"无法检出 {git_tag}")
        return

    # 2. 编译
    if not os.path.isfile(output_path):
        log_debug("开始编译...")
        os.makedirs(build_dir, exist_ok=True)
        env = os.environ.copy()
        env["CC"] = compiler
        env["CXX"] = compiler + "++" if compiler == "gcc" else "clang++"
        env["CFLAGS"] = f"-g -{opt_level}"
        env["CXXFLAGS"] = f"-g -{opt_level}"

        configure_cmd = [
            os.path.join(REPO_DIR, "configure"),
            f"CFLAGS={env['CFLAGS']}",
            f"CXXFLAGS={env['CXXFLAGS']}",
            "--enable-all",
            "--enable-debug"
        ]
        with open(log_file, "w", encoding="utf-8") as logf:
            logf.write(f"=== 开始配置 {git_tag} ===\n")
            proc = subprocess.run(configure_cmd, cwd=build_dir, env=env, stdout=logf, stderr=logf)
            if proc.returncode != 0:
                log_error(f"configure 阶段失败，详见 {log_file}")
                log_failure(git_tag, "CONFIGURE_ERROR", f"configure 阶段失败，详见 {log_file}")
                return
            logf.write(f"\n=== 开始编译 {git_tag} ===\n")
            proc = subprocess.run(["make", f"-j{os.cpu_count()}"], cwd=build_dir, env=env, stdout=logf, stderr=logf)
            if proc.returncode != 0:
                log_error(f"make 阶段失败，详见 {log_file}")
                log_failure(git_tag, "COMPILE_ERROR", f"make 阶段失败，详见 {log_file}")
                return
        # 检查编译结果
        final_sqlite = None
        if os.path.isfile(sqlite_executable):
            final_sqlite = sqlite_executable
        elif os.path.isfile(alt_sqlite_executable):
            final_sqlite = alt_sqlite_executable
        else:
            log_error(f"错误：编译后未找到 sqlite3 可执行文件。请检查 {log_file}")
            log_failure(git_tag, "BINARY_NOT_FOUND", f"sqlite3 未找到。请检查 {log_file}")
            return
        # 3. 复制二进制文件
        os.makedirs(BINARIES_DIR, exist_ok=True)
        shutil.copy(final_sqlite, output_path)
        log_debug(f"复制 {final_sqlite} 到 {output_path}")
    else:
        log_debug(f"{output_path} 已存在，跳过编译。")
        return
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_file=DEBUG_LOG)
    log_debug(f"--- 完成处理 input tag: {input_tag} ---")

def main():
    parser = argparse.ArgumentParser(description="批量编译SQLite指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()

    os.makedirs(BINARIES_DIR, exist_ok=True)
    if not os.path.isfile(VERSIONS_FILE):
        log_error(f"错误: {VERSIONS_FILE} 在当前目录未找到。")
        return

    log_debug("===== 开始处理 SQLite 版本 (Tags) =====")
    with open(VERSIONS_FILE, "r") as vf:
        for line in vf:
            input_tag = line.strip().replace('\r', '')
            if not input_tag:
                continue
            git_tag = f"version-{input_tag}"
            log_debug(f">>> 处理 Tag: {input_tag} (Git Tag: {git_tag}) <<<")
            compile_tag(input_tag, git_tag, args.compiler, args.opt)
    log_debug("===== 所有处理完成 =====")
    log_debug(f"二进制文件应位于: {BINARIES_DIR}")

if __name__ == "__main__":
    main() 