#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/curl"
VERSIONS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/curl/versions"
REFERENCE_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/curl"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/curl"
BUILD_DIR_PREFIX = f"{REPO_DIR}/build"

now_str = datetime.now().strftime("%Y%m%d_%H%M")
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

def log_debug(msg, log_file):
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def log_error(msg):
    with open("logs/failed_target", "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def run_cmd(cmd, cwd=None, env=None, shell=False, log_file=None):
    try:
        with open(log_file, "a", encoding="utf-8") if log_file else open(os.devnull, "w") as logf:
            result = subprocess.run(
                cmd, cwd=cwd, env=env, shell=shell,
                stdout=logf, stderr=logf, check=True
            )
        return True
    except subprocess.CalledProcessError as e:
        if log_file:
            log_debug(f"命令执行失败: {' '.join(cmd) if isinstance(cmd, list) else cmd}", log_file)
            log_debug(f"详情见日志: {log_file}", log_file)
        return False

def compile_and_copy_curl(git_checkout_ref, output_binary_name, destination_dir, compiler, opt_level):
    run_cmd(["make","clean"],cwd=REPO_DIR)
    run_cmd(["git","stash","--include-untracked"],cwd=REPO_DIR)
    sanitized_ref = git_checkout_ref.replace("/", "_")
    current_build_dir = f"{BUILD_DIR_PREFIX}-{sanitized_ref}"
    curl_executable = os.path.join(current_build_dir, "src/curl")
    log_file = os.path.join(LOGS_DIR, f"compile_target{now_str}.log")
    os.makedirs(current_build_dir, exist_ok=True)
    os.makedirs(destination_dir, exist_ok=True)

    # 1. 检查目标二进制是否已存在
    output_path = os.path.join(destination_dir, output_binary_name)
    if os.path.isfile(output_path):
        log_debug(f"二进制文件 {output_path} 已存在，跳过编译。", log_file)
        return True


    # 2. 检出代码
    log_debug(f"正在检出 {git_checkout_ref} ...", log_file)
    if not run_cmd(["git", "checkout", git_checkout_ref], cwd=REPO_DIR):
        log_debug(f"错误：无法检出 {git_checkout_ref}", log_file)
        log_error(f"{output_binary_name}--错误：无法检出 {git_checkout_ref}")
        return False

    # 3. autoreconf
    log_debug(f"运行 autoreconf ...", log_file)
    if not run_cmd(["autoreconf", "-fi"], cwd=REPO_DIR):
        log_debug(f"错误：autoreconf 失败", log_file)
        log_error(f"{output_binary_name}--错误：autoreconf 失败")
        return False

    # 4. 配置和编译
    log_debug(f"开始编译 {git_checkout_ref} ...", log_file)
    env = os.environ.copy()
    env["CC"] = compiler
    env["CXX"] = compiler.replace("gcc", "g++").replace("clang", "clang++")
    env["CFLAGS"] = f"-g -{opt_level}"
    env["CXXFLAGS"] = f"-g -{opt_level}"

    configure_cmd = [
        os.path.join(REPO_DIR, "configure"),
        f"CFLAGS=-g -{opt_level}",
        f"CXXFLAGS=-g -{opt_level}",
        "--disable-werror",
        "--disable-shared",
        "--enable-debug",
        "--with-openssl"
    ]
    if not run_cmd(configure_cmd, cwd=current_build_dir, env=env):
        log_debug(f"错误：configure 失败，详情见 {log_file}", log_file)
        log_error(f"{output_binary_name}--错误：configure 失败")
        return False

    if not run_cmd(["make", f"-j{os.cpu_count()}"], cwd=current_build_dir, env=env):
        log_debug(f"错误：make 失败，详情见 {log_file}", log_file)
        log_error(f"{output_binary_name}--make 失败")
        return False

    # 5. 查找并复制二进制
    if not os.path.isfile(curl_executable):
        log_debug(f"错误：未找到 curl 可执行文件，详情见 {log_file}", log_file)
        log_error(f"{output_binary_name}--错误：未找到 curl 可执行文件")
        return False
    shutil.copy(curl_executable, output_path)
    log_debug(f"已复制 {curl_executable} 到 {output_path}", log_file)
    return True

def main():
    parser = argparse.ArgumentParser(description="批量编译curl指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()

    os.makedirs(REFERENCE_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)
    os.makedirs(BUILD_DIR_PREFIX, exist_ok=True)

    if not os.path.isfile(VERSIONS_FILE):
        print(f"错误: {VERSIONS_FILE} 文件未找到。")
        return

    print("===== 开始处理 curl 版本 (Tags) =====")
    with open(VERSIONS_FILE, "r") as vf:
        for line in vf:
            input_tag = line.strip().replace('\r', '')
            if not input_tag:
                continue
            # 版本号如 7.87.0 -> tag curl-7_87_0
            tag_name = f"curl-{input_tag.replace('.', '_')}"
            output_name_tag = f"curl-{input_tag}-{args.opt.lower()}-curl"
            print(f">>> 处理 Tag: {input_tag} (Git Tag: {tag_name}) <<<")
            ok = compile_and_copy_curl(
                tag_name, output_name_tag, TARGET_DIR, args.compiler, args.opt
            )
            if not ok:
                print(f"错误：编译 curl tag {tag_name} 失败。继续下一个 Tag。")
    print("===== 所有处理完成 =====")
    print(f"Version binaries: {TARGET_DIR}")

if __name__ == "__main__":
    main() 