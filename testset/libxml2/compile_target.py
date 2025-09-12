#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/libxml2"
VERSIONS_FILE = "versions"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target_clang/libxml2"
BUILD_DIR_PREFIX = f"{REPO_DIR}/build"
LOGS_DIR = "logs"

# 获取当前时间字符串
now_str = datetime.now().strftime("%Y%m%d_%H%M")
DEBUG_LOG = os.path.join(LOGS_DIR, f"compile_target_{now_str}.log")
ERROR_LOG = os.path.join(LOGS_DIR, "compile_target_error.log")

os.makedirs(LOGS_DIR, exist_ok=True)

def log_debug(msg):
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def log_error(msg):
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def run_cmd(cmd, cwd=None, env=None, shell=False, log_file=None):
    # log_file = None
    try:
        with open(log_file, "a", encoding="utf-8") if log_file else open(os.devnull, "w") as logf:
            result = subprocess.run(
                cmd, cwd=cwd, env=env, shell=shell,
                stdout=logf, stderr=logf, check=True
            )
        return True
    except subprocess.CalledProcessError as e:
        err_msg = f"命令执行失败: {' '.join(cmd) if isinstance(cmd, list) else cmd}"
        log_error(err_msg)
        if log_file:
            log_error(f"详情见日志: {log_file}")
        return False

def find_libxml2_so(build_dir):
    # 查找 ELF 类型的 libxml2.so 文件
    for root, dirs, files in os.walk(build_dir):
        for file in files:
            if file.startswith("libxml2.so"):
                full_path = os.path.join(root, file)
                try:
                    out = subprocess.check_output(["file", full_path], encoding="utf-8")
                    if "ELF" in out:
                        return full_path
                except Exception:
                    continue
    return None

def compile_and_copy_libxml2(git_checkout_ref, output_binary_name, destination_dir, compiler, opt_level):
    sanitized_ref = git_checkout_ref.replace("/", "_")
    current_build_dir = f"{BUILD_DIR_PREFIX}-{sanitized_ref}"
    log_file = os.path.join(current_build_dir, "compile.log")
    os.makedirs(current_build_dir, exist_ok=True)
    os.makedirs(destination_dir, exist_ok=True)

    # 1. 检查目标二进制是否已存在
    output_path = os.path.join(destination_dir, output_binary_name)
    if os.path.isfile(output_path):
        log_debug(f"二进制文件 {output_path} 已存在，跳过编译。")
        return True

    # 2. 检出代码
    log_debug(f"正在检出 {git_checkout_ref} ...")
    if not run_cmd(["git", "checkout", git_checkout_ref], cwd=REPO_DIR, log_file=DEBUG_LOG):
        log_error(f"错误：无法检出 {git_checkout_ref}")
        return False

    # 3. 配置和编译
    log_debug(f"开始编译 {git_checkout_ref} ...")
    env = os.environ.copy()
    env["CC"] = compiler
    env["CFLAGS"] = f"-g -{opt_level}"

    autogen_path = os.path.join(REPO_DIR, "autogen.sh")
    configure_cmd = [
        autogen_path,
        "--with-debug",
        "--with-modules",
        f"--prefix={current_build_dir}"
    ]
    if not run_cmd(configure_cmd, cwd=current_build_dir, env=env):
        log_error(f"错误：配置失败，详情见 {DEBUG_LOG}")
        return False
    run_cmd(["make", "-j18"], cwd=current_build_dir, env=env)
    
    # if not run_cmd(["make", "-j18"], cwd=current_build_dir, env=env):
    #     log_error(f"错误：make 失败，详情见 {DEBUG_LOG}")
    #     return False
    # run_cmd(["make", "install"], cwd=current_build_dir, env=env)
    # if not run_cmd(["make", "install"], cwd=current_build_dir, env=env, log_file=DEBUG_LOG):
    #     log_error(f"错误：make install 失败，详情见 {DEBUG_LOG}")
    #     return False

    # 4. 查找并复制二进制
    so_path = find_libxml2_so(f"{current_build_dir}/.libs")
    if not so_path:
        log_error(f"错误：未找到 libxml2.so，详情见 {DEBUG_LOG}")
        return False
    shutil.copy(so_path, output_path)
    log_debug(f"已复制 {so_path} 到 {output_path}")
    return True

def main():
    parser = argparse.ArgumentParser(description="批量编译libxml2指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()

    output_dir = TARGET_DIR
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(BUILD_DIR_PREFIX, exist_ok=True)

    if not os.path.isfile(VERSIONS_FILE):
        log_error(f"错误: {VERSIONS_FILE} 文件未找到。")
        return

    log_debug("===== 开始处理 libxml2 版本 (Tags) =====")
    with open(VERSIONS_FILE, "r") as vf:
        for line in vf:
            input_tag = line.strip().replace('\r', '')
            if not input_tag:
                continue
            git_tag_name = f"v{input_tag}"
            output_name_tag = f"libxml2-{input_tag}-{args.opt.lower()}-libxml2"
            log_debug(f">>> 处理 Tag: {input_tag} (Git Tag: {git_tag_name}) <<<")
            ok = compile_and_copy_libxml2(
                git_tag_name, output_name_tag, output_dir, args.compiler, args.opt
            )
            if not ok:
                log_error(f"错误：编译 libxml2 tag {git_tag_name} 失败。继续下一个 Tag。")
    log_debug("===== 所有处理完成 =====")
    log_debug(f"二进制文件应位于: {output_dir}")

if __name__ == "__main__":
    main() 