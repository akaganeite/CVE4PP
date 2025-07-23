#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path
from datetime import datetime
import argparse

# --- 配置 ---
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/ffmpeg"
VERSIONS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/ffmpeg/versions"
REFERENCE_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/ffmpeg"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/ffmpeg"
BUILD_DIR_PREFIX = f"{REPO_DIR}/build"
LOG_DIR = "logs"
LOG_FILE = f"{LOG_DIR}/compile_target.log"

# 日志设置
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def log_failure(tag: str, error_type: str, error_details: str, binary_type: str) -> None:
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] Tag: {tag} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    logger.error(log_message)
    with open(f"{LOG_DIR}/failed_target", "a") as f:
        f.write(log_message + "\n")

def run_cmd(cmd, cwd=None, env=None, shell=False, log_output=True):
    try:
        result = subprocess.run(cmd, cwd=cwd, env=env, shell=shell, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')
        if log_output:
            logger.info(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"命令执行失败: {' '.join(cmd) if isinstance(cmd, list) else cmd}--{e.output}")
        logger.error(e.output)
        return None

def compile_and_copy_ffmpeg(git_checkout_ref, output_binary_name, destination_dir, compiler, opt_level):
    sanitized_ref = git_checkout_ref.replace('/', '_')
    current_build_dir = REPO_DIR
    ffmpeg_executable = os.path.join(current_build_dir, "ffmpeg_g")
    log_file = os.path.join(current_build_dir, "compile.log")

    logger.info(f"\n--- [BEGIN] Processing Git Ref: {git_checkout_ref} ---")
    logger.info(f"Build directory:      {current_build_dir}")
    logger.info(f"ffmpeg executable:    {ffmpeg_executable}")
    logger.info(f"Log file:             {log_file}")
    logger.info(f"Output destination:   {os.path.join(destination_dir, output_binary_name)}")

    # 1. 检查目标二进制是否已存在
    if os.path.isfile(os.path.join(destination_dir, output_binary_name)):
        logger.info(f"--- [SKIP] Target already exists ---\nSkipping compilation for {git_checkout_ref}")
        return True

    # 2. 仓库准备
    if not os.path.isdir(REPO_DIR):
        logger.error(f"错误：无法切换到仓库目录 {REPO_DIR}")
        log_failure(git_checkout_ref, "REPO_ACCESS_ERROR", f"仓库目录不存在 {REPO_DIR}", "ffmpeg")
        return False
    # git stash
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR)

    # 3. git checkout
    if run_cmd(["git", "checkout", git_checkout_ref], cwd=REPO_DIR) is None:
        logger.error(f"错误：无法检出 {git_checkout_ref}.")
        log_failure(git_checkout_ref, "CHECKOUT_ERROR", f"无法检出 {git_checkout_ref}", "ffmpeg")
        return False
    logger.info(f"已成功检出 {git_checkout_ref}.")

    # 4. 编译
    if not os.path.isfile(ffmpeg_executable):
        logger.info(f"{ffmpeg_executable} 不存在，开始编译...")
        os.makedirs(current_build_dir, exist_ok=True)
        env = os.environ.copy()
        env["CC"] = compiler
        env["CFLAGS"] = f"-g3 -{opt_level}"
        with open(log_file, "w") as logf:
            logf.write(f"=== 开始配置 {git_checkout_ref} ===\n")
            proc = subprocess.run([os.path.join(REPO_DIR, "configure"), "--enable-debug=3"], cwd=current_build_dir, env=env, stdout=logf, stderr=logf)
            if proc.returncode != 0:
                logger.error(f"configure 阶段失败，详见 {log_file}")
                log_failure(git_checkout_ref, "CONFIGURE_ERROR", f"configure 阶段失败，详见 {log_file}", "ffmpeg")
                return False
            logf.write(f"\n=== 开始编译 {git_checkout_ref} ===\n")
            proc = subprocess.run(["make", "-j18"], cwd=current_build_dir, env=env, stdout=logf, stderr=logf)
            if proc.returncode != 0:
                logger.error(f"make 阶段失败，详见 {log_file}")
                log_failure(git_checkout_ref, "COMPILE_ERROR", f"make 阶段失败，详见 {log_file}", "ffmpeg")
                return False
        if not os.path.isfile(ffmpeg_executable):
            logger.error(f"错误：编译后 {ffmpeg_executable} 未找到。详情请查看 {log_file}")
            log_failure(git_checkout_ref, "BINARY_NOT_FOUND", f"编译后未找到 {ffmpeg_executable}，详见 {log_file}", "ffmpeg")
            return False
        logger.info(f"{git_checkout_ref} 编译成功。")
    else:
        logger.info(f"{ffmpeg_executable} 已存在于 {current_build_dir}，跳过编译。")

    # 5. 复制二进制
    logger.info(f"复制 {ffmpeg_executable} 到 {os.path.join(destination_dir, output_binary_name)}")
    os.makedirs(destination_dir, exist_ok=True)
    try:
        shutil.copy2(ffmpeg_executable, os.path.join(destination_dir, output_binary_name))
        logger.info("二进制文件复制成功。")
    except Exception as e:
        logger.error(f"错误：复制 {ffmpeg_executable} 失败: {e}")
        log_failure(git_checkout_ref, "COPY_ERROR", f"复制二进制失败: {e}", "ffmpeg")
        return False

    # 6. 清理
    run_cmd(["make", "clean"], cwd=current_build_dir, log_output=False)
    run_cmd(["git", "stash", "--include-untracked"], cwd=REPO_DIR, log_output=False)
    run_cmd(["git", "reset", "--hard", "origin/master"], cwd=REPO_DIR, log_output=False)
    logger.info(f"--- [END] Processing Git Ref: {git_checkout_ref} ---\n")
    return True


def main():
    parser = argparse.ArgumentParser(description="批量编译ffmpeg指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()

    os.makedirs(REFERENCE_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)
    os.makedirs(BUILD_DIR_PREFIX, exist_ok=True)

    logger.info("===== 开始处理 ffmpeg 版本 (Tags) =====")
    if not os.path.isfile(VERSIONS_FILE):
        logger.error(f"错误: {VERSIONS_FILE} 文件未找到。跳过 Tag 处理。")
        return
    with open(VERSIONS_FILE, "r") as f:
        for line in f:
            input_tag = line.strip().replace('\r', '')
            if not input_tag:
                continue
            git_tag_name = f"n{input_tag}"
            output_name_tag = f"ffmpeg-{input_tag}-{args.opt.lower()}-ffmpeg"
            logger.info(f"\n>>> 处理 Tag: {input_tag} (Git Tag: {git_tag_name}) <<<")
            success = compile_and_copy_ffmpeg(git_tag_name, output_name_tag, TARGET_DIR, args.compiler, args.opt)
            if not success:
                logger.error(f"错误：编译 ffmpeg tag {git_tag_name} 失败。继续下一个 Tag。")
    logger.info("===== 所有处理完成 =====")
    logger.info(f"CVE 相关二进制文件应位于: {REFERENCE_DIR}")
    logger.info(f"Tag (版本) 相关二进制文件应位于: {TARGET_DIR}")
    logger.info(f"编译日志和中间构建产物位于以 '{BUILD_DIR_PREFIX}-' 为前缀的各个目录中。")

if __name__ == "__main__":
    main() 