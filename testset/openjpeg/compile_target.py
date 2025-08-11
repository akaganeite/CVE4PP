#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python script to compile different versions (tags) of openjpeg.
Equivalent to the bash script compile_target.sh
"""

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional
import argparse
import glob
import multiprocessing

# Configuration
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/openjpeg"
VERSIONS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/openjpeg/versions"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/openjpeg"
FAILED_LOG_DIR = "logs"

# Setup time string for log file naming
now_str = datetime.now().strftime("%Y%m%d_%H%M")
FAILED_LOG_FILE = f"{FAILED_LOG_DIR}/compile_target_openjpeg_{now_str}.log"

# Setup logging
os.makedirs(FAILED_LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(FAILED_LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def log_failure(tag: str, error_type: str, error_details: str, binary_type: str) -> None:
    """Log failure information to the failed log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] Tag: {tag} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    logger.error(log_message)
    with open("logs/failed_target_openjpeg", "a", encoding="utf-8") as f:
        f.write(log_message + "\n")


def run_command(cmd: List[str], cwd: Optional[str] = None, capture_output: bool = True, redirect_to_devnull: bool = False) -> Tuple[int, str, str]:
    """Run a shell command and return (return_code, stdout, stderr)."""
    try:
        if redirect_to_devnull:
            # 重定向输出到/dev/null
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    cmd,
                    cwd=cwd,
                    stdout=devnull,
                    stderr=devnull,
                    text=True,
                    timeout=600  # 10 minutes timeout
                )
            return result.returncode, "", ""
        else:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=capture_output,
                text=True,
                timeout=600  # 10 minutes timeout
            )
            return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def git_checkout(repo_dir: str, tag: str) -> bool:
    """Checkout a specific tag in the git repository."""
    # Stash any uncommitted changes
    run_command(["git", "stash", "--include-untracked"], cwd=repo_dir, redirect_to_devnull=True)
    
    # Checkout the tag
    return_code, stdout, stderr = run_command(["git", "checkout", "--force", tag], cwd=repo_dir)
    if return_code != 0:
        logger.error(f"Failed to checkout {tag}: {stderr}")
        return False
    return True


def find_openjpeg_binary(build_dir: str) -> Tuple[bool, str]:
    """Find openjpeg binary after compilation."""
    # openjpeg 通常生成共享库文件
    patterns = [
        # 常见的 .so 文件路径
        os.path.join(build_dir, "bin", "*.so*"),
        os.path.join(build_dir, "lib", "*.so*"),
        os.path.join(build_dir, "**", "*.so*"),
    ]
    
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            if os.path.isfile(match) and 'libopenjp2' in os.path.basename(match):
                # 优先选择 .so 文件
                if match.endswith(('.so', '.so.2', '.so.1')) or '.so.' in match:
                    logger.info(f"Found openjpeg shared library: {match}")
                    return True, match
    
    logger.error("openjpeg shared library not found")
    return False, ""


def compile_openjpeg_tag(git_checkout_ref: str, output_binary_name: str, destination_dir: str, compiler: str, opt_level: str) -> bool:
    """Compile openjpeg for a specific git tag with given compiler and optimization level."""
    
    logger.info(f"--- [BEGIN] Processing: {git_checkout_ref} ---")
    logger.info(f"Output binary: {output_binary_name}")
    logger.info(f"Destination: {destination_dir}")
    
    # Check if target already exists
    output_file = os.path.join(destination_dir, output_binary_name)
    if os.path.exists(output_file):
        logger.info(f"--- [SKIP] Target binary {output_binary_name} already exists ---")
        logger.info(f"Skipping compilation for {git_checkout_ref}")
        return True
    
    # Check repository directory
    if not os.path.exists(REPO_DIR):
        logger.error(f"Repository directory does not exist: {REPO_DIR}")
        log_failure(git_checkout_ref, "REPO_ACCESS_ERROR", "Repository directory does not exist", output_binary_name)
        return False
    
    # Checkout the tag
    if not git_checkout(REPO_DIR, git_checkout_ref):
        log_failure(git_checkout_ref, "CHECKOUT_ERROR", "Failed to checkout tag", output_binary_name)
        return False
    
    # 创建唯一的构建目录
    build_dir = os.path.join(REPO_DIR, f"build-{git_checkout_ref.replace('/', '_')}-{compiler}-{opt_level}")
    os.makedirs(build_dir, exist_ok=True)
    
    logger.info(f"Build directory: {build_dir}")
    
    # 配置环境变量
    env = os.environ.copy()
    env["CC"] = compiler
    env["CXX"] = "g++" if compiler == "gcc" else "clang++"
    env["CFLAGS"] = f"-g3 -{opt_level}"
    env["CXXFLAGS"] = f"-g3 -{opt_level}"
    
    compilation_success = False
    
    # Configure openjpeg using cmake
    logger.info("Starting configuration...")
    config_cmd = [
        "cmake",
        "..",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_C_COMPILER={compiler}",
        f"-DCMAKE_CXX_COMPILER={env['CXX']}"
    ]
    
    return_code, stdout, stderr = run_command(config_cmd, cwd=build_dir)
    
    if return_code != 0:
        logger.error(f"Configuration failed: {stderr}")
        log_failure(git_checkout_ref, "CONFIGURE_ERROR", f"Configuration failed: {stderr}", output_binary_name)
        return False
    
    logger.info("Configuration successful")
    
    # Make openjpeg
    logger.info("Starting compilation...")
    nproc = multiprocessing.cpu_count()
    make_cmd = ["make", f"-j{nproc}"]
    return_code, stdout, stderr = run_command(make_cmd, cwd=build_dir)
    
    if return_code != 0:
        logger.error(f"Compilation failed: {stderr}")
        log_failure(git_checkout_ref, "COMPILATION_ERROR", f"Make failed: {stderr}", output_binary_name)
        return False
    
    logger.info("Compilation successful")
    compilation_success = True
    
    # Find binary files
    binary_found, target_binary = find_openjpeg_binary(build_dir)
    
    if not binary_found:
        logger.error("No openjpeg binary found after build")
        log_failure(git_checkout_ref, "BINARY_NOT_FOUND", "No openjpeg binary found after successful build", output_binary_name)
        return False
    
    # Copy binary to destination
    os.makedirs(destination_dir, exist_ok=True)
    try:
        shutil.copy2(target_binary, output_file)
        logger.info(f"Copied to {output_file}")
    except Exception as e:
        logger.error(f"Failed to copy binary: {e}")
        log_failure(git_checkout_ref, "COPY_ERROR", f"Failed to copy binary: {e}", output_binary_name)
        return False
    
    logger.info(f"--- [END] Processed: {git_checkout_ref} ---")
    return True


def version_to_tag(version: str) -> str:
    """Convert version to git tag format."""
    # 2.3.1 -> v2.3.1
    if version.startswith("2.0") or version=="2.1":
        # 特例处理，2.0.x 和 2.1.x 版本需要特殊处理
        return f"version.{version}"
    return f"v{version}"


def main():
    """Main function to process openjpeg versions."""
    parser = argparse.ArgumentParser(description="批量编译openjpeg指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()
    
    # Create necessary directories
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    logger.info("===== Processing openjpeg versions =====")
    
    if not os.path.exists(VERSIONS_FILE):
        logger.warning(f"Versions file {VERSIONS_FILE} not found, skipping version processing")
        return
    
    with open(VERSIONS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            version = line.strip()
            if not version:
                continue
            
            # Remove carriage return if present
            version = version.replace('\r', '')
            
            logger.info(f"Processing version: {version}")
            
            # Convert version to git tag
            git_tag = version_to_tag(version)
            
            opt_lower = args.opt.lower()
            # 编译 openjpeg 共享库
            output_name = f"openjpeg-{version}-{opt_lower}-openjpeg"
            compile_openjpeg_tag(git_tag, output_name, TARGET_DIR, args.compiler, args.opt)
    
    logger.info("===== All tasks completed =====")
    logger.info(f"Version binaries: {TARGET_DIR}")


if __name__ == "__main__":
    main()
