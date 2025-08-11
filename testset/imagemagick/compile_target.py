#!/usr/bin/env python3
"""
Python script to compile different versions (tags) of ImageMagick.
Equivalent to the bash script compile_target.sh for ImageMagick.
"""

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path
from datetime import datetime
import multiprocessing
from typing import List, Tuple, Optional
import argparse
import glob

# 需要额外编译 MagickWand 的版本
MAGIC_WAND = [
    "7.0.10-45",
    "6.9.11-22",
    "7.0.10-46",
    "7.0.10-47",
    "7.0.10-48",
    "7.0.8-67",
    "7.0.8-66",
    "7.0.8-65",
    "7.1.0-0",
    "7.1.0-1",
    "7.1.0-2",
    "7.0.1-1",
    "7.0.1-0",
    "7.0.10-0",
    "7.0.11-0",
    "7.0.11-1",
    "7.0.11-2"
]

now_str = datetime.now().strftime("%Y%m%d_%H")

# Configuration
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/ImageMagick"
VERSIONS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/imagemagick/versions"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/imagemagick"
FAILED_LOG_DIR = "logs"
FAILED_LOG_FILE = f"{FAILED_LOG_DIR}/compile_target_{now_str}.log"
BUILD_DIR_PREFIX = os.path.join(REPO_DIR, "build")

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
    with open("logs/failed_target_imagemagick.log", "a", encoding="utf-8") as f:
        f.write(log_message + "\n")


def run_command(cmd: List[str], cwd: Optional[str] = None, capture_output: bool = True, 
                redirect_to_devnull: bool = False, env: Optional[dict] = None) -> Tuple[int, str, str]:
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
                    env=env,
                    timeout=600  # 10 minutes timeout
                )
            return result.returncode, "", ""
        else:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=capture_output,
                text=True,
                env=env,
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


def find_imagemagick_binary(build_dir: str, binary_type: str) -> Tuple[bool, str]:
    """Find appropriate ImageMagick binary files after compilation."""
    if binary_type == "magickcore":
        patterns = [
            os.path.join(build_dir, "MagickCore", ".libs", "*.so.*.*"),
        ]
    elif binary_type == "magickwand":
        patterns = [
            os.path.join(build_dir, "MagickWand", ".libs", "*.so.*.*"),
        ]
    else:
        logger.error(f"Unknown binary type: {binary_type}")
        return False, ""
    
    for pattern in patterns:
        matches = glob.glob(pattern)
        for match in matches:
            try:
                with open(match, 'rb') as f:
                    # 读取文件前 4 字节检查 ELF 魔数
                    magic = f.read(4)
                    if magic == b'\x7fELF':
                        logger.info(f"Found valid {binary_type} binary: {match}")
                        return True, match
            except Exception as e:
                logger.warning(f"Error checking file {match}: {e}")
                continue
    
    logger.error(f"No valid {binary_type} binary found in {build_dir}")
    return False, ""


def compile_imagemagick_tag(git_checkout_ref: str, output_binary_name: str, destination_dir: str, 
                           compiler: str, opt_level: str, binary_type: str) -> bool:
    """Compile ImageMagick for a specific git tag with given compiler and optimization level."""
    
    logger.info(f"--- [BEGIN] Processing: {git_checkout_ref} for {binary_type} ---")
    logger.info(f"Output binary: {output_binary_name}")
    logger.info(f"Destination: {destination_dir}")
    
    # Check if target already exists
    output_file = os.path.join(destination_dir, output_binary_name)
    if os.path.exists(output_file):
        logger.info(f"--- [SKIP] Target binary {output_binary_name} already exists ---")
        return True
    
    # Check repository directory
    if not os.path.exists(REPO_DIR):
        logger.error(f"Repository directory does not exist: {REPO_DIR}")
        log_failure(git_checkout_ref, "REPO_ACCESS_ERROR", "Repository directory does not exist", binary_type)
        return False
    
    # Checkout the tag
    if not git_checkout(REPO_DIR, git_checkout_ref):
        log_failure(git_checkout_ref, "CHECKOUT_ERROR", "Failed to checkout tag", binary_type)
        return False
    
    # Create build directory
    sanitized_ref = git_checkout_ref.replace('/', '_')
    current_build_dir = f"{BUILD_DIR_PREFIX}-{sanitized_ref}"
    os.makedirs(current_build_dir, exist_ok=True)
    log_file = os.path.join(current_build_dir, f"compile_{binary_type}.log")
    
    # 配置环境变量
    env = os.environ.copy()
    env["CC"] = compiler
    env["CFLAGS"] = f"-g -{opt_level}"
    env["CXXFLAGS"] = f"-g -{opt_level}"
    
    compilation_success = False
    binary_found = False
    target_binary = ""
    
    # 在构建目录中执行编译
    with open(log_file, "w", encoding="utf-8") as logf:
        logf.write(f"=== 开始配置 {git_checkout_ref} for {binary_type} ===\n")
    
    # Configure
    configure_cmd = [
        os.path.join(REPO_DIR, "configure"),
        f"CFLAGS={env['CFLAGS']}",
        f"CXXFLAGS={env['CXXFLAGS']}",
        "--disable-werror",
        "--enable-shared",
        "--disable-install",
    ]
    
    return_code, stdout, stderr = run_command(configure_cmd, cwd=current_build_dir, env=env)
    
    if return_code == 0:
        logger.info("Configuration successful")
        
        # Write configure success to log
        with open(log_file, "a", encoding="utf-8") as logf:
            logf.write(f"\n=== 开始编译 {git_checkout_ref} for {binary_type} ===\n")
        
        # Make
        nproc = multiprocessing.cpu_count()
        make_cmd = ["make", "-j", str(nproc)]
        return_code, stdout, stderr = run_command(make_cmd, cwd=current_build_dir, env=env)
        
        logger.info("Build ended")
        compilation_success = True
        
        # Find binary files
        binary_found, target_binary = find_imagemagick_binary(current_build_dir, binary_type)
        
    else:
        logger.error(f"Configuration failed for {git_checkout_ref}")
        with open(log_file, "a", encoding="utf-8") as logf:
            logf.write(f"Configuration failed: {stderr}\n")
    
    # Log compilation failure
    if not compilation_success:
        log_failure(git_checkout_ref, "COMPILATION_ERROR", f"Configuration/build failed, see {log_file}", binary_type)
        return False
    
    # Check if binary was found
    if not binary_found:
        logger.error(f"No suitable {binary_type} binary found after build")
        log_failure(git_checkout_ref, "BINARY_NOT_FOUND", f"No suitable {binary_type} binary found after successful build", binary_type)
        return False
    
    # Copy binary to destination
    os.makedirs(destination_dir, exist_ok=True)
    try:
        shutil.copy2(target_binary, output_file)
        logger.info(f"Copied {binary_type} to {output_file}")
    except Exception as e:
        logger.error(f"Failed to copy {binary_type} binary: {e}")
        log_failure(git_checkout_ref, "COPY_ERROR", f"Failed to copy binary: {e}", binary_type)
        return False
    
    logger.info(f"--- [END] Processed: {git_checkout_ref} for {binary_type} ---")
    return True


def main():
    """Main function to process ImageMagick tags."""
    parser = argparse.ArgumentParser(description="批量编译ImageMagick指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()
    
    # Create necessary directories
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    logger.info("===== Processing ImageMagick Tags =====")
    
    if not os.path.exists(VERSIONS_FILE):
        logger.warning(f"Versions file {VERSIONS_FILE} not found, skipping tag processing")
        return
    
    with open(VERSIONS_FILE, 'r') as f:
        for line in f:
            tag = line.strip()
            if not tag:
                continue
            
            # Remove carriage return if present
            tag = tag.replace('\r', '')
            
            logger.info(f"Processing tag: {tag}")
            
            opt_lower = args.opt.lower()
            
            # 编译 MagickCore (所有版本都需要)
            compile_imagemagick_tag(tag, f"imagemagick-{tag}-{opt_lower}-magickcore", 
                                  TARGET_DIR, args.compiler, args.opt, "magickcore")
            
            # 编译 MagickWand (仅 MAGIC_WAND 中的版本需要)
            if tag in MAGIC_WAND:
                logger.info(f"Tag {tag} is in MAGIC_WAND list, also compiling MagickWand")
                compile_imagemagick_tag(tag, f"imagemagick-{tag}-{opt_lower}-magickwand", 
                                      TARGET_DIR, args.compiler, args.opt, "magickwand")
            else:
                logger.info(f"Tag {tag} not in MAGIC_WAND list, skipping MagickWand compilation")
    
    logger.info("===== All ImageMagick tasks completed =====")
    logger.info(f"Version binaries: {TARGET_DIR}")


if __name__ == "__main__":
    main()