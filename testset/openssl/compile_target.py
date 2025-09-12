#!/usr/bin/env python3
"""
Python script to compile different versions (tags) of OpenSSL.
Equivalent to the bash script compile_target.sh
"""

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path
from datetime import datetime
# from tkinter import N
from typing import List, Tuple, Optional
import re
import argparse
now_str = datetime.now().strftime("%Y%m%d_%H")
# Configuration
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/openssl"
VERSIONS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/openssl/versions"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/openssl"
FAILED_LOG_DIR = "logs"
FAILED_LOG_FILE = f"{FAILED_LOG_DIR}/compile_target_{now_str}.log"

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
    with open("logs/failed_target", "a") as f:
        f.write(log_message)
        f.write("\n")


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
                    timeout=300  # 5 minutes timeout
                )
            return result.returncode, "", ""
        else:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=capture_output,
                text=True,
                timeout=300  # 5 minutes timeout
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


def find_binary_files(repo_dir: str, output_binary_name: str) -> Tuple[bool, str, str]:
    """Find appropriate binary files after compilation."""
    binary_found = False
    target_binary = ""
    binary_type = ""
    type = output_binary_name.split("-")[-1]
    # Check for openssl executable
    if type == "openssl" and os.path.exists(os.path.join(repo_dir, "apps", "openssl")):
        target_binary = os.path.join(repo_dir, "apps", "openssl")
        binary_found = True
        binary_type = "openssl"
        logger.info(f"Found openssl executable: {target_binary}")
    
    # Check for shared libraries
    else:
        if type == "libcrypto":
            # Find the latest libcrypto.so
            crypto_libs = list(Path(repo_dir).rglob("libcrypto.so.*"))
            if crypto_libs:
                target_binary = str(max(crypto_libs, key=lambda x: x.stat().st_mtime))
                binary_found = True
                binary_type = "libcrypto"
                logger.info(f"Found crypto library: {target_binary}")
        
        elif type == "libssl":
            # Find the latest libssl.so
            ssl_libs = list(Path(repo_dir).rglob("libssl.so.*"))
            if ssl_libs:
                target_binary = str(max(ssl_libs, key=lambda x: x.stat().st_mtime))
                binary_found = True
                binary_type = "libssl"
                logger.info(f"Found ssl library: {target_binary}")
        
        else:
           logger.error("no target binary type found")
           return False,"Fail","Fail"
    
    return binary_found, target_binary, binary_type


def compile_openssl_tag(git_checkout_ref: str, output_binary_name: str, destination_dir: str, compiler: str, opt_level: str) -> bool:
    """Compile OpenSSL for a specific git tag with given compiler and optimization level."""
    
    logger.info(f"--- [BEGIN] Processing: {git_checkout_ref} ---")
    logger.info(f"Output binary: {output_binary_name}")
    logger.info(f"Destination: {destination_dir}")
    
    # Check if target already exists
    output_file = os.path.join(destination_dir, output_binary_name)
    existing_files = list(Path(destination_dir).glob(f"{output_binary_name}"))
    if existing_files:
        logger.info(f"--- [SKIP] Target binary {output_binary_name} already exists ---")
        logger.info(f"Skipping compilation for {git_checkout_ref}")
        return True
    
    # Change to repository directory
    if not os.path.exists(REPO_DIR):
        logger.error(f"Repository directory does not exist: {REPO_DIR}")
        log_failure(git_checkout_ref, "REPO_ACCESS_ERROR", "Repository directory does not exist", output_binary_name)
        return False
    
    # Checkout the tag
    if not git_checkout(REPO_DIR, git_checkout_ref):
        log_failure(git_checkout_ref, "CHECKOUT_ERROR", "Failed to checkout tag", output_binary_name)
        return False
    
    # Create build directory
    
    # Compilation configurations to try
    config_options_list = [
        ["-d"],
        ["-d", "shared"],
        ["-d", "shared", "no-apps"]
    ]
    
    compilation_success = False
    binary_found = False
    target_binary = ""
    binary_type = ""
    
    for config_options in config_options_list:
        logger.info(f"Trying configuration: ./config {' '.join(config_options)}")
        
        # Clean previous build
        run_command(["make", "clean"], cwd=REPO_DIR, redirect_to_devnull=True)
        
        # 配置环境变量
        env = os.environ.copy()
        env["CC"] = compiler
        env["CFLAGS"] = f"-g -{opt_level}"
        # Configure
        config_cmd = ["./config"] + config_options
        return_code, stdout, stderr = run_command(config_cmd, cwd=REPO_DIR)
        
        if return_code == 0:
            logger.info("Configuration successful")
            
            # Make depend
            run_command(["make", "depend"], cwd=REPO_DIR, redirect_to_devnull=True)
            
            # Make
            return_code, stdout, stderr = run_command(["make", "-j", "$(nproc)"], cwd=REPO_DIR)
            
            logger.info("Build ended")
            compilation_success = True
            
            # Find binary files
            binary_found, target_binary, binary_type = find_binary_files(REPO_DIR, output_binary_name)
            if binary_found:
                break
            run_command(["make", "clean"], cwd=REPO_DIR, redirect_to_devnull=True)
        else:
            logger.error(f"Configuration failed")
    
    # Log compilation failure
    if not compilation_success:
        log_failure(git_checkout_ref, "COMPILATION_ERROR", "All configuration/build attempts failed", output_binary_name)
        return False
    
    # Check if binary was found
    if not binary_found:
        logger.error("No suitable binary found after build")
        log_failure(git_checkout_ref, "BINARY_NOT_FOUND", "No suitable binary found after successful build", output_binary_name)
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
    
    # Clean up
    run_command(["make", "clean"], cwd=REPO_DIR, redirect_to_devnull=True)
    logger.info(f"--- [END] Processed: {git_checkout_ref} ---")
    return True


def main():
    """Main function to process OpenSSL tags."""
    parser = argparse.ArgumentParser(description="批量编译OpenSSL指定版本，支持不同编译器和优化级别")
    parser.add_argument("--compiler", choices=["gcc", "clang"], default="gcc", help="选择编译器")
    parser.add_argument("--opt", choices=["O0", "O1", "O2", "O3"], default="O0", help="优化级别")
    args = parser.parse_args()
    # Create necessary directories
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    logger.info("===== Processing Tags =====")
    
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
            # 编译 openssl 可执行文件
            compile_openssl_tag(tag, f"openssl-{tag}-{opt_lower}-openssl", TARGET_DIR, args.compiler, args.opt)
            
            # 编译 libcrypto
            compile_openssl_tag(tag, f"openssl-{tag}-{opt_lower}-libcrypto", TARGET_DIR, args.compiler, args.opt)
            
            # 编译 libssl
            compile_openssl_tag(tag, f"openssl-{tag}-{opt_lower}-libssl", TARGET_DIR, args.compiler, args.opt)
    
    logger.info("===== All tasks completed =====")
    logger.info(f"Version binaries: {TARGET_DIR}")


if __name__ == "__main__":
    main() 