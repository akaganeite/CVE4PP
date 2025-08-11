#!/usr/bin/env python3
"""
Python script to compile different versions (commits and tags) of OpenSSL.
Equivalent to the bash script compile_reference.sh
"""

import os
import sys
import subprocess
import shutil
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional, Dict
import re
now_str = datetime.now().strftime("%Y%m%d_%H%M")
# Configuration
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/openssl"
DETAILS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/openssl/details"
REFERENCE_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/openssl"
BUILD_DIR_PREFIX = f"{REPO_DIR}/../build"
FAILED_LOG_DIR = "logs"
FAILED_LOG_FILE = f"{FAILED_LOG_DIR}/compile_reference_{now_str}.log"
CVE_ISSUES_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/cve_compilation_issues.json"




# Global blacklist for CVEs to skip
CVE_BLACKLIST = set()

def load_cve_blacklist():
    """Load CVE blacklist from JSON file."""
    global CVE_BLACKLIST
    
    if not os.path.exists(CVE_ISSUES_FILE):
        logger.warning(f"CVE issues file {CVE_ISSUES_FILE} not found, no blacklist will be applied")
        return
    
    try:
        with open(CVE_ISSUES_FILE, 'r') as f:
            data = json.load(f)
        
        # Find openssl project data
        openssl_data = None
        for project in data:
            if project.get("project") == "openssl":
                openssl_data = project
                break
        
        if openssl_data:
            # Add failed CVEs to blacklist
            failed_cves = openssl_data.get("failed", [])
            CVE_BLACKLIST.update(failed_cves)
            
            # Add multiple branch CVEs to blacklist
            multiple_branch_cves = openssl_data.get("multiple branch", [])
            CVE_BLACKLIST.update(multiple_branch_cves)
            
            logger.info(f"Loaded {len(CVE_BLACKLIST)} CVEs to blacklist")
            logger.info(f"Blacklisted CVEs: {sorted(list(CVE_BLACKLIST))}")
        else:
            logger.warning("No openssl project data found in CVE issues file")
            
    except Exception as e:
        logger.error(f"Failed to load CVE blacklist: {e}")


def is_cve_blacklisted(cve_id: str) -> bool:
    """Check if a CVE is in the blacklist."""
    return cve_id in CVE_BLACKLIST

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


def log_failure(cve_id: str, commit_hash: str, error_type: str, error_details: str, binary_type: str) -> None:
    """Log failure information to the failed log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] CVE: {cve_id} | Commit: {commit_hash} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    logger.error(log_message)
    with open("logs/failed","a") as f:
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


def git_checkout(repo_dir: str, commit_hash: str) -> bool:
    """Checkout a specific commit in the git repository."""
    # Stash any uncommitted changes
    run_command(["git", "stash", "--include-untracked"], cwd=repo_dir, redirect_to_devnull=True)
    
    # Checkout the commit
    return_code, stdout, stderr = run_command(["git", "checkout", "--force", commit_hash], cwd=repo_dir)
    if return_code != 0:
        logger.error(f"Failed to checkout {commit_hash}: {stderr}")
        return False
    return True


def find_binary_files(repo_dir: str, output_binary_name: str) -> Tuple[bool, str, str]:
    """Find appropriate binary files after compilation."""
    binary_found = False
    target_binary = ""
    binary_type = ""
    type = output_binary_name.split("-")[-1]
    # Check for openssl executable
    if type == "openssl" in output_binary_name and os.path.exists(os.path.join(repo_dir, "apps", "openssl")):
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
        
        elif type == "libssl" :
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


def check_symbols(binary_path: str, func_names: str) -> Tuple[bool, List[str]]:
    """Check if required symbols exist in the binary file."""
    if not func_names:
        return True, []
    
    # Parse function names
    func_list = [func.strip() for func in func_names.split(',')]
    missing_funcs = []
    
    # Check each function
    for func in func_list:
        return_code, stdout, stderr = run_command(["nm", binary_path])
        if return_code != 0:
            logger.error(f"Failed to run nm on {binary_path}: {stderr}")
            return False, func_list
        
        if f" {func}" not in stdout:
            missing_funcs.append(func)
            logger.error(f"Function '{func}' not found in binary")
    
    return len(missing_funcs) == 0, missing_funcs


def compile_openssl(git_checkout_ref: str, output_binary_name: str, destination_dir: str, details_line: str) -> bool:
    """Compile OpenSSL for a specific git reference."""
    sanitized_ref = git_checkout_ref.replace('/', '_')
    current_build_dir = f"{BUILD_DIR_PREFIX}-{sanitized_ref}"
    log_file = os.path.join(current_build_dir, "compile.log")
    
    # Extract CVE ID from details_line
    cve_id = ""
    if details_line:
        parts = details_line.split()
        if parts:
            cve_hash_field = parts[0]
            cve_id = cve_hash_field.split('_')[0] if '_' in cve_hash_field else ""
    
    logger.info(f"--- [BEGIN] Processing: {git_checkout_ref} ---")
    logger.info(f"Build directory: {current_build_dir}")
    logger.info(f"Output binary: {output_binary_name}")
    logger.info(f"Destination: {destination_dir}")
    
    # Check if target already exists
    output_file = os.path.join(destination_dir, output_binary_name)
    prefix_name = re.sub(r'-libcrypto$|-libssl$|-openssl$', '', output_binary_name)
    existing_files = list(Path(destination_dir).glob(f"{prefix_name}*"))
    if existing_files:
        logger.info(f"--- [SKIP] Target prefix already exists ---")
        logger.info(f"Found existing file with prefix: {prefix_name}")
        logger.info(f"Skipping compilation for {git_checkout_ref}")
        return True
    
    # Change to repository directory
    if not os.path.exists(REPO_DIR):
        logger.error(f"Repository directory does not exist: {REPO_DIR}")
        if cve_id:
            log_failure(cve_id, git_checkout_ref, "REPO_ACCESS_ERROR", "Repository directory does not exist", output_binary_name)
        return False
    
    # Checkout the commit
    if not git_checkout(REPO_DIR, git_checkout_ref):
        if cve_id:
            log_failure(cve_id, git_checkout_ref, "CHECKOUT_ERROR", "Failed to checkout commit", output_binary_name)
        return False
    
    # Create build directory
    os.makedirs(current_build_dir, exist_ok=True)
    
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
        
        # Configure
        config_cmd = ["./config"] + config_options
        return_code, stdout, stderr = run_command(config_cmd, cwd=REPO_DIR)
        
        if return_code == 0:
            logger.info("Configuration successful")
            
            # Make depend
            run_command(["make", "depend"], cwd=REPO_DIR, redirect_to_devnull=True)
            
            # Make
            return_code, stdout, stderr = run_command(["make", "-j", "18"], cwd=REPO_DIR)
            
            if return_code == 0:
                logger.info("Build successful")
                compilation_success = True
                
                # Find binary files
                binary_found, target_binary, binary_type = find_binary_files(REPO_DIR, output_binary_name)
                if binary_found:
                    break
            else:
                logger.error(f"Build failed")
                run_command(["make", "clean"], cwd=REPO_DIR, redirect_to_devnull=True)
        else:
            logger.error(f"Configuration failed")
    
    # Log compilation failure
    if not compilation_success:
        if cve_id:
            log_failure(cve_id, git_checkout_ref, "COMPILATION_ERROR", "All configuration/build attempts failed", output_binary_name)
        return False
    
    # Check if binary was found
    if not binary_found:
        logger.error("No suitable binary found after build")
        if cve_id:
            log_failure(cve_id, git_checkout_ref, "BINARY_NOT_FOUND", "No suitable binary found after successful build", output_binary_name)
        return False
    
    # Check symbols if details_line contains function names
    if details_line and len(details_line.split()) > 2:
        func_names = ' '.join(details_line.split()[2:])
        symbols_ok, missing_funcs = check_symbols(target_binary, func_names)
        
        if not symbols_ok:
            missing_func_list = ','.join(missing_funcs)
            logger.error(f"Missing functions in {binary_type}, skipping copy")
            if cve_id:
                log_failure(cve_id, git_checkout_ref, "MISSING_SYMBOLS", f"Missing functions: {missing_func_list}", output_binary_name)
            return False
    
    # Copy binary to destination
    os.makedirs(destination_dir, exist_ok=True)
    try:
        shutil.copy2(target_binary, output_file)
        logger.info(f"Copied to {output_file}")
    except Exception as e:
        logger.error(f"Failed to copy binary: {e}")
        if cve_id:
            log_failure(cve_id, git_checkout_ref, "COPY_ERROR", f"Failed to copy binary: {e}", output_binary_name)
        return False
    
    # Clean up
    run_command(["make", "clean"], cwd=REPO_DIR, redirect_to_devnull=True)
    logger.info(f"--- [END] Processed: {git_checkout_ref} ---")
    return True


def get_parent_commit(repo_dir: str, commit_hash: str) -> Optional[str]:
    """Get the parent commit of the given commit."""
    return_code, stdout, stderr = run_command(["git", "rev-parse", f"{commit_hash}~1"], cwd=repo_dir)
    if return_code == 0:
        return stdout.strip()
    return None


def main():
    """Main function to process CVEs."""
    # Create necessary directories
    os.makedirs(REFERENCE_DIR, exist_ok=True)
    os.makedirs(BUILD_DIR_PREFIX, exist_ok=True)
    
    # Load CVE blacklist
    load_cve_blacklist()
    
    logger.info("===== Processing CVEs =====")
    
    if not os.path.exists(DETAILS_FILE):
        logger.warning(f"Details file {DETAILS_FILE} not found, skipping CVE processing")
        return
    
    with open(DETAILS_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Parse CVE and commit hash
            parts = line.split()
            cve_hash_field = parts[0]
            
            cve_id, commit_hash = cve_hash_field.split('_', 1)
            short_hash = commit_hash[:12]
            
            # Check if CVE is blacklisted
            if is_cve_blacklisted(cve_id):
                logger.info(f"Skipping blacklisted CVE: {cve_id}")
                continue
            
            logger.info(f"Processing CVE: {cve_id}")
            
            # Try to compile executable version first
            if compile_openssl(commit_hash, f"{cve_id}-patch-{short_hash}-openssl", REFERENCE_DIR, line):
                logger.info(f"Successfully compiled executable version for {cve_id}")
            else:
                # If executable compilation failed, try library versions
                logger.info("Executable compilation failed, trying library versions...")
                compile_openssl(commit_hash, f"{cve_id}-patch-{short_hash}-libcrypto", REFERENCE_DIR, line)
                compile_openssl(commit_hash, f"{cve_id}-patch-{short_hash}-libssl", REFERENCE_DIR, line)
            
            # Compile vulnerable version (parent commit)
            prev_commit = get_parent_commit(REPO_DIR, commit_hash)
            if prev_commit:
                short_prev = prev_commit[:12]
                # Try executable version first
                if compile_openssl(prev_commit, f"{cve_id}-vuln-{short_prev}-openssl", REFERENCE_DIR, line):
                    logger.info(f"Successfully compiled executable version for {cve_id} (vulnerable)")
                else:
                    # If executable compilation failed, try library versions
                    logger.info("Executable compilation failed, trying library versions...")
                    compile_openssl(prev_commit, f"{cve_id}-vuln-{short_prev}-libcrypto", REFERENCE_DIR, line)
                    compile_openssl(prev_commit, f"{cve_id}-vuln-{short_prev}-libssl", REFERENCE_DIR, line)
            else:
                logger.warning(f"No parent commit for {commit_hash}")
    
    logger.info("===== All tasks completed =====")
    logger.info(f"CVE binaries: {REFERENCE_DIR}")


if __name__ == "__main__":
    
    main() 