#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
import sys
import logging
from typing import Optional, Tuple
from logging.handlers import RotatingFileHandler 
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)
file_handler = RotatingFileHandler('logs/compile_ref.log')
file_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
logger.addHandler(file_handler)
# --- Configuration ---
# NOTE: Modify these paths according to your needs
CONFIG = {
    "REPO_DIR": "/home/zhangxb/patch/related-works/CVE-Dataset/target/sqlite",
    "DETAILS_FILE": "/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/sqlite/diff_files/details",
    "VALID_FILE": "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/sqlite/valid",
    "REFERENCE_DIR": "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/sqlite-new",
    "TARGET_DIR": "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/sqlite",
    "BUILD_DIR_PREFIX": "/home/zhangxb/patch/related-works/CVE-Dataset/target/sqlite/build_sqlite_versions",
}


def run_command(cmd: str, cwd: Optional[str] = None, log_file: Optional[str] = None, 
                check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Run a shell command with proper error handling and logging."""
    logger.debug(f"Running command: {' '.join(cmd)} in {cwd or os.getcwd()}")
    
    stdout = subprocess.PIPE if capture_output else None
    stderr = subprocess.STDOUT if capture_output else None
    
    if log_file:
        with open(log_file, "a") as f:
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                text=True
            )
            stdout_output, stderr_output = process.communicate()
            if stdout_output:
                f.write(stdout_output)
                if stderr_output:
                    f.write(stderr_output)
            return_code = process.returncode
    else:
        process = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            text=True,
            check=False
        )
        return_code = process.returncode
        stdout_output = process.stdout
        stderr_output = process.stderr
    
    if check and return_code != 0:
        error_msg = f"Command failed with exit code {return_code}: {' '.join(cmd)}"
        logger.error(error_msg)
        if capture_output and stdout_output:
            logger.error(f"Output:\n{stdout_output}")
        raise subprocess.CalledProcessError(return_code, cmd, output=stdout_output)
    
    return subprocess.CompletedProcess(cmd, return_code, stdout=stdout_output, stderr=stderr_output)


def git_stash_save(cwd: str, ref_name: str) -> bool:
    """Save changes in git repository and return if stash was created."""
    try:
        # Check if repository is clean
        status = run_command(["git", "status", "--porcelain"], cwd=cwd, capture_output=True, check=False)
        if not status.stdout.strip():
            logger.debug("Repository is clean, no stash needed")
            return False
        
        # Create stash with unique message
        stash_msg = f"autostash_before_compile_{ref_name}"
        run_command(["git", "stash", "push", "-u", "-m", stash_msg], cwd=cwd,capture_output=True)
        logger.info("Current state stashed")
        return True
    except Exception as e:
        logger.warning(f"Stash operation failed: {str(e)}")
        return False


def git_checkout_ref(cwd: str, ref: str) -> bool:
    """Checkout a specific git reference (commit or tag)."""
    logger.info(f"Checking out {ref}")
    try:
        run_command(["git", "checkout", ref], cwd=cwd)
        logger.info(f"Successfully checked out {ref}")
        return True
    except Exception as e:
        logger.error(f"Failed to checkout {ref}: {str(e)}")
        return False


def compile_sqlite(build_dir: str, repo_dir: str) -> bool:
    """Compile SQLite from source in the specified build directory."""
    logger.info("Starting SQLite compilation")
    
    # Run configure
    configure_cmd = [
        os.path.join(repo_dir, "configure"),
        "CFLAGS=-g -O0",
        "CXXFLAGS=-g -O0",
        "--enable-all",
        "--enable-debug"
    ]
    run_command(configure_cmd, cwd=build_dir, log_file=os.path.join(build_dir, "compile.log"),capture_output=True)
    
    # Run make
    num_cores = os.cpu_count() or 4
    make_cmd = ["make", "-j", "18"]
    run_command(make_cmd, cwd=build_dir, log_file=os.path.join(build_dir, "compile.log"),capture_output=True)
    
    # Return success even if executable is not found (let caller check)
    return True


def verify_functions(binary_path: str, functions: str) -> bool:
    """Verify that all required functions exist in the binary."""
    try:
        result = run_command(["nm", binary_path], check=False,capture_output=True)
        nm_output = result.stdout
        
        # Handle multiple functions (comma-separated list)
        funcs = [f.strip() for f in functions.split(",") if f.strip()]
        missing = []
        
        for func in funcs:
            # Look for function name with type 'T' (text section)
            pattern = re.escape(func)
            if not re.search(pattern, nm_output, re.MULTILINE):
                missing.append(func)
        
        if missing:
            logger.error(f"Missing functions: {', '.join(missing)}")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Function verification failed: {str(e)}")
        return False


def compile_and_copy_sqlite(
    git_ref: str,
    output_name: str,
    destination_dir: str,
    details_line: str,
    config: dict
) -> Tuple[bool, str]:
    """Main compilation and deployment function."""
    logger.info(f"--- [BEGIN] Processing Git Ref: {git_ref} ---")
    
    # Sanitize reference for use in directory names
    sanitized_ref = re.sub(r"[^a-zA-Z0-9_-]", "_", git_ref)
    build_dir = f"{config['BUILD_DIR_PREFIX']}-{sanitized_ref}"
    sqlite_executable = os.path.join(build_dir, ".libs", "libsqlite3.so.0.8.6")
    log_file = os.path.join(build_dir, "compile.log")
    
    # Final output path
    output_path = os.path.join(destination_dir, output_name)
    
    logger.info(f"Build directory: {build_dir}")
    logger.info(f"SQLite executable: {sqlite_executable}")
    logger.info(f"Output destination: {output_path}")
    
    # Skip if binary already exists
    # if os.path.exists(output_path):
    #     logger.info(f"Binary {output_path} already exists, skipping")
    #     return False, "Skipped existing binary"
    
    # Prepare repository context
    repo_dir = config["REPO_DIR"]
    os.makedirs(repo_dir, exist_ok=True)
    
    # Save current state if needed
    stashed = git_stash_save(repo_dir, sanitized_ref)
    
    # Attempt git checkout
    if not git_checkout_ref(repo_dir, git_ref):
        logger.error("Failed to checkout, aborting")
        return False, f"Failed to checkout {git_ref}"
    
    # Prepare build directory
    os.makedirs(build_dir, exist_ok=True)
    
    # Check if we need to compile
    if not os.path.exists(sqlite_executable):
        # Try alternate location
        alt_executable = os.path.join(build_dir, "sqlite3")
        
        if not os.path.exists(alt_executable):
            try:
                logger.info("Starting compilation")
                compile_sqlite(build_dir, repo_dir)
            except Exception as e:
                logger.error(f"Compilation failed: {str(e)}")
                return False, f"Compilation failed: {str(e)}"
            
            # Final verification of executable
            if not os.path.exists(sqlite_executable):
                if os.path.exists(alt_executable):
                    logger.info(f"Using alternate executable: {alt_executable}")
                    sqlite_executable = alt_executable
                else:
                    logger.error("Executable not found after compilation")
                    return False, "Executable not found"
    
    # Extract function names from details line
    function_names = details_line.split()[2] if len(details_line.split()) > 2 else ""
    
    # Verify functions in binary
    if function_names:
        logger.info(f"Verifying functions: {function_names}")
        if not verify_functions(sqlite_executable, function_names):
            return False, f"Missing functions: {function_names}"
    
    # Copy to final destination
    os.makedirs(destination_dir, exist_ok=True)
    try:
        shutil.copy(sqlite_executable, output_path)
        logger.info(f"Successfully copied to {output_path}")
    except Exception as e:
        logger.error(f"Copy failed: {str(e)}")
        return False, f"Copy failed: {str(e)}"
    
    logger.info("--- [END] Processing Git Ref: {git_ref} ---")
    return True, "Success"

def parse_valid_file(file_path):
    result = []
    
    # 解析每行数据的正则表达式
    pattern = re.compile(
        r'^(CVE-\d{4}-\d+)\s+'       # CVE ID
        r'(\d{4}-\d{2}-\d{2})\s+'    # 日期
        r'([a-f0-9]{12})\s+'          # 提交哈希（12字符）
        r'(\w+)\s+'                   # 项目名称
        r'([\w,]+)$'                  # 函数列表（逗号分隔）
    )
    
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue  # 跳过空行和注释行
                
            # 使用正则表达式匹配行内容
            match = pattern.match(line)
            if not match:
                print(f"警告: 第 {line_num} 行格式不符合预期: {line}")
                continue
                
            # 提取匹配的组
            cve_id, date, commit_hash, project, functions = match.groups()
            
            # 函数拆分为列表
            func_list = [f.strip() for f in functions.split(',')]
            
            # 添加到结果列表
            result.append({
                'cve_id': cve_id,
                'date': date,
                'commit_hash': commit_hash,
                'project': project,
                'functions': func_list
            })
    
    return result

def process_valid_file(config):
    # 从配置中获取文件路径
    valid_file_path = config["VALID_FILE"]
    
    # 解析文件
    cve_entries = parse_valid_file(valid_file_path)
    
    for entry in cve_entries:
        cve_id = entry['cve_id']
        commit_hash = entry['commit_hash']
        functions = ','.join(entry['functions'])  # 转换为逗号分隔的字符串
        
        # 构造编译所需的数据行
        details_line = f"{cve_id}_{commit_hash} {cve_id} {functions}"
        
        # 后续编译逻辑
        short_commit = commit_hash[:12]
        output_patch = f"{cve_id}-patch-{short_commit}-sqlite3"
        
        success, message = compile_and_copy_sqlite(
                commit_hash,
                output_patch,
                config["REFERENCE_DIR"],
                details_line,
                config
            )
            
        if not success:
            logger.error(f"Failed to compile patch version: {message}")
            continue
        
        # 2. Get parent commit (vulnerable version)
        try:
            result = run_command(
                ["git", "rev-parse", f"{commit_hash}^"],
                cwd=config["REPO_DIR"],
                capture_output=False
            )
            prev_commit = result.stdout
            if not prev_commit:
                raise ValueError("Empty commit hash")
        except Exception as e:
            logger.error(f"Failed to get parent commit: {str(e)}")
            continue
        
        # 3. Compile vulnerable version (parent commit)
        short_prev = prev_commit[:12]
        output_vuln = f"{cve_id}-vuln-{short_prev}-sqlite3"
        success, message = compile_and_copy_sqlite(
            prev_commit,
            output_vuln,
            config["REFERENCE_DIR"],
            details_line,
            config
        )
        
        if not success:
            logger.error(f"Failed to compile vulnerable version: {message}")


def main() -> None:
    """Main entry point for the script."""
    logger.info("===== Starting SQLite Compilation Script =====")
    
    # Create necessary directories
    os.makedirs(CONFIG["REFERENCE_DIR"], exist_ok=True)
    # os.makedirs(CONFIG["TARGET_DIR"], exist_ok=True)
    os.makedirs(CONFIG["BUILD_DIR_PREFIX"], exist_ok=True)
    
    # Process CVE details
    logger.info("===== Processing CVE Entries =====")
    process_valid_file(CONFIG)
    
    # Final message
    logger.info("\n===== All Processing Complete =====")
    logger.info(f"CVE-related binaries at: {CONFIG['REFERENCE_DIR']}")
    logger.info(f"Build artifacts at: {CONFIG['BUILD_DIR_PREFIX']}-*")


if __name__ == "__main__":
    main()