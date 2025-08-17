#!/usr/bin/env python3
"""
Script to compile different versions (commits and tags) of ffmpeg.
Supports configurable compiler and optimization levels via command line.
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
from datetime import datetime
import multiprocessing

# --- Configuration ---
# Global configuration variables (previously command line arguments)
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/ffmpeg"
DETAILS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/ffmpeg/diff_files/details2"
REFERENCE_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/ffmpeg"
TARGET_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/ffmpeg"
LOG_DIR = "logs"

# 日志文件名带时间戳
now_str = datetime.now().strftime("%Y%m%d_%H%M")
DEBUG_LOG = os.path.join(LOG_DIR, f"compile_reference_{now_str}.log")
ERROR_LOG = os.path.join(LOG_DIR, "compile_reference_error.log")

# 确保日志目录存在
os.makedirs(LOG_DIR, exist_ok=True)

def log_debug(msg):
    """记录调试信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {msg}"
    print(log_msg)
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def log_error(msg):
    """记录错误信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] ERROR: {msg}"
    print(log_msg)
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def log_failure(cve_id: str, commit_hash: str, error_type: str, error_details: str, binary_type: str) -> None:
    """记录失败信息到失败日志文件"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] CVE: {cve_id} | Commit: {commit_hash} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
    log_error(log_message)
    with open("logs/failed_reference", "a", encoding="utf-8") as f:
        f.write(log_message + "\n")

class FFmpegCompiler:
    def __init__(self, compiler="gcc", optimization="-O0"):
        self.repo_dir = Path(REPO_DIR)
        self.details_file = Path(DETAILS_FILE)
        self.reference_dir = Path(REFERENCE_DIR)
        self.target_dir = Path(TARGET_DIR)
        self.build_dir_prefix = self.repo_dir / "build"
        self.compiler = compiler
        self.optimization = optimization
        
        # 创建必要的目录
        self.reference_dir.mkdir(parents=True, exist_ok=True)
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir_prefix.parent.mkdir(parents=True, exist_ok=True)

    def run_command(self, cmd, cwd=None, capture_output=True):
        """执行命令并返回结果"""
        try:
            result = subprocess.run(
                cmd, shell=True, cwd=cwd, 
                capture_output=capture_output, text=True
            )
            if result.returncode == 0:
                log_debug(f"命令成功: {cmd}")
            else:
                log_error(f"命令失败 (退出码 {result.returncode}): {cmd}")
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            log_error(f"命令执行异常: {cmd} - {str(e)}")
            return 1, "", str(e)

    def is_repo_clean(self):
        """检查仓库是否干净"""
        os.chdir(self.repo_dir)
        
        # 检查工作区是否有修改
        ret1, _, _ = self.run_command("git diff --quiet --exit-code")
        ret2, _, _ = self.run_command("git diff --cached --quiet --exit-code")
        ret3, stdout3, _ = self.run_command("git ls-files --others --exclude-standard")
        
        is_clean = ret1 == 0 and ret2 == 0 and not stdout3.strip()
        log_debug(f"仓库清洁状态检查: {'干净' if is_clean else '有未提交更改'}")
        return is_clean

    def stash_changes(self):
        """存储当前更改"""
        os.chdir(self.repo_dir)
        if not self.is_repo_clean():
            timestamp = subprocess.check_output("date +%s", shell=True, text=True).strip()
            stash_msg = f"autostash_before_compile_{timestamp}"
            ret, _, _ = self.run_command(f"git stash push -u -m '{stash_msg}'")
            if ret == 0:
                log_debug("当前工作区状态已存储")
            return ret == 0
        log_debug("仓库已处于干净状态，无需 stash")
        return False

    def checkout_ref(self, git_ref):
        """检出指定的 git 引用"""
        os.chdir(self.repo_dir)
        log_debug(f"正在检出 {git_ref}...")
        ret, stdout, stderr = self.run_command(f"git checkout {git_ref}")
        if ret == 0:
            log_debug(f"已成功检出 {git_ref}")
            return True
        else:
            log_error(f"无法检出 {git_ref}: {stderr}")
            return False

    def configure_and_compile(self, build_dir, log_file, cve_id, commit_hash, binary_type):
        """配置和编译 ffmpeg"""
        build_dir.mkdir(parents=True, exist_ok=True)
        
        log_debug(f"开始配置和编译 {binary_type} 版本")
        
        with open(log_file, 'w') as log:
            # 配置阶段
            print(f"=== 开始配置 (日志于 {log_file}) ===", file=log)
            configure_cmd = f"{self.repo_dir}/configure --enable-debug=3"
            
            # 设置编译器环境变量
            env = os.environ.copy()
            env['CC'] = self.compiler
            env['CFLAGS'] = f"{env.get('CFLAGS', '')} {self.optimization}".strip()
            
            log_debug(f"配置命令: {configure_cmd}")
            log_debug(f"编译器: {self.compiler}, 优化级别: {self.optimization}")
            
            ret = subprocess.run(
                configure_cmd, shell=True, cwd=build_dir,
                stdout=log, stderr=subprocess.STDOUT, env=env
            )
            
            if ret.returncode != 0:
                error_msg = f"配置失败，退出码: {ret.returncode}"
                log_error(error_msg)
                log_failure(cve_id, commit_hash, "CONFIGURE_ERROR", 
                           f"配置失败，详见 {log_file}", binary_type)
                return False
            
            # 编译阶段
            print(f"\n=== 开始编译 (使用 {self.compiler}, {self.optimization}) ===", file=log)
            nproc = multiprocessing.cpu_count()
            make_cmd = f"make -j{nproc}"
            
            log_debug(f"编译命令: {make_cmd} (使用 {nproc} 个并行任务)")
            
            ret = subprocess.run(
                make_cmd, shell=True, cwd=build_dir,
                stdout=log, stderr=subprocess.STDOUT, env=env
            )
            
            if ret.returncode != 0:
                error_msg = f"编译失败，退出码: {ret.returncode}"
                log_error(error_msg)
                log_failure(cve_id, commit_hash, "COMPILE_ERROR", 
                           f"编译失败，详见 {log_file}", binary_type)
                return False
                
            print("编译完成", file=log)
            log_debug(f"{binary_type} 版本编译完成")
            return True

    def check_functions_in_binary(self, binary_path, func_names, cve_id, commit_hash, binary_type):
        """检查二进制文件中是否包含指定函数"""
        if not func_names.strip():
            log_debug("无需检查函数，跳过函数验证")
            return True
            
        func_list = [f.strip() for f in func_names.split(',') if f.strip()]
        missing_funcs = []
        
        log_debug(f"检查二进制文件中的函数: {', '.join(func_list)}")
        
        for func in func_list:
            ret, stdout, _ = self.run_command(f"nm {binary_path} | grep ' {func}$'")
            if ret != 0:
                missing_funcs.append(func)
                log_error(f"函数 '{func}' 在 {binary_path} 中未找到")
        
        if missing_funcs:
            log_failure(cve_id, commit_hash, "FUNCTION_CHECK_FAILED", 
                       f"缺少函数: {', '.join(missing_funcs)}", binary_type)
            return False
        
        log_debug(f"所有函数检查通过: {', '.join(func_list)}")
        return True

    def cleanup_repo(self):
        """清理仓库状态"""
        log_debug("开始清理仓库状态...")
        os.chdir(self.repo_dir)
        self.run_command("make clean", capture_output=False)
        self.run_command("git stash --include-untracked", capture_output=False)
        self.run_command("git reset --hard origin/master", capture_output=False)
        log_debug("仓库状态清理完成")

    def compile_and_copy_ffmpeg(self, git_checkout_ref, output_binary_name, destination_dir, details_line, cve_id, binary_type):
        """编译指定 git 引用的 ffmpeg 并复制到目标目录"""
        sanitized_ref = git_checkout_ref.replace('/', '_')
        current_build_dir = Path(f"{self.build_dir_prefix}-{sanitized_ref}")
        ffmpeg_executable = current_build_dir / "ffmpeg_g"
        log_file = current_build_dir / "compile.log"
        
        log_debug(f"--- [开始] 处理 Git Ref: {git_checkout_ref} ({binary_type}) ---")
        log_debug(f"编译目录: {current_build_dir}")
        log_debug(f"ffmpeg 可执行文件: {ffmpeg_executable}")
        log_debug(f"日志文件: {log_file}")
        log_debug(f"输出目标: {destination_dir}/{output_binary_name}")
        log_debug(f"编译器: {self.compiler}, 优化级别: {self.optimization}")
        
        # 检查二进制文件是否已存在
        final_binary_path = destination_dir / output_binary_name
        if final_binary_path.exists():
            log_debug(f"二进制文件 {final_binary_path} 已存在，跳过编译")
            return True
        
        # 存储当前状态
        stash_made = self.stash_changes()
        
        try:
            # 检出指定引用
            if not self.checkout_ref(git_checkout_ref):
                log_failure(cve_id, git_checkout_ref, "CHECKOUT_ERROR", 
                           f"无法检出 {git_checkout_ref}", binary_type)
                return False
            
            # 编译 (如果可执行文件不存在)
            if not ffmpeg_executable.exists():
                log_debug(f"{ffmpeg_executable} 不存在，开始编译...")
                
                if not self.configure_and_compile(current_build_dir, log_file, cve_id, git_checkout_ref, binary_type):
                    log_error(f"编译失败。详情请查看 {log_file}")
                    return False
                
                if not ffmpeg_executable.exists():
                    error_msg = f"编译后 {ffmpeg_executable} 未找到"
                    log_error(error_msg)
                    log_failure(cve_id, git_checkout_ref, "BINARY_NOT_FOUND", 
                               f"{error_msg}，详见 {log_file}", binary_type)
                    return False
                    
                log_debug(f"{git_checkout_ref} ({binary_type}) 编译成功")
            else:
                log_debug(f"{ffmpeg_executable} 已存在，跳过编译")
            
            # 检查函数
            func_names = details_line.split(' ', 2)[2] if len(details_line.split(' ')) > 2 else ""
            if not self.check_functions_in_binary(ffmpeg_executable, func_names, cve_id, git_checkout_ref, binary_type):
                return False
            
            # 复制二进制文件
            log_debug(f"复制 {ffmpeg_executable} 到 {final_binary_path}")
            destination_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ffmpeg_executable, final_binary_path)
            log_debug("二进制文件复制成功")
            
            log_debug(f"--- [结束] 处理 Git Ref: {git_checkout_ref} ({binary_type}) ---")
            return True
            
        except Exception as e:
            error_msg = f"处理 {git_checkout_ref} 时发生错误: {e}"
            log_error(error_msg)
            log_failure(cve_id, git_checkout_ref, "EXCEPTION", str(e), binary_type)
            return False
        finally:
            # 清理仓库状态
            self.cleanup_repo()

    def get_parent_commit(self, commit_hash):
        """获取指定提交的父提交"""
        os.chdir(self.repo_dir)
        ret, stdout, stderr = self.run_command(f"git rev-parse {commit_hash}~1")
        if ret == 0 and stdout.strip():
            parent_commit = stdout.strip()
            log_debug(f"获取父提交: {commit_hash} -> {parent_commit}")
            return parent_commit
        log_error(f"无法获取 {commit_hash} 的父提交: {stderr}")
        return None

    def process_cve_entries(self):
        """处理 CVE 条目"""
        log_debug("===== 开始处理 CVE 条目 =====")
        
        if not self.details_file.exists():
            log_error(f"{self.details_file} 文件未找到。跳过 CVE 处理")
            return
        
        # 用于存储已处理的CVE
        processed_cves = set()
        
        with open(self.details_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split(' ', 2)
                if len(parts) < 2:
                    log_error(f"第{line_num}行格式错误: '{line}'")
                    continue
                
                cve_hash_field = parts[0]
                if '_' not in cve_hash_field:
                    log_error(f"第{line_num}行格式错误: '{line}'")
                    continue
                
                cve_id, commit_hash = cve_hash_field.split('_', 1)
                
                if not cve_id or not commit_hash or cve_id == commit_hash:
                    log_error(f"第{line_num}行格式错误: '{line}'")
                    continue
                
                # 如果这个CVE已经处理过，跳过
                if cve_id in processed_cves:
                    log_debug(f"跳过已处理的CVE: {cve_id}")
                    continue
                
                log_debug(f"\n>>> 处理 CVE: {cve_id}, 补丁 Commit: {commit_hash} <<<")
                
                # 编译补丁版本
                short_commit_hash = commit_hash[:12]
                output_name_patch = f"{cve_id}-patch-{short_commit_hash}-ffmpeg"
                
                patch_success = self.compile_and_copy_ffmpeg(
                    commit_hash, output_name_patch, self.reference_dir, line, cve_id, "patch"
                )
                
                if not patch_success:
                    log_error(f"编译 CVE {cve_id} 的补丁版本 ({commit_hash}) 失败。继续下一个条目")
                    continue
                
                # 编译漏洞版本 (父提交)
                prev_commit_full = self.get_parent_commit(commit_hash)
                if not prev_commit_full:
                    log_error(f"无法获取 {commit_hash} 的父提交。跳过 {cve_id} 的漏洞版本")
                    log_failure(cve_id, commit_hash, "PARENT_COMMIT_ERROR", 
                               f"无法获取父提交", "vuln")
                    continue
                
                short_prev_commit_hash = prev_commit_full[:12]
                output_name_vuln = f"{cve_id}-vuln-{short_prev_commit_hash}-ffmpeg"
                
                log_debug(f"漏洞版本 (父提交): {prev_commit_full}")
                vuln_success = self.compile_and_copy_ffmpeg(
                    prev_commit_full, output_name_vuln, self.reference_dir, line, cve_id, "vuln"
                )
                
                if not vuln_success:
                    log_error(f"编译 CVE {cve_id} 的漏洞版本 ({prev_commit_full}) 失败。继续下一个条目")
                
                # 标记这个CVE已处理
                processed_cves.add(cve_id)

def main():
    parser = argparse.ArgumentParser(
        description="编译不同版本的 ffmpeg，支持指定编译器和优化级别",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  %(prog)s                                    # 使用默认设置 (gcc, -O0)
  %(prog)s --compiler clang --optimization -O3   # 使用 clang 和 -O3 优化
  %(prog)s --compiler gcc --optimization -O0     # 使用 gcc 和无优化
        """
    )
    
    parser.add_argument(
        "--compiler", 
        default="gcc",
        choices=["gcc", "clang"],
        help="指定编译器 (默认: gcc)"
    )
    
    parser.add_argument(
        "--optimization", 
        default="-O0",
        choices=["-O0", "-O1", "-O2", "-O3"],
        help="指定优化级别 (默认: -O0)"
    )
    
    args = parser.parse_args()
    
    log_debug("===== FFmpeg 编译参考脚本启动 =====")
    log_debug(f"编译配置:")
    log_debug(f"  编译器: {args.compiler}")
    log_debug(f"  优化级别: {args.optimization}")
    log_debug(f"  仓库目录: {REPO_DIR}")
    log_debug(f"  详情文件: {DETAILS_FILE}")
    log_debug(f"  输出目录: {REFERENCE_DIR}")
    log_debug(f"  调试日志: {DEBUG_LOG}")
    log_debug(f"  错误日志: {ERROR_LOG}")
    
    # 创建编译器实例
    compiler = FFmpegCompiler(
        compiler=args.compiler,
        optimization=args.optimization
    )
    
    try:
        # 处理 CVE 条目
        compiler.process_cve_entries()
        
        log_debug("\n===== 所有处理完成 =====")
        log_debug(f"CVE 相关二进制文件应位于: {REFERENCE_DIR}")
        log_debug(f"编译日志和中间构建产物位于以 '{compiler.build_dir_prefix}-' 为前缀的各个目录中")
        log_debug(f"详细日志请查看: {DEBUG_LOG}")
        log_debug(f"错误日志请查看: {ERROR_LOG}")
        
    except KeyboardInterrupt:
        log_error("用户中断，清理并退出...")
        compiler.cleanup_repo()
        sys.exit(1)
    except Exception as e:
        log_error(f"发生未预期的错误: {e}")
        compiler.cleanup_repo()
        sys.exit(1)