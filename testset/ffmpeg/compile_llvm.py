#!/usr/bin/env python3
"""
ffmpeg LLVM编译脚本 - 用于编译ffmpeg的CVE补丁版本和漏洞版本
从bash脚本重写为Python版本，参考binutils和tcpdump的实现
"""

import os
import subprocess
import sys
from pathlib import Path
import logging
from datetime import datetime
import re
import glob
import multiprocessing
import shutil

# 配置参数
REPO_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/target/ffmpeg"
DETAILS_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/ffmpeg/diff_files/details_llvm"
REFERENCE_DIR = "/home/zhangxb/patch/related-works/CVE-Dataset/bitcode/reference/ffmpeg"
LOG_DIR = "logs"

# 日志文件名带时间戳
now_str = datetime.now().strftime("%Y%m%d_%H%M")
DEBUG_LOG = os.path.join(LOG_DIR, f"compile_llvm_{now_str}.log")
ERROR_LOG = os.path.join(LOG_DIR, "compile_llvm_error.log")
FAILURE_LOG = os.path.join(LOG_DIR, "failed_llvm")

# 确保日志目录存在
os.makedirs(LOG_DIR, exist_ok=True)

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FFmpegLLVMCompiler:
    def __init__(self):
        self.processed_cves = set()
        self.setup_environment()
        
    def log_debug(self, msg):
        """记录调试信息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"[{timestamp}] {msg}"
        print(log_msg)
        logger.info(msg)
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(log_msg + "\n")

    def log_error(self, msg):
        """记录错误信息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"[{timestamp}] ERROR: {msg}"
        print(log_msg)
        logger.error(msg)
        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(log_msg + "\n")

    def log_failure(self, cve_id: str, commit_hash: str, error_type: str, error_details: str, binary_type: str) -> None:
        """记录失败信息到失败日志文件"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] CVE: {cve_id} | Commit: {commit_hash} | Type: {error_type} | Binary: {binary_type} | Details: {error_details}"
        self.log_error(log_message)
        with open(FAILURE_LOG, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")
        
    def setup_environment(self):
        """设置编译环境变量"""
        os.environ.update({
            'CC': 'clang',
            'CXX': 'clang++',
            'RANLIB': 'llvm-ranlib',
            'CFLAGS': '-flto -std=gnu99 -g -O0',
            'LDFLAGS': '-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps'
        })
        
        # 创建输出目录
        Path(REFERENCE_DIR).mkdir(parents=True, exist_ok=True)
        
    def run_command(self, cmd, cwd=None, capture_output=False, log_file=None, shell=True):
        """执行shell命令"""
        try:
            if log_file:
                with open(log_file, 'a', encoding='utf-8') as f:
                    if isinstance(cmd, list):
                        result = subprocess.run(
                            cmd, 
                            cwd=cwd,
                            stdout=f,
                            stderr=subprocess.STDOUT,
                            text=True
                        )
                    else:
                        result = subprocess.run(
                            cmd, 
                            shell=shell, 
                            cwd=cwd,
                            stdout=f,
                            stderr=subprocess.STDOUT,
                            text=True
                        )
            else:
                if isinstance(cmd, list):
                    result = subprocess.run(
                        cmd, 
                        cwd=cwd,
                        capture_output=capture_output,
                        text=True
                    )
                else:
                    result = subprocess.run(
                        cmd, 
                        shell=shell, 
                        cwd=cwd,
                        capture_output=capture_output,
                        text=True
                    )
            
            if result.returncode == 0:
                cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
                self.log_debug(f"命令成功: {cmd_str}")
            else:
                cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
                self.log_error(f"命令执行失败: {cmd_str}")
                
            return result.returncode == 0, result
        except Exception as e:
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
            self.log_error(f"执行命令失败: {cmd_str}, 错误: {e}")
            return False, None
    
    def is_repo_clean(self):
        """检查仓库是否干净"""
        # 检查工作区是否有修改
        ret1, _ = self.run_command(["git", "diff", "--quiet", "--exit-code"], cwd=REPO_DIR, capture_output=True)
        ret2, _ = self.run_command(["git", "diff", "--cached", "--quiet", "--exit-code"], cwd=REPO_DIR, capture_output=True)
        ret3, result3 = self.run_command(["git", "ls-files", "--others", "--exclude-standard"], cwd=REPO_DIR, capture_output=True)
        
        is_clean = ret1 and ret2 and (not result3 or not result3.stdout.strip())
        self.log_debug(f"仓库清洁状态检查: {'干净' if is_clean else '有未提交更改'}")
        return is_clean

    def stash_changes(self):
        """存储当前更改"""
        if not self.is_repo_clean():
            timestamp = subprocess.check_output("date +%s", shell=True, text=True).strip()
            stash_msg = f"autostash_before_compile_{timestamp}"
            ret, _ = self.run_command(["git", "stash", "push", "-u", "-m", stash_msg], cwd=REPO_DIR, capture_output=True)
            if ret:
                self.log_debug("当前工作区状态已存储")
            return ret
        self.log_debug("仓库已处于干净状态，无需 stash")
        return False

    def cleanup_repo(self):
        """清理仓库状态"""
        self.log_debug("开始清理仓库状态...")
        
        # 删除 .bc 文件
        bc_files = glob.glob(os.path.join(REPO_DIR, "*.bc"))
        for bc_file in bc_files:
            try:
                os.remove(bc_file)
                self.log_debug(f"删除文件: {bc_file}")
            except OSError:
                pass
        
        # 清理构建
        self.run_command(["make", "clean"], cwd=REPO_DIR, capture_output=True)
        self.run_command(["make", "distclean"], cwd=REPO_DIR, capture_output=True)
        self.run_command(["git", "reset", "--hard", "origin/master"], cwd=REPO_DIR, capture_output=True)
        self.run_command(["git", "stash", "--include-untracked"], cwd=REPO_DIR, capture_output=True)
        
        self.log_debug("仓库状态清理完成")

    def git_checkout(self, commit_hash):
        """检出指定的git commit"""
        self.log_debug(f"正在检出 {commit_hash}...")
        ret, result = self.run_command(["git", "checkout", commit_hash], cwd=REPO_DIR, capture_output=True)
        if ret:
            self.log_debug(f"已成功检出 {commit_hash}")
        else:
            self.log_error(f"无法检出 {commit_hash}: {result.stderr if result else ''}")
        return ret

    def get_prev_commit(self, commit_hash):
        """获取前一个commit的哈希值"""
        success, result = self.run_command(
            ["git", "rev-parse", f"{commit_hash}~1"],
            cwd=REPO_DIR,
            capture_output=True
        )
        if success and result.stdout:
            return result.stdout.strip()
        return None

    def check_symbols_in_bc(self, bc_file_path, symbols):
        """检查bc文件是否包含所有指定的符号"""
        try:
            # 使用llvm-nm检查bc文件中的符号
            result = subprocess.run(["llvm-nm", str(bc_file_path)], 
                                  capture_output=True, text=True, check=True)
            nm_output = result.stdout
            
            missing_symbols = []
            for symbol in symbols:
                symbol = symbol.strip()
                # 检查符号是否在输出中（更准确的匹配）
                if not re.search(rf'\b{re.escape(symbol)}\b', nm_output):
                    missing_symbols.append(symbol)
            
            if missing_symbols:
                self.log_error(f"BC文件 {bc_file_path} 缺少符号: {', '.join(missing_symbols)}")
                return False
            else:
                self.log_debug(f"BC文件 {bc_file_path} 包含所有必需符号: {', '.join(symbols)}")
                return True
                
        except subprocess.CalledProcessError as e:
            self.log_error(f"无法使用llvm-nm检查BC文件 {bc_file_path}: {e}")
            return False
        except FileNotFoundError:
            self.log_error("llvm-nm命令未找到，请确保LLVM工具链已安装")
            return False

    def compile_and_copy_ffmpeg(self, git_checkout_ref, output_binary_name, destination_dir, details_line, cve_id, version_type):
        """编译指定 git 引用的 ffmpeg 并复制到目标目录"""
        sanitized_ref = git_checkout_ref.replace('/', '_')
        ffmpeg_executable = os.path.join(REPO_DIR, "ffmpeg_g.0.5.precodegen.bc")
        log_file = os.path.join(REPO_DIR, f"compile_{sanitized_ref}.log")
        
        self.log_debug(f"\n--- [开始] 处理 Git Ref: {git_checkout_ref} ---")
        self.log_debug(f"ffmpeg 可执行文件: {ffmpeg_executable}")
        self.log_debug(f"日志文件: {log_file}")
        self.log_debug(f"输出目标: {destination_dir}/{output_binary_name}")
        
        # 检查二进制文件是否已存在
        final_binary_path = os.path.join(destination_dir, output_binary_name)
        if os.path.exists(final_binary_path):
            self.log_debug(f"二进制文件 {final_binary_path} 已存在，跳过编译")
            return True
        
        # 清理并准备工作区
        self.cleanup_repo()
        
        # 存储当前状态
        stash_made = self.stash_changes()
        
        try:
            # 检出指定引用
            if not self.git_checkout(git_checkout_ref):
                self.log_failure(cve_id, git_checkout_ref, "CHECKOUT_ERROR", 
                               f"无法检出 {git_checkout_ref}", version_type)
                return False
            
            # 编译 (如果可执行文件不存在)
            if not os.path.exists(ffmpeg_executable):
                self.log_debug(f"{ffmpeg_executable} 不存在，开始编译...")
                
                # 配置阶段
                self.log_debug("=== 开始配置 ===")
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== 开始配置 {git_checkout_ref} ===\n")
                
                configure_cmd = ["./configure", "--disable-optimizations", "--cc=clang"]
                
                success, _ = self.run_command(configure_cmd, cwd=REPO_DIR, log_file=log_file)
                if not success:
                    self.log_error(f"配置失败: {git_checkout_ref}")
                    self.log_failure(cve_id, git_checkout_ref, "CONFIGURE_ERROR", 
                                   f"configure 阶段失败，详见 {log_file}", version_type)
                    return False
                
                # 编译阶段
                self.log_debug("=== 开始编译 ===")
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n=== 开始编译 {git_checkout_ref} ===\n")
                
                nproc = multiprocessing.cpu_count()
                make_cmd = ["make", f"-j{nproc}"]
                
                success, _ = self.run_command(make_cmd, cwd=REPO_DIR, log_file=log_file)
                if not success:
                    self.log_error(f"编译失败: {git_checkout_ref}")
                    self.log_failure(cve_id, git_checkout_ref, "COMPILE_ERROR", 
                                   f"make 阶段失败，详见 {log_file}", version_type)
                    return False
                
                if not os.path.exists(ffmpeg_executable):
                    error_msg = f"编译后 {ffmpeg_executable} 未找到"
                    self.log_error(error_msg)
                    self.log_failure(cve_id, git_checkout_ref, "BINARY_NOT_FOUND", 
                                   f"{error_msg}，详见 {log_file}", version_type)
                    return False
                    
                self.log_debug(f"{git_checkout_ref} ({version_type}) 编译成功")
            else:
                self.log_debug(f"{ffmpeg_executable} 已存在，跳过编译")
            
            # 检查函数
            func_names = details_line.split()[3] if len(details_line.split()) > 3 else ""
            if func_names:
                functions = [f.strip() for f in func_names.split(',') if f.strip()]
                if not self.check_symbols_in_bc(ffmpeg_executable, functions):
                    self.log_failure(cve_id, git_checkout_ref, "SYMBOL_CHECK_FAILED", 
                                   f"BC文件不包含符号: {', '.join(functions)}", version_type)
                    return False
            
            # 复制二进制文件
            self.log_debug(f"复制 {ffmpeg_executable} 到 {final_binary_path}")
            os.makedirs(destination_dir, exist_ok=True)
            shutil.copy2(ffmpeg_executable, final_binary_path)
            self.log_debug("二进制文件复制成功")
            
            self.log_debug(f"--- [结束] 处理 Git Ref: {git_checkout_ref} ({version_type}) ---")
            return True
            
        except Exception as e:
            error_msg = f"处理 {git_checkout_ref} 时发生错误: {e}"
            self.log_error(error_msg)
            self.log_failure(cve_id, git_checkout_ref, "EXCEPTION", str(e), version_type)
            return False
        finally:
            # 清理仓库状态
            self.cleanup_repo()

    def process_details_file(self):
        """处理details文件中的每一行"""
        self.log_debug("===== 开始处理 CVE 条目 =====")
        
        if not os.path.exists(DETAILS_FILE):
            self.log_error(f"details文件不存在: {DETAILS_FILE}")
            return False
        
        try:
            with open(DETAILS_FILE, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        self.process_line(line, line_num)
                    except Exception as e:
                        self.log_error(f"处理第{line_num}行时出错: {e}")
                        continue
                        
        except Exception as e:
            self.log_error(f"读取details文件失败: {e}")
            return False
        
        return True
    
    def process_line(self, line, line_num):
        """处理details文件中的单行数据"""
        parts = line.split()
        if len(parts) < 2:
            self.log_error(f"第{line_num}行格式不正确，跳过: {line}")
            return
        
        # 解析details行 - 格式: CVE_CommitHash [other_fields] functions
        cve_hash = parts[0]
        if '_' not in cve_hash:
            self.log_error(f"CVE hash格式不正确: {cve_hash}")
            return
        
        cve_parts = cve_hash.split('_')
        if len(cve_parts) < 2:
            self.log_error(f"CVE hash格式不正确: {cve_hash}")
            return
            
        cve_id = cve_parts[0]
        commit_hash = '_'.join(cve_parts[1:])  # 获取剩余部分作为commit_hash
        
        # 如果这个CVE已经处理过，跳过
        if cve_id in self.processed_cves:
            self.log_debug(f"跳过已处理的CVE: {cve_id}")
            return
        
        self.log_debug(f"\n>>> 处理 CVE: {cve_id}, 补丁 Commit: {commit_hash} <<<")
        
        # 1. 编译补丁版本
        output_name_patch = f"{cve_id}_patch.bc"
        
        patch_success = self.compile_and_copy_ffmpeg(
            commit_hash, output_name_patch, REFERENCE_DIR, line, cve_id, "patch"
        )
        
        if not patch_success:
            self.log_error(f"编译 CVE {cve_id} 的补丁版本 ({commit_hash}) 失败。继续下一个条目")
        else:
            # 2. 编译漏洞版本 (父提交)
            prev_commit_full = self.get_prev_commit(commit_hash)
            if not prev_commit_full:
                self.log_error(f"无法获取 {commit_hash} 的父提交。跳过 {cve_id} 的漏洞版本")
                self.log_failure(cve_id, commit_hash, "PREV_COMMIT_ERROR", 
                               f"无法获取父提交", "vuln")
            else:
                output_name_vuln = f"{cve_id}_vuln.bc"
                
                self.log_debug(f"漏洞版本 (父提交): {prev_commit_full}")
                vuln_success = self.compile_and_copy_ffmpeg(
                    prev_commit_full, output_name_vuln, REFERENCE_DIR, line, cve_id, "vuln"
                )
                
                if not vuln_success:
                    self.log_error(f"编译 CVE {cve_id} 的漏洞版本 ({prev_commit_full}) 失败。继续下一个条目")
        
        # 标记这个CVE已处理
        self.processed_cves.add(cve_id)

def main():
    """主函数"""
    print("===== 开始 ffmpeg LLVM 编译流程 =====")
    
    # 检查必要的目录和文件
    if not Path(REPO_DIR).exists():
        print(f"仓库目录不存在: {REPO_DIR}")
        return 1
    
    if not Path(DETAILS_FILE).exists():
        print(f"details文件不存在: {DETAILS_FILE}")
        return 1
    
    compiler = FFmpegLLVMCompiler()
    compiler.log_debug("开始ffmpeg LLVM编译流程")
    
    try:
        success = compiler.process_details_file()
        if success:
            compiler.log_debug(f"所有操作完成，结果保存在 {REFERENCE_DIR}/")
            print("===== 所有操作完成 =====")
            print(f"结果保存在 {REFERENCE_DIR}/")
            print(f"调试日志: {DEBUG_LOG}")
            print(f"错误日志: {ERROR_LOG}")
            print(f"失败记录: {FAILURE_LOG}")
            return 0
        else:
            compiler.log_error("处理过程中出现错误")
            return 1
    except KeyboardInterrupt:
        compiler.log_debug("用户中断执行")
        return 1
    except Exception as e:
        compiler.log_error(f"执行过程中出现未预期的错误: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
