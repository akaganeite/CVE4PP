#!/usr/bin/env python3
"""
imagemagick LLVM编译脚本 - 用于编译imagemagick的CVE补丁版本和漏洞版本
参考compile_reference.py和binutils的compile_llvm.py编写
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

# 获取当前脚本的绝对路径，然后计算相对路径
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.join(CURRENT_DIR, "..", "..", "..")

# 配置参数
REPO_DIR = os.path.join(BASE_DIR, "target", "imagemagick")
DETAILS_FILE = os.path.join(CURRENT_DIR, "..", "..", "Diff", "imagemagick", "details_llvm")
BINARIES_DIR = os.path.join(BASE_DIR, "bitcode", "reference", "imagemagick")
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

class imagemagickCVECompiler:
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
            'CFLAGS': '-flto -g -O0',
            'CXXFLAGS': '-flto -g -O0',
            'LDFLAGS': '-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps'
        })
        
        # 创建输出目录
        Path(BINARIES_DIR).mkdir(parents=True, exist_ok=True)
        
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
    
    def git_checkout(self, commit_hash):
        """检出指定的git commit"""
        success, _ = self.run_command(
            ["git", "checkout", commit_hash], 
            cwd=REPO_DIR,
            capture_output=True
        )
        if success:
            self.log_debug(f"成功检出commit: {commit_hash}")
        else:
            self.log_error(f"检出commit失败: {commit_hash}")
        return success
    
    def git_stash(self):
        """清理工作区"""
        self.run_command(
            ["git", "stash", "--include-untracked"], 
            cwd=REPO_DIR,
            capture_output=True
        )
    
    def get_prev_commit(self, commit_hash):
        """获取前一个commit的哈希值"""
        success, result = self.run_command(
            ["git", "rev-parse", f"{commit_hash}~1"],
            cwd=REPO_DIR,
            capture_output=True
        )
        if success and result.stdout:
            # 截取前12位
            return result.stdout.strip()[:12]
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

    def find_valid_bc_file(self, build_dir, symbols, bin_name):
        """找到包含所有符号的bc文件"""
        # imagemagick的.bc文件通常在MagickCore/.libs/和MagickWand/.libs/目录下
        patterns = [
            os.path.join(build_dir, "MagickCore", ".libs", "*.0.5.precodegen.bc"),
            os.path.join(build_dir, "MagickWand", ".libs", "*.0.5.precodegen.bc"),
            os.path.join(build_dir, "**", "*.0.5.precodegen.bc"),
        ]
        
        for pattern in patterns:
            matches = glob.glob(pattern, recursive=True)
            for match in matches:
                # 只检查文件名包含bin_name的BC文件
                if os.path.isfile(match) and bin_name.lower() in os.path.basename(match).lower():
                    self.log_debug(f"检查BC文件: {match}")
                    if self.check_symbols_in_bc(match, symbols):
                        self.log_debug(f"找到包含所有符号的BC文件: {match}")
                        return match
        
        self.log_error(f"未找到包含bin_name '{bin_name}' 且含有所有必需符号的BC文件")
        return None

    def clean_build(self):
        """清理构建目录"""
        clean_commands = [
            ["make", "clean"],
            ["rm", "-rf", "autom4te.cache"],
        ]
        
        for cmd in clean_commands:
            self.run_command(cmd, cwd=REPO_DIR, capture_output=True)

    def compile_version(self, hash_val, version_type, cve_id, symbols, bin_name):
        """编译指定版本"""
        # 替换路径中的特殊字符
        build_dir = f"{REPO_DIR}"
        log_file = os.path.join(build_dir, "compile.log")
        
        self.log_debug(f"处理 {version_type} 版本 ({hash_val})")
        self.log_debug(f"构建目录: {build_dir}")
        
        # 检查目标二进制是否已存在
        target_file = Path(BINARIES_DIR) / f"{cve_id}_{version_type}.bc"
        if target_file.exists():
            self.log_debug(f"目标二进制已存在，检查符号: {target_file}")
            # 检查已存在的文件是否包含所需符号
            if self.check_symbols_in_bc(target_file, symbols):
                self.log_debug(f"目标二进制符号检查通过，跳过编译: {target_file}")
                return True
            else:
                self.log_error(f"目标二进制符号检查失败，重新编译: {target_file}")
                # 删除不符合要求的文件，重新编译
                target_file.unlink()
        
        # 创建构建目录
        Path(build_dir).mkdir(parents=True, exist_ok=True)
        
        # 设置环境变量
        env = os.environ.copy()
        
        # 配置和编译
        self.log_debug("=== start configure ===")
        
        # 配置命令
        configure_cmd = [
            f"{REPO_DIR}/configure",
            "--disable-werror",
            "--enable-shared",
            "--disable-install",
        ]
        
        with open(log_file, 'w') as f:
            f.write(f"=== 开始配置 {hash_val} ===\n")
        
        success, _ = self.run_command(configure_cmd, cwd=build_dir, log_file=log_file)
        if not success:
            self.log_error(f"配置失败: {hash_val}")
            self.log_failure(cve_id, hash_val, "CONFIGURE_ERROR", 
                           f"configure 阶段失败，详见 {log_file}", version_type)
            return False
        
        # 执行编译
        self.log_debug("=== start make ===")
        nproc = multiprocessing.cpu_count()
        make_cmd = ["make", f"-j{nproc}"]
        
        with open(log_file, 'a') as f:
            f.write(f"\n=== 开始编译 {hash_val} ===\n")
        
        success, _ = self.run_command(make_cmd, cwd=build_dir, log_file=log_file)
        if not success:
            self.log_error(f"编译失败: {hash_val}")
            self.log_failure(cve_id, hash_val, "COMPILE_ERROR", 
                           f"make 阶段失败，详见 {log_file}", version_type)
            return False
        
        self.log_debug("编译子任务完成")
        
        # 查找并复制.bc文件
        source_bc = self.find_valid_bc_file(build_dir, symbols, bin_name)
        if source_bc:
            self.log_debug("找到有效的BC文件，检查符号...")
            
            # 检查bc文件是否包含所需符号
            if not self.check_symbols_in_bc(source_bc, symbols):
                self.log_error(f"BC文件不包含所需符号: {cve_id}-{version_type}")
                self.log_failure(cve_id, hash_val, "SYMBOL_CHECK_FAILED", 
                               f"BC文件不包含符号: {', '.join(symbols)}", version_type)
                return False
            
            try:
                import shutil
                shutil.copy2(source_bc, target_file)
                self.log_debug(f"符号检查通过，已复制 {source_bc} 到 {target_file}")
                return True
            except Exception as e:
                self.log_error(f"复制文件失败: {e}")
                self.log_failure(cve_id, hash_val, "COPY_ERROR", 
                               f"复制文件失败: {e}", version_type)
                return False
        else:
            self.log_error(f"Error: no valid .bc file for {cve_id}-{version_type}")
            self.log_failure(cve_id, hash_val, "BC_FILE_NOT_FOUND", 
                           f"未找到包含必需符号的 .bc 文件", version_type)
            return False

    def process_details_file(self):
        """处理details文件中的每一行"""
        try:
            with open(DETAILS_FILE, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        self.process_line(line, line_num)
                    except Exception as e:
                        self.log_error(f"处理第{line_num}行时出错: {e}")
                        continue
                        
        except FileNotFoundError:
            self.log_error(f"details文件不存在: {DETAILS_FILE}")
            return False
        except Exception as e:
            self.log_error(f"读取details文件失败: {e}")
            return False
        
        return True
    
    def process_line(self, line, line_num):
        """处理details文件中的单行数据"""
        parts = line.split()
        if len(parts) < 3:
            self.log_error(f"第{line_num}行格式不正确，跳过: {line}")
            return
        
        # 解析details行 - 格式: CVE_CommitHash bin_name functions
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
        bin_name = parts[2]  # parts[1]是bin_name
        
        # 提取函数名（从第三个字段开始，即parts[2:]）
        symbols = []
        if len(parts) > 2:
            func_str = ' '.join(parts[2:])  # 合并所有剩余字段
            symbols = [func.strip() for func in func_str.split(',') if func.strip()]
        
        # 如果这个CVE已经处理过，跳过
        if cve_id in self.processed_cves:
            self.log_debug(f"跳过已处理的CVE: {cve_id}")
            return
        
        self.log_debug(f"处理: {cve_id}, 符号: {', '.join(symbols)}")
        
        # 1. 检出补丁commit并编译
        self.git_stash()

        if not self.git_checkout(commit_hash):
            self.log_error(f"检出补丁commit失败: {commit_hash}")
            self.log_failure(cve_id, commit_hash, "CHECKOUT_ERROR", 
                           f"无法检出补丁commit {commit_hash}", "patch")
            return
        
        # 编译补丁版本
        if not self.compile_version(commit_hash, "patch", cve_id, symbols, bin_name):
            self.log_error(f"编译补丁版本失败: {cve_id}")
        
        # 2. 检出上一个commit(漏洞版本)并编译
        prev_commit = self.get_prev_commit(commit_hash)
        if not prev_commit:
            self.log_error(f"获取前一个commit失败: {commit_hash}")
            self.log_failure(cve_id, commit_hash, "PREV_COMMIT_ERROR", 
                           f"无法获取上一个commit: {commit_hash}~1", "vuln")
            return
        
        if not self.git_checkout(prev_commit):
            self.log_error(f"检出漏洞commit失败: {prev_commit}")
            self.log_failure(cve_id, prev_commit, "CHECKOUT_ERROR", 
                           f"无法检出漏洞commit {prev_commit}", "vuln")
            return
        
        # 编译漏洞版本
        if not self.compile_version(prev_commit, "vuln", cve_id, symbols, bin_name):
            self.log_error(f"编译漏洞版本失败: {cve_id}")
        
        # 标记这个CVE已处理
        self.processed_cves.add(cve_id)
        
        # 清理工作区
        self.git_stash()

def main():
    """主函数"""
    print("===== 开始 imagemagick LLVM 编译流程 =====")
    
    # 检查必要的目录和文件
    if not Path(REPO_DIR).exists():
        print(f"仓库目录不存在: {REPO_DIR}")
        return 1
    
    if not Path(DETAILS_FILE).exists():
        print(f"details文件不存在: {DETAILS_FILE}")
        return 1
    
    compiler = imagemagickCVECompiler()
    compiler.log_debug("开始imagemagick LLVM编译流程")
    
    try:
        success = compiler.process_details_file()
        if success:
            compiler.log_debug(f"所有操作完成，结果保存在 {BINARIES_DIR}/")
            print("===== 所有操作完成 =====")
            print(f"结果保存在 {BINARIES_DIR}/")
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
if __name__ == "__main__":
    sys.exit(main())
