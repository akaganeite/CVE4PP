#!/bin/bash

# 配置参数
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb"          # 仓库目录
DETAILS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/binutils/details_llvm"   # details文件路径
BINARIES_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/bitcode/reference/binutils"  # 输出目录
BUILD_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/build"        # 编译目录

# 新增：日志文件
FAILURE_LOG="logs/failed_llvm.log"
mkdir -p logs
touch "$FAILURE_LOG"
# 记录失败信息的函数
log_failure() {
    local cve_id=$1
    local commit_hash=$2
    local error_type=$3
    local error_details=$4
    local binary_type=$5
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] CVE: $cve_id | Commit: $commit_hash | Type: $error_type | Binary: $binary_type | Details: $error_details"
}

# 用于存储已处理的CVE
declare -A processed_cves

# 编译函数
compile_version() {
    local hash=$1
    local type=$2
    local bc_name=$3
    local symbols=$4  # 符号参数
    local build_dir="${BUILD_DIR}-${hash}"
    local binutils_dir="${build_dir}/binutils"
    local log_file="${build_dir}/compile.log"

    echo "处理 $type 版本 ($hash)" 

    # 检查目标二进制是否已存在
    local target_pattern="${BINARIES_DIR}/${cve_id}_${type}.bc"
    if ls $target_pattern >/dev/null 2>&1; then
        echo "目标二进制已存在，检查符号: $target_pattern" 
        # 检查已存在文件的符号
        if check_symbols_in_bc "$target_pattern" "$symbols"; then
            echo "目标二进制符号检查通过，跳过编译: $target_pattern"
            return 0
        else
            echo "目标二进制符号检查失败，重新编译"
            rm -f "$target_pattern"
        fi
    fi

    mkdir -p "$build_dir"
    
    cd "$build_dir"
    echo "=== start configure ==="
    {
        
        "${REPO_DIR}/configure" \
            --disable-werror
        
        echo -e "\n=== start make ==="
        make -j$(nproc) all-binutils all-ld all-gas
    } > "$log_file" 2>&1

    # 检查二进制文件是否存在
    if [ ! -d "$binutils_dir" ]; then
        log_failure "$cve_id" "$hash" "BINARY_DIR_NOT_FOUND" "二进制目录 $binutils_dir 不存在" "$type"
        return 1
    fi
    
    # 检查bc文件
    if [ -f "${binutils_dir}/${bc_name}" ]; then
        echo "找到.bc文件，检查符号..."
        
        # 检查符号
        if check_symbols_in_bc "${binutils_dir}/${bc_name}" "$symbols"; then
            echo "符号检查通过"
            cp "${binutils_dir}/${bc_name}" "${BINARIES_DIR}/${cve_id}_${type}.bc"
            echo "copied ${binutils_dir}/${bc_name} to ${BINARIES_DIR}/${cve_id}_${type}.bc"
        else
            log_failure "$cve_id" "$hash" "SYMBOL_CHECK_FAILED" "BC文件 $bc_name 不包含符号: $symbols" "$type"
            return 1
        fi
    else
        log_failure "$cve_id" "$hash" "BC_FILE_NOT_FOUND" "未找到 .bc 文件: $bc_name" "$type"
        return 1
    fi
    cd "$REPO_DIR" || exit 1
    git stash --include-untracked > /dev/null 2>&1 # 清理工作区
}

# 符号检查函数
check_symbols_in_bc() {
    local bc_file=$1
    local symbols=$2
    
    if [ ! -f "$bc_file" ]; then
        echo "Error: BC文件不存在: $bc_file"
        return 1
    fi
    
    # 获取符号列表
    local nm_output=$(llvm-nm "$bc_file" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Error: 无法使用llvm-nm检查BC文件: $bc_file"
        return 1
    fi
    
    # 检查每个符号
    IFS=',' read -ra symbol_array <<< "$symbols"
    for symbol in "${symbol_array[@]}"; do
        symbol=$(echo "$symbol" | xargs)  # 去除空格
        if ! echo "$nm_output" | grep -q "\b$symbol\b"; then
            echo "Error: 符号 '$symbol' 未在BC文件中找到"
            return 1
        fi
    done
    
    echo "所有符号检查通过: $symbols"
    return 0
}

# 创建输出目录
mkdir -p "$BINARIES_DIR"
export CC=clang
export CXX=clang++
export RANLIB=llvm-ranlib
export CFLAGS=" -flto -std=gnu99 -g -O0"
export LDFLAGS=" -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps "
echo "开始LLVM编译流程"
while read -r line; do
    # 解析details行
    cve_hash=$(echo "$line" | awk '{print $1}')
    cve_id=$(echo "$cve_hash" | cut -d'_' -f1)
    commit_hash=$(echo "$cve_hash" | cut -d'_' -f2)
    bc_name="$(echo "$line" | awk '{print $3}').0.5.precodegen.bc"
    functions=$(echo "$line" | awk '{print $4}')  # 保持逗号分隔格式
    
    # 如果这个CVE已经处理过，跳过
    if [ "${processed_cves[$cve_id]}" = "1" ]; then
        echo "跳过已处理的CVE: $cve_id"
        continue
    fi
    
    echo "处理: $cve_id, 符号: $functions"
    
    # 进入仓库目录
    cd "$REPO_DIR" || exit 1
    
    # 1. 检出补丁commit并编译
    if ! git checkout "$commit_hash" > /dev/null 2>&1; then
        log_failure "$cve_id" "$commit_hash" "CHECKOUT_ERROR" "无法检出补丁commit $commit_hash" "patch"
        continue
    fi
    cd ..
    
    # 编译补丁版本
    if ! compile_version "$commit_hash" "patch" "$bc_name" "$functions"; then
        echo "编译补丁版本失败: $cve_id"
    fi
    
    # 2. 检出上一个commit(漏洞版本)并编译
    cd "$REPO_DIR"
    # 获取完整哈希后截取前12位
    prev_commit_full=$(git rev-parse "$commit_hash~1" 2>/dev/null)
    if [ -z "$prev_commit_full" ]; then
        log_failure "$cve_id" "$commit_hash" "PREV_COMMIT_ERROR" "无法获取上一个commit: ${commit_hash}~1" "vuln"
        processed_cves[$cve_id]=1
        continue
    fi
    
    prev_commit="${prev_commit_full:0:12}"
    if ! git checkout "$prev_commit" > /dev/null 2>&1; then
        log_failure "$cve_id" "$prev_commit" "CHECKOUT_ERROR" "无法检出漏洞commit $prev_commit" "vuln"
        processed_cves[$cve_id]=1
        continue
    fi
    cd ..

    # 编译漏洞版本
    if ! compile_version "$prev_commit" "vuln" "$bc_name" "$functions"; then
        echo "编译漏洞版本失败: $cve_id"
    fi
    
    # 标记这个CVE已处理
    processed_cves[$cve_id]=1
    
done < "$DETAILS_FILE"

echo "所有操作完成，结果保存在 $BINARIES_DIR/"
echo "===== 所有操作完成 ====="
echo "结果保存在 $BINARIES_DIR/"
echo "失败记录: $FAILURE_LOG"