#!/bin/bash

# 配置参数
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb"          # 仓库目录
DETAILS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/binutils/diff_files/details_llvm"   # details文件路径
BINARIES_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/bitcode/reference/binutils"  # 输出目录
BUILD_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/build"        # 编译目录

# 用于存储已处理的CVE
declare -A processed_cves

# 编译函数
compile_version() {
    local hash=$1
    local type=$2
    local bc_name=$3
    local build_dir="${BUILD_DIR}-${hash}"
    local binutils_dir="${build_dir}/binutils"
    local log_file="${build_dir}/compile.log"

    echo "处理 $type 版本 ($hash)"

    # 检查目标二进制是否已存在
    local target_pattern="${BINARIES_DIR}/${cve_id}_${type}.bc"
    if ls $target_pattern >/dev/null 2>&1; then
        echo "目标二进制已存在，跳过编译: $target_pattern"
        return 0
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
        echo "错误：二进制目录 $binutils_dir 不存在"
        return 1
    fi
    
    # 优先检查 objdump
    target_binary=""
    if [ -f "${binutils_dir}/${bc_name}" ]; then
        echo "find valid .bc file"
        cp "${binutils_dir}/${bc_name}" "${BINARIES_DIR}/${cve_id}_${type}.bc"
        echo "copied ${binutils_dir}/${bc_name} to ${BINARIES_DIR}/${cve_id}_${type}.bc"
    else
        echo "Error: no valid .bc file for ${cve_id}-${type}"
    fi
    cd "$REPO_DIR" || exit 1
    git stash --include-untracked > /dev/null 2>&1 # 清理工作区
}

# 创建输出目录
mkdir -p "$BINARIES_DIR"
export CC=clang
export CXX=clang++
export RANLIB=llvm-ranlib
export CFLAGS=" -flto -std=gnu99 -g -O0"
export LDFLAGS=" -flto -fuse-ld=gold  -Wl,-plugin-opt=save-temps "
while read -r line; do
    # 解析details行
    cve_hash=$(echo "$line" | awk '{print $1}')
    cve_id=$(echo "$cve_hash" | cut -d'_' -f1)
    commit_hash=$(echo "$cve_hash" | cut -d'_' -f2)
    bc_name="$(echo "$line" | awk '{print $3}').0.5.precodegen.bc"
    functions=$(echo "$line" | awk '{print $4}' | tr ',' ' ')
    # 如果这个CVE已经处理过，跳过
    if [ "${processed_cves[$cve_id]}" = "1" ]; then
        echo "跳过已处理的CVE: $cve_id"
        continue
    fi
    
    echo "处理: $cve_id "
    
    # 进入仓库目录
    cd "$REPO_DIR" || exit 1
    
    # 1. 检出漏洞commit并编译
    git checkout "$commit_hash" > /dev/null 2>&1
    cd ..
    
    # 编译补丁版本
    compile_version "$commit_hash" "patch" "$bc_name"
    
    # 2. 检出上一个commit(漏洞版本)并编译
    cd "$REPO_DIR"
    # 获取完整哈希后截取前7位
    prev_commit_full=$(git rev-parse "$commit_hash~1")
    prev_commit="${prev_commit_full:0:12}"
    git checkout "$prev_commit" > /dev/null 2>&1
    cd ..

    # 编译漏洞版本
    compile_version "$prev_commit" "vuln" "$bc_name"
    
    # 标记这个CVE已处理
    processed_cves[$cve_id]=1
    
done < "$DETAILS_FILE"

echo "所有操作完成，结果保存在 $BINARIES_DIR/"