#!/bin/bash

# 配置参数
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb"          # 仓库目录
DETAILS_FILE="details"   # details文件路径
BINARIES_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/binutils"  # 输出目录
BUILD_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/build"        # 编译目录

# 编译函数
# 修改后的函数逻辑
# 修改后的绝对路径版本
compile_version() {
    local hash=$1
    local type=$2
    local build_dir="${BUILD_DIR}-${hash}"
    local binutils_dir="${build_dir}/binutils"
    local log_file="${build_dir}/compile.log"

    echo "处理 $type 版本 ($hash)"

    # 检查构建目录是否存在
    if [ ! -d "$build_dir" ]; then
        echo "构建目录不存在，开始编译..."
        mkdir -p "$build_dir"
        
        # 在子shell中执行编译
        # 在子shell中执行编译并重定向输出
        (
            cd "$build_dir"
            {
                echo "=== 开始配置 ==="
                "${REPO_DIR}/configure" \
                    CFLAGS="-g3 -O0" \
                    CXXFLAGS="-g3 -O0" \
                    --disable-werror \
                    --enable-debug
                
                echo -e "\n=== 开始编译 ==="
                make -j$(nproc) all-binutils all-ld all-gas
            } > "$log_file" 2>&1
        )
    else
        echo "构建目录已存在，跳过编译步骤"
    fi

    # 检查二进制文件是否存在
    if [ ! -d "$binutils_dir" ]; then
        echo "错误：二进制目录 $binutils_dir 不存在"
        return 1
    fi
    
    # 优先检查 objdump
    target_binary=""
    if [ -f "${binutils_dir}/objdump" ]; then
        found_all=true
        for func in $functions; do
            if ! nm "${binutils_dir}/objdump" | grep -q "$func"; then
                found_all=false
                break
            fi
        done
        if $found_all; then
            target_binary="${binutils_dir}/objdump"
        fi
    fi
    
    # 如果 objdump 不满足，遍历其他二进制
    if [ -z "$target_binary" ]; then
        for binary in "${binutils_dir}"/*; do
            if [ -f "$binary" ] && [ -x "$binary" ]; then
                found_all=true
                for func in $functions; do
                    if ! nm "$binary" | grep -q "$func"; then
                        found_all=false
                        break
                    fi
                done
                if $found_all; then
                    target_binary="$binary"
                    break  # 找到第一个符合条件的即退出
                fi
            fi
        done
    fi
    
    # 复制找到的二进制
    if [ -n "$target_binary" ]; then
        bin_name=$(basename "$target_binary")
        echo "找到有效二进制: $bin_name"
        cp "$target_binary" "${BINARIES_DIR}/${cve_id}-${type}-${hash}-${bin_name}"
    else
        echo "未找到包含所有函数的二进制"
    fi
    cd "$REPO_DIR" || exit 1
    git stash --include-untracked # 清理工作区
}

# 创建输出目录
mkdir -p "$BINARIES_DIR"

# 处理每个CVE条目
while read -r line; do
    # 解析details行
    cve_hash=$(echo "$line" | awk '{print $1}')
    cve_id=$(echo "$cve_hash" | cut -d'_' -f1)
    commit_hash=$(echo "$cve_hash" | cut -d'_' -f2)
    functions=$(echo "$line" | awk '{print $3}' | tr ',' ' ')
    
    echo "处理: $cve_id ($commit_hash)"
    
    # 进入仓库目录
    cd "$REPO_DIR" || exit 1
    
    # 1. 检出漏洞commit并编译
    git checkout "$commit_hash"
    cd ..
    
    # 编译补丁版本
    compile_version "$commit_hash" "patch"
    
    # 2. 检出上一个commit(漏洞版本)并编译
    cd "$REPO_DIR"
    # 获取完整哈希后截取前6位
    prev_commit_full=$(git rev-parse "$commit_hash~1")
    prev_commit="${prev_commit_full:0:7}"  # 截取前6位
    git checkout "$prev_commit"
    cd ..

    # 编译漏洞版本时使用短哈希
    compile_version "$prev_commit" "vuln" 
    
done < "$DETAILS_FILE"

echo "所有操作完成，结果保存在 $BINARIES_DIR/"