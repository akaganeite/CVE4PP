#!/bin/bash

# 配置参数
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb"  # 仓库目录
VERSIONS_FILE="versions"  # 包含tag号的文件路径 (当前目录)
BINARIES_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/binutils" # 输出目录
BASE_BUILD_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb/build" # 基础编译目录

# 编译函数
compile_tag() {
    local input_tag=$1 # e.g., 2.32
    local git_tag=$2   # e.g., binutils-2_32
    local build_dir="${BASE_BUILD_DIR}-${git_tag}" # 使用git_tag保证目录唯一性
    local objdump_path="${build_dir}/binutils/objdump"
    local log_file="${build_dir}/compile.log"
    # 使用原始input_tag命名输出文件
    local target_file="${BINARIES_DIR}/binutils-${input_tag}-o0-objdump"

    echo "--- Processing input tag: $input_tag (Git tag: $git_tag) ---"

    # 1. 检出tag
    cd "$REPO_DIR" || { echo "错误：无法切换到 $REPO_DIR"; return 1; }
    echo "清理工作区..."
    git stash --include-untracked > /dev/null 2>&1 # 清理工作区，抑制输出
    git checkout "$git_tag" || { echo "错误：无法检出 $git_tag"; return 1; }
    echo "已检出 $git_tag"

    # 2. 编译 (如果objdump不存在)
    if [ ! -f "$objdump_path" ]; then
        echo "objdump 不存在，开始编译..."
        mkdir -p "$build_dir"

        # 在子shell中执行编译并重定向输出
        (
            cd "$build_dir"
            {
                echo "=== 开始配置 $git_tag ==="
                "${REPO_DIR}/configure" \
                    CFLAGS="-g3 -O0" \
                    CXXFLAGS="-g3 -O0" \
                    --disable-werror \
                    --enable-debug

                echo -e "\n=== 开始编译 $git_tag ==="
                make -j$(nproc) all-binutils all-ld all-gas
            } > "$log_file" 2>&1
        )

        # 检查编译是否成功以及objdump是否存在
        if [ ! -f "$objdump_path" ]; then
            echo "错误：编译失败或 $git_tag 的 objdump 未找到。请检查 $log_file"
            cd "$REPO_DIR" || exit 1
            git stash --include-untracked > /dev/null 2>&1 # 清理
            return 1
        fi
        echo "$git_tag 编译成功。"
    else
        echo "objdump 已存在，跳过编译。"
    fi

    # 3. 复制 objdump
    echo "复制 objdump 到 $target_file"
    cp "$objdump_path" "$target_file" || { echo "错误：复制 $git_tag 的 objdump 失败"; return 1; }

    # 清理工作区
    cd "$REPO_DIR" || exit 1
    git stash --include-untracked > /dev/null 2>&1

    echo "--- 完成处理 input tag: $input_tag ---"
    return 0
}

# 创建输出目录
mkdir -p "$BINARIES_DIR"

# 检查versions文件是否存在
if [ ! -f "$VERSIONS_FILE" ]; then
    echo "错误: $VERSIONS_FILE 在当前目录未找到。"
    exit 1
fi

# 处理每个tag
while IFS= read -r input_tag || [[ -n "$input_tag" ]]; do
    # 移除可能存在的\r字符
    input_tag=$(echo "$input_tag" | tr -d '\r')
    # 忽略空行
    if [ -n "$input_tag" ]; then
        # 转换tag格式: 2.32 -> binutils-2_32
        git_tag="binutils-$(echo "$input_tag" | tr '.' '_')"
        # 调用编译函数，传入原始tag和转换后的git_tag
        compile_tag "$input_tag" "$git_tag"
    fi
done < "$VERSIONS_FILE"

echo "所有操作完成，结果保存在 $BINARIES_DIR/"