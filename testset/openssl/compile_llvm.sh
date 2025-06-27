#!/bin/bash

# Script to compile different versions (commits and tags) of OpenSSL.

# --- Configuration ---
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/openssl"
DETAILS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/openssl/diff_files/details_llvm"
REFERENCE_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/bitcode/reference/openssl"
TARGET_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/openssl"

# --- Helper function to compile a specific git ref ---
compile_and_copy_openssl() {
    local git_checkout_ref=$1
    local output_binary_name=$2
    local destination_dir=$3
    local bin_name=$4  
    local details_line=$5
    local sanitized_ref=$(echo "$git_checkout_ref" | tr '/' '_')
    local current_build_dir="${REPO_DIR}"
    local log_file="${current_build_dir}/compile.log"
    local binary_type=""  # 新增变量，用于标记二进制类型


    echo "--- [BEGIN] Processing: $git_checkout_ref ---"
    echo "Build directory:  $current_build_dir"
    echo "Output binary:    $output_binary_name"
    echo "Destination:      $destination_dir"

    local output_file="${destination_dir}/${output_binary_name}"
    # 检查文件名前缀是否存在（去掉最后的-libcrypto或-libssl或-openssl）
    local prefix_name=$(echo "$output_binary_name" | sed -E 's/\.bc$//')
    if ls "${destination_dir}/${prefix_name}"* >/dev/null 2>&1; then
        echo
        echo "--- [SKIP] Target prefix already exists ---"
        echo "Found existing file with prefix: ${prefix_name}"
        echo "Skipping compilation for $git_checkout_ref"
        echo
        return 0
    fi

    # 1. Prepare repository
    cd "$REPO_DIR" || { echo "Error: Cannot enter repo dir"; return 1; }
    #git stash --include-untracked > /dev/null 2>&1  # 确保工作区干净

    # 2. Checkout the ref
    echo "Checking out $git_checkout_ref..."
    if ! git reset --hard "$git_checkout_ref" > /dev/null 2>&1; then
        echo "Error checking out: $git_checkout_ref"
        return 1
    fi
    # 3. Clean and prepare build dir
    # mkdir -p "$current_build_dir"
    
    # 4. Compile OpenSSL
    echo "Compiling $git_checkout_ref..."
    rm apps/*.bc
    rm *.bc
    local config_passed=0
    local build_passed=0
    local target_binary=""
    
    # 配置顺序：1. ./config -d  2. -d shared  3. -d shared no-apps
    for config_options in "-d", "-d  shared", "-d shared no-apps"; do
        echo "Trying configuration: ./config $config_options" | tee -a "$log_file"
        make clean > /dev/null 2>&1
        
        # 配置
        if ./config $config_options >> "$log_file" 2>&1 ; then
            # 检查log中是否有"is not supported"
            if tail -n 20 "$log_file" | grep -q "is not supported"; then
                echo "Configuration failed: contains 'is not supported'"
                continue
            fi
            config_passed=1
            echo "Configuration successful"
            
            # 编译
            make depend >> "$log_file" 2>&1
            if make -j 18 >> "$log_file" 2>&1; then
                build_passed=1
                echo "Build successful"
                
                # 查找合适的二进制文件
                if [[ "$bin_name" == "openssl" ]]; then
                    target_binary="./apps/openssl"
                    binary_type="openssl.bc"
                else
                    local lib_name=$(find . -name "${bin_name}.*.0.5.precodegen.bc" -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
                    target_binary="${lib_name}"
                    binary_type="${bin_name}.bc"
                fi
                break
            else
                echo "Build failed, see $log_file"
                make clean >> /dev/null 2>&1
            fi
        else
            echo "Configuration failed, see $log_file"
        fi
    done

    # 5. 复制找到的二进制文件
    if [[ -f "$target_binary" ]]; then
        # 只取 details_line 的第四列（函数名部分），不包含 binary 字段
        local func_names=$(echo "$details_line" | awk '{print $4}')
        local missing_funcs=0

        # 检查每个函数是否存在于库文件中
        # 将函数名字符串按逗号分割成数组
        IFS=',' read -ra func_array <<< "$func_names"
        for func in "${func_array[@]}"; do
            # 去除可能的空格
            func=$(echo "$func" | xargs)
            if ! llvm-nm "$target_binary" | grep " $func$"; then
                echo "Error: Function '$func' not found in $binary_type"
                missing_funcs=1
            fi
        done
        if [[ $missing_funcs -ne 0 ]]; then
            echo "Error: Missing functions in $binary_type, skipping copy"
            return 1
        fi
        mkdir -p "$destination_dir"
        cp "$target_binary" "${output_file}" && \
        echo "Copied to ${output_file}"
    else
        echo "Error: No suitable binary ${target_binary} found after build"
        return 1
    fi
    
    # 6. 清理
    make clean >> /dev/null 2>&1
    echo "--- [END] Processed: $git_checkout_ref ---"
    return 0
}

# --- Main Logic ---
mkdir -p "$REFERENCE_DIR" "$TARGET_DIR" 


echo "===== Processing CVEs ====="

export CC=clang
export CXX=clang++
export RANLIB=llvm-ranlib
export CFLAGS=" -flto -std=gnu99 -g -O0"
export LDFLAGS=" -flto -fuse-ld=gold  -Wl,-plugin-opt=save-temps "

if [[ -f "$DETAILS_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        
        # 解析CVE和commit哈希
        parts=($line)
        cve_hash_field=${parts[0]}
        bin_name=${parts[2]}
        IFS='_' read -ra hash_parts <<< "$cve_hash_field"
        cve_id=${hash_parts[0]}
        commit_hash=${hash_parts[1]}

        # 先尝试编译可执行文件版本
        if ! compile_and_copy_openssl "$commit_hash" "${cve_id}-patch.bc" "$REFERENCE_DIR" "$bin_name" "$line"; then
            continue
        fi
        # 编译漏洞版本 (commit_hash 的上一个提交)
        prev_commit=$(git -C "$REPO_DIR" rev-parse "${commit_hash}~1" 2>/dev/null)
        if [[ -n "$prev_commit" ]]; then
            # 同样先尝试编译可执行文件版本
            compile_and_copy_openssl "$prev_commit" "${cve_id}-vuln.bc" "$REFERENCE_DIR" "$bin_name" "$line"
        else
            echo "Warning: No parent commit for $commit_hash"
        fi
    done < "$DETAILS_FILE"
else
    echo "Warning: Details file $DETAILS_FILE not found, skipping CVE processing"
fi

echo "===== All tasks completed ====="
echo "CVE binaries: $REFERENCE_DIR"
echo "Version binaries: $TARGET_DIR"