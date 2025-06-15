#!/bin/bash

# Script to compile different versions (commits and tags) of OpenSSL.

# --- Configuration ---
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/openssl"
DETAILS_FILE="details"
VERSIONS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/openssl/versions"
REFERENCE_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/openssl"
TARGET_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/openssl"
BUILD_DIR_PREFIX="${REPO_DIR}/../build"

# --- Helper function to compile a specific git ref ---
compile_and_copy_openssl() {
    local git_checkout_ref=$1
    local output_binary_name=$2
    local destination_dir=$3

    local sanitized_ref=$(echo "$git_checkout_ref" | tr '/' '_')
    local current_build_dir="${BUILD_DIR_PREFIX}-${sanitized_ref}"
    local log_file="${current_build_dir}/compile.log"
    local binary_found=0

    echo
    echo "--- [BEGIN] Processing: $git_checkout_ref ---"
    echo "Build directory:  $current_build_dir"
    echo "Output binary:    $output_binary_name"
    echo "Destination:      $destination_dir"

    local output_file="${destination_dir}/${output_binary_name}"
    if [[ -f "$output_file" ]]; then
        echo
        echo "--- [SKIP] Target already exists ---"
        echo "Reference binary: $output_file"
        echo "Skipping compilation for $git_checkout_ref"
        echo
        return 0
    fi

    # 1. Prepare repository
    cd "$REPO_DIR" || { echo "Error: Cannot enter repo dir"; return 1; }
    git stash --include-untracked > /dev/null 2>&1  # 确保工作区干净

    # 2. Checkout the ref
    echo "Checking out $git_checkout_ref..."
    if ! git checkout --force "$git_checkout_ref" > /dev/null 2>&1; then
        echo "Error checking out: $git_checkout_ref"
        return 1
    fi

    # 3. Clean and prepare build dir
    mkdir -p "$current_build_dir"
    
    # 4. Compile OpenSSL
    echo "Compiling $git_checkout_ref..."
    local config_passed=0
    local build_passed=0
    local target_binary=""
    
    # 配置顺序：1. ./config -d  2. -d shared  3. -d shared no-apps
    for config_options in "-d", "-d  shared", "-d shared no-apps"; do
        echo "Trying configuration: ./config $config_options" | tee -a "$log_file"
        make clean > /dev/null 2>&1
        
        # 配置
        if ./config $config_options >> "$log_file" 2>&1; then
            config_passed=1
            echo "Configuration successful"
            
            # 编译
            make depend >> "$log_file" 2>&1
            if make -j$(nproc) >> "$log_file" 2>&1; then
                build_passed=1
                echo "Build successful"
                
                # 查找合适的二进制文件
                # 1. 首先查找可执行文件 (apps/openssl)
                if [[ -f "./apps/openssl" ]]; then
                    target_binary="./apps/openssl"
                    echo "Found openssl executable: $target_binary"
                    binary_found=1
                    break
                
                # 2. 查找共享库
                else
                    # 根据输出文件名确定查找哪个库
                    if [[ "$output_binary_name" == *"libcrypto"* ]]; then
                        # 查找最新的 libcrypto.so
                        local crypto_lib=$(find . -name 'libcrypto.so.*' -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
                        if [[ -f "$crypto_lib" ]]; then
                            target_binary="$crypto_lib"
                            echo "Found crypto library: $target_binary"
                            binary_found=1
                            break
                        fi
                    
                    elif [[ "$output_binary_name" == *"libssl"* || "$output_binary_name" == *"openssl"* ]]; then
                        # 查找最新的 libssl.so
                        local ssl_lib=$(find . -name 'libssl.so.*' -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
                        if [[ -f "$ssl_lib" ]]; then
                            target_binary="$ssl_lib"
                            echo "Found ssl library: $target_binary"
                            binary_found=1
                            break
                        fi
                    
                    else
                        # 默认查找 libssl
                        local ssl_lib=$(find . -name 'libssl.so.*' -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
                        if [[ -f "$ssl_lib" ]]; then
                            target_binary="$ssl_lib"
                            echo "Found default library: $target_binary"
                            binary_found=1
                            break
                        fi
                    fi
                fi
            else
                echo "Build failed, see $log_file"
                make clean >> /dev/null 2>&1
            fi
        else
            echo "Configuration failed, see $log_file"
        fi
    done

    # 5. 复制找到的二进制文件
    if [[ $binary_found -eq 1 ]]; then
        mkdir -p "$destination_dir"
        cp "$target_binary" "${output_file}" && \
        echo "Copied to ${output_file}"
    else
        echo "Error: No suitable binary found after build"
        return 1
    fi
    
    # 6. 清理
    make clean >> /dev/null 2>&1
    echo "--- [END] Processed: $git_checkout_ref ---"
    return 0
}

# --- Main Logic ---
mkdir -p "$REFERENCE_DIR" "$TARGET_DIR" "$BUILD_DIR_PREFIX"

# Process CVEs
echo "===== Processing CVEs ====="
if [[ -f "$DETAILS_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        
        # 解析CVE和commit哈希
        parts=($line)
        cve_hash_field=${parts[0]}
        
        IFS='_' read -ra hash_parts <<< "$cve_hash_field"
        cve_id=${hash_parts[0]}
        commit_hash=${hash_parts[1]}
        
        # 使用7位短哈希
        short_hash=${commit_hash:0:7}

        # 先尝试编译可执行文件版本
        if compile_and_copy_openssl "$commit_hash" "${cve_id}-patch-${short_hash}-openssl" "$REFERENCE_DIR"; then
            echo "Successfully compiled executable version for ${cve_id}"
        else
            # 如果可执行文件版本编译失败，尝试编译库文件版本
            echo "Executable compilation failed, trying library versions..."
            compile_and_copy_openssl "$commit_hash" "${cve_id}-patch-${short_hash}-libcrypto" "$REFERENCE_DIR"
            compile_and_copy_openssl "$commit_hash" "${cve_id}-patch-${short_hash}-libssl" "$REFERENCE_DIR"
        fi

        # 编译漏洞版本 (commit_hash 的上一个提交)
        prev_commit=$(git -C "$REPO_DIR" rev-parse "${commit_hash}~1" 2>/dev/null)
        if [[ -n "$prev_commit" ]]; then
            short_prev=${prev_commit:0:7}
            # 同样先尝试编译可执行文件版本
            if compile_and_copy_openssl "$prev_commit" "${cve_id}-vuln-${short_prev}-openssl" "$REFERENCE_DIR"; then
                echo "Successfully compiled executable version for ${cve_id} (vulnerable)"
            else
                # 如果可执行文件版本编译失败，尝试编译库文件版本
                echo "Executable compilation failed, trying library versions..."
                compile_and_copy_openssl "$prev_commit" "${cve_id}-vuln-${short_prev}-libcrypto" "$REFERENCE_DIR"
                compile_and_copy_openssl "$prev_commit" "${cve_id}-vuln-${short_prev}-libssl" "$REFERENCE_DIR"
            fi
        else
            echo "Warning: No parent commit for $commit_hash"
        fi
    done < "$DETAILS_FILE"
else
    echo "Warning: Details file $DETAILS_FILE not found, skipping CVE processing"
fi

# Process versions
echo "===== Processing Tags ====="
if [[ -f "$VERSIONS_FILE" ]]; then
    while IFS= read -r tag || [[ -n "$tag" ]]; do
        tag=$(tr -d '\r' <<< "$tag")
        [[ -z "$tag" ]] && continue
        
        # 编译可执行文件版本
        compile_and_copy_openssl "$tag" "openssl-${tag}-o0-openssl" "$TARGET_DIR"

        # 编译crypto版本
        compile_and_copy_openssl "$tag" "openssl-${tag}-o0-libcrypto" "$TARGET_DIR"

        # 编译ssl版本
        compile_and_copy_openssl "$tag" "openssl-${tag}-o0-libssl" "$TARGET_DIR"
        

        
    done < "$VERSIONS_FILE"
else
    echo "Warning: Versions file $VERSIONS_FILE not found, skipping tag processing"
fi

echo "===== All tasks completed ====="
echo "CVE binaries: $REFERENCE_DIR"
echo "Version binaries: $TARGET_DIR"