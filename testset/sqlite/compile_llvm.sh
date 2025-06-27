#!/bin/bash

# Script to compile different versions (commits and tags) of SQLite.

# --- Configuration ---
# REPO_DIR: Path to the root of the SQLite git repository.
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/sqlite"

DETAILS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/sqlite/diff_files/details_llvm"


# Output directories for compiled binaries
# REFERENCE_DIR: For CVE-related binaries (patched and vulnerable versions).
REFERENCE_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/bitcode/reference/sqlite"


BUILD_DIR_PREFIX="${REPO_DIR}/build_sqlite_versions"

# --- Helper function to compile a specific git ref (commit or tag) ---
compile_and_copy_sqlite() {
    local git_checkout_ref=$1   # Commit hash or full tag name (e.g., abcdef1, version-3.49.2)
    local output_binary_name=$2 # Desired final name of the binary in the destination directory
    local destination_dir=$3    # Directory to copy the final binary to
    local details_line=$4        # Details line from the input file

    # Sanitize git_checkout_ref for use in directory names (replace / with _ if tags contain them)
    local sanitized_ref=$(echo "$git_checkout_ref" | tr '/' '_')
    local current_build_dir="${BUILD_DIR_PREFIX}-${sanitized_ref}"
    local sqlite_executable="${current_build_dir}/sqlite3.0.5.precodegen.bc" # Expected compiled binary
    local log_file="${current_build_dir}/compile.log"

    echo # Blank line for readability
    echo "--- [BEGIN] Processing Git Ref: $git_checkout_ref ---"
    echo "Build directory:      $current_build_dir"
    echo "SQLite executable:    $sqlite_executable"
    echo "Log file:             $log_file"
    echo "Output destination:   ${destination_dir}/${output_binary_name}"

    if [ -f "${destination_dir}/${output_binary_name}" ]; then
        echo "二进制文件 ${destination_dir}/${output_binary_name} 已存在，跳过编译。"
        return 0
    fi
    # 1. Prepare repository: Navigate to repo and stash current state
    cd "$REPO_DIR" || { echo "Error：无法切换到仓库目录 $REPO_DIR"; return 1; }
    # git stash --include-untracked
    make clean > /dev/null 2>&1
    make distclean > /dev/null 2>&1
    # 2. Checkout the specified git reference
    echo "正在检出 $git_checkout_ref..."
    if ! git checkout "$git_checkout_ref"; then
        echo "Error：无法检出 $git_checkout_ref."
        return 1
    fi
    echo "已成功检出 $git_checkout_ref."

    # 3. Compile SQLite (if the executable doesn't already exist in its build directory)
    if [ ! -f "$sqlite_executable" ]; then
        echo "$sqlite_executable 不存在，开始编译..."
        mkdir -p "$current_build_dir"

        # Perform compilation in a subshell to isolate directory changes and capture all output to log
        (
            cd "$current_build_dir" || { echo "Error：无法进入编译目录 $current_build_dir"; exit 1; }
            echo "=== 开始配置 $git_checkout_ref (日志于 $log_file) ==="
            # SQLite's configure script is typically in the root of the source tree.
            # We run it from the build directory.
            "${REPO_DIR}/configure" \
                --enable-debug
            local configure_exit_code=$?
            if [ $configure_exit_code -ne 0 ]; then
                echo "Error：配置失败，退出码: $configure_exit_code. 详情请查看 $log_file"
                exit $configure_exit_code # Exit subshell
            fi

            echo -e "\n=== 开始编译 $git_checkout_ref (日志于 $log_file) ==="
            make -j 18
            echo "编译子任务完成。"
        ) > "$log_file" 2>&1 # Redirect stdout and stderr of subshell to log_file




        # Verify compilation outcome by checking for the executable
        if [ ! -f "$sqlite_executable" ]; then
            echo "Error：编译后 $sqlite_executable 未找到。详情请查看 $log_file"
            make clean > /dev/null 2>&1
            return 1
        fi
        echo "$git_checkout_ref 编译成功。"
    else
        echo "$sqlite_executable 已存在于 $current_build_dir，跳过编译。"
    fi


    # 4. Check if the binary is valid
    local func_names=$(echo "$details_line" | awk '{print $4}')
    # 4. Check if the binary is valid
    local missing_funcs=0
    IFS=',' read -ra func_array <<< "$func_names"
    for func in "${func_array[@]}"; do
        # 去除可能的空格
        func=$(echo "$func" | xargs)
        if ! llvm-nm "$sqlite_executable" | grep " $func$"; then
            echo "Error: Function '$func' not found in $sqlite_executable"
            missing_funcs=1
        fi
    done
    if [ $missing_funcs -eq 1 ]; then
        echo "Do not copy"
        make clean > /dev/null 2>&1
        return 1
    fi

    echo "复制 $sqlite_executable 到 ${destination_dir}/${output_binary_name}"
    if ! cp "$sqlite_executable" "${destination_dir}/${output_binary_name}"; then
        rm *.bc
        echo "Error：复制 $sqlite_executable 失败。"
        make clean > /dev/null 2>&1
        return 1
    fi
    # 5. Clean up repository: Restore previous state if stashed
    rm *.bc
    make clean > /dev/null 2>&1

    echo "--- [END] Processing Git Ref: $git_checkout_ref ---"
    return 0
}

# --- Main Script Logic ---

# Create output and base build directories if they don't exist
mkdir -p "$REFERENCE_DIR"
mkdir -p "$BUILD_DIR_PREFIX" 


echo "===== 开始处理 CVE 条目 ====="
export CC=clang
export CXX=clang++        
export RANLIB=llvm-ranlib
export CFLAGS=" -flto -std=gnu99 -g -O0"
export LDFLAGS=" -flto -fuse-ld=gold  -Wl,-plugin-opt=save-temps "
if [ ! -f "$DETAILS_FILE" ]; then
    echo "Error: $DETAILS_FILE 文件未找到。跳过 CVE 处理。"
else
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines
        if [ -z "$line" ]; then continue; fi

        cve_hash_field=$(echo "$line" | awk '{print $1}') # Expected: CVEID_CommitHash
        cve_id=$(echo "$cve_hash_field" | cut -d'_' -f1)
        commit_hash=$(echo "$cve_hash_field" | cut -d'_' -f2-) # Get the rest as commit_hash

        # Validate parsed fields
        if [ -z "$cve_id" ] || [ -z "$commit_hash" ] || [ "$cve_id" = "$commit_hash" ]; then
            echo "警告：跳过格式不正确的行: '$line'"
            continue
        fi

        echo # Blank line for readability
        echo ">>> 处理 CVE: $cve_id, 补丁 Commit: $commit_hash <<<"

        # 1. Compile patch version (the commit_hash itself)
        # Use full commit_hash for checkout, and its short version for the output binary name
        output_name_patch="${cve_id}_patch.bc"

        compile_and_copy_sqlite "$commit_hash" "$output_name_patch" "$REFERENCE_DIR" "$line"
        if [ $? -ne 0 ]; then
            echo "Error：编译 CVE $cve_id 的补丁版本 ($commit_hash) 失败。继续下一个条目。"
            continue
        fi
        # 2. Compile vulnerable version (parent of the patch commit)
        # Need to be in REPO_DIR to run git rev-parse
        current_pwd=$(pwd)
        cd "$REPO_DIR" || { echo "Error：无法进入 $REPO_DIR 以获取父提交。跳过 $cve_id 的漏洞版本。"; cd "$current_pwd"; continue; }
        
        prev_commit_full=$(git rev-parse "${commit_hash}~1" 2>/dev/null)
        rev_parse_status=$?
        cd "$current_pwd" # Return to original pwd before this block

        if [ $rev_parse_status -ne 0 ] || [ -z "$prev_commit_full" ]; then
            echo "Error：无法获取 $commit_hash 的父提交。跳过 $cve_id 的漏洞版本。"
            continue # Continue to the next CVE entry in the loop
        fi

        output_name_vuln="${cve_id}_vuln.bc"
        
        echo "漏洞版本 (父提交): $prev_commit_full"
        compile_and_copy_sqlite "$prev_commit_full" "$output_name_vuln" "$REFERENCE_DIR" "$line"
        if [ $? -ne 0 ]; then
            echo "Error：编译 CVE $cve_id 的漏洞版本 ($prev_commit_full) 失败。继续下一个条目。"
        fi
    done < "$DETAILS_FILE"
fi

echo # Blank line
echo "===== 所有处理完成 ====="
echo "CVE 相关二进制文件应位于: $REFERENCE_DIR"
echo "编译日志和中间构建产物位于以 '${BUILD_DIR_PREFIX}-' 为前缀的各个目录中。"
