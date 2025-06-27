#!/bin/bash

# Script to compile different versions (commits and tags) of ffmpeg.

# --- Configuration ---
# REPO_DIR: Path to the root of the ffmpeg git repository.
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/ffmpeg"

# DETAILS_FILE: File containing CVE information. Format: CVEID_CommitHash CVE_ID Functions
DETAILS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/ffmpeg/diff_files/details_llvm"

# Output directories for compiled binaries
# REFERENCE_DIR: For CVE-related binaries (patched and vulnerable versions).
REFERENCE_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/bitcode/reference/ffmpeg"


# --- Helper function to compile a specific git ref (commit or tag) ---
compile_and_copy_ffmpeg() {
    local git_checkout_ref=$1   # Commit hash or full tag name (e.g., abcdef1, version-3.49.2)
    local output_binary_name=$2 # Desired final name of the binary in the destination directory
    local destination_dir=$3    # Directory to copy the final binary to
    local details_line=$4       # Details line from the CVE file
    # Sanitize git_checkout_ref for use in directory names (replace / with _ if tags contain them)
    local sanitized_ref=$(echo "$git_checkout_ref" | tr '/' '_')
    local ffmpeg_executable="${REPO_DIR}/ffmpeg_g.0.5.precodegen.bc" # Expected compiled binary
    local log_file="${REPO_DIR}/compile_${sanitized_ref}.log"

    echo # Blank line for readability
    echo "--- [BEGIN] Processing Git Ref: $git_checkout_ref ---"
    echo "ffmpeg executable:    $ffmpeg_executable"
    echo "Log file:             $log_file"
    echo "Output destination:   ${destination_dir}/${output_binary_name}"

    # 0. Check if the binary already exists in the destination directory
    if [ -f "${destination_dir}/${output_binary_name}" ]; then
        echo "二进制文件 ${destination_dir}/${output_binary_name} 已存在，跳过编译。"
        return 0
    fi

    # 1. Prepare repository: Navigate to repo and stash current state
    cd "$REPO_DIR" || { echo "错误：无法切换到仓库目录 $REPO_DIR"; return 1; }

    echo "清理工作区 (stash)..."
    rm *.bc
    make clean > /dev/null 2>&1
    make distclean > /dev/null 2>&1
    git reset --hard origin/master
    git stash --include-untracked
    
    git diff --quiet --exit-code && git diff --cached --quiet --exit-code && git ls-files --others --exclude-standard --empty-directory --error-unmatch . > /dev/null 2>&1
    local is_repo_clean=$? # 0 if clean, 1 if dirty or has untracked files
    
    local stash_made=1 # 0 if stash was made, 1 if not (repo was clean or stash failed)
    if [ "$is_repo_clean" -ne 0 ]; then
        git stash push -u -m "autostash_before_compile_$(date +%s)_${sanitized_ref}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "当前工作区状态已存储。"
            stash_made=0
        else
            echo "警告：git stash push 失败，但仓库可能并非完全干净。"
        fi
    else
        echo "仓库已处于干净状态，无需 stash。"
    fi

    # 2. Checkout the specified git reference
    echo "正在检出 $git_checkout_ref..."
    if ! git checkout "$git_checkout_ref"; then
        echo "错误：无法检出 $git_checkout_ref."
        if [ "$stash_made" -eq 0 ]; then # If a stash was made by this function
            echo "尝试恢复之前存储的 stashed 状态..."
            git stash pop --index > /dev/null 2>&1 || git stash pop > /dev/null 2>&1
        fi
        return 1
    fi
    echo "已成功检出 $git_checkout_ref."

    # 3. Compile ffmpeg (if the executable doesn't already exist in its build directory)
    if [ ! -f "$ffmpeg_executable" ]; then
        echo "$ffmpeg_executable 不存在，开始编译..."
        # Perform compilation in a subshell to isolate directory changes and capture all output to log
        (
            echo "=== 开始配置 $git_checkout_ref (日志于 $log_file) ==="
            # ffmpeg's configure script is typically in the root of the source tree.
            # We run it from the build directory.
            "./configure" \
                --disable-optimizations \
                --cc=clang
            # local configure_exit_code=$?
            # if [ $configure_exit_code -ne 0 ]; then
            #     echo "错误：配置失败，退出码: $configure_exit_code. 详情请查看 $log_file"
            #     exit $configure_exit_code # Exit subshell
            # fi

            echo -e "\n=== 开始编译 $git_checkout_ref (日志于 $log_file) ==="
            make -j$(nproc)
            local make_exit_code=$?
            if [ $make_exit_code -ne 0 ]; then
                echo "错误：编译失败，退出码: $make_exit_code. 详情请查看 $log_file"
                exit $make_exit_code # Exit subshell
            fi
            echo "编译子任务完成。"
        ) > "$log_file" 2>&1 # Redirect stdout and stderr of subshell to log_file
        local compile_subshell_exit_code=$?

        if [ $compile_subshell_exit_code -ne 0 ]; then
             echo "错误：编译子 shell 执行失败 (退出码 $compile_subshell_exit_code)。详情请查看 $log_file"
             if [ "$stash_made" -eq 0 ]; then
                git stash pop --index > /dev/null 2>&1 || git stash pop > /dev/null 2>&1
             fi
             return 1
        fi

        # Verify compilation outcome by checking for the executable
        if [ ! -f "$ffmpeg_executable" ]; then
            echo "错误：编译后 $ffmpeg_executable 未找到。详情请查看 $log_file"
            if [ "$stash_made" -eq 0 ]; then
                git stash pop --index > /dev/null 2>&1 || git stash pop > /dev/null 2>&1
            fi
            return 1
        fi
        echo "$git_checkout_ref 编译成功。"
    else
        echo "$ffmpeg_executable 已存在 跳过编译。"
    fi

    local func_names=$(echo "$details_line" | awk '{print $4}')
    # 4. Check if the binary is valid
    local missing_funcs=0   
    IFS=',' read -ra func_array <<< "$func_names"
    for func in "${func_array[@]}"; do
        # 去除可能的空格
        func=$(echo "$func" | xargs)
        if ! llvm-nm "$ffmpeg_executable" | grep " $func$"; then
            echo "Error: Function '$func' not found in $ffmpeg_executable"
            missing_funcs=1
        fi
    done

    if [ "$missing_funcs" -eq 0 ]; then
        # 4. Copy compiled binary to its final destination
        echo "复制 $ffmpeg_executable 到 ${destination_dir}/${output_binary_name}"
        mkdir -p "$destination_dir" # Ensure destination directory exists
        if ! cp "$ffmpeg_executable" "${destination_dir}/${output_binary_name}"; then
            echo "错误：复制 $ffmpeg_executable 失败。"
            if [ "$stash_made" -eq 0 ]; then
                git stash pop --index > /dev/null 2>&1 || git stash pop > /dev/null 2>&1
            fi
            return 1
        fi
        echo "二进制文件复制成功。"
        # 5. Clean up repository: Restore previous state if stashed
        cd "$REPO_DIR" || exit 1 # Ensure we are in the repo directory


        echo "--- [END] Processing Git Ref: $git_checkout_ref ---"
        return 0
    fi
    cd "$REPO_DIR" || exit 1 # Ensure we are in the repo directory

    echo "--- [END] Processing Git Ref: $git_checkout_ref ---, it failed"
    
    return 1
    
}

# --- Main Script Logic ---

# Create output and base build directories if they don't exist
mkdir -p "$REFERENCE_DIR"
mkdir -p "$BUILD_DIR_PREFIX" # Ensure the base for all build directories exists

export CC=clang
export CXX=clang++        
export RANLIB=llvm-ranlib
export CFLAGS=" -flto -std=gnu99 -g -O0"
export LDFLAGS=" -flto -fuse-ld=gold  -Wl,-plugin-opt=save-temps "

echo "===== 开始处理 CVE 条目 ====="
if [ ! -f "$DETAILS_FILE" ]; then
    echo "错误: $DETAILS_FILE 文件未找到。跳过 CVE 处理。"
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

        compile_and_copy_ffmpeg "$commit_hash" "$output_name_patch" "$REFERENCE_DIR" "$line"
        if [ $? -ne 0 ]; then
            echo "错误：编译 CVE $cve_id 的补丁版本 ($commit_hash) 失败。继续下一个条目。"
            # Consider adding a flag to exit script on first error if desired
        else
                # 2. Compile vulnerable version (parent of the patch commit)
            # Need to be in REPO_DIR to run git rev-parse
            current_pwd=$(pwd)
            cd "$REPO_DIR" || { echo "错误：无法进入 $REPO_DIR 以获取父提交。跳过 $cve_id 的漏洞版本。"; cd "$current_pwd"; continue; }
            
            prev_commit_full=$(git rev-parse "${commit_hash}~1" 2>/dev/null)
            rev_parse_status=$?
            cd "$current_pwd" # Return to original pwd before this block

            if [ $rev_parse_status -ne 0 ] || [ -z "$prev_commit_full" ]; then
                echo "错误：无法获取 $commit_hash 的父提交。跳过 $cve_id 的漏洞版本。"
                continue # Continue to the next CVE entry in the loop
            fi

            output_name_vuln="${cve_id}_vuln.bc"
            
            echo "漏洞版本 (父提交): $prev_commit_full"
            compile_and_copy_ffmpeg "$prev_commit_full" "$output_name_vuln" "$REFERENCE_DIR" "$line"
            if [ $? -ne 0 ]; then
                echo "错误：编译 CVE $cve_id 的漏洞版本 ($prev_commit_full) 失败。继续下一个条目。"
            fi
        fi
        
    done < "$DETAILS_FILE"
fi

echo # Blank line
echo "===== 所有处理完成 ====="
echo "CVE 相关二进制文件应位于: $REFERENCE_DIR"
echo "编译日志和中间构建产物位于以 '${BUILD_DIR_PREFIX}-' 为前缀的各个目录中。"
