#!/bin/bash

# Script to compile different versions (commits and tags) of curl.

# --- Configuration ---
REPO_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/target/curl"
DETAILS_FILE="details"
VERSIONS_FILE="/home/zhangxb/patch/related-works/CVE-Dataset/New/Diff/curl/versions"
REFERENCE_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/reference/curl"
TARGET_DIR="/home/zhangxb/patch/related-works/CVE-Dataset/binaries/target/curl"
BUILD_DIR_PREFIX="${REPO_DIR}/build"

# --- Helper function to compile a specific git ref ---
compile_and_copy_curl() {
    local git_checkout_ref=$1
    local output_binary_name=$2
    local destination_dir=$3

    local sanitized_ref=$(echo "$git_checkout_ref" | tr '/' '_')
    local current_build_dir="${BUILD_DIR_PREFIX}-${sanitized_ref}"
    local curl_executable="${current_build_dir}/src/curl"  # curl二进制路径
    local log_file="${current_build_dir}/compile.log"

    echo
    echo "--- [BEGIN] Processing: $git_checkout_ref ---"
    echo "Build directory:    $current_build_dir"
    echo "Curl executable:    $curl_executable"
    echo "Output destination: ${destination_dir}/${output_binary_name}"

    # 1. Prepare repository
    cd "$REPO_DIR" || { echo "Error: Cannot enter repo dir"; return 1; }

    echo "Cleaning workspace..."
    git diff --quiet --exit-code && git diff --cached --quiet --exit-code && git ls-files --others --exclude-standard --empty-directory --error-unmatch . > /dev/null 2>&1
    local is_repo_clean=$?
    
    local stash_made=1
    if [ "$is_repo_clean" -ne 0 ]; then
        git stash push -u -m "autostash_$(date +%s)" > /dev/null 2>&1 && stash_made=0
    fi

    # 2. Checkout the ref
    echo "Checking out $git_checkout_ref..."
    if ! git checkout "$git_checkout_ref"; then
        [ "$stash_made" -eq 0 ] && git stash pop > /dev/null 2>&1
        return 1
    fi

    # 3. Compile curl
    if [ ! -f "$curl_executable" ]; then
        echo "Compiling $git_checkout_ref..."
        mkdir -p "$current_build_dir"
        
        (
            cd "$current_build_dir" || exit 1
            echo "=== Configure $git_checkout_ref ==="
            cd "$REPO_DIR" || exit 1
            autoreconf -fi
            cd "$current_build_dir" || exit 1

            "$REPO_DIR/configure" \
                CFLAGS="-g -O0" \
                CXXFLAGS="-g -O0" \
                --disable-werror \
                --disable-shared \
                --enable-debug \
                --with-openssl  # 根据实际需要调整
            
            echo -e "\n=== Make ==="
            make -j$(nproc)
        ) > "$log_file" 2>&1

        if [ ! -f "$curl_executable" ]; then
            echo "Compilation failed! See $log_file"
            [ "$stash_made" -eq 0 ] && git stash pop > /dev/null 2>&1
            return 1
        fi
    else
        echo "Using existing build."
    fi

    # 4. Copy binary
    echo "Copying to ${destination_dir}/${output_binary_name}"
    mkdir -p "$destination_dir"
    cp "$curl_executable" "${destination_dir}/${output_binary_name}" || return 1

    # 5. Cleanup
    git reset --hard origin/master
    echo "--- [END] Processed: $git_checkout_ref ---"
    return 0
}

# --- Main Logic ---
mkdir -p "$REFERENCE_DIR" "$TARGET_DIR" "$BUILD_DIR_PREFIX"

# Process CVEs
echo "===== Processing CVEs ====="
[ -f "$DETAILS_FILE" ] && while IFS= read -r line; do
    [ -z "$line" ] && continue

    cve_hash_field=$(awk '{print $1}' <<< "$line")
    cve_id=$(cut -d'_' -f1 <<< "$cve_hash_field")
    commit_hash=$(cut -d'_' -f2- <<< "$cve_hash_field")

    # Compile patch version
    short_hash="${commit_hash:0:7}"
    compile_and_copy_curl \
        "$commit_hash" \
        "${cve_id}-patch-${short_hash}-curl" \
        "$REFERENCE_DIR"

    # Compile vulnerable version
    prev_commit=$(git -C "$REPO_DIR" rev-parse "${commit_hash}~1" 2>/dev/null)
    if [ -n "$prev_commit" ]; then
        short_prev="${prev_commit:0:7}"
        compile_and_copy_curl \
            "$prev_commit" \
            "${cve_id}-vuln-${short_prev}-curl" \
            "$REFERENCE_DIR"
    fi
done < "$DETAILS_FILE"

# Process versions
echo "===== Processing Tags ====="
[ -f "$VERSIONS_FILE" ] && while IFS= read -r ver; do
    ver=$(tr -d '\r' <<< "$ver")
    [ -z "$ver" ] && continue
    
    # Convert version format: 3.49.2 -> curl-3_49_2
    tag_name="curl-$(tr '.' '_' <<< "$ver")"
    
    echo ">>> Processing tag: $tag_name <<<"
    compile_and_copy_curl \
        "$tag_name" \
        "curl-${ver}-debug" \
        "$TARGET_DIR"
done < "$VERSIONS_FILE"

echo "===== All tasks completed ====="
echo "CVE binaries: $REFERENCE_DIR"
echo "Version binaries: $TARGET_DIR"