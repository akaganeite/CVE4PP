#!/usr/bin/env python3

# 读取details2文件
with open('../../Diff/ffmpeg/diff_files/details2', 'r') as f:
    details2_lines = f.readlines()

# 转换格式并添加到valid文件
with open('valid', 'a') as f:
    for line in details2_lines:
        line = line.strip()
        if not line:
            continue
            
        # 解析details2格式: CVE-id_commit_hash 日期 函数名
        parts = line.split(' ', 2)  # 最多分割2次
        if len(parts) >= 3:
            cve_with_hash = parts[0]
            date = parts[1]
            functions = parts[2]
            
            # 分离CVE-id和commit hash
            if '_' in cve_with_hash:
                cve_id, commit_hash = cve_with_hash.split('_', 1)
                
                # 转换为valid格式: CVE-id 日期 commit_hash ffmpeg 函数名
                valid_line = f"{cve_id} {date} {commit_hash} ffmpeg {functions}\n"
                f.write(valid_line)
                print(f"添加: {valid_line.strip()}")

print("完成！已将所有details2中的条目添加到valid文件中") 