import requests
import re
import os
import glob
from collections import defaultdict

input_file = "ffmpeg_cve_commit.csv"
output_dir = "diff_files"
os.makedirs(output_dir, exist_ok=True)

with open(input_file, "r") as f:
    lines = f.readlines()

for line in lines[1:]:  # 跳过表头
    cve, commit = line.strip().split(",")
    # 只处理2020年及以后的CVE
    year = int(cve.split("-")[1])
    if year < 2020:
        continue

    commit_url = f"https://github.com/FFmpeg/FFmpeg/commit/{commit}"
    diff_url = f"{commit_url}.diff"
    print(f"Checking {commit_url} ...")
    try:
        resp = requests.get(commit_url)
        if "cherry picked from commit" not in resp.text:
            
            print(f"Downloading diff for {commit} ...")
            os.system(f"wget -O {output_dir}/ffmpeg_{cve}_{commit[:12]}.diff {diff_url}")
        else:
            print(f"Commit {commit} is a cherry-pick, skip downloading.")
    except Exception as e:
        print(f"Error processing {commit}: {e}")

# 下载完成后，检查是否有CVE对应多个diff文件
print("\n检查重复的CVE diff文件...")
cve_files = defaultdict(list)

# 获取所有diff文件
diff_files = glob.glob(f"{output_dir}/ffmpeg_*.diff")
for file_path in diff_files:
    filename = os.path.basename(file_path)
    # 从文件名中提取CVE ID (格式: ffmpeg_CVE-YYYY-XXXXX_commit.diff)
    parts = filename.split("_")
    if len(parts) >= 3:
        cve_id = parts[1]  # CVE-YYYY-XXXXX
        cve_files[cve_id].append(file_path)

# 检查并删除有多个diff文件的CVE
deleted_count = 0
for cve_id, file_list in cve_files.items():
    if len(file_list) > 1:
        print(f"发现CVE {cve_id} 对应 {len(file_list)} 个diff文件，正在删除...")
        for file_path in file_list:
            try:
                os.remove(file_path)
                print(f"  删除: {os.path.basename(file_path)}")
                deleted_count += 1
            except Exception as e:
                print(f"  删除失败 {os.path.basename(file_path)}: {e}")

print(f"\n清理完成！共删除了 {deleted_count} 个重复的diff文件。")
print(f"剩余 {len(glob.glob(f'{output_dir}/ffmpeg_*.diff'))} 个diff文件。")