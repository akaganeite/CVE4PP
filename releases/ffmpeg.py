import re
import csv
import requests
from datetime import datetime

url = "https://ffmpeg.org/releases/"
response = requests.get(url)
if response.status_code == 200:
    data = response.text
# data = """
# Index of /releases

# Index of /releases
#  Name                                     Last modified      Size  Description
# Parent Directory                                              -   
# ffmpeg-0.10.1.tar.bz2                    2012-03-17 02:45  5.5M  
# ffmpeg-0.10.1.tar.bz2.asc                2012-03-17 03:15  490   
# ffmpeg-0.10.1.tar.gz                     2012-03-17 02:45  6.7M  
# ...（其余数据）
# """
# print(data)

# 正则表达式匹配核心文件行
pattern = re.compile(
    r'<img\s+.*?>\s*<a\s+href="ffmpeg-(\d+\.\d+(?:\.\d+)*)\.tar\.(?:gz|bz2|xz)">.*?</a>\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2})'
)

version_dict = {}

# 解析每行数据
for line in data.splitlines():
    if match := pattern.search(line.strip()):
        version, datetime = match.groups()
        version_dict[version] = datetime[:11]  # 自动去重，保留最后出现的时间

# 版本号排序函数
def version_key(ver):
    return tuple(map(int, ver.split('.')))

# 生成CSV文件
with open('ffmpeg_releases.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Version', 'Release Time'])
    for ver in sorted(version_dict, key=version_key):
        writer.writerow([ver, version_dict[ver]])

# import csv
# from datetime import datetime

# def parse_time(time_str):
#     """处理可能的时间格式问题（如末尾空格或缺少时间部分）"""
#     cleaned = time_str.strip()
#     if len(cleaned) == 10:  # 只有日期部分（如 '2009-03-10'）
#         return datetime.strptime(cleaned, "%Y-%m-%d")
#     else:  # 完整时间（如 '2009-03-10 00:06'）
#         return datetime.strptime(cleaned, "%Y-%m-%d %H:%M")

# def sort_ffmpeg_versions(input_file, output_file):
#     # 读取数据
#     with open(input_file, 'r', encoding='utf-8') as f:
#         reader = csv.reader(f)
#         header = next(reader)  # 跳过标题行
#         data = [row for row in reader]

#     # 解析时间并排序
#     sorted_data = sorted(data, key=lambda x: parse_time(x[1]))

#     # 写入排序结果
#     with open(output_file, 'w', newline='', encoding='utf-8') as f:
#         writer = csv.writer(f)
#         writer.writerow(header)
#         writer.writerows(sorted_data)

#     print(f"已排序 {len(sorted_data)} 条数据，结果保存至 {output_file}")

# if __name__ == "__main__":
#     input_csv = "ffmpeg.csv"   # 输入文件名
#     output_csv = "ffmpeg_sorted.csv"    # 输出文件名
#     sort_ffmpeg_versions(input_csv, output_csv)