import re
import csv
import requests
# 假设原始数据已存储在变量data中


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
        version_dict[version] = datetime  # 自动去重，保留最后出现的时间

# 版本号排序函数
def version_key(ver):
    return tuple(map(int, ver.split('.')))

# 生成CSV文件
with open('ffmpeg_releases.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Version', 'Release Time'])
    for ver in sorted(version_dict, key=version_key):
        writer.writerow([ver, version_dict[ver]])