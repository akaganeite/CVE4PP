import csv
import requests
import json
from datetime import datetime
from dateutil import parser  # pip install python-dateutil

def get_all_tags(repo_owner: str, repo_name: str, github_token: str = None) -> list:
    """
    获取GitHub仓库所有tag信息（含发布时间）
    
    参数:
        repo_owner: 仓库所有者
        repo_name: 仓库名称
        github_token: GitHub个人访问令牌（可选，用于提升速率限制）
    
    返回:
        List[dict]: 包含tag信息的字典列表
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    query = """
    query ($owner: String!, $name: String!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        refs(refPrefix: "refs/tags/", first: 100, after: $cursor) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            name
            target {
              ... on Commit {
                committedDate
                oid
              }
              ... on Tag {
                tagger {
                  date
                }
                target {
                  ... on Commit {
                    committedDate
                    oid
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    tags = []
    cursor = None
    retry_count = 0
    max_retries = 3

    while True:
        try:
            variables = {"owner": repo_owner, "name": repo_name, "cursor": cursor}
            response = requests.post(
                "https://api.github.com/graphql",
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=15
            )
            response.raise_for_status()

            data = response.json()
            if "errors" in data:
                raise ValueError(f"GraphQL Error: {data['errors'][0]['message']}")

            refs = data["data"]["repository"]["refs"]
            if not refs:
                break

            for node in refs["nodes"]:
                try:
                    # 处理不同tag类型（轻量tag/注释tag）
                    if "tagger" in node["target"]:
                        date_str = node["target"]["tagger"]["date"]
                        commit_sha = node["target"]["target"]["oid"]
                    else:
                        date_str = node["target"]["committedDate"]
                        commit_sha = node["target"]["oid"]

                    # 安全解析日期（兼容所有ISO 8601变体）
                    parsed_date = parser.isoparse(date_str).strftime("%Y-%m-%d %H:%M:%S")
                    
                    tags.append({
                        "tag": node["name"],
                        "commit_sha": commit_sha,
                        "date": parsed_date
                    })
                except KeyError as e:
                    print(f"警告：跳过异常tag数据，缺失字段 {str(e)}")
                    continue

            if not refs["pageInfo"]["hasNextPage"]:
                break
            cursor = refs["pageInfo"]["endCursor"]
            retry_count = 0  # 成功请求后重置重试计数器

        except requests.exceptions.RequestException as e:
            if retry_count < max_retries:
                print(f"请求失败，正在重试 ({retry_count+1}/{max_retries})...")
                retry_count += 1
                continue
            raise RuntimeError(f"API请求失败: {str(e)}") from e

    return tags

def dump_tags():
    # 从环境变量读取token（更安全）
    TOKEN = ""  # 设置环境变量或直接赋值
    
    tags = get_all_tags(
        repo_owner="openssl",
        repo_name="openssl",
        github_token=TOKEN
    )
    
    # 输出结果
    print(f"共获取 {len(tags)} 个tag")
    
    # 保存到文件
    with open("openssl_tags.json", "w") as f:
        json.dump(tags, f, indent=2)

def process_tags(input_json, output_csv):
    """
    处理JSON数据并生成CSV文件
    
    参数:
        input_json (str): 输入JSON文件路径
        output_csv (str): 输出CSV文件路径
    """
    # 读取JSON数据
    with open(input_json, 'r', encoding='utf-8') as json_file:
        try:
            data = json.load(json_file)
        except json.JSONDecodeError as e:
            print(f"JSON解析失败: {str(e)}")
            return

    # 处理数据
    processed = []
    for item in data:
        # 筛选以v开头的tag
        # if not item.get('tag', '').startswith('v'):
        #     continue
            
        try:
            # 处理tag名称
            clean_tag = item['tag'][:]
            
            # 处理日期
            raw_date = item.get('date', '')
            if not raw_date:
                continue
                
            # 解析日期并格式化
            date_obj = datetime.strptime(raw_date, "%Y-%m-%d %H:%M:%S")
            formatted_date = date_obj.strftime("%Y-%m-%d")
            
            # 获取commit sha
            commit_sha = item.get('commit_sha', '')
            
            processed.append({
                'tag': clean_tag,
                'date': formatted_date,
                'commit_sha': commit_sha
            })
            
        except (KeyError, ValueError) as e:
            print(f"处理条目失败: {item.get('tag')} - {str(e)}")
            continue

    # 写入CSV文件
    if not processed:
        print("没有符合条件的数据")
        return

    try:
        with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
            fieldnames = ['tag', 'date', 'commit_sha']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            
            writer.writeheader()
            writer.writerows(processed)
            
        print(f"成功生成 {len(processed)} 条记录到 {output_csv}")
        
    except IOError as e:
        print(f"文件写入失败: {str(e)}")



# 使用示例
if __name__ == "__main__":
    # dump_tags()
        # 输入输出文件配置
    input_json_path = "openssl_tags.json"  # 输入JSON文件路径
    output_csv_path = "openssl.csv"       # 输出CSV文件路径
    
    process_tags(input_json_path, output_csv_path)
    