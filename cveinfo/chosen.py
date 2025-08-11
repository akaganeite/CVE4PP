import json
PROJ = "imagemagick"
def print_top_100_cves(json_file):
    try:
        # 读取JSON文件
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 确保数据是列表类型
        if not isinstance(data, list):
            print(f"错误: JSON文件结构不是列表类型")
            return
        
        # 按CVE年份降序排序，获取最新的120个CVE
        # 从CVE ID中提取年份进行排序 (CVE-YYYY-NNNN格式)
        def extract_year_from_cve(cve_entry):
            cve_id = cve_entry.get("id", "")
            try:
                # 从CVE-YYYY-NNNN格式中提取年份
                year = int(cve_id.split("-")[1])
                return year
            except (IndexError, ValueError):
                return 0  # 如果无法解析年份，返回0作为默认值
        
        sorted_data = sorted(data, key=extract_year_from_cve, reverse=True)
        
        # 提取最新的120个CVE ID
        cve_ids = [entry["id"] for entry in sorted_data[:120]]
        
        # 打印结果
        print(f"按时间顺序最新的 {len(cve_ids)} 个CVE ID:")
        with open(f"../testset/{PROJ}/chosen.txt", "w") as f:
            for i, cve_id in enumerate(cve_ids, 1):
                f.write(f"{cve_id}\n")
                print(f"{i}: {cve_id}")
            
    except FileNotFoundError:
        print(f"错误: 文件 '{json_file}' 未找到")
    except json.JSONDecodeError:
        print(f"错误: 文件 '{json_file}' 不是有效的JSON格式")
    except KeyError:
        print("错误: JSON条目缺少 'id' 字段")
    except Exception as e:
        print(f"处理文件时出错: {str(e)}")

if __name__ == "__main__":
    json_file = f"{PROJ}/{PROJ}_parsed.json"  # JSON文件名
    print_top_100_cves(json_file)