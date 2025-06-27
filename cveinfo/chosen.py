import json
PROJ = "ffmpeg"
def print_top_100_cves(json_file):
    try:
        # 读取JSON文件
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 确保数据是列表类型
        if not isinstance(data, list):
            print(f"错误: JSON文件结构不是列表类型")
            return
        
        # 提取前100个CVE ID
        cve_ids = [entry["id"] for entry in data[:100] if not (entry["id"].startswith("CVE-2025"))]
        
        # 打印结果
        print(f"前 {len(cve_ids)} 个CVE ID:")
        with open(f"../testset/{PROJ}/chosen.txt", "w") as f:
            for i, cve_id in enumerate(cve_ids, 1):
                f.write(f"{cve_id}\n")
            
    except FileNotFoundError:
        print(f"错误: 文件 '{json_file}' 未找到")
    except json.JSONDecodeError:
        print(f"错误: 文件 '{json_file}' 不是有效的JSON格式")
    except KeyError:
        print("错误: JSON条目缺少 'id' 字段")
    except Exception as e:
        print(f"处理文件时出错: {str(e)}")

if __name__ == "__main__":
    json_file = f"{PROJ}/{PROJ}_filtered.json"  # JSON文件名
    print_top_100_cves(json_file)