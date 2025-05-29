import sys
from collections import defaultdict

def process_file(input_file):
    cve_dict = defaultdict(lambda: {'date': None, 'functions': set()})
    
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # 分割为三部分：CVE_Hash, Date, Functions
            parts = line.split(' ', 2)
            if len(parts) != 3:
                print(f"忽略格式错误行: {line}")
                continue
                
            cve_hash, date, functions = parts
            func_list = functions.split(',')
            
            # 检查日期一致性
            if cve_hash in cve_dict:
                existing_date = cve_dict[cve_hash]['date']
                if existing_date != date:
                    print(f"警告: {cve_hash} 日期不一致 ({existing_date} vs {date})")
            
            # 更新记录
            cve_dict[cve_hash]['date'] = date
            cve_dict[cve_hash]['functions'].update(func_list)
    
    # 生成排序结果
    sorted_entries = sorted(
        ((k, v['date'], sorted(v['functions'])) for k, v in cve_dict.items()),
        key=lambda x: (x[1], x[0])
    )
    
    return sorted_entries

def save_output(sorted_entries, output_file):
    with open(output_file, 'w') as f:
        for cve_hash, date, funcs in sorted_entries:
            line = f"{cve_hash} {date} {','.join(funcs)}\n"
            f.write(line)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("使用方法: python dedup_cve.py 输入文件 输出文件")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    entries = process_file(input_file)
    save_output(entries, output_file)
    print(f"处理完成，共去重 {len(entries)} 个条目")