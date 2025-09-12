import os
import csv

def count_targets_and_func_not_found(directory):
    total_targets = 0
    total_func_not_found = 0
    total_valid_targets = 0
    for fname in os.listdir(directory):
        if fname.endswith('result.csv'):
            fpath = os.path.join(directory, fname)
            file_targets = 0
            file_func_not_found = 0
            with open(fpath, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    targets = int(row.get('targets', 0))
                    file_targets += targets
                    func_not_found = row.get('func_not_found', '')
                    if func_not_found:
                        file_func_not_found += len([v for v in func_not_found.split(';') if v.strip()])
            file_valid_targets = file_targets - file_func_not_found
            print(f"{fname}: target={file_targets}, func_not_found={file_func_not_found}, 有效target={file_valid_targets}")
            total_targets += file_targets
            total_func_not_found += file_func_not_found
            total_valid_targets += file_valid_targets
    print(f"总计: target={total_targets}, func_not_found={total_func_not_found}, 有效target={total_valid_targets}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("用法: python script.py <目录路径>")
    else:
        count_targets_and_func_not_found(sys.argv[1])