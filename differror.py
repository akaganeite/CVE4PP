import argparse
import os

# 解析命令行参数
def parse_args():
    parser = argparse.ArgumentParser(description='Diff error processor')
    parser.add_argument('-proj', required=True, help='Project name')
    return parser.parse_args()

def parse_diff_error(diff_error_path):
    diff_map = {}
    print(f"[DEBUG] 读取diff-error文件: {diff_error_path}")
    with open(diff_error_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '|' in line:
                left, right = line.split('|', 1)
                left = left.strip()
                right = right.strip()
            else:
                left = line
                right = ''
            parts = left.split()
            cve = parts[0]
            remove_funcs = []
            if len(parts) > 1:
                remove_funcs = parts[1].split(',')
            add_funcs = []
            if right:
                add_funcs = [f.strip() for f in right.split(',') if f.strip()]
            diff_map[cve] = {'remove': set(remove_funcs), 'add': set(add_funcs)}
            print(f"[DEBUG] CVE: {cve}, 删除: {remove_funcs}, 新增: {add_funcs}")
    return diff_map

def process_valid(valid_path, diff_map):
    lines = []
    print(f"[DEBUG] 处理valid文件: {valid_path}")
    with open(valid_path, 'r') as f:
        for line in f:
            orig_line = line.rstrip('\n')
            parts = orig_line.split()
            if not parts or len(parts) < 5:
                lines.append(orig_line)
                continue
            cve = parts[0]
            if cve in diff_map:
                func_field = parts[4]
                funcs = set(func_field.split(','))
                funcs_before = list(func_field.split(','))
                funcs -= diff_map[cve]['remove']
                funcs |= diff_map[cve]['add']
                # 保持原有顺序，新增的在后面
                new_funcs = [f for f in func_field.split(',') if f in funcs]
                for f in diff_map[cve]['add']:
                    if f not in new_funcs:
                        new_funcs.append(f)
                parts[4] = ','.join(new_funcs)
                new_line = ' '.join(parts)
                print(f"[DEBUG] 修改CVE: {cve}")
                print(f"    原函数: {funcs_before}")
                print(f"    新函数: {new_funcs}")
                lines.append(new_line)
            else:
                lines.append(orig_line)
    with open(valid_path, 'w') as f:
        for line in lines:
            f.write(line + '\n')

def main():
    args = parse_args()
    project = args.proj
    diff_error_path = os.path.join('Diff', project, 'diff_error')
    valid_path = os.path.join('testset', project, 'valid')
    diff_map = parse_diff_error(diff_error_path)
    process_valid(valid_path, diff_map)

if __name__ == '__main__':
    main()
