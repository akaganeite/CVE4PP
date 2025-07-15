import json

# 读取原始 testset.json
with open('testset.json', 'r') as f:
    testset = json.load(f)

# 读取勘误文件
with open('correction.json', 'r') as f:
    corrections = json.load(f)

# 生成新的 testset2.json 只包含被纠正的条目
new_testset = {}
for cve, fix in corrections.items():
    if cve in testset:
        # 复制原始条目
        entry = testset[cve].copy()
        # 用勘误内容替换
        if 'vuln' in fix:
            entry['vuln'] = fix['vuln']
        if 'patch' in fix:
            entry['patch'] = fix['patch']
        new_testset[cve] = entry

# 写入 testset2.json
with open('testset2.json', 'w') as f:
    json.dump(new_testset, f, indent=2, ensure_ascii=False)

print("testset2.json 已生成，只包含被纠正的条目。")