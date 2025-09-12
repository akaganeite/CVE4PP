import json
import os
from collections import defaultdict

# 假设cwe、pattern、patch size数据文件路径
CLUSTER_JSON = 'cluster.json'
CWE_FILE = '../cwe_analysis/cwe_refined.json'  # 需根据实际路径调整
PATTERN_FILE = '../pattern_analysis/pattern.json'  # 需根据实际路径调整
PATCH_SIZE_FILE = '../size_analysis/cve_patch_size.pkl'  # 需根据实际路径调整

def load_json(path):
	try:
		with open(path, 'r', encoding='utf-8') as f:
			return json.load(f)
	except Exception as e:
		print(f"读取{path}失败: {e}")
		return {}

def load_patch_size(path):
	import pickle
	try:
		with open(path, 'rb') as f:
			return pickle.load(f)
	except Exception as e:
		print(f"读取{path}失败: {e}")
		return []

def categorize_patch_size(total_lines):
	if total_lines == 0:
		return "0"
	elif total_lines <= 5:
		return "1-5"
	elif total_lines <= 10:
		return "6-10"
	elif total_lines <= 20:
		return "11-20"
	elif total_lines <= 30:
		return "21-30"
	elif total_lines <= 40:
		return "31-40"
	elif total_lines <= 50:
		return "41-50"
	elif total_lines <= 60:
		return "51-60"
	elif total_lines <= 70:
		return "61-70"
	elif total_lines <= 80:
		return "71-80"
	else:
		return ">80"

def main():
	# 1. 加载cluster.json
	cluster_data = load_json(CLUSTER_JSON)
	# 2. 加载CWE、pattern、patch size数据
	cwe_data = load_json(CWE_FILE)
	pattern_data = load_json(PATTERN_FILE)
	patch_size_data = load_patch_size(PATCH_SIZE_FILE)

	# 3. 构建CVE到CWE、pattern、patch size的映射
	cve2cwe = {}
	for cwe, cves in cwe_data.items():
		for cve in cves:
			cve2cwe[cve] = cwe

	cve2pattern = pattern_data  # pattern_data: {cve: [pattern_ids]}

	cve2patchsize = {}
	for record in patch_size_data:
		cve_id = record.get('cve_id')
		total_lines = record.get('total_changed_lines', 0)
		cve2patchsize[cve_id] = categorize_patch_size(total_lines)

	# 4. 遍历cluster.json，聚类
	cwe_clusters = defaultdict(list)
	pattern_clusters = defaultdict(list)
	patchsize_clusters = defaultdict(list)

	for project, cve_list in cluster_data.items():
		for entry in cve_list:
			cve = entry['CVE']
			# cwe聚类
			cwe = cve2cwe.get(cve, 'Unknown')
			cwe_clusters[cwe].append(cve)
			# pattern聚类
			patterns = cve2pattern.get(cve, [])
			if patterns:
				for p in patterns:
					pattern_clusters[str(p)].append(cve)
			else:
				pattern_clusters['Unknown'].append(cve)
			# patch size聚类
			patchsize = cve2patchsize.get(cve, 'Unknown')
			patchsize_clusters[patchsize].append(cve)

	# 5. 打印结果
	print("\n=== CWE 聚类结果 ===")
	for cwe, cves in sorted(cwe_clusters.items(), key=lambda x: len(x[1]), reverse=True):
		print(f"{cwe}: {len(cves)}")

	print("\n=== Pattern 聚类结果 ===")
	for pattern, cves in sorted(pattern_clusters.items(), key=lambda x: len(x[1]), reverse=True):
		print(f"Pattern {pattern}: {len(cves)}")

	print("\n=== Patch Size 聚类结果 ===")
	for size, cves in sorted(patchsize_clusters.items(), key=lambda x: len(x[1]), reverse=True):
		print(f"Patch Size {size}: {len(cves)}")
		if size == "Unknown":
			for cve in cves:
				print(f"  {cve}")

if __name__ == "__main__":
	main()
