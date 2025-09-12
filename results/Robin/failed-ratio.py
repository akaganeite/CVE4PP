import json
import csv
import os

# 读取 cluster.json
with open('../../RQs/failed_patch_clustering/cluster.json', 'r', encoding='utf-8') as f:
    cluster_data = json.load(f)

project_cve_map = {}
all_cves = set()
for proj, items in cluster_data.items():
    cves = set(item['CVE'] for item in items)
    project_cve_map[proj] = cves
    all_cves.update(cves)

success_cves = set()
project_success = {}

for proj in project_cve_map:
    gen_csv = f'generation/{proj}-gen.csv'
    proj_success = set()
    if os.path.exists(gen_csv):
        with open(gen_csv, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = row.get('CVE_ID')
                status = row.get('status')
                if cve in all_cves and status=="success":
                    cve = cve.strip()
                    proj_success.add(cve)
                    success_cves.add(cve)
    project_success[proj] = proj_success

print("Project\tTotal_CVE\tSuccess_CVE\tSuccess_Ratio")
for proj in project_cve_map:
    total = len(project_cve_map[proj])
    succ = len(project_success[proj])
    ratio = succ / total if total else 0
    print(f"{proj}\t{total}\t{succ}\t{ratio:.2%}")

print("\n=== Overall ===")
print(f"Total unique CVEs: {len(all_cves)}")
print(f"Total succeeded CVEs: {len(success_cves)}")
print(f"Overall success ratio: {len(success_cves)/len(all_cves):.2%}")