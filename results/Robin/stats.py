import  csv

total_succeed = 0
total_targets = 0
total_func_not_found = 0
with open("results_with_project.csv", newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        succeed = int(row['succeed']) if row['succeed'] else 0
        targets = int(row['targets']) if row['targets'] else 0
        total_succeed += succeed
        total_targets += targets
acc1 = total_succeed / total_targets if total_targets else 0
print(acc1, total_succeed, total_targets)