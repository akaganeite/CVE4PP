import csv
import os

def calc_accuracy(csv_path):
    total_succeed = 0
    total_targets = 0
    total_func_not_found = 0
    total_failed_versions = 0
    total_false_positive = 0
    total_false_negative = 0
    
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            succeed = int(row['succeed']) if row['succeed'] else 0
            targets = int(row['targets']) if row['targets'] else 0
            
            # 计算各种失败情况的数量
            func_not_found = 0
            if row['func_not_found']:
                func_not_found = len(row['func_not_found'].split(';')) if row['func_not_found'] else 0
            
            failed_versions = 0
            if row['failed_versions']:
                failed_versions = len(row['failed_versions'].split(';')) if row['failed_versions'] else 0
            
            false_positive = 0
            if row['false_positive']:
                false_positive = len(row['false_positive'].split(';')) if row['false_positive'] else 0
            
            false_negative = 0
            if row['false_negative']:
                false_negative = len(row['false_negative'].split(';')) if row['false_negative'] else 0
            
            total_succeed += succeed
            total_targets += targets
            total_func_not_found += func_not_found
            total_failed_versions += failed_versions
            total_false_positive += false_positive
            total_false_negative += false_negative
    
    # 计算各种准确率
    acc1 = total_succeed / total_targets if total_targets else 0
    acc2 = total_succeed / (total_targets - total_func_not_found) if (total_targets - total_func_not_found) else 0
    
    # 只考虑false positive和false negative的准确率
    # 总的有效目标数 = succeed + false_positive + false_negative
    total_valid_targets = total_succeed + total_false_positive + total_false_negative
    acc3 = total_succeed / total_valid_targets if total_valid_targets else 0
    
    return acc1, acc2, acc3, total_succeed, total_targets, total_func_not_found, total_valid_targets

for fname in os.listdir('.'):
    if fname.endswith('.csv'):
        acc1, acc2, acc3, succeed, targets, func_not_found, valid_targets = calc_accuracy(fname)
        print(f'{fname}:')
        print(f'  succeed/targets = {succeed}/{targets} = {acc1:.4f}')
        print(f'  succeed/(targets-func_not_found) = {succeed}/({targets}-{func_not_found}) = {acc2:.4f}')
        print(f'  succeed/valid_targets = {succeed}/{valid_targets} = {acc3:.4f} (只考虑FP/FN)')
        print()