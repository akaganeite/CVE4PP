import json
from collections import Counter

with open('cluster.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

all_classes = []
for proj in data.values():
    for item in proj:
        all_classes.append(item['class'])

total = len(all_classes)
counter = Counter(all_classes)

print("class\tcount\tratio")
for cls, cnt in counter.items():
    print(f"{cls}\t{cnt}\t{cnt/total:.2%}")

print(f"\nTotal: {total}")