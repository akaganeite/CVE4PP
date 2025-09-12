import json

# CWE编号与描述的映射
cwe_ids = {
    "CWE-125": "Out-of-bounds Read",
    "CWE-466": "Return of Pointer Value Outside of Expected Range",
    "CWE-786": "Access of Memory Location Before Start of Buffer",
    "CWE-787": "Out-of-bounds Write",
    "CWE-788": "Access of Memory Location After End of Buffer",
    "CWE-805": "Buffer Access with Incorrect Length Value",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-823": "Use of Out-of-range Pointer Offset",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-825": "Expired Pointer Dereference",
    "CWE-476": "NULL Pointer Dereference"
}

def main():
    with open('cwe_mapping.json', 'r', encoding='utf-8') as f:
        mapping = json.load(f)

    merged = {}
    for cwe in cwe_ids:
        if cwe in mapping:
            merged[cwe] = mapping[cwe]

    with open('cwe_merged.json', 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)

    print("已输出cwe_merged.json")

if __name__ == "__main__":
    main()
