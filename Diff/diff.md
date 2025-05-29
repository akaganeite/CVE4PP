- details.py: Parse diff files, extract commit-date and functions modified
- testset.py: Given
## Whats in each project's directory
- diff format: `{project}_{cve_id}_{git_hash[:7]}_{CWE_ID}.diff`
- details: `{cve_id}_{git_hash[:7]}` `commit-date` `affetced_functions`
- testset.json: 3 vuln and 3 patch verison for each CVE
- bash scripts: compile reference and target binaries
    - compile options: -o0 , with debug symbol
    - versions: release versions compiled by bash scripts as target binaries
- cve2diff.py: extract diff files given references from {project}_filtered.json
