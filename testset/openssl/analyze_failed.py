#!/usr/bin/env python3
"""
Python script to analyze failed compilation logs and update cve_compilation_issues.json
"""

import json
import re
import os
from typing import Dict, List, Set
from collections import defaultdict

# Configuration
FAILED_LOG_FILE = "logs/failed"
CVE_ISSUES_FILE = "/home/zhangxb/patch/related-works/CVE-Dataset/New/testset/cve_compilation_issues.json"
COUNT  = 0

def parse_failed_log(log_file: str) -> Dict[str, Set[str]]:
    """
    Parse the failed log file and extract CVE information by error type.
    
    Returns:
        Dict with keys: 'missing_symbols', 'checkout_error', 'compilation_error'
        Each value is a set of CVE IDs
    """
    error_categories = {
        'missing_symbols': set(),
        'checkout_error': set(),
        'compilation_error': set()
    }
    
    if not os.path.exists(log_file):
        print(f"Warning: Log file {log_file} not found")
        return error_categories
    
    # Regex pattern to extract CVE ID and error type from log line
    pattern = r'\[.*?\] CVE: (CVE-\d{4}-\d+) \| Commit: .*? \| Type: (\w+) \| Binary: .*? \| Details: (.*)'
    LAST_ID = ""
    with open(log_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            match = re.match(pattern, line)
            if match:
                cve_id = match.group(1)
                error_type = match.group(2)
                details = match.group(3)
                if cve_id != LAST_ID:
                    COUNT = 0
                    LAST_ID  = cve_id
                # Categorize based on error type
                if error_type == "MISSING_SYMBOLS":
                    COUNT +=1
                    if COUNT == 6:
                        error_categories['missing_symbols'].add(cve_id)
                elif error_type == "CHECKOUT_ERROR":
                    error_categories['checkout_error'].add(cve_id)
                elif error_type in ["COMPILATION_ERROR", "BINARY_NOT_FOUND", "REPO_ACCESS_ERROR", "COPY_ERROR"]:
                    error_categories['compilation_error'].add(cve_id)
    
    return error_categories

def load_cve_issues() -> List[Dict]:
    """Load the existing CVE issues JSON file."""
    if not os.path.exists(CVE_ISSUES_FILE):
        print(f"Warning: CVE issues file {CVE_ISSUES_FILE} not found, creating new structure")
        return []
    
    try:
        with open(CVE_ISSUES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading CVE issues file: {e}")
        return []

def find_openssl_project(data: List[Dict]) -> Dict:
    """Find the openssl project entry in the data, create if not exists."""
    for project in data:
        if project.get("project") == "openssl":
            return project
    
    # Create new openssl project entry
    openssl_project = {
        "project": "openssl",
        "failed": [],
        "no_func": [],
        "checkout_err": [],
        "multiple branch": []
    }
    data.append(openssl_project)
    return openssl_project

def update_cve_issues(openssl_project: Dict, error_categories: Dict[str, Set[str]]):
    """Update the openssl project with new error categories."""
    
    # Helper function to add items without duplicates
    def add_unique_items(target_list: List[str], new_items: Set[str]):
        existing_set = set(target_list)
        for item in new_items:
            if item not in existing_set:
                target_list.append(item)
    
    # Update missing symbols (no_func)
    if error_categories['missing_symbols']:
        add_unique_items(openssl_project['no_func'], error_categories['missing_symbols'])
        print(f"Added {len(error_categories['missing_symbols'])} CVEs to no_func: {sorted(error_categories['missing_symbols'])}")
    
    # Update checkout errors
    if error_categories['checkout_error']:
        if 'checkout_err' not in openssl_project:
            openssl_project['checkout_err'] = []
        add_unique_items(openssl_project['checkout_err'], error_categories['checkout_error'])
        print(f"Added {len(error_categories['checkout_error'])} CVEs to checkout_err: {sorted(error_categories['checkout_error'])}")
    
    # Update compilation errors (failed)
    if error_categories['compilation_error']:
        add_unique_items(openssl_project['failed'], error_categories['compilation_error'])
        print(f"Added {len(error_categories['compilation_error'])} CVEs to failed: {sorted(error_categories['compilation_error'])}")

def save_cve_issues(data: List[Dict]):
    """Save the updated CVE issues to JSON file."""
    try:
        # Create backup
        if os.path.exists(CVE_ISSUES_FILE):
            backup_file = f"{CVE_ISSUES_FILE}.backup"
            with open(CVE_ISSUES_FILE, 'r') as src, open(backup_file, 'w') as dst:
                dst.write(src.read())
            print(f"Created backup: {backup_file}")
        
        # Save updated data
        with open(CVE_ISSUES_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Successfully updated {CVE_ISSUES_FILE}")
        
    except Exception as e:
        print(f"Error saving CVE issues file: {e}")

def print_summary(openssl_project: Dict):
    """Print a summary of the current openssl project data."""
    print("\n=== Current OpenSSL Project Summary ===")
    print(f"Failed CVEs: {len(openssl_project.get('failed', []))}")
    print(f"No Function CVEs: {len(openssl_project.get('no_func', []))}")
    print(f"Checkout Error CVEs: {len(openssl_project.get('checkout_err', []))}")
    print(f"Multiple Branch CVEs: {len(openssl_project.get('multiple branch', []))}")
    
    if openssl_project.get('failed'):
        print(f"\nFailed CVEs: {sorted(openssl_project['failed'])}")
    if openssl_project.get('no_func'):
        print(f"\nNo Function CVEs: {sorted(openssl_project['no_func'])}")
    if openssl_project.get('checkout_err'):
        print(f"\nCheckout Error CVEs: {sorted(openssl_project['checkout_err'])}")
    if openssl_project.get('multiple branch'):
        print(f"\nMultiple Branch CVEs: {sorted(openssl_project['multiple branch'])}")

def main():
    """Main function to analyze failed logs and update JSON."""
    print("=== Analyzing Failed Compilation Logs ===")
    
    # Parse failed log file
    error_categories = parse_failed_log(FAILED_LOG_FILE)
    
    # Print analysis results
    print(f"\nAnalysis Results:")
    print(f"Missing Symbols: {len(error_categories['missing_symbols'])} CVEs")
    print(f"Checkout Errors: {len(error_categories['checkout_error'])} CVEs")
    print(f"Compilation Errors: {len(error_categories['compilation_error'])} CVEs")
    
    if error_categories['missing_symbols']:
        print(f"Missing Symbols CVEs: {sorted(error_categories['missing_symbols'])}")
    if error_categories['checkout_error']:
        print(f"Checkout Error CVEs: {sorted(error_categories['checkout_error'])}")
    if error_categories['compilation_error']:
        print(f"Compilation Error CVEs: {sorted(error_categories['compilation_error'])}")
    
    # Load existing CVE issues
    data = load_cve_issues()
    
    # Find or create openssl project entry
    openssl_project = find_openssl_project(data)
    
    # Update with new error categories
    update_cve_issues(openssl_project, error_categories)
    
    # Save updated data
    save_cve_issues(data)
    
    # Print final summary
    print_summary(openssl_project)
    
    print("\n=== Analysis Complete ===")

if __name__ == "__main__":
    main()