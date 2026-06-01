#!/usr/bin/env python3
import json, sys
from pathlib import Path

REQUIRED_FIELDS = ["rule_id", "name", "description", "severity",
                   "type", "language", "query", "tags", "threat"]
VALID_SEVERITIES = ["low", "medium", "high", "critical"]
ERRORS = []

def validate_rule(filepath):
    with open(filepath) as f:
        try:
            rule = json.load(f)
        except json.JSONDecodeError as e:
            ERRORS.append(f"[INVALID JSON] {filepath}: {e}")
            return
    for field in REQUIRED_FIELDS:
        if field not in rule:
            ERRORS.append(f"[MISSING FIELD] {filepath}: '{field}' is required")
    if rule.get("severity") not in VALID_SEVERITIES:
        ERRORS.append(f"[BAD SEVERITY] {filepath}: must be one of {VALID_SEVERITIES}")
    if not any("T" in tag for tag in rule.get("tags", [])):
        ERRORS.append(f"[NO MITRE TAG] {filepath}: at least one ATT&CK technique tag required")
    if rule.get("rule_id", "").strip() == "":
        ERRORS.append(f"[EMPTY RULE_ID] {filepath}: rule_id cannot be empty")
    print(f"  [PASS] {filepath.name}")

rules_path = Path("elk/detection-rules")
rule_files = list(rules_path.rglob("*.json"))

if not rule_files:
    print("No ELK rule files found — skipping.")
    sys.exit(0)

print(f"\nValidating {len(rule_files)} ELK rule(s)...\n")
for rule_file in rule_files:
    validate_rule(rule_file)

if ERRORS:
    print("\n--- VALIDATION ERRORS ---")
    for err in ERRORS:
        print(err)
    sys.exit(1)

print(f"\nAll {len(rule_files)} ELK rules passed validation.")
