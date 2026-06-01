#!/usr/bin/env python3
import json, os, sys, warnings
import requests
from pathlib import Path
warnings.filterwarnings("ignore")

KIBANA_URL  = os.environ["KIBANA_URL"].rstrip("/")
ELASTIC_KEY = os.environ["ELASTIC_API_KEY"]
RULES_DIR   = Path("elk/detection-rules")

HEADERS = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {ELASTIC_KEY}"
}

def rule_exists(rule_id):
    r = requests.get(
        f"{KIBANA_URL}/api/detection_engine/rules",
        headers=HEADERS,
        params={"rule_id": rule_id},
        verify=False
    )
    return r.status_code == 200

def deploy_rule(filepath):
    with open(filepath) as f:
        rule = json.load(f)
    rule_id = rule.get("rule_id")
    if rule_exists(rule_id):
        r = requests.put(f"{KIBANA_URL}/api/detection_engine/rules",
                         headers=HEADERS, json=rule, verify=False)
        action = "UPDATED"
    else:
        r = requests.post(f"{KIBANA_URL}/api/detection_engine/rules",
                          headers=HEADERS, json=rule, verify=False)
        action = "CREATED"
    if r.status_code in [200, 201]:
        print(f"  [{action}] {rule.get(chr(110)+chr(97)+chr(109)+chr(101))}")
    else:
        print(f"  [FAILED] {rule.get(chr(110)+chr(97)+chr(109)+chr(101))} -> {r.status_code}: {r.text}")
        sys.exit(1)

rule_files = list(RULES_DIR.rglob("*.json"))
print(f"\nDeploying {len(rule_files)} ELK rule(s) to {KIBANA_URL}...\n")
for rule_file in rule_files:
    deploy_rule(rule_file)
print(f"\nDeployment complete.")
