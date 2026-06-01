#!/usr/bin/env python3
"""Deploys converted KQL rules to Microsoft Sentinel as Analytic Rules."""

import os
import requests
from pathlib import Path

TENANT_ID       = os.environ["AZURE_TENANT_ID"]
CLIENT_ID       = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET   = os.environ["AZURE_CLIENT_SECRET"]
SUBSCRIPTION_ID = os.environ["AZURE_SUBSCRIPTION_ID"]
RESOURCE_GROUP  = os.environ["AZURE_RESOURCE_GROUP"]
WORKSPACE_NAME  = os.environ["SENTINEL_WORKSPACE_NAME"]

RULES_DIR = Path("converted/sentinel")

def get_token():
    print(f"[INFO] Requesting Azure token for tenant {TENANT_ID[:8]}...")
    r = requests.post(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope":         "https://management.azure.com/.default"
        }
    )
    if r.status_code != 200:
        print(f"[ERROR] Token request failed {r.status_code}: {r.text}")
        raise Exception("Authentication failed")
    print(f"[OK] Token acquired successfully")
    return r.json()["access_token"]

def deploy_rule(kql_file, token):
    rule_name = kql_file.stem.replace("_", "-")
    kql_query = kql_file.read_text()

    print(f"[INFO] Deploying rule: {rule_name}")
    print(f"[INFO] KQL query length: {len(kql_query)} chars")

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/alertRules/{rule_name}"
        f"?api-version=2023-02-01"
    )

    print(f"[INFO] URL: {url}")

    payload = {
        "kind": "Scheduled",
        "properties": {
            "displayName":         rule_name.replace("-", " ").title(),
            "description":         "Deployed via Detection-as-Code pipeline from Sigma rule",
            "severity":            "High",
            "enabled":             True,
            "query":               kql_query,
            "queryFrequency":      "PT5M",
            "queryPeriod":         "PT1H",
            "triggerOperator":     "GreaterThan",
            "triggerThreshold":    0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled":  False,
            "tactics":             ["CredentialAccess"],
        }
    }

    r = requests.put(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json"
        },
        json=payload
    )

    if r.status_code in [200, 201]:
        print(f"  [DEPLOYED] {rule_name}")
    else:
        print(f"  [FAILED]   {rule_name} → {r.status_code}: {r.text}")

print(f"[INFO] Scanning {RULES_DIR} for .kql files...")
kql_files = list(RULES_DIR.rglob("*.kql"))
print(f"[INFO] Found {len(kql_files)} rule(s)")

if not kql_files:
    print("[WARN] No .kql files found - nothing to deploy")
else:
    token = get_token()
    for kql_file in kql_files:
        deploy_rule(kql_file, token)

print("[INFO] Sentinel deployment complete")