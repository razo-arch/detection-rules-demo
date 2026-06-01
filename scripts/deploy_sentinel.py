#!/usr/bin/env python3
"""Deploys converted KQL rules to Microsoft Sentinel as Analytic Rules."""

import os
import json
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
    r = requests.post(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope":         "https://management.azure.com/.default"
        }
    )
    return r.json()["access_token"]

def deploy_rule(kql_file, token):
    rule_name = kql_file.stem.replace("_", "-")
    kql_query = kql_file.read_text()

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/alertRules/{rule_name}"
        f"?api-version=2023-02-01"
    )

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

token = get_token()
for kql_file in RULES_DIR.rglob("*.kql"):
    deploy_rule(kql_file, token)