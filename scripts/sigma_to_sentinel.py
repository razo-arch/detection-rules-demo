#!/usr/bin/env python3
"""
Custom Sigma to Microsoft Sentinel KQL converter.
Generates valid Sentinel analytic rule queries.
"""

import sys
import yaml
from pathlib import Path

def sigma_to_sentinel_kql(sigma_file: Path) -> str:
    with open(sigma_file) as f:
        rule = yaml.safe_load(f)

    title       = rule.get("title", "Sigma Rule")
    detection   = rule.get("detection", {})
    conditions  = []

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field, patterns in val.items():
                field_name = field.split("|")[0]
                # Map Sigma field names to Sentinel DeviceProcessEvents fields
                field_map = {
                    "CommandLine":       "ProcessCommandLine",
                    "Image":             "FolderPath",
                    "ParentImage":       "InitiatingProcessFolderPath",
                    "TargetImage":       "FolderPath",
                    "ParentCommandLine": "InitiatingProcessCommandLine",
                }
                sentinel_field = field_map.get(field_name, field_name)
                if isinstance(patterns, list):
                    parts = " or ".join(
                        f'{sentinel_field} has "{p}"' for p in patterns
                    )
                    conditions.append(f"({parts})")
                elif isinstance(patterns, str):
                    conditions.append(f'{sentinel_field} has "{patterns}"')

    where_clause = "\n| where ".join(conditions) if conditions else "true"

    kql = f"""DeviceProcessEvents
| where {where_clause}
| project TimeGenerated, DeviceName, FolderPath, ProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by TimeGenerated desc
"""
    return kql


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sigma_to_sentinel.py <input.yml> <output.kql>")
        sys.exit(1)

    sigma_file  = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(sigma_to_sentinel_kql(sigma_file))
    print(f"[PASS] Sentinel KQL written to {output_file}")