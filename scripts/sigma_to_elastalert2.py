#!/usr/bin/env python3
"""
Custom Sigma to ElastAlert2 YAML converter.
Reads a Sigma YAML rule and outputs an ElastAlert2 rule.
"""

import sys
import yaml
from pathlib import Path

LEVEL_MAP = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

def sigma_to_elastalert2(sigma_file: Path) -> str:
    with open(sigma_file) as f:
        rule = yaml.safe_load(f)

    title       = rule.get("title", "Sigma Rule")
    description = rule.get("description", title)
    if isinstance(description, str):
        description = description.strip().replace("\n", " ")
    level    = rule.get("level", "medium").lower()
    priority = LEVEL_MAP.get(level, 3)

    detection = rule.get("detection", {})
    filters   = []

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field, patterns in val.items():
                field_name = field.split("|")[0]
                if isinstance(patterns, list):
                    for p in patterns:
                        filters.append(
                            f'      - query_string:\n'
                            f'          query: "{field_name}: *{p}*"'
                        )
                elif isinstance(patterns, str):
                    filters.append(
                        f'      - query_string:\n'
                        f'          query: "{field_name}: *{patterns}*"'
                    )

    filters_block = "\n".join(filters) if filters else \
        f'      - query_string:\n          query: "{title}"'

    output = f"""# AUTO-GENERATED from Sigma rule - DO NOT EDIT
# Source: {sigma_file}

name: "{title}"
type: any
index: wazuh-alerts-4.x-*

filter:
  - bool:
      should:
{filters_block}

alert:
  - debug

priority: {priority}

realert:
  minutes: 30

description: "{description}"
"""
    return output


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sigma_to_elastalert2.py <input.yml> <output.yml>")
        sys.exit(1)

    sigma_file  = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(sigma_to_elastalert2(sigma_file))
    print(f"[PASS] ElastAlert2 YAML written to {output_file}")