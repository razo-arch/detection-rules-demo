#!/usr/bin/env python3
"""
Custom Sigma to Wazuh XML converter.
Reads a Sigma YAML rule and outputs a Wazuh XML rule.
"""

import sys
import yaml
from pathlib import Path

LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 10,
    "high": 12,
    "critical": 15,
}

def sigma_to_wazuh_xml(sigma_file: Path) -> str:
    with open(sigma_file) as f:
        rule = yaml.safe_load(f)

    title       = rule.get("title", "Sigma Rule")
    description = rule.get("description", title)
    if isinstance(description, str):
        description = description.strip().replace("\n", " ")
    level      = rule.get("level", "medium").lower()
    rule_level = LEVEL_MAP.get(level, 10)
    tags       = rule.get("tags", [])

    # Stable rule ID derived from sigma ID
    sigma_id = rule.get("id", "00000000-0000-0000-0000-000000000000")
    clean_id = sigma_id.replace("-", "")
    rule_id  = 100000 + (int(clean_id, 16) % 9000)

    detection = rule.get("detection", {})
    conditions = []

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field, patterns in val.items():
                field_name = field.split("|")[0]
                if isinstance(patterns, list):
                    for p in patterns:
                        safe = str(p).replace("\\", "\\\\").replace('"', '&quot;')
                        conditions.append(
                            f'    <field name="{field_name}" type="pcre2">{safe}</field>'
                        )
                elif isinstance(patterns, str):
                    safe = patterns.replace("\\", "\\\\").replace('"', '&quot;')
                    conditions.append(
                        f'    <field name="{field_name}" type="pcre2">{safe}</field>'
                    )

    mitre_lines = []
    for t in tags:
        if t.startswith("attack.t"):
            tid = t.replace("attack.", "").upper()
            mitre_lines.append(f'    <mitre><id>{tid}</id></mitre>')

    conditions_block = "\n".join(conditions) if conditions else \
        f'    <field name="full_log" type="pcre2">{title}</field>'

    mitre_block = "\n" + "\n".join(mitre_lines) if mitre_lines else ""

    xml = f"""<group name="sigma,custom,">
  <rule id="{rule_id}" level="{rule_level}">
    <description>Sigma: {title}</description>
{conditions_block}
    <info type="text">{description}</info>{mitre_block}
  </rule>
</group>
"""
    return xml


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sigma_to_wazuh.py <input.yml> <output.xml>")
        sys.exit(1)

    sigma_file  = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    output_file.parent.mkdir(parents=True, exist_ok=True)
    xml = sigma_to_wazuh_xml(sigma_file)
    output_file.write_text(xml)
    print(f"[PASS] Wazuh XML written to {output_file}")