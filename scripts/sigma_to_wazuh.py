#!/usr/bin/env python3
"""
Custom Sigma → Wazuh XML converter.
Reads a Sigma YAML rule and outputs a Wazuh XML rule.
"""

import sys
import uuid
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
    description = rule.get("description", title).strip().replace("\n", " ")
    level       = rule.get("level", "medium").lower()
    rule_level  = LEVEL_MAP.get(level, 10)
    tags        = rule.get("tags", [])
    mitre_tags  = [t for t in tags if t.startswith("attack.")]

    # Stable rule ID derived from sigma ID so it never changes
    sigma_id = rule.get("id", str(uuid.uuid4()))
    rule_id  = 100000 + (int(sigma_id.replace("-", ""), 16) % 9000)

    detection = rule.get("detection", {})
    conditions = []

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field, patterns in val.items():
                if "|" in field:
                    field_name = field.split("|")[0]
                else:
                    field_name = field
                if isinstance(patterns, list):
                    for p in patterns:
                        conditions.append(f'<field name="{field_name}" type="pcre2">{p}</field>')
                elif isinstance(patterns, str):
                    conditions.append(f'<field name="{field_name}" type="pcre2">{patterns}</field>')

    if not conditions:
        conditions.append(f'<description>Sigma: {title}</description>')

    mitre_block = ""
    if mitre_tags:
        mitre_block = "\n      " + "\n      ".join(
            f'<mitre><id>{t.replace("attack.", "").upper()}</id></mitre>'
            for t in mitre_tags[:3]
        )

    xml = f"""<group name="sigma,">
  <rule id="{rule_id}" level="{rule_level}">
    <description>Sigma: {title}</description>
    {"".join(chr(10)+"    "+c for c in conditions)}
    <info type="text">{description}</info>{mitre_block}
  </rule>
</group>"""
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
    print(f"[PASS] Wazuh XML → {output_file}")
