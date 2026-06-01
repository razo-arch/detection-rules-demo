#!/bin/bash
echo ""
echo "Validating Wazuh rules..."
echo ""

ERRORS=0

for rule_file in wazuh/rules/*.xml; do
    xmllint --noout "$rule_file" 2>&1
    if [ $? -ne 0 ]; then
        echo "  [FAIL] Invalid XML: $rule_file"
        ERRORS=$((ERRORS + 1))
    else
        echo "  [PASS] $rule_file"
    fi

    INVALID_IDS=$(grep -oP 'id="\K[0-9]+' "$rule_file" | awk '$1 < 100000')
    if [ -n "$INVALID_IDS" ]; then
        echo "  [FAIL] $rule_file: Rule IDs must be >= 100000. Found: $INVALID_IDS"
        ERRORS=$((ERRORS + 1))
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "$ERRORS validation error(s) found."
    exit 1
fi

echo ""
echo "All Wazuh rules passed validation."
