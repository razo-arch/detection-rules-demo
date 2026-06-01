#!/bin/bash
set -e

SIGMA_DIR="sigma/rules"
OUT_DIR="converted"

echo ""
echo "==> Installing Sigma backends..."
pip install -q sigma-cli \
  pySigma-backend-elasticsearch \
  pySigma-backend-kusto \
  pyyaml

echo ""
echo "==> Installing Sigma plugins..."
sigma plugin install elasticsearch 2>/dev/null || true
sigma plugin install kusto 2>/dev/null || true

mkdir -p ${OUT_DIR}/elk
mkdir -p ${OUT_DIR}/wazuh
mkdir -p ${OUT_DIR}/elastalert2
mkdir -p ${OUT_DIR}/sentinel

RULE_COUNT=0

for rule in $(find ${SIGMA_DIR} -name "*.yml"); do

  BASENAME=$(basename "$rule" .yml)
  SUBDIR=$(dirname "$rule" | sed "s|${SIGMA_DIR}/||")

  mkdir -p ${OUT_DIR}/elk/${SUBDIR}
  mkdir -p ${OUT_DIR}/wazuh/${SUBDIR}
  mkdir -p ${OUT_DIR}/elastalert2/${SUBDIR}
  mkdir -p ${OUT_DIR}/sentinel/${SUBDIR}

  echo ""
  echo "  Processing: $rule"

  # ELK - EQL format
  sigma convert -t elasticsearch -f eql -p sysmon \
    "$rule" -o "${OUT_DIR}/elk/${SUBDIR}/${BASENAME}.json" 2>/dev/null \
    && echo "    [PASS] ELK EQL" || echo "    [WARN] ELK EQL skipped"

  # ELK - KQL/Kibana format
  sigma convert -t elasticsearch -f kibana_ndjson \
    "$rule" -o "${OUT_DIR}/elk/${SUBDIR}/${BASENAME}.ndjson" 2>/dev/null \
    && echo "    [PASS] ELK KQL" || echo "    [WARN] ELK KQL skipped"

  # Wazuh XML (custom converter)
  python3 scripts/sigma_to_wazuh.py \
    "$rule" "${OUT_DIR}/wazuh/${SUBDIR}/${BASENAME}.xml" \
    && echo "    [PASS] Wazuh" || echo "    [WARN] Wazuh skipped"

  # ElastAlert2 (custom converter)
  python3 scripts/sigma_to_elastalert2.py \
    "$rule" "${OUT_DIR}/elastalert2/${SUBDIR}/${BASENAME}.yml" \
    && echo "    [PASS] ElastAlert2" || echo "    [WARN] ElastAlert2 skipped"

  # Microsoft Sentinel KQL (via kusto backend - no pipeline needed)
  sigma convert -t kusto \
    "$rule" -o "${OUT_DIR}/sentinel/${SUBDIR}/${BASENAME}.kql" 2>/dev/null \
    && echo "    [PASS] Sentinel KQL" || echo "    [WARN] Sentinel KQL skipped"

  RULE_COUNT=$((RULE_COUNT + 1))
done

echo ""
echo "==> Conversion complete. Processed ${RULE_COUNT} rule(s)."