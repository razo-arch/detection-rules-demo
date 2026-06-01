#!/bin/bash
set -e

SIGMA_DIR="sigma/rules"
OUT_DIR="converted"

echo ""
echo "==> Installing Sigma backends..."
pip install -q sigma-cli \
  pySigma-backend-elasticsearch \
  pySigma-backend-wazuh \
  pySigma-backend-elastalert2 \
  pySigma-backend-microsoft365defender

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

  sigma convert -t elasticsearch -f eql -p sysmon \
    "$rule" -o "${OUT_DIR}/elk/${SUBDIR}/${BASENAME}.json" 2>/dev/null \
    && echo "    [PASS] ELK EQL" || echo "    [WARN] ELK EQL skipped"

  sigma convert -t elasticsearch -f kibana_ndjson \
    "$rule" -o "${OUT_DIR}/elk/${SUBDIR}/${BASENAME}.ndjson" 2>/dev/null \
    && echo "    [PASS] ELK KQL" || echo "    [WARN] ELK KQL skipped"

  sigma convert -t wazuh \
    "$rule" -o "${OUT_DIR}/wazuh/${SUBDIR}/${BASENAME}.xml" 2>/dev/null \
    && echo "    [PASS] Wazuh" || echo "    [WARN] Wazuh skipped"

  sigma convert -t elastalert2 -p sysmon \
    "$rule" -o "${OUT_DIR}/elastalert2/${SUBDIR}/${BASENAME}.yml" 2>/dev/null \
    && echo "    [PASS] ElastAlert2" || echo "    [WARN] ElastAlert2 skipped"

  sigma convert -t microsoft365defender -f kusto \
    "$rule" -o "${OUT_DIR}/sentinel/${SUBDIR}/${BASENAME}.kql" 2>/dev/null \
    && echo "    [PASS] Sentinel KQL" || echo "    [WARN] Sentinel KQL skipped"

  RULE_COUNT=$((RULE_COUNT + 1))
done

echo ""
echo "==> Conversion complete. Processed ${RULE_COUNT} rule(s)."