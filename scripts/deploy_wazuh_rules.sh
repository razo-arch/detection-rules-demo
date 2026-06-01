#!/bin/bash
set -e

REMOTE_RULES_DIR="/var/ossec/etc/rules"
LOCAL_RULES_DIR="converted/wazuh"
SSH_OPTS="-o StrictHostKeyChecking=no -i /tmp/wazuh_key"

echo "==> Writing SSH key..."
echo "$WAZUH_SSH_KEY" | base64 -d > /tmp/wazuh_key
chmod 600 /tmp/wazuh_key

echo "==> Validating rules before deploy..."
for f in $(find ${LOCAL_RULES_DIR} -name "*.xml"); do
    xmllint --noout "$f" || { echo "Invalid XML: $f"; exit 1; }
done

echo "==> Copying rules to Wazuh Manager..."
scp $SSH_OPTS -r ${LOCAL_RULES_DIR}/* \
    ${WAZUH_USER}@${WAZUH_HOST}:/tmp/sigma-rules/

echo "==> Moving rules to Wazuh rules directory..."
ssh $SSH_OPTS ${WAZUH_USER}@${WAZUH_HOST} \
    'sudo cp -r /tmp/sigma-rules/*.xml /var/ossec/etc/rules/ 2>/dev/null; sudo cp -r /tmp/sigma-rules/**/*.xml /var/ossec/etc/rules/ 2>/dev/null || true'

echo "==> Reloading Wazuh Manager..."
ssh $SSH_OPTS ${WAZUH_USER}@${WAZUH_HOST} \
    'sudo /var/ossec/bin/wazuh-control reload'

echo "==> Wazuh deployment complete."
