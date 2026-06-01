#!/bin/bash
set -e

REMOTE_RULES_DIR="/var/ossec/etc/rules"
LOCAL_RULES_DIR="converted/wazuh"
SSH_OPTS="-o StrictHostKeyChecking=no -i /tmp/wazuh_key"

echo "==> Writing SSH key..."
echo "$WAZUH_SSH_KEY" | base64 -d > /tmp/wazuh_key
chmod 600 /tmp/wazuh_key

echo "==> Creating remote temp directory..."
ssh $SSH_OPTS ${WAZUH_USER}@${WAZUH_HOST} 'mkdir -p /tmp/sigma-rules'

echo "==> Validating rules before deploy..."
for f in $(find ${LOCAL_RULES_DIR} -name "*.xml"); do
    xmllint --noout "$f" || { echo "Invalid XML: $f"; exit 1; }
done

echo "==> Copying rules to Wazuh Manager..."
find ${LOCAL_RULES_DIR} -name "*.xml" | while read f; do
    scp $SSH_OPTS "$f" ${WAZUH_USER}@${WAZUH_HOST}:/tmp/sigma-rules/
done

echo "==> Moving rules to Wazuh rules directory..."
ssh $SSH_OPTS ${WAZUH_USER}@${WAZUH_HOST} 'sudo cp /tmp/sigma-rules/*.xml /var/ossec/etc/rules/'

echo "==> Reloading Wazuh Manager..."
ssh $SSH_OPTS ${WAZUH_USER}@${WAZUH_HOST} 'sudo /var/ossec/bin/wazuh-control reload'

echo "==> Wazuh deployment complete."