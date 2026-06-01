#!/bin/bash
set -e

REMOTE_RULES_DIR="/var/ossec/etc/rules"
LOCAL_RULES_DIR="wazuh/rules"
SSH_OPTS="-o StrictHostKeyChecking=no -i /tmp/wazuh_key"

echo "==> Writing SSH key..."
echo "$WAZUH_SSH_KEY" | base64 -d > /tmp/wazuh_key
chmod 600 /tmp/wazuh_key

echo "==> Validating rules before deploy..."
for f in ${LOCAL_RULES_DIR}/*.xml; do
    xmllint --noout "$f" || { echo "Invalid XML: $f"; exit 1; }
done

echo "==> Copying rules to Wazuh Manager..."
scp $SSH_OPTS ${LOCAL_RULES_DIR}/*.xml \
    ${WAZUH_USER}@${WAZUH_HOST}:${REMOTE_RULES_DIR}/

echo "==> Reloading Wazuh Manager..."
ssh $SSH_OPTS ${WAZUH_USER}@${WAZUH_HOST} \
    'sudo /var/ossec/bin/wazuh-control reload'

echo "==> Wazuh deployment complete."
