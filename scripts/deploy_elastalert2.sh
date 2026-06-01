#!/bin/bash
set -e

RULES_SRC="converted/elastalert2"
RULES_DEST="/etc/elastalert2/rules"
SSH_OPTS="-o StrictHostKeyChecking=no -i /tmp/ea2_key"

echo "$EA2_SSH_KEY" | base64 -d > /tmp/ea2_key
chmod 600 /tmp/ea2_key

echo "==> Copying ElastAlert2 rules..."
scp $SSH_OPTS -r ${RULES_SRC}/* \
    ${EA2_USER}@${EA2_HOST}:${RULES_DEST}/

echo "==> Restarting ElastAlert2..."
ssh $SSH_OPTS ${EA2_USER}@${EA2_HOST} \
    'sudo systemctl restart elastalert2'

echo "==> ElastAlert2 deployment done."