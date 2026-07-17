#!/usr/bin/env bash
# Deterministically exercises ONE branch of ddos_score_alert.py's decision
# by posting a synthetic alert directly to the Shuffle DDoS webhook —
# bypassing Wazuh/real flood traffic entirely, so the score is exact and
# repeatable instead of depending on however much real traffic happened to
# land.
#
# Scoring recap (roles/shuffle/files/ddos_score_alert.py):
#   D1 rule level:   >=12 -> +40   >=10 -> +25   else -> +0
#   D2 24h history:  >=20 -> +30   >=5  -> +20   else -> +0
#   D3 AbuseIPDB:    >=80 -> +70   >=50 -> +40   else -> +0
#   >=70 AUTO_BLOCK | 40-69 NOTIFY_SOC | <40 LOG_ONLY
#
# AbuseIPDB always returns abuseConfidenceScore=0 for the private/
# documentation-range test IPs used here (verified live), so D3 never
# contributes in this lab — AUTO_BLOCK is reached via D1+D2 (level 12 +
# 20 seeded history hits), matching the ddos-plan.txt design note that D3
# alone is what would auto-block in a real deployment with public IPs.
#
# Usage:
#   ./test_scoring.sh log_only|notify_soc|auto_block|auto_block_error_flood [srcip]
#
# A fresh random srcip is generated if you don't pass one, so dedupe_check
# and 24h history never collide with a previous test run.
#
# Note: this script posts straight to the Shuffle DDoS webhook, bypassing
# custom-shuffle.py entirely - it proves the SCORING path only, never the
# DDOS_FORWARD_RULE_IDS gate that decides whether a real Wazuh alert reaches
# Shuffle at all. Only ./run_attack.sh's real-traffic cases exercise that.

set -euo pipefail

CASE="${1:?Usage: $0 log_only^|notify_soc^|auto_block^|auto_block_error_flood [srcip]}"
SRCIP="${2:-203.0.113.$((RANDOM % 200 + 30))}"

MANAGER_CONTAINER="single-node-wazuh.manager-1"
INDEXER_URL="https://127.0.0.1:9200"
INDEXER_USER="admin"
INDEXER_PASS="SecretPassword"

case "$CASE" in
    log_only)
        RULE_LEVEL=8
        RULE_ID=100210
        RULE_DESC="HTTP rate spike (synthetic)"
        ;;
    notify_soc)
        RULE_LEVEL=12
        RULE_ID=100213
        RULE_DESC="Confirmed DDoS (synthetic)"
        ;;
    auto_block)
        RULE_LEVEL=12
        RULE_ID=100213
        RULE_DESC="Confirmed DDoS (synthetic)"
        INDEX_NAME="wazuh-alerts-4.x-$(date -u +%Y.%m.%d)"
        echo "Seeding 22 synthetic history docs for $SRCIP in $INDEX_NAME (needed for D2 >=20 -> +30)..."
        {
            for i in $(seq 1 22); do
                echo "{\"index\":{\"_index\":\"$INDEX_NAME\"}}"
                echo "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S).000Z\",\"data\":{\"srcip\":\"$SRCIP\"},\"rule\":{\"id\":\"100210\",\"level\":8}}"
            done
        } | curl -sk -u "$INDEXER_USER:$INDEXER_PASS" -X POST "$INDEXER_URL/_bulk" \
            -H "Content-Type: application/x-ndjson" --data-binary @- \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print('  bulk insert errors:', d.get('errors'))"
        curl -sk -u "$INDEXER_USER:$INDEXER_PASS" -X POST "$INDEXER_URL/wazuh-alerts-*/_refresh" >/dev/null
        ;;
    auto_block_error_flood)
        # Same score band as auto_block (level 12 -> D1=+40), but using the
        # generic-4xx-flood rule id (100222) instead of the HTTP-flood rule
        # id (100213) - proves D1 scoring only cares about rule_level, never
        # rule_id (see ddos_score_alert.py's Dimension 1).
        RULE_LEVEL=12
        RULE_ID=100222
        RULE_DESC="Confirmed 4xx error-flood DDoS (synthetic)"
        INDEX_NAME="wazuh-alerts-4.x-$(date -u +%Y.%m.%d)"
        echo "Seeding 22 synthetic history docs for $SRCIP in $INDEX_NAME (needed for D2 >=20 -> +30)..."
        {
            for i in $(seq 1 22); do
                echo "{\"index\":{\"_index\":\"$INDEX_NAME\"}}"
                echo "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S).000Z\",\"data\":{\"srcip\":\"$SRCIP\"},\"rule\":{\"id\":\"100221\",\"level\":8}}"
            done
        } | curl -sk -u "$INDEXER_USER:$INDEXER_PASS" -X POST "$INDEXER_URL/_bulk" \
            -H "Content-Type: application/x-ndjson" --data-binary @- \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print('  bulk insert errors:', d.get('errors'))"
        curl -sk -u "$INDEXER_USER:$INDEXER_PASS" -X POST "$INDEXER_URL/wazuh-alerts-*/_refresh" >/dev/null
        ;;
    *)
        echo "Usage: $0 log_only|notify_soc|auto_block|auto_block_error_flood [srcip]" >&2
        exit 1
        ;;
esac

WEBHOOK_URL=$(docker exec "$MANAGER_CONTAINER" grep -m1 '^DDOS_WEBHOOK_URL' /var/ossec/integrations/custom-shuffle \
    | sed -E 's/.*"(http[^"]+)".*/\1/')

if [[ -z "$WEBHOOK_URL" ]]; then
    echo "ERROR: could not find DDOS_WEBHOOK_URL in custom-shuffle on $MANAGER_CONTAINER" >&2
    exit 1
fi

echo "=== Firing synthetic '$CASE' alert: srcip=$SRCIP rule=$RULE_ID level=$RULE_LEVEL ==="
echo "Webhook: $WEBHOOK_URL"
RESP=$(curl -sk -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "{
  \"id\": \"test-$CASE-$(date +%s)\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)\",
  \"rule\": {\"id\": \"$RULE_ID\", \"level\": $RULE_LEVEL, \"description\": \"$RULE_DESC\"},
  \"agent\": {\"id\": \"007\", \"name\": \"dmz-ubuntu\"},
  \"data\": {\"srcip\": \"$SRCIP\"}
}")
echo "$RESP"

cat <<EOF

Expected: srcip=$SRCIP should score toward '$CASE'.
Check the actual decision in Shuffle UI -> Workflows -> "Wazuh DDoS Auto-Response" -> Runs
(look for the score_alert node's output), or via the API once you have the
current workflow id:
  curl -sk -H "Authorization: Bearer <shuffle_default_apikey>" \\
    http://127.0.0.1:5001/api/v1/workflows/<workflow_id>/executions
EOF
