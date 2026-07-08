#!/bin/bash
# Wazuh Active Response — block a source IP on ports 80/443 only (iptables).
# Manual/API-triggered only (ddos-plan.txt Part 3): this command has no
# rules_id in ossec.conf, so it never fires automatically off an alert match —
# Shuffle calls it via PUT /active-response after the N5 scoring node returns
# AUTO_BLOCK. Wazuh re-invokes this script with "delete" after the AR
# <timeout> (5 min) expires, so a mis-scored legitimate user recovers on
# their own.
# Reads JSON from stdin per Wazuh AR protocol; supports add/delete commands.
# Lives at /var/ossec/active-response/bin/ip-limit.sh on the agent.
#
# Reads exactly ONE line, not to EOF: wazuh-execd sends the payload as a
# single newline-terminated line but does not reliably close its end of the
# stdin pipe afterward (confirmed live, matches known unresolved upstream
# bugs — wazuh/wazuh#25784 "Active Response gets stuck after first
# execution" and wazuh/wazuh#25915). `INPUT_JSON=$(cat)` blocks forever
# waiting for EOF that never arrives, permanently wedging that pipe (and,
# per #25784, apparently execd's ability to service later AR requests too)
# until the agent is restarted. `read -r` returns as soon as it sees the
# newline, matching the documented AR stdin protocol exactly and sidestepping
# the bug entirely.

LOG_FILE="/var/ossec/logs/active-responses.log"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') ip-limit: $1" >> "$LOG_FILE"
}

IFS= read -r INPUT_JSON
[ -z "$INPUT_JSON" ] && { log "no stdin"; exit 1; }

COMMAND=$(echo "$INPUT_JSON" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("command", ""))
except Exception:
    print("")
')

SRCIP=$(echo "$INPUT_JSON" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    alert = d.get("parameters", {}).get("alert", {})
    print(alert.get("data", {}).get("srcip") or alert.get("srcip", ""))
except Exception:
    print("")
')

if [ -z "$SRCIP" ]; then
    log "no srcip in alert"
    exit 1
fi

RULE_ARGS=(-s "$SRCIP" -p tcp -m multiport --dports 80,443 -j DROP)

case "$COMMAND" in
    add)
        if iptables -C INPUT "${RULE_ARGS[@]}" 2>/dev/null; then
            log "$SRCIP already blocked on ports 80/443"
        else
            iptables -I INPUT "${RULE_ARGS[@]}"
            log "blocked $SRCIP on ports 80/443"
        fi
        ;;
    delete)
        while iptables -C INPUT "${RULE_ARGS[@]}" 2>/dev/null; do
            iptables -D INPUT "${RULE_ARGS[@]}"
        done
        log "unblocked $SRCIP"
        ;;
    *)
        log "unknown command: $COMMAND"
        exit 1
        ;;
esac

exit 0
