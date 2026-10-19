#!/bin/bash
# Wazuh Active Response — block a source IP on ports 80/443 only (iptables).
# Manual/API-triggered only (ddos-plan.txt Part 3): this command has no
# rules_id in ossec.conf, so it never fires automatically off an alert match —
# Shuffle calls it via PUT /active-response after the N5 scoring node returns
# AUTO_BLOCK. Reads JSON from stdin per Wazuh AR protocol; supports add/delete
# commands via stdin dispatch, plus --release/--check-expiry CLI paths for the
# self-managed auto-release timer (see below).
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
#
# AUTO-RELEASE: ar.conf's own <timeout>300</timeout> (see
# inject_active_response.py.j2) does NOT reliably auto-reverse an
# API-dispatched (PUT /active-response) command — confirmed live over a
# clean 320s window with zero manager restarts in between: the block stayed
# in place with no trace of any timeout-driven release in wazuh-execd's log
# even at debug=2. This appears to be a real gap in Wazuh 4.9.2's handling
# of manually-dispatched (not rule-triggered) stateful Active Response, not
# a config mistake on this repo's side — the exact same symptom this
# script's sibling (host-isolate.sh, see
# roles/insider_threat_agent_linux/templates/host-isolate.sh.j2) hit and
# worked around the same way: don't rely on Wazuh's native timeout at all,
# self-manage the release with a detached sleeper plus a periodic wodle
# backstop (roles/wazuh_ddos_rules's deploy_dmz_ubuntu_nginx.yml registers
# the matching wodle). Scoped PER-SRCIP here (unlike host-isolate's single
# global deadline file) since multiple different attacker IPs can be
# AUTO_BLOCKed concurrently.

SCRIPT_PATH="/var/ossec/active-response/bin/ip-limit.sh"
LOG_FILE="/var/ossec/logs/active-responses.log"
TIMEOUT_SECONDS=300

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ip-limit: $1" >> "$LOG_FILE"
}

# IPs are dotted-decimal only (validated indirectly: iptables itself rejects
# anything else when the rule is applied) — safe to use directly as a
# filename component without further sanitization.
deadline_file() { echo "/var/run/ip-limit-deadline-$1"; }
sleeper_pid_file() { echo "/var/run/ip-limit-sleeper-$1.pid"; }

rule_args() {
    echo -s "$1" -p tcp -m multiport --dports 80,443 -j DROP
}

is_blocked() {
    # shellcheck disable=SC2046
    iptables -C INPUT $(rule_args "$1") 2>/dev/null
}

do_block() {
    local srcip="$1"
    if is_blocked "$srcip"; then
        log "$srcip already blocked on ports 80/443"
    else
        # shellcheck disable=SC2046
        iptables -I INPUT $(rule_args "$srcip")
        log "blocked $srcip on ports 80/443"
    fi
}

do_unblock() {
    local srcip="$1"
    # shellcheck disable=SC2046
    while iptables -C INPUT $(rule_args "$srcip") 2>/dev/null; do
        # shellcheck disable=SC2046
        iptables -D INPUT $(rule_args "$srcip")
    done
}

kill_stale_sleeper() {
    local srcip="$1" pidfile old_pid
    pidfile=$(sleeper_pid_file "$srcip")
    if [ -f "$pidfile" ]; then
        old_pid=$(cat "$pidfile" 2>/dev/null)
        [ -n "$old_pid" ] && kill "$old_pid" 2>/dev/null
        rm -f "$pidfile"
    fi
}

# Re-triggering "add" for an IP already blocked (e.g. a second AUTO_BLOCK
# while the first window hasn't expired yet) resets the clock instead of
# racing two independent timers against the same deadline file.
start_timer() {
    local srcip="$1" deadlinefile pidfile deadline token sleeper_pid
    kill_stale_sleeper "$srcip"
    deadlinefile=$(deadline_file "$srcip")
    pidfile=$(sleeper_pid_file "$srcip")
    deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
    token="${deadline}_${RANDOM}${RANDOM}"
    echo "${deadline}:${token}" > "$deadlinefile"
    setsid bash -c "sleep ${TIMEOUT_SECONDS}; '${SCRIPT_PATH}' --release timer '${srcip}' '${token}'" </dev/null >/dev/null 2>&1 &
    sleeper_pid=$!
    disown
    echo "$sleeper_pid" > "$pidfile"
    log "auto-release in ${TIMEOUT_SECONDS}s for $srcip via detached sleeper pid ${sleeper_pid}, token ${token}"
}

do_release() {
    local source="$1" srcip="$2"
    kill_stale_sleeper "$srcip"
    do_unblock "$srcip"
    if is_blocked "$srcip"; then
        log "RELEASE FAILED released-by=${source} srcip=${srcip} - still blocked after unblock attempt"
    else
        log "auto-released (verified) released-by=${source} srcip=${srcip}"
        rm -f "$(deadline_file "$srcip")"
    fi
}

if [ "$1" = "--release" ]; then
    SOURCE="${2:-manual}"
    SRCIP="$3"
    TOKEN="$4"
    DEADLINEFILE=$(deadline_file "$SRCIP")
    if [ "$SOURCE" = "timer" ]; then
        CURRENT=$(cat "$DEADLINEFILE" 2>/dev/null)
        if [ -z "$CURRENT" ]; then
            # Already released by something else (manual delete, or the
            # wodle backstop) in the meantime - nothing to do.
            exit 0
        fi
        CURRENT_TOKEN="${CURRENT#*:}"
        if [ "$TOKEN" != "$CURRENT_TOKEN" ]; then
            log "stale timer fired for $SRCIP (token ${TOKEN}) - a newer block is active (token ${CURRENT_TOKEN}), ignoring"
            exit 0
        fi
    fi
    do_release "$SOURCE" "$SRCIP"
    exit 0
fi

if [ "$1" = "--check-expiry" ]; then
    now=$(date +%s)
    for deadlinefile in /var/run/ip-limit-deadline-*; do
        [ -e "$deadlinefile" ] || continue
        srcip="${deadlinefile#/var/run/ip-limit-deadline-}"
        content=$(cat "$deadlinefile" 2>/dev/null)
        deadline="${content%%:*}"
        if [ -n "$deadline" ] && [ "$now" -ge "$deadline" ]; then
            log "found expired deadline file for $srcip (was due ${deadline}, now ${now}) - releasing via wodle"
            do_release "wodle" "$srcip"
        fi
    done
    exit 0
fi

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

case "$COMMAND" in
    add)
        do_block "$SRCIP"
        start_timer "$SRCIP"
        ;;
    delete)
        do_release "manual" "$SRCIP"
        ;;
    *)
        log "unknown command: $COMMAND"
        exit 1
        ;;
esac

exit 0
