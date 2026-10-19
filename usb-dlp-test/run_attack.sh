#!/usr/bin/env bash
# Simulates insider file-write "attacks" against the simulated removable disk
# (C:\SimulatedUSB on dmz-windows) and verifies the FULL real pipeline end to
# end: real file write -> Wazuh FIM -> rule 100500 -> custom-shuffle forward
# -> Shuffle scoring (roles/shuffle/files/usb_dlp_score_alert.py) ->
# ESCALATE_AND_CONTAIN / NOTIFY_SOC / LOG_ONLY, including the REAL Active
# Response write-block for the escalate case (verified via icacls, not just
# a log line).
#
# Unlike ddos-attacker/test_scoring.sh (which posts a synthetic payload
# straight to the Shuffle webhook, bypassing Wazuh entirely), this script
# writes REAL files on the real dmz-windows agent via Ansible/WinRM, so it
# proves the whole chain - including the rule-100500 detection itself and
# custom-shuffle's forwarding - not just the scoring math in isolation.
#
# Usage:
#   ./run_attack.sh [log_only|notify_soc|escalate|all]
#
# Scoring recap (roles/shuffle/files/usb_dlp_score_alert.py):
#   D1 file size:  >100MB->25   10-100MB->15   1-10MB->10   <1MB->5
#   D2 extension:  zip/7z/rar->25   xlsx/csv/docx/pdf/txt->20   jpg/png->5
#   D3 time:       outside business hours (Asia/Taipei, Mon-Fri 09-18)->10
#   D4 history:    >=10 hits/10min->40   >=5->25   >=2->10
#   score >=60 ESCALATE_AND_CONTAIN | 40-59 NOTIFY_SOC | <40 LOG_ONLY
#
# D3 depends on the REAL wall-clock time when the alert fires - a real file
# write can't fake its own timestamp the way a synthetic webhook payload
# can. So each case below is deliberately built to land in its target band
# using ONLY D1+D2+D4 (all controllable), regardless of what D3 contributes:
#   log_only:   small .dat, no history buildup            -> 5+0+(0|10)+0  = 5-15
#   notify_soc: ~5MB .docx, history built to >=2 (+10)     -> 10+20+(0|10)+10 = 40-50
#   escalate:   >100MB .zip, history built to >=2 (+10)    -> 25+25+(0|10)+10 = 60-70
# Both notify_soc and escalate already clear their floor (40 / 60) from
# D1+D2+D4 alone, so D3's swing (+0 or +10 depending on time of day) can
# only push them further INTO their intended band (or, worst case for
# notify_soc, into escalate - see the note printed at runtime).
#
# History (D4) is keyed per-agent (dmz-windows = agent 006), not per-file,
# and the window is a rolling 10 minutes - so running this script back to
# back, or two cases within 10 minutes of each other, lets earlier runs'
# history bleed into later ones. `all` runs log_only FIRST for exactly this
# reason (before any buildup happens), and each case's own filler-write
# count is chosen to reliably clear its own floor even without contamination
# - but if you run individual cases repeatedly within 10 minutes, don't be
# surprised if notify_soc scores as escalate (documented, not a bug: D4
# doesn't know why a hit happened, only that it did). For a fully clean
# read, wait 10 minutes between invocations.
#
# Also documented (README.md / earlier live testing): rule 100500 can fire
# TWICE for a single real file write (Wazuh syscheck sometimes emits both an
# "added" and a near-simultaneous "modified" event for the same file). Each
# firing is forwarded and scored independently - this script accounts for
# that when reading back results (it reports every matching execution, not
# just the first).
#
# IMPORTANT FINDING (confirmed live, not a bug in this repo): the stock
# Wazuh Windows agent MSI ships a GLOBAL syscheck <ignore type="sregex">
# pattern - ".log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$" - in
# ossec.conf's default <syscheck> block. This silently drops FIM events for
# ANY monitored path, including C:\SimulatedUSB, for those extensions -
# meaning a real .jpg/.png write to the simulated disk NEVER reaches rule
# 100500, and D2's "image -> +5" scoring category (usb_dlp_score_alert.py)
# can never actually be exercised by a real file in this environment as
# currently configured. This is why log_only below uses .txt, not .jpg/
# .png - a real image-extension test would silently produce zero alerts
# and look like a detection failure. If you want real jpg/png coverage,
# that ignore pattern needs to be edited out of ossec.conf (it's global,
# not scoped to one directory - affects all monitored paths, so that's a
# deliberate decision to make separately, not done here).

set -euo pipefail

CASE="${1:-all}"
case "$CASE" in
    log_only|notify_soc|escalate|all) ;;
    *)
        echo "Usage: $0 [log_only|notify_soc|escalate|all]" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INVENTORY="$REPO_ROOT/inventory/hosts.ini"
HOST="dmz-windows"
MANAGER_CONTAINER="single-node-wazuh.manager-1"
SIMULATED_PATH='C:\SimulatedUSB'
RUN_ID="$(date +%s)"

# ── Pull the currently-live Shuffle wiring straight from the deployed
#    integration script, not from group_vars - group_vars' shuffle_*_id
#    values are templating INPUTS; Shuffle re-generates its own internal
#    workflow/trigger UUIDs on every `configure_integration.yml` import (see
#    that playbook's own comment on this), so the only ground truth for
#    "what's actually wired up right now" is what got baked into
#    custom-shuffle at the last deploy. ────────────────────────────────────
USB_DLP_WEBHOOK_URL="$(docker exec "$MANAGER_CONTAINER" grep -m1 '^USB_DLP_WEBHOOK_URL' /var/ossec/integrations/custom-shuffle \
    | sed -E 's/.*"(http[^"]+)".*/\1/')"
SHUFFLE_API_KEY="$(docker exec "$MANAGER_CONTAINER" grep -m1 '^SHUFFLE_API_KEY' /var/ossec/integrations/custom-shuffle \
    | sed -E 's/.*"([^"]+)".*/\1/')"
SHUFFLE_TRIGGER_ID="$(echo "$USB_DLP_WEBHOOK_URL" | sed -E 's#.*/hooks/webhook_##')"
SHUFFLE_BASE_URL="$(echo "$USB_DLP_WEBHOOK_URL" | sed -E 's#(https?://[^/]+).*#\1#')"

if [[ -z "$USB_DLP_WEBHOOK_URL" || -z "$SHUFFLE_API_KEY" ]]; then
    echo "ERROR: could not read USB_DLP_WEBHOOK_URL / SHUFFLE_API_KEY from custom-shuffle on $MANAGER_CONTAINER" >&2
    echo "       Has configure_integration.yml been run since deploy_usb_dlp_response.yml?" >&2
    exit 1
fi

WORKFLOW_ID="$(curl -sk -H "Authorization: Bearer $SHUFFLE_API_KEY" "$SHUFFLE_BASE_URL/api/v1/workflows" \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
for w in d:
    if w.get('triggers') and w['triggers'][0]['id'] == '$SHUFFLE_TRIGGER_ID':
        print(w['id'])
        break
")"

if [[ -z "$WORKFLOW_ID" ]]; then
    echo "ERROR: could not find the Shuffle workflow wired to trigger $SHUFFLE_TRIGGER_ID" >&2
    exit 1
fi

echo "=== Live wiring: workflow=$WORKFLOW_ID  trigger=$SHUFFLE_TRIGGER_ID ==="

win_shell() {
    ansible -i "$INVENTORY" "$HOST" -m ansible.windows.win_shell -a "$1" 2>&1 | tail -n +2
}

# Unconditionally clear any write-block left over from a previous run
# before starting (mirrors ddos-attacker/run_attack.sh's "docker rm -f
# unconditionally at the top" philosophy) - otherwise every write_file
# below fails silently (Access Denied) and rule 100500 never fires, which
# looks identical to a real detection failure. Confirmed live: this exact
# failure mode happened when a prior escalate test's block wasn't released.
echo "Ensuring $SIMULATED_PATH isn't left write-blocked from a previous run..."
win_shell "icacls $SIMULATED_PATH /remove:d Everyone 2>\$null" >/dev/null || true

write_file() {
    local name="$1" size="$2"
    local out
    out="$(win_shell "\$b = New-Object byte[] $size; (New-Object Random).NextBytes(\$b); [IO.File]::WriteAllBytes('$SIMULATED_PATH\\$name', \$b); 'WROTE_OK'")"
    if [[ "$out" != *"WROTE_OK"* ]]; then
        echo "  [FAIL] could not write $name - $SIMULATED_PATH may still be write-blocked:" >&2
        echo "$out" | sed 's/^/    /' >&2
        return 1
    fi
}

# Builds D4 (history) up to >=2 hits for the agent by writing $1 small,
# harmless filler files a few seconds apart (real rule-100500 firings in
# their own right - each scores LOG_ONLY on its own, so they don't trigger
# any action themselves, they just accumulate in the Shuffle Cache history
# list that usb_dlp_score_alert.py reads for D4).
build_history() {
    local n="$1"
    for i in $(seq 1 "$n"); do
        echo "  (history filler $i/$n)"
        write_file "filler_${RUN_ID}_${i}.txt" 1000
        sleep 3
    done
}

# Polls the manager's real alerts.log for rule 100500 matching a filename.
# Returns the number of times it fired (can legitimately be 2 - see header).
count_alerts() {
    local fname="$1" tries=0 count=0
    while (( tries < 8 )); do
        count="$(docker exec "$MANAGER_CONTAINER" sh -c "grep -ac '\"id\":\"100500\".*$fname' /var/ossec/logs/alerts/alerts.json" || true)"
        (( count > 0 )) && break
        sleep 2
        tries=$((tries + 1))
    done
    echo "$count"
}

# Polls Shuffle executions for this workflow and prints every execution
# whose score_alert output references this filename (there can be more than
# one - see header note on rule 100500 double-firing).
show_executions() {
    local fname="$1" tries=0
    # $execs is real Wazuh/Shuffle JSON containing Windows paths (raw
    # backslashes) and escaped quotes - embedding it into a python -c
    # string via bash substitution hits the exact same class of bug fixed
    # in usb_dlp_score_alert.py (Python's OWN string-literal escape
    # processing corrupts "\f"/"\v"/etc before json.loads ever sees it,
    # sometimes badly enough to break the JSON and fail silently). Routing
    # through a temp file and json.load()-ing it from disk sidesteps the
    # entire bash->python string-embedding hazard class instead of trying
    # to out-escape it again.
    local tmpfile; tmpfile="$(mktemp)"
    while (( tries < 10 )); do
        # `|| true`: under `set -e`, a bare command (not part of an if/&&/||
        # test) that fails aborts the WHOLE script immediately, silently -
        # confirmed live that a single transient curl hiccup here (Shuffle
        # under load from repeated testing) killed the entire run with no
        # error message, well before this loop's own retry/timeout logic
        # ever got a chance to run.
        curl -sk -H "Authorization: Bearer $SHUFFLE_API_KEY" "$SHUFFLE_BASE_URL/api/v1/workflows/$WORKFLOW_ID/executions" > "$tmpfile" || true
        local found
        found="$(python3 -c "
import json, sys
with open('$tmpfile') as f:
    execs = json.load(f)
# Newest-first, and this list only grows across a test session (every
# prior run's executions stay in it) - re-scanning/json.dumps()-ing the
# WHOLE thing on every poll gets slower each call as the session goes on,
# confirmed live to eventually outrun the retry budget below. Our own
# execution is always near the front, so only look there.
matches = [e for e in execs[:10] if '$fname' in json.dumps(e)]
# A match on the raw execution text isn't enough - the filename shows up
# in the webhook trigger's own payload the instant the execution starts,
# well before score_alert has actually run. Confirmed live: this made the
# retry loop below accept an in-progress execution (no score_alert result
# yet) as 'found', printing only the '---' separator with no score/action
# line. Require an actual score_alert result before treating this as done.
lines = []
saw_score = False
for ex in matches:
    for r in ex.get('results', []):
        lbl = r.get('action', {}).get('label')
        if lbl == 'score_alert':
            saw_score = True
            res = r.get('result')
            msg = json.loads(res)['message'] if isinstance(res, str) else res
            lines.append(f\"    score={msg.get('score')} action={msg.get('action')} history_count={msg.get('history_count')} file={msg.get('file_path')}\")
        elif lbl in ('wazuh_ar_block_usb', 'escalate_iris_alert', 'notify_soc_review', 'iris_log_alert'):
            lines.append(f\"    {lbl} -> {r.get('status')}\")
    lines.append('    ---')
if not saw_score:
    sys.exit(1)
print('\n'.join(lines))
" 2>/dev/null)" && { echo "$found"; rm -f "$tmpfile"; return 0; }
        sleep 3
        tries=$((tries + 1))
    done
    rm -f "$tmpfile"
    echo "    (no matching Shuffle execution found after 30s - check Shuffle UI manually)"
    return 1
}

verify_ar_block_applied() {
    echo "  Verifying the real Active Response block on $HOST..."
    # A Shuffle "wazuh_ar_block_usb -> SUCCESS" only means the manager's
    # PUT /active-response API accepted and queued the dispatch - the agent
    # still has to receive and actually run block-usb-write.ps1
    # asynchronously afterward. Confirmed live: checking icacls immediately
    # after Shuffle reports success is a real race and can read the OLD
    # (unblocked) ACL state. Poll for a few seconds instead of a single
    # fixed-delay check.
    local acl tries=0
    while (( tries < 6 )); do
        acl="$(win_shell "icacls $SIMULATED_PATH")"
        echo "$acl" | grep -q 'Everyone:.*(DENY)(W)' && break
        sleep 2
        tries=$((tries + 1))
    done
    if echo "$acl" | grep -q 'Everyone:.*(DENY)(W)'; then
        echo "  [OK] icacls shows Everyone write-DENY on $SIMULATED_PATH"
    else
        echo "  [FAIL] no write-DENY found on $SIMULATED_PATH after 12s - AR did not apply"
        return 1
    fi
    local write_test
    write_test="$(win_shell "try { [IO.File]::WriteAllBytes('$SIMULATED_PATH\\should_fail_${RUN_ID}.txt', [byte[]](1)); 'WRITE SUCCEEDED (BAD)' } catch { 'WRITE BLOCKED (expected)' }")"
    echo "  Functional check: $write_test"
    [[ "$write_test" == *"WRITE BLOCKED"* ]]
}

release_ar_block() {
    echo "  Releasing the block (icacls /remove:d Everyone) so the folder is left usable..."
    win_shell "icacls $SIMULATED_PATH /remove:d Everyone" >/dev/null
    win_shell "Remove-Item $SIMULATED_PATH\\*_${RUN_ID}_* -Force -ErrorAction SilentlyContinue" >/dev/null
}

run_log_only() {
    echo
    echo "=== [log_only] expect score ~5-15, LOG_ONLY, no action ==="
    # .dat (uncategorized extension, +0) - NOT .txt: usb_dlp_score_alert.py's
    # DOCUMENT_EXTS explicitly includes .txt (+20, per the requirements'
    # "常見文件或資料檔案" list), so it would push this case toward
    # NOTIFY_SOC, not exercise LOG_ONLY. And NOT .jpg/.png: see the header
    # note above - Wazuh's stock ignore list silently drops FIM events for
    # image extensions, so a real .jpg/.png write would never reach rule
    # 100500 at all here. .dat is genuinely uncategorized (+0), cleanly
    # proving both the LOG_ONLY band and the scorer's "uncategorized
    # extension" code path via a real file+alert.
    local fname="log_only_${RUN_ID}.dat"
    write_file "$fname" 200000   # <1MB (+5), uncategorized ext (+0)
    echo "  Wrote $fname (200KB, .dat). Waiting for detection..."
    sleep 6
    local n; n="$(count_alerts "$fname")"
    echo "  rule 100500 fired ${n}x for $fname"
    (( n > 0 )) || { echo "  [FAIL] rule 100500 never fired"; return 1; }
    show_executions "$fname"
}

run_notify_soc() {
    echo
    echo "=== [notify_soc] expect score ~40-50, NOTIFY_SOC, human review alert (no block) ==="
    echo "  Building D4 history (2 filler hits, +10)..."
    build_history 2
    local fname="notify_soc_${RUN_ID}.docx"
    write_file "$fname" 5242880   # 1-10MB (+10), .docx (+20)
    echo "  Wrote $fname (5MB, .docx). Waiting for detection..."
    sleep 6
    local n; n="$(count_alerts "$fname")"
    echo "  rule 100500 fired ${n}x for $fname"
    (( n > 0 )) || { echo "  [FAIL] rule 100500 never fired"; return 1; }
    show_executions "$fname"
    win_shell "Remove-Item $SIMULATED_PATH\\filler_${RUN_ID}_* -Force -ErrorAction SilentlyContinue" >/dev/null
}

run_escalate() {
    echo
    echo "=== [escalate] expect score ~60-70, ESCALATE_AND_CONTAIN, REAL write-block ==="
    echo "  Building D4 history (2 filler hits, +10)..."
    build_history 2
    local fname="escalate_${RUN_ID}.zip"
    write_file "$fname" 157286400   # >100MB (+25), .zip (+25)
    echo "  Wrote $fname (150MB, .zip). Waiting for detection..."
    sleep 8
    local n; n="$(count_alerts "$fname")"
    echo "  rule 100500 fired ${n}x for $fname"
    (( n > 0 )) || { echo "  [FAIL] rule 100500 never fired"; return 1; }
    show_executions "$fname"
    sleep 3
    if verify_ar_block_applied; then
        echo "  [PASS] ESCALATE_AND_CONTAIN action verified for real."
    else
        echo "  [FAIL] Active Response did not actually apply - check wazuh_ar_block_usb node in Shuffle."
    fi
    release_ar_block
}

case "$CASE" in
    log_only)   run_log_only ;;
    notify_soc) run_notify_soc ;;
    escalate)   run_escalate ;;
    all)
        run_log_only
        run_notify_soc
        run_escalate
        ;;
esac

win_shell "Remove-Item $SIMULATED_PATH\\*_${RUN_ID}* -Force -ErrorAction SilentlyContinue" >/dev/null || true

echo
echo "Done. Check the Shuffle UI -> Workflows -> \"Wazuh USB-DLP Auto-Response\" -> Runs for full node-by-node detail,"
echo "or the manager's alerts:"
echo "  docker exec $MANAGER_CONTAINER tail -f /var/ossec/logs/alerts/alerts.json | grep '\"id\":\"100500\"'"
