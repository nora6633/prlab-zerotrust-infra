# Shared helpers for the per-sub-scenario manual test scripts in this
# directory (scenario_a.sh / scenario_b.sh / scenario_c.sh / scenario_d.sh).
# Mirrors the account/IP/gap resolution logic in ../run_attack.sh so these
# stay equivalent to it, but each scenario_*.sh here runs ONLY that one
# sub-scenario's command chain - no --reset, no indexer history clearing,
# no isolation release. For those, use ../run_attack.sh --reset, or the
# manual steps in insider-threat-test/README.md's
# "手動解除隔離 / 隔離卡住" section.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ALL_YML="$REPO_ROOT/group_vars/all.yml"
SSH_KEY="$REPO_ROOT/secrets/insider_threat_test_key"
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

step_gap() {
  echo "[wait] sleeping ${STEP_GAP_SECONDS}s (indexer settle, see ../DEVIATIONS.md #27)..."
  sleep "$STEP_GAP_SECONDS"
}
