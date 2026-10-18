#!/bin/bash
# Manual, standalone version of run_attack.sh's scenario_c() (routine
# admin, whitelisted account it.prlab). Must run on the Docker host
# itself, not inside any container. Does NOT reset artifacts/isolation/
# indexer history first - do that yourself beforehand if needed
# (../run_attack.sh --reset, or see ../README.md's "手動解除隔離" section).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./_lib.sh

echo "=== Sub-scenario C (routine admin, it.prlab, whitelisted) ==="
run_as it.prlab "whoami"
step_gap
run_as it.prlab "nmap -sn ${LINK_SUBNET}"
step_gap
run_as it.prlab "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@${LAN_IP} exit" || true
step_gap
run_as it.prlab "tar czf /tmp/logs.tgz /var/log" || true
echo "=== Sub-scenario C done ==="
