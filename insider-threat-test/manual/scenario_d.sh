#!/bin/bash
# Manual, standalone version of run_attack.sh's scenario_d() - SUPPLEMENTARY,
# not part of docs/report.txt (see ../DEVIATIONS.md #26). Same command
# chain as scenario_b.sh, run as the whitelisted it.prlab account instead
# of ubuntu, to test whether a whitelisted account still gets AUTO_BLOCK'd
# once it reaches the nc 4444 C2 stage. Only run this after A/B/C have
# already completed. Must run on the Docker host itself, not inside any
# container. Does NOT reset artifacts/isolation/indexer history first - do
# that yourself beforehand if needed (../run_attack.sh --reset, or see
# ../README.md's "手動解除隔離" section).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./_lib.sh

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
echo "=== Sub-scenario D done ==="
