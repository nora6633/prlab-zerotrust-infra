#!/bin/bash
# Flips the insider-threat score_alert node's FORCE_OFF_HOURS constant
# in-place on the ALREADY-DEPLOYED Shuffle workflow, via
# PUT /api/v1/workflows/{id} - never via the import/create API.
#
# Why this exists: Shuffle's workflow-import API is not an upsert - every
# POST to /api/v1/workflows creates a brand new workflow object, even if
# one with the same name already exists (confirmed repo-wide: the other
# three scenarios have each accumulated 6-7 duplicates this way). Re-running
# configure_insider_threat_integration.yml after changing
# insider_threat_v5_force_off_hours in group_vars/all.yml does NOT pick up
# the change for this exact reason - that playbook only imports when no
# workflow with this name exists yet. This script is the only supported way
# to change the flag on a workflow that's already been imported once.
#
# Usage: insider-threat-test/set_force_off_hours.sh <on|off>
#   on  -> FORCE_OFF_HOURS = True  (use for acceptance/test runs)
#   off -> FORCE_OFF_HOURS = False (restore after - this is the default
#          group_vars/all.yml value and should be the resting state)
#
# Never hardcodes or prints credentials - shuffle_default_apikey is read
# from group_vars/soc.yml at call time only, passed to the Python helper
# via an environment variable (not argv, to avoid exposure via `ps`), and
# never echoed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALL_YML="$REPO_ROOT/group_vars/all.yml"
SOC_YML="$REPO_ROOT/group_vars/soc.yml"
WF_NAME="Wazuh Insider-Threat Auto-Response"

MODE="${1:-}"
case "$MODE" in
  on)  FORCE_VALUE="true" ;;
  off) FORCE_VALUE="false" ;;
  *)
    echo "Usage: $0 <on|off>" >&2
    exit 1
    ;;
esac

yaml_get() {
  python3 -c "
import yaml
with open('$1') as f:
    d = yaml.safe_load(f)
print(d.get('$2', ''))
"
}

wz_mgr=$(ansible-inventory -i "$REPO_ROOT/inventory/hosts.ini" --list 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['_meta']['hostvars']['soc-host']['ansible_host'])")

SHUFFLE_APIKEY=$(yaml_get "$SOC_YML" shuffle_default_apikey)
export SHUFFLE_APIKEY
export WZ_SERVER="$wz_mgr"
export WF_NAME
export FORCE_VALUE
export TEMPLATE_PATH="$REPO_ROOT/roles/shuffle/files/insider_threat_score.py.j2"
export ACCOUNTS_JSON=$(python3 -c "
import yaml, json
with open('$ALL_YML') as f:
    d = yaml.safe_load(f)
accounts = d.get('insider_threat_accounts', [])
whitelist = [a['name'] for a in accounts if a.get('whitelist')]
print(json.dumps(whitelist))
")

python3 - <<'PY'
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

apikey = os.environ["SHUFFLE_APIKEY"]
server = os.environ["WZ_SERVER"]
wf_name = os.environ["WF_NAME"]
force_value = os.environ["FORCE_VALUE"] == "true"
template_path = os.environ["TEMPLATE_PATH"]
whitelist_json = os.environ["ACCOUNTS_JSON"]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def api_get(path):
    req = urllib.request.Request(
        f"http://{server}:5001{path}",
        headers={"Authorization": f"Bearer {apikey}"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read())


def api_put(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://{server}:5001{path}",
        data=data,
        method="PUT",
        headers={"Authorization": f"Bearer {apikey}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return resp.status


def render_score_code():
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)))
    tmpl = env.get_template(os.path.basename(template_path))
    return tmpl.render(
        insider_threat_whitelist_json=whitelist_json,
        insider_threat_v5_force_off_hours=force_value,
    )


try:
    workflows = api_get("/api/v1/workflows")
except urllib.error.URLError as e:
    print(f"[set_force_off_hours] FAILED to reach Shuffle: {e}", file=sys.stderr)
    sys.exit(1)

before_total = len(workflows)
before_named = [w for w in workflows if w["name"] == wf_name]
print(f"[set_force_off_hours] before: total workflows={before_total}, '{wf_name}' count={len(before_named)}")

if len(before_named) != 1:
    print(
        f"[set_force_off_hours] ABORTING: expected exactly 1 workflow named "
        f"'{wf_name}', found {len(before_named)}. Not touching anything.",
        file=sys.stderr,
    )
    sys.exit(1)

wf_id = before_named[0]["id"]
wf = api_get(f"/api/v1/workflows/{wf_id}")

score_action = next((a for a in wf["actions"] if a["id"] == "score_alert"), None)
if score_action is None:
    print("[set_force_off_hours] ABORTING: score_alert action not found in workflow. Not touching anything.", file=sys.stderr)
    sys.exit(1)

code_param = next((p for p in score_action["parameters"] if p["name"] == "code"), None)
if code_param is None:
    print("[set_force_off_hours] ABORTING: code parameter not found on score_alert. Not touching anything.", file=sys.stderr)
    sys.exit(1)

code_param["value"] = render_score_code()

try:
    status = api_put(f"/api/v1/workflows/{wf_id}", wf)
except urllib.error.URLError as e:
    print(f"[set_force_off_hours] FAILED to PUT updated workflow, nothing was changed server-side (PUT either fully applies or not at all): {e}", file=sys.stderr)
    sys.exit(1)

if status != 200:
    print(f"[set_force_off_hours] FAILED: PUT returned HTTP {status}", file=sys.stderr)
    sys.exit(1)

workflows_after = api_get("/api/v1/workflows")
after_total = len(workflows_after)
after_named = [w for w in workflows_after if w["name"] == wf_name]
print(f"[set_force_off_hours] after: total workflows={after_total}, '{wf_name}' count={len(after_named)}")

if after_total != before_total or len(after_named) != 1:
    print(
        "[set_force_off_hours] WARNING: workflow count changed after the PUT! "
        "This should be impossible (PUT never creates a new workflow) - "
        "investigate before trusting the scoring pipeline.",
        file=sys.stderr,
    )
    sys.exit(1)

wf_check = api_get(f"/api/v1/workflows/{wf_id}")
score_check = next(a for a in wf_check["actions"] if a["id"] == "score_alert")
code_check = next(p["value"] for p in score_check["parameters"] if p["name"] == "code")

expected = "FORCE_OFF_HOURS = True" if force_value else "FORCE_OFF_HOURS = False"
if expected not in code_check:
    print(f"[set_force_off_hours] FAILED verification: live code does not contain '{expected}'", file=sys.stderr)
    sys.exit(1)

print(f"[set_force_off_hours] OK - force_off_hours is now {'on' if force_value else 'off'}, workflow count unchanged ({after_total} total, 1 insider-threat).")
PY
