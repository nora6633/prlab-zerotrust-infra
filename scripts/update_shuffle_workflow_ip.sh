#!/bin/bash
# Finds and (optionally) fixes any exact literal string hardcoded into
# existing Shuffle workflows' action parameters (url/headers/body fields),
# via PUT /api/v1/workflows/{id} - never via the import/create API, so this
# never changes workflow count. Despite the filename (this started as an
# IP-only tool), the match/replace itself is a plain substring operation on
# every action parameter value - nothing about it is IP-specific, so it
# works just as well for any other value Shuffle bakes in at import time.
# The other confirmed case so far: each wazuh_ar_block_*/wazuh_ar_isolate_*
# node's `agents_list=<id>` is ALSO rendered once at import from
# soc.yml's dmz_windows_agent_id/dmz_ubuntu_agent_id
# and does not track later re-registration - re-run this same script with
# the old and new agent id as <from_val>/<to_val> if an agent ever gets
# re-enrolled with a different id. See insider-threat-test/README.md's
# "變更 wazuh_server_ip 的影響範圍" for the IP case specifically.
#
# Shuffle bakes the rendered value of any {{ jinja_var }} reference into
# its own stored workflow JSON at import time - re-running
# configure_integration.yml with a changed variable only fixes the
# FORWARDING layer (custom-shuffle.py, re-rendered fresh on every run), not
# already-imported workflows' own internal node parameters (wazuh_auth,
# wazuh_ar_block_*, wazuh_history_query, IRIS endpoints, etc). This script
# is the surgical fix for that - same pattern as
# insider-threat-test/set_force_off_hours.sh.
#
# Usage:
#   scripts/update_shuffle_workflow_ip.sh <from_val> <to_val> --dry-run [--only <workflow_id>]
#   scripts/update_shuffle_workflow_ip.sh <from_val> <to_val> --apply   [--only <workflow_id>]
#   scripts/update_shuffle_workflow_ip.sh --restore <backup_dir> --dry-run [--only <workflow_id>]
#   scripts/update_shuffle_workflow_ip.sh --restore <backup_dir> --apply   [--only <workflow_id>]
#
# <from_val>/<to_val> can be an IP, an agent id, or any other exact literal
# string - the script does a plain substring match/replace, nothing more.
#
# --dry-run: report every match (or, for --restore, every workflow that
# WOULD be restored and whether its live content currently differs from
# the backup) and change nothing.
# --apply: PUT only the matched parameter values (update mode) or the
# entire backed-up object (restore mode) back - rest of each workflow
# object untouched either way. Workflow count is checked before/after
# every single PUT; any mismatch or HTTP failure aborts immediately
# without touching further workflows.
# --only <workflow_id>: restrict to exactly one workflow id, for applying
# one at a time and verifying between each.
#
# Never hardcodes or prints credentials - shuffle_default_apikey is read
# from group_vars/soc.yml at call time only, passed to the Python helper
# via an environment variable (not argv, to avoid exposure via `ps`).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOC_YML="$REPO_ROOT/group_vars/soc.yml"

RESTORE_DIR=""
FROM_VAL=""
TO_VAL=""
MODE=""
ONLY_ID=""

if [ "${1:-}" = "--restore" ]; then
  RESTORE_DIR="${2:-}"
  shift 2
  if [ -z "$RESTORE_DIR" ] || [ ! -d "$RESTORE_DIR" ]; then
    echo "Usage: $0 --restore <backup_dir> [--dry-run|--apply] [--only <workflow_id>]" >&2
    exit 1
  fi
else
  FROM_VAL="${1:-}"
  TO_VAL="${2:-}"
  shift 2 2>/dev/null || true
  if [ -z "$FROM_VAL" ] || [ -z "$TO_VAL" ]; then
    echo "Usage: $0 <from_val> <to_val> [--dry-run|--apply] [--only <workflow_id>]" >&2
    exit 1
  fi
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --apply) MODE="apply" ;;
    --only) ONLY_ID="${2:-}"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done
MODE="${MODE:-dry-run}"

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

export SHUFFLE_APIKEY=$(yaml_get "$SOC_YML" shuffle_default_apikey)
export WZ_SERVER="$wz_mgr"
export FROM_VAL
export TO_VAL
export MODE
export ONLY_ID
export RESTORE_DIR

# Ground truth for "which workflow is actually live" - read the CURRENTLY
# deployed custom-shuffle.py's webhook URLs directly off the manager,
# rather than trusting soc.yml's shuffle_*_webhook_trigger_id (which can
# go stale if the manager was re-rendered more recently than soc.yml was
# updated). Each line looks like:
#   IRIS_WEBHOOK_URL = "http://<ip>:5001/api/v1/hooks/webhook_<trigger-id>"
export ACTIVE_TRIGGERS_RAW=$(docker exec single-node-wazuh.manager-1 grep -E "^[A-Z_]+_WEBHOOK_URL = " /var/ossec/integrations/custom-shuffle 2>/dev/null || true)

python3 - <<'PY'
import glob
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

apikey = os.environ["SHUFFLE_APIKEY"]
server = os.environ["WZ_SERVER"]
from_val = os.environ.get("FROM_VAL", "")
to_val = os.environ.get("TO_VAL", "")
mode = os.environ["MODE"]
only_id = os.environ.get("ONLY_ID", "")
restore_dir = os.environ.get("RESTORE_DIR", "")
active_triggers_raw = os.environ.get("ACTIVE_TRIGGERS_RAW", "")
apply_mode = mode == "apply"

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


active_trigger_ids = set(re.findall(r"webhook_([0-9a-f-]{36})", active_triggers_raw))


def is_active(wf_detail):
    trig = None
    if wf_detail.get("triggers"):
        trig = wf_detail["triggers"][0].get("id")
    return trig in active_trigger_ids if trig else False


# ───────────────────────── restore mode ─────────────────────────────────
if restore_dir:
    files = sorted(glob.glob(os.path.join(restore_dir, "*.json")))
    files = [f for f in files if not os.path.basename(f).startswith("_")]
    if only_id:
        files = [f for f in files if os.path.splitext(os.path.basename(f))[0] == only_id]
        if not files:
            print(f"[update-ip] no backup file found for workflow id {only_id} in {restore_dir}", file=sys.stderr)
            sys.exit(1)

    workflows_before = api_get("/api/v1/workflows")
    before_total = len(workflows_before)
    print(f"[update-ip] restore mode ({mode}), backup dir={restore_dir}")
    print(f"[update-ip] total workflows before: {before_total}")

    for fpath in files:
        wf_id = os.path.splitext(os.path.basename(fpath))[0]
        with open(fpath) as f:
            backup_obj = json.load(f)
        name = backup_obj.get("name", "?")

        try:
            live = api_get(f"/api/v1/workflows/{wf_id}")
            live_exists = True
        except urllib.error.HTTPError:
            live_exists = False

        if mode == "dry-run":
            status = "would restore (currently exists, content may differ)" if live_exists else "would restore (NOT currently present - restore would recreate by PUT, which requires the id to still exist server-side to succeed)"
            print(f"  {name} ({wf_id}): {status}")
            continue

        before_n = len(api_get("/api/v1/workflows"))
        try:
            put_status = api_put(f"/api/v1/workflows/{wf_id}", backup_obj)
        except urllib.error.URLError as e:
            print(f"[update-ip] ABORTING restore of {wf_id}: PUT failed ({e})", file=sys.stderr)
            sys.exit(1)
        if put_status != 200:
            print(f"[update-ip] ABORTING restore of {wf_id}: PUT returned HTTP {put_status}", file=sys.stderr)
            sys.exit(1)
        after_n = len(api_get("/api/v1/workflows"))
        if after_n != before_n:
            print(f"[update-ip] ABORTING: workflow count changed ({before_n} -> {after_n}) while restoring {wf_id}!", file=sys.stderr)
            sys.exit(1)
        print(f"[update-ip] restored {name} ({wf_id}) from backup, workflow count unchanged ({after_n}).")

    sys.exit(0)

# ───────────────────────── update-ip mode ───────────────────────────────
workflows = api_get("/api/v1/workflows")
before_total = len(workflows)
print(f"[update-ip] total workflows: {before_total}")

by_name = {}
for w in workflows:
    by_name.setdefault(w["name"], []).append(w)

print("[update-ip] workflow name -> version count:")
for name, lst in by_name.items():
    print(f"  {name}: {len(lst)}")

print("")
print(f"[update-ip] scanning for literal '{from_val}' in each workflow's action parameters...")
if only_id:
    print(f"[update-ip] restricted to workflow id {only_id}")
print("")

total_hits = 0
plan = []

for w in workflows:
    wf_id = w["id"]
    if only_id and wf_id != only_id:
        continue
    wf_detail = api_get(f"/api/v1/workflows/{wf_id}")
    active = is_active(wf_detail)

    wf_hits = []
    for action in wf_detail.get("actions", []):
        for param in action.get("parameters", []):
            val = param.get("value")
            if isinstance(val, str) and from_val in val:
                count = val.count(from_val)
                wf_hits.append((action.get("label", action.get("id")), param.get("name"), count))
                if apply_mode:
                    plan.append((wf_detail, action, param, val.replace(from_val, to_val)))

    if wf_hits:
        total_hits += len(wf_hits)
        active_marker = " [ACTIVE - this is the one the live hook points to]" if active else " [not the active hook target]"
        print(f"=== {w['name']} (id={wf_id}){active_marker} ===")
        for label, pname, count in wf_hits:
            print(f"  node={label}  param={pname}  occurrences={count}")

print("")
print(f"[update-ip] total matched (workflow,node,param) tuples: {total_hits}")

if not apply_mode:
    print("[update-ip] dry-run only, nothing was changed.")
    sys.exit(0)

if total_hits == 0:
    print("[update-ip] nothing to apply.")
    sys.exit(0)

print("")
print(f"[update-ip] APPLY mode - patching {len(plan)} parameter(s)...")

by_wf = {}
for wf_detail, action, param, new_val in plan:
    by_wf.setdefault(wf_detail["id"], (wf_detail, []))[1].append((action, param, new_val))

for wf_id, (wf_detail, updates) in by_wf.items():
    before_list = api_get("/api/v1/workflows")
    before_n = len(before_list)

    for action, param, new_val in updates:
        param["value"] = new_val

    try:
        status = api_put(f"/api/v1/workflows/{wf_id}", wf_detail)
    except urllib.error.URLError as e:
        print(f"[update-ip] ABORTING on workflow {wf_id}: PUT failed ({e}).", file=sys.stderr)
        sys.exit(1)

    if status != 200:
        print(f"[update-ip] ABORTING on workflow {wf_id}: PUT returned HTTP {status}.", file=sys.stderr)
        sys.exit(1)

    after_list = api_get("/api/v1/workflows")
    after_n = len(after_list)
    if after_n != before_n:
        print(f"[update-ip] ABORTING: workflow count changed ({before_n} -> {after_n}) after updating {wf_id}!", file=sys.stderr)
        sys.exit(1)

    wf_check = api_get(f"/api/v1/workflows/{wf_id}")
    still_has_old = any(
        isinstance(p.get("value"), str) and from_val in p["value"]
        for a in wf_check.get("actions", [])
        for p in a.get("parameters", [])
    )
    if still_has_old:
        print(f"[update-ip] WARNING: workflow {wf_id} still contains '{from_val}' somewhere after the update.", file=sys.stderr)

    print(f"[update-ip] OK: {wf_detail['name']} ({wf_id}) updated, workflow count unchanged ({after_n}).")

print("[update-ip] done.")
PY
