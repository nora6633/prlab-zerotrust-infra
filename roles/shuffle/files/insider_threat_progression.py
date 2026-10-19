"""
Node 3/4 - progression_calc. Reconstructs how many attack-chain stages the
current subject has advanced through in the last 24h, via a Wazuh-indexer
query (node 2, wazuh_history_query) instead of the original thesis design's
Splunk query - same LIS (longest increasing subsequence, by time then
stage) algorithm, just fed from an OpenSearch _search response instead of
a Splunk CSV export, which needs no rex/table/sort post-processing at all
since the indexer query already returns structured JSON hits.

The indexer query itself (see wazuh_insider_threat_workflow.json.j2) is a
`term` filter on data.audit.auid + agent.name + rule.id in the known stage
set + a 24h range, so every candidate row here already belongs to the same
subject on the same host - this node only needs to order them and find the
longest chain ending at the triggering event's own stage.
"""
import json
import re
from datetime import datetime

ID_STAGE = {
    "100400": 1, "100402": 1,
    "100406": 2,
    "100407": 3,
    "100405": 4, "100403": 4,
    "100408": 5,
}
STAGE_NAME = {1: "Discovery", 2: "Lateral Movement", 3: "Collection",
              4: "Command and Control", 5: "Exfiltration"}

resp_raw = r"""$wazuh_history_query.body"""
ctx_raw = r"""$alert_preprocessing.message"""


def to_epoch(ts):
    if not ts:
        return None
    m = re.match(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})', str(ts))
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return None


try:
    resp = json.loads(resp_raw, strict=False)
except Exception:
    resp = {}
try:
    ctx = json.loads(ctx_raw, strict=False)
except Exception:
    ctx = {}

hits = (resp.get("hits") or {}).get("hits") or []

trigger_stage = int(ctx.get("trigger_stage", 0) or 0)
trigger_rule_id = str(ctx.get("rule_id", ""))
trigger_ts = ctx.get("timestamp", "")
trigger_ep = to_epoch(trigger_ts)

cand = []
for h in hits:
    src = h.get("_source") or {}
    rid = str((src.get("rule") or {}).get("id", ""))
    st = ID_STAGE.get(rid)
    if st is None or st > trigger_stage:
        continue
    ep = to_epoch(src.get("@timestamp", ""))
    if ep is None:
        continue
    # Same +2s trigger-side tolerance as the original design: the
    # triggering event's own SYSCALL record may itself have landed in the
    # indexer by the time this query runs, so don't exclude it for being
    # "after" trigger_ep by a couple seconds of indexing lag.
    if trigger_ep is not None and ep > trigger_ep + 2:
        continue
    cand.append({"ep": ep, "stage": st, "id": rid, "ts": src.get("@timestamp", "")})

# Guarantee the triggering event itself is a candidate even if the indexer
# hasn't ingested it yet (replication lag) - without this, a subject's
# very first-ever event would reconstruct to depth 0 instead of 1.
cand.append({
    "ep": trigger_ep if trigger_ep is not None else 9e18,
    "stage": trigger_stage, "id": trigger_rule_id, "ts": trigger_ts,
    "_is_trigger": True,
})

cand.sort(key=lambda x: (x["ep"], x["stage"]))
n = len(cand)
best = [1] * n
prev = [-1] * n
for i in range(n):
    for j in range(i):
        if cand[j]["stage"] < cand[i]["stage"] and cand[j]["ep"] <= cand[i]["ep"]:
            if best[j] + 1 > best[i]:
                best[i] = best[j] + 1
                prev[i] = j

end_idx = -1
end_len = 0
for i in range(n):
    if cand[i]["stage"] == trigger_stage and best[i] >= end_len:
        end_len = best[i]
        end_idx = i

depth = end_len if end_idx >= 0 else (1 if trigger_stage > 0 else 0)

path_nodes = []
k = end_idx
while k != -1:
    path_nodes.append(cand[k])
    k = prev[k]
path_nodes.reverse()

path = [STAGE_NAME.get(p["stage"], "?") for p in path_nodes]
evidence = [f"[+] {p['ts']} stage{p['stage']} {STAGE_NAME.get(p['stage'], '?')} (rule {p['id']})" for p in path_nodes]

v2 = 30 if depth >= 3 else (15 if depth == 2 else 0)

out = dict(ctx)
out["progression_depth"] = depth
out["progression_path"] = path
out["v2_score"] = v2
out["v2_evidence"] = evidence
out["reconstruction_rows"] = len(cand)
print(json.dumps(out, ensure_ascii=False))
