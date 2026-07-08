"""
N5: 3-dimension confidence scoring for the DDoS auto-response workflow.
Design follows ddos-plan.txt Part 4 exactly (dimensions, caps, decision bands,
degraded-evidence safety valve), adapted to this lab's actual upstream nodes.

Runs inside Shuffle Tools `execute_python` action. Shuffle substitutes
$exec.rule.level / $exec.rule.id / $exec.data.srcip / $exec.timestamp,
$abuseipdb_query.status/.body, $wazuh_history.status/.body as raw text
before execution.

Fields come from $exec.<field> individually, NOT from re-parsing a whole
`json.loads('''$exec''')` blob: verified live against a real flood that the
whole-blob approach silently breaks on real Wazuh alerts. Wazuh's alert JSON
includes full_log, which for an nginx access line contains JSON-escaped
quotes (\\"); embedding that raw text inside a Python triple-quoted string
lets PYTHON'S OWN string-literal escape processing consume those backslashes
before json.loads ever sees them, corrupting the JSON and silently tripping
the try/except fallback to `alert = {}` — so rule_level (worth up to 40
points) silently defaulted to 0 for every real alert, and srcip showed
"unknown" in the audit trail, even though the workflow otherwise looked like
it was working end-to-end. Individual field substitution has none of the
re-parse-a-blob failure mode.

Outputs JSON to stdout — subsequent actions reference fields via
$score_alert.score / $score_alert.action / etc. Nothing downstream
extracts individual fields FROM this node's output via a dot-path — verified
live that Shuffle unreliably resolves $score_alert.<field> in a *consumer*
node's parameters (always empty, execute_python-specific, unrelated to the
bug above). Only the whole-value "$score_alert contains ACTION" branch-
condition pattern is used downstream, which is reliable.
"""
import json

# ── Coercion helper — distinguishes "genuinely 0/absent" from "we never got
#    a value" so a failed upstream lookup can't silently masquerade as a
#    clean result. ──────────────────────────────────────────────────────────
def as_int(raw, default=None):
    try:
        s = str(raw).strip()
        return int(s) if s not in ("", "None", "null") else default
    except (ValueError, TypeError):
        return default

# ── The alert (individual fields substituted directly by Shuffle) ──────────
rule_level = as_int("$exec.rule.level", default=0)
rule_id = "$exec.rule.id"
srcip = "$exec.data.srcip"
timestamp = "$exec.timestamp"

# ── N4: Wazuh indexer 24h history for this srcip ────────────────────────────
# Checked via HTTP status first, not just body-parse success — a node that
# returns 401/503 with an HTML error body would otherwise parse as "0 hits"
# and get scored as a clean IP instead of "we don't know".
history_status = as_int("$wazuh_history.status", default=None)
alerts_24h = None
if history_status == 200:
    try:
        history_body = json.loads('''$wazuh_history.body''')
        total = history_body.get("hits", {}).get("total", 0)
        alerts_24h = total.get("value", 0) if isinstance(total, dict) else int(total)
    except Exception:
        alerts_24h = None

# ── N3: AbuseIPDB reputation ─────────────────────────────────────────────────
abuse_status = as_int("$abuseipdb_query.status", default=None)
abuse_score = None
if abuse_status == 200:
    try:
        abuse_body = json.loads('''$abuseipdb_query.body''')
        abuse_score = as_int(abuse_body.get("data", {}).get("abuseConfidenceScore"), default=None)
    except Exception:
        abuse_score = None

score = 0
evidence = []
degraded = []   # dimensions we couldn't evaluate this run

# ── DIMENSION 1 — Wazuh rule level (cap 40) ─────────────────────────────────
# "How bad does the traffic pattern ITSELF look?" elif (not separate ifs) so
# a level-12 alert scores 40 once, never 40+25. Cap 40 is deliberate: a
# textbook attack pattern from a first-time, clean IP lands on EXACTLY 40 =
# NOTIFY_SOC, one point short of auto-block — local pattern alone never
# auto-blocks; first offense gets a human.
if rule_level >= 12:
    score += 40
    evidence.append(f"Rule level {rule_level} (Critical)")
elif rule_level >= 10:
    score += 25
    evidence.append(f"Rule level {rule_level} (High)")
else:
    evidence.append(f"Rule level {rule_level} (Medium)")

# ── DIMENSION 2 — 24h history from Wazuh indexer (cap 30) ──────────────────
# "Is this IP a repeat offender against US?" Cap 30 is BELOW the 40 notify
# threshold on purpose: persistence ALONE can never escalate to NOTIFY_SOC —
# a chatty-but-benign crawler racks up history but must not get flagged on
# frequency without severity.
if alerts_24h is None:
    degraded.append("history_unavailable")
elif alerts_24h >= 20:
    score += 30
    evidence.append(f"Historical: {alerts_24h} alerts in 24h (persistent)")
elif alerts_24h >= 5:
    score += 20
    evidence.append(f"Historical: {alerts_24h} alerts in 24h")

# ── DIMENSION 3 — AbuseIPDB reputation (cap 70) ─────────────────────────────
# "Is this IP known-bad to the WHOLE WORLD?" This is the ONLY single
# dimension that can auto-block on its own (>=80 -> +70): it's externally
# validated by hundreds of independent reporters, so we trust it to act
# unilaterally, unlike our own single-window observation. In a private-IP lab
# this always returns 0/degraded, so this path never fires there — the
# level-12 + history combo is what actually reaches 70 in the experiment.
if abuse_score is None:
    degraded.append("reputation_unavailable")
elif abuse_score >= 80:
    score += 70
    evidence.append(f"AbuseIPDB score: {abuse_score} (known-bad)")
elif abuse_score >= 50:
    score += 40
    evidence.append(f"AbuseIPDB score: {abuse_score} (suspicious)")

# ── DECISION BANDS ───────────────────────────────────────────────────────────
#   >= 70  AUTO_BLOCK   (machine acts alone)
#   40-69  NOTIFY_SOC   (human decides)
#   < 40   LOG_ONLY     (just record)
if score >= 70:
    action = "AUTO_BLOCK"
elif score >= 40:
    action = "NOTIFY_SOC"
else:
    action = "LOG_ONLY"

# Safety valve: never auto-block on a score computed with a missing
# dimension — downgrade to human review. A failed AbuseIPDB lookup could
# otherwise silently drop a real attacker from 70->40; if we're about to
# auto-block but evidence is degraded, force NOTIFY_SOC so a human sees the
# gap.
if action == "AUTO_BLOCK" and degraded:
    action = "NOTIFY_SOC"
    evidence.append(f"DEGRADED evidence, downgraded from AUTO_BLOCK: {','.join(degraded)}")

# stdout IS the node's output in Shuffle — downstream nodes only ever check
# the WHOLE value ("$score_alert contains AUTO_BLOCK/NOTIFY_SOC/LOG_ONLY"),
# never a dot-path field extraction (see module docstring for why).
print(json.dumps({
    "score": score,
    "action": action,
    "srcip": srcip,
    "rule_id": rule_id,
    "rule_level": rule_level,
    "alerts_24h": alerts_24h,
    "abuse_score": abuse_score,
    "alert_timestamp": timestamp,
    "evidence": evidence,
    "evidence_md": "\n".join(f"- {e}" for e in evidence),
    "degraded": degraded,
}))
