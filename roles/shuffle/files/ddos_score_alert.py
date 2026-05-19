"""
N5: 5-dimension confidence scoring for the DDoS auto-response workflow.

Runs inside Shuffle Tools `execute_python` action. Shuffle substitutes
$exec, $abuseipdb_query.body, $wazuh_history.body before execution.

Outputs JSON to stdout — subsequent actions reference fields via
$score_alert.score / $score_alert.action / $score_alert.srcip / etc.
"""
import json
import datetime
import re

# ── Inputs (Shuffle substitutes $... before execution) ─────────────────
try:
    alert = json.loads('''$exec''')
except Exception:
    alert = {}

try:
    abuse = json.loads('''$abuseipdb_query.body''')
    abuse_score = int(abuse.get("data", {}).get("abuseConfidenceScore", 0))
except Exception:
    abuse_score = 0

try:
    history = json.loads('''$wazuh_history.body''')
    # OpenSearch returns hits.total.value (modern) or hits.total (legacy)
    total = history.get("hits", {}).get("total", 0)
    history_count = total.get("value", 0) if isinstance(total, dict) else int(total)
except Exception:
    history_count = 0

rule_level = int(alert.get("rule", {}).get("level", 0))
rule_groups = alert.get("rule", {}).get("groups", []) or []
srcip = alert.get("data", {}).get("srcip", "unknown")
timestamp = alert.get("timestamp", "")

# ── Scoring (5 dimensions) ─────────────────────────────────────────────
score = 0
evidence = []

# D1: Rule level
if rule_level >= 12:
    score += 40
    evidence.append(f"D1 rule level {rule_level} >= 12 (+40)")
elif rule_level >= 10:
    score += 25
    evidence.append(f"D1 rule level {rule_level} >= 10 (+25)")

# D2: Rule groups
if "ddos" in rule_groups and "high_severity" in rule_groups:
    score += 30
    evidence.append("D2 ddos + high_severity groups (+30)")
elif "ddos" in rule_groups:
    score += 15
    evidence.append("D2 ddos group only (+15)")

# D3: Wazuh history (same srcip last 24h)
if history_count >= 20:
    score += 20
    evidence.append(f"D3 history {history_count} alerts >= 20 (+20)")
elif history_count >= 5:
    score += 10
    evidence.append(f"D3 history {history_count} alerts >= 5 (+10)")

# D4: AbuseIPDB
if abuse_score >= 50:
    score += 10
    evidence.append(f"D4 AbuseIPDB score {abuse_score} >= 50 (+10)")

# D5: Off-hours (before 08:00 or after 18:00 local of the alert timestamp)
hour = -1
try:
    # Wazuh timestamp format: "2026-05-13T10:30:21.659+0000"
    m = re.match(r"^\d{4}-\d{2}-\d{2}T(\d{2}):", timestamp)
    if m:
        hour = int(m.group(1))
except Exception:
    pass
if 0 <= hour < 8 or hour >= 18:
    score += 10
    evidence.append(f"D5 off-hours (hour {hour}) (+10)")

# ── Decision ───────────────────────────────────────────────────────────
if score >= 70:
    action = "AUTO_BLOCK"
elif score >= 40:
    action = "NOTIFY_SOC"
else:
    action = "LOG_ONLY"

# ── Outputs ────────────────────────────────────────────────────────────
now = datetime.datetime.utcnow()
ts_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
ts_safe = now.strftime("%Y%m%d-%H%M%S")
# PA object names can't contain "." — replace with underscore for srcip
srcip_safe = re.sub(r"[^A-Za-z0-9_-]", "_", srcip)

result = {
    "score": score,
    "action": action,
    "srcip": srcip,
    "srcip_safe": srcip_safe,
    "rule_level": rule_level,
    "rule_groups": rule_groups,
    "history_count": history_count,
    "abuse_score": abuse_score,
    "alert_timestamp": timestamp,
    "ts_iso": ts_iso,
    "ts_safe": ts_safe,
    "evidence": evidence,
    "evidence_md": "\n".join(f"- {e}" for e in evidence),
}

print(json.dumps(result))
