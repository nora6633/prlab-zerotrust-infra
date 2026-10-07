"""
4-dimension confidence scoring for the USB-DLP auto-response workflow
(simulated removable-disk file writes, Wazuh rule 100500). Dimensions,
point values, and decision bands follow the requirements exactly:

  D1 file size      (0-25, cap 25)
  D2 file extension (0-25, cap 25)
  D3 time-of-day    (0-10, cap 10)
  D4 10-min history (0-40, cap 40)   -- via Shuffle Cache, see below
                                          max total = 100

  score >= 60      ESCALATE_AND_CONTAIN
  40 <= score < 60  NOTIFY_SOC
  score < 40        LOG_ONLY

Runs inside Shuffle Tools `execute_python`. Shuffle substitutes $exec.<field>
/ $history_check.<field> as raw text before execution. Fields are read
individually (as $exec.syscheck.path / $exec.syscheck.size_after / etc.),
NOT by re-parsing a whole json.loads('''$exec''') blob - see
roles/shuffle/files/ddos_score_alert.py's module docstring for exactly why
that whole-blob approach silently corrupts on real Wazuh alerts (full_log
contains JSON-escaped quotes that collide with Python's own string-literal
escaping). Same reasoning applies here, so the same field-by-field style is
used even though this workflow has no full_log-bearing fields itself.

D4 (10-minute same-endpoint history) is Shuffle-side state, not a Wazuh
frequency rule: rule 100500 fires once per real file write (see
roles/wazuh_usb_dlp_rules/files/local_rules_usb_dlp.xml), so there is no
Wazuh-side counter to read. Instead, a Shuffle Cache entry keyed
"usb_dlp_history:<agent_id>" stores a JSON list of this endpoint's last
100500-firing epoch timestamps. This node counts how many of those fall in
the preceding 10 minutes (excluding the current event) for D4, then also
emits the updated list (old entries within the window, plus this event)
so a downstream set_cache_value node can persist it - every event updates
the history regardless of which decision band it lands in, since D4 needs
to see ALL prior firings, not just escalations.

Like ddos_score_alert.py, downstream branch conditions match the exact
`"action": "ESCALATE_AND_CONTAIN"` / `"NOTIFY_SOC"` / `"LOG_ONLY"`
key-value substring (never a bare decision-band word, which could
coincidentally appear elsewhere in this output) - see
wazuh_usb_dlp_workflow.json.j2. Non-branch fields (file path, evidence,
etc.) are read via $score_alert.message.<field>, the same dot-path style
already proven live in the DDoS workflow's notify_soc/iris_log_alert nodes
(e.g. $score_alert.message.alert_timestamp) - the "whole-value only"
restriction documented in ddos_score_alert.py applies specifically to the
branch-condition consumers, not every consumer.
"""
import json
from datetime import datetime, timedelta, timezone

# ── Business hours (D3) — Mon-Fri 09:00-18:00, Asia/Taipei (UTC+8, no DST).
#    Not specified precisely by the requirements; this lab's containers
#    already standardize on TZ=Asia/Taipei (see docker-compose.yaml files),
#    so alert timestamps (Wazuh emits UTC) are converted to that zone here
#    for the business-hours comparison. ──────────────────────────────────
TAIPEI_OFFSET = timezone(timedelta(hours=8))
BUSINESS_HOUR_START = 9
BUSINESS_HOUR_END = 18  # exclusive

# ── D1 file size — MB = 1024*1024 (binary), matching how Windows Explorer
#    labels file sizes (which is actually MiB despite the "MB" label). ────
ONE_MB = 1024 * 1024
TEN_MB = 10 * ONE_MB
HUNDRED_MB = 100 * ONE_MB

# ── D2 file extension groups ────────────────────────────────────────────
COMPRESSED_EXTS = {"zip", "7z", "rar"}
DOCUMENT_EXTS = {"xlsx", "csv", "docx", "pdf", "txt"}
IMAGE_EXTS = {"jpg", "jpeg", "png"}

# ── D4 10-minute history window ─────────────────────────────────────────
HISTORY_WINDOW_SECONDS = 10 * 60
# Safety bound on the cached list's growth, independent of the 10-minute
# scoring window - a pathological runaway (e.g. cache never getting read
# for a long time) shouldn't let this grow unbounded.
HISTORY_MAX_ENTRIES = 200


def as_int(raw, default=None):
    try:
        s = str(raw).strip()
        return int(s) if s not in ("", "None", "null") else default
    except (ValueError, TypeError):
        return default


# ── The alert (individual fields substituted directly by Shuffle) ──────────
agent_id = "$exec.agent.id"
agent_name = "$exec.agent.name"
# Raw string literal (r"..."), not a plain "...": Shuffle substitutes the
# Windows path's literal backslashes directly into this source text before
# it's executed, and a plain double-quoted literal lets PYTHON'S OWN
# string-escape processing consume them - confirmed live that
# "c:\simulatedusb\vacation_photo.jpg" silently became
# "c:\simulatedusb\x0bacation_photo.jpg" ('\v' = vertical-tab escape) with a
# plain literal, corrupting the path in every downstream node that reads
# $score_alert.message.file_path (AR dispatch + every IRIS alert body). r"..."
# disables backslash-escape interpretation entirely, so this is immune to
# whatever letter follows the backslash in the real path.
file_path = r"$exec.syscheck.path"
size_bytes = as_int("$exec.syscheck.size_after", default=0)
timestamp = "$exec.timestamp"

alert_dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
alert_epoch = alert_dt.timestamp()

# Forward-slash form for anything Shuffle re-substitutes into a DOWNSTREAM
# JSON body (wazuh_ar_block_usb / escalate_iris_alert / notify_soc_review /
# iris_log_alert in wazuh_usb_dlp_workflow.json.j2). Confirmed live: Shuffle
# substitutes $score_alert.message.<field> as raw text, so a Windows path's
# backslashes land inside a JSON string literal unescaped - "\f" in
# "...usb\full_dump2.zip" gets consumed as the JSON form-feed escape,
# silently corrupting the path to "...usbull_dump2.zip" in both the AR
# dispatch and every IRIS alert body. This is display/logging-only (the
# actual block action always targets the fixed simulated-disk folder, not
# this path), so normalizing separators is a safe, complete fix.
file_path_display = file_path.replace("\\", "/")

# ── D4: prior history for this endpoint ─────────────────────────────────
history_found = "$history_check.found"
history_list = []
if str(history_found).strip().lower() == "true":
    try:
        history_list = json.loads('''$history_check.value''')
        if not isinstance(history_list, list):
            history_list = []
    except Exception:
        history_list = []

prior_in_window = [t for t in history_list if isinstance(t, (int, float)) and 0 <= alert_epoch - t < HISTORY_WINDOW_SECONDS]
history_count = len(prior_in_window)

updated_history = (prior_in_window + [alert_epoch])[-HISTORY_MAX_ENTRIES:]

score = 0
evidence = []

# ── DIMENSION 1 — file size (cap 25) ────────────────────────────────────
if size_bytes > HUNDRED_MB:
    score += 25
    evidence.append(f"File size {size_bytes} bytes (>100MB, mass data transfer)")
elif size_bytes >= TEN_MB:
    score += 15
    evidence.append(f"File size {size_bytes} bytes (10-100MB)")
elif size_bytes >= ONE_MB:
    score += 10
    evidence.append(f"File size {size_bytes} bytes (1-10MB)")
else:
    score += 5
    evidence.append(f"File size {size_bytes} bytes (<1MB)")

# ── DIMENSION 2 — file extension (cap 25) ───────────────────────────────
ext = file_path.lower().rsplit(".", 1)[-1] if "." in file_path else ""
if ext in COMPRESSED_EXTS:
    score += 25
    evidence.append(f"Extension .{ext} (compressed archive)")
elif ext in DOCUMENT_EXTS:
    score += 20
    evidence.append(f"Extension .{ext} (document/data file)")
elif ext in IMAGE_EXTS:
    score += 5
    evidence.append(f"Extension .{ext} (image)")
else:
    evidence.append(f"Extension .{ext or '(none)'} (uncategorized)")

# ── DIMENSION 3 — time-of-day (cap 10) ──────────────────────────────────
local_dt = alert_dt.astimezone(TAIPEI_OFFSET)
is_business_hours = (
    local_dt.weekday() < 5  # Mon-Fri
    and BUSINESS_HOUR_START <= local_dt.hour < BUSINESS_HOUR_END
)
if not is_business_hours:
    score += 10
    evidence.append(f"Written outside business hours ({local_dt.strftime('%Y-%m-%d %H:%M')} Asia/Taipei)")
else:
    evidence.append(f"Written during business hours ({local_dt.strftime('%H:%M')} Asia/Taipei)")

# ── DIMENSION 4 — 10-minute same-endpoint history (cap 40) ──────────────
if history_count >= 10:
    score += 40
    evidence.append(f"{history_count} rule-100500 hits from this endpoint in the last 10 min (batch transfer)")
elif history_count >= 5:
    score += 25
    evidence.append(f"{history_count} rule-100500 hits from this endpoint in the last 10 min")
elif history_count >= 2:
    score += 10
    evidence.append(f"{history_count} rule-100500 hits from this endpoint in the last 10 min")
else:
    evidence.append(f"{history_count} rule-100500 hits from this endpoint in the last 10 min (isolated event)")

# ── DECISION BANDS ───────────────────────────────────────────────────────
if score >= 60:
    action = "ESCALATE_AND_CONTAIN"
elif score >= 40:
    action = "NOTIFY_SOC"
else:
    action = "LOG_ONLY"

print(json.dumps({
    "score": score,
    "action": action,
    "agent_id": agent_id,
    "agent_name": agent_name,
    "file_path": file_path_display,
    "file_size": size_bytes,
    "extension": ext,
    "alert_timestamp": timestamp,
    "history_count": history_count,
    "evidence": evidence,
    # Semicolon-joined, not newline-joined: this gets embedded directly into
    # downstream nodes' JSON request bodies (wazuh_usb_dlp_workflow.json.j2's
    # notify_soc_review/iris_log_alert/escalate_iris_alert) via Shuffle's raw
    # text substitution - a literal newline there produces an invalid JSON
    # payload. Confirmed live: an earlier newline-joined version made
    # iris_log_alert fail with "SyntaxError - unterminated string literal"
    # on every single execution.
    "evidence_md": "; ".join(f"- {e}" for e in evidence),
    "updated_history_json": json.dumps(updated_history),
}))
