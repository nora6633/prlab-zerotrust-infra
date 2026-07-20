# Wazuh Active Response — block a source IP on ports 80/443 only, via netsh
# advfirewall. Manual/API-triggered only (ddos-plan.txt Part 3): this command
# has no <rules_id>/<level> in ossec.conf, so it never fires automatically off
# an alert match — Shuffle calls it via PUT /active-response after the N5
# scoring node returns AUTO_BLOCK.
#
# add: applies the block, then launches ip-limit-release.ps1 as a DETACHED
# background process (Start-Process, no -Wait) to unblock after 5 minutes,
# and returns immediately. delete: also handled directly, in case a "delete"
# is ever dispatched some other way (e.g. manual API cleanup).
#
# Release is self-managed (NOT Wazuh's <timeout>, despite ossec.conf still
# configuring <timeout>300> on ip-limit-windows for symmetry with
# ip-limit-linux — that element is effectively inert here): confirmed live
# that Wazuh's execd never actually re-dispatches a "delete" for
# active-responses triggered manually via the API (no <rules_id>/<level>
# bound, per ddos-plan.txt Part 3) even with <timeout> configured — a live
# test block sat blocked for 6+ minutes with zero delete dispatch.
# ip-limit.sh (Linux) has the identical config and has never once logged an
# "unblocked" line in this environment's history, confirming the gap is not
# Windows-specific (separate, pre-existing issue on the Linux side — not
# fixed here).
#
# An EARLIER version of this script self-managed release differently: it
# blocked for the full 5 minutes INSIDE the same invocation (Start-Sleep 300,
# then self-delete). Because invocations of the same ar.conf command
# serialize on this agent (confirmed live: a manual dispatch queued for
# 1m41s behind an unrelated, still-sleeping invocation), that meant a fresh
# block for a NEW attacker IP could sit queued behind an old invocation's
# Start-Sleep for however many 5-minute slots were already ahead of it —
# silently failing to block the CURRENT attacker while an old one was still
# "in the sleep". Launching the sleep+delete in a separate detached process
# (this version) keeps the "add" invocation itself near-instant — same as
# Linux — so nothing queues, while still self-managing the actual release
# instead of depending on Wazuh's timeout re-dispatch, which doesn't happen.
#
# Reads the AR payload from STDIN, not a script parameter: wazuh-execd pipes
# the JSON to the process's stdin — confirmed live via /proc/<pid>/fd
# inspection on the Linux agent (fd 0 is a pipe, not argv). Reads exactly one
# line, not to EOF: wazuh-execd sends the payload as a single
# newline-terminated line but does not reliably close its end of the stdin
# pipe afterward (wazuh/wazuh#25784, #25915) — reading to EOF
# ([Console]::In.ReadToEnd()) hangs forever waiting for a stream close that
# never arrives; ReadLine() returns as soon as it sees the newline.

$LogPath = "C:\Program Files (x86)\ossec-agent\active-response\bin\ip-limit.log"

function Write-Log ($Message) {
    $CurrentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$CurrentTime] $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8 | Out-Null
}

try {
    $RawArgs = [Console]::In.ReadLine()
    if ([string]::IsNullOrEmpty($RawArgs)) {
        Write-Log "[ERROR] No stdin payload received."
        exit 0
    }
    $Payload = $RawArgs.Trim('"').Replace('\"', '"')
    if ([string]::IsNullOrWhiteSpace($Payload) -or $Payload -eq '""') {
        Write-Log "[ERROR] Empty payload after trim."
        exit 0
    }

    # Real JSON parse, mirroring ip-limit.sh's python3 json.load — a plain
    # regex "first IPv4 in the payload" was safe only as long as srcip was the
    # only IP-shaped field present; parsing properly avoids that assumption
    # entirely and lets us also read the "command" field (add/delete).
    $Obj = $Payload | ConvertFrom-Json
    $Command = $Obj.command
    $TargetIP = $Obj.parameters.alert.data.srcip
    if ([string]::IsNullOrEmpty($TargetIP)) {
        $TargetIP = $Obj.parameters.alert.srcip
    }
    if ([string]::IsNullOrWhiteSpace($TargetIP)) {
        Write-Log "[ERROR] No srcip found in payload."
        exit 0
    }

    $RuleName = "Wazuh-DDoS-Limit-$TargetIP"

    switch ($Command) {
        "add" {
            # Idempotency check, mirroring ip-limit.sh's `iptables -C` guard:
            # a redundant AUTO_BLOCK re-dispatch for an IP that's ALREADY
            # blocked (e.g. from Shuffle's dedupe cache repeatedly failing to
            # persist - confirmed live, a known separate issue) is a no-op
            # instead of clobbering the existing rule/timer.
            if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
                Write-Log "[SKIP] $TargetIP already blocked - not re-adding."
                exit 0
            }
            Write-Log "[START] Protecting against DDoS from IP: $TargetIP. Mitigating via Windows Netsh Firewall for 5 mins."
            netsh advfirewall firewall add rule name=$RuleName dir=in action=block remoteip=$TargetIP protocol=TCP localport=80,443 | Out-Null
            Write-Log "[SUCCESS] Firewall Rule '$RuleName' applied successfully. Blocked high-frequency web ports for this IP."

            $ReleaseScript = Join-Path $PSScriptRoot "ip-limit-release.ps1"
            Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -ArgumentList @(
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$ReleaseScript`"",
                "-RuleName", "`"$RuleName`"", "-TargetIP", "`"$TargetIP`"", "-LogPath", "`"$LogPath`""
            ) | Out-Null
        }
        "delete" {
            netsh advfirewall firewall delete rule name=$RuleName | Out-Null
            Write-Log "[RELEASE] Firewall Rule '$RuleName' removed. IP $TargetIP restored to normal."
        }
        default {
            Write-Log "[ERROR] Unknown command: '$Command'."
        }
    }
} catch {
    Write-Log "[CRITICAL ERROR] $($_.Exception.Message)"
}
