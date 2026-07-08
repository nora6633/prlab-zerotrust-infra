# Wazuh Active Response — block a source IP on ports 80/443 only (Windows Firewall).
# Manual/API-triggered only (ddos-plan.txt Part 3): this command has no <rules_id>
# in ossec.conf, so it never fires automatically off an alert match — Shuffle
# calls it via PUT /active-response after the N5 scoring node returns AUTO_BLOCK.
# Wazuh re-invokes this script with "delete" after the AR <timeout> (5 min)
# expires, so a mis-scored legitimate user recovers on their own.
# Reads JSON from stdin per Wazuh AR protocol; supports add/delete commands.
#
# Reads exactly ONE line, not to EOF: wazuh-execd sends the payload as a
# single newline-terminated line but does not reliably close its end of the
# stdin pipe afterward (confirmed live on the Linux agent, matches known
# unresolved upstream bugs — wazuh/wazuh#25784 "Active Response gets stuck
# after first execution" and wazuh/wazuh#25915, which reports the identical
# symptom on .NET's ReadToEnd()). [Console]::In.ReadToEnd() blocks forever
# waiting for a stream close that never arrives. ReadLine() returns as soon
# as it sees the newline, matching the documented AR stdin protocol exactly.

$ErrorActionPreference = 'Stop'
$logPath = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'

function Write-ARLog($msg) {
    "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') ip-limit: $msg" |
        Out-File -FilePath $logPath -Append -Encoding ASCII
}

try {
    $raw = [Console]::In.ReadLine()
    if (-not $raw) { Write-ARLog 'no stdin'; exit 1 }

    $payload = $raw | ConvertFrom-Json
    $cmd     = $payload.command
    $srcip   = $payload.parameters.alert.data.srcip
    if (-not $srcip) { $srcip = $payload.parameters.alert.srcip }
    if (-not $srcip) { Write-ARLog 'no srcip in alert'; exit 1 }

    $ruleName = "Wazuh-AR-IPLimit-$srcip"

    if ($cmd -eq 'add') {
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Description "Auto-blocked by Shuffle DDoS workflow (ip-limit)" `
                -Direction Inbound `
                -Action Block `
                -Protocol TCP `
                -LocalPort 80,443 `
                -RemoteAddress $srcip | Out-Null
            Write-ARLog "blocked $srcip on ports 80/443"
        } else {
            Write-ARLog "rule for $srcip already exists"
        }
    }
    elseif ($cmd -eq 'delete') {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule
        Write-ARLog "unblocked $srcip"
    }
    else {
        Write-ARLog "unknown command: $cmd"
        exit 1
    }
    exit 0
}
catch {
    Write-ARLog "error: $_"
    exit 1
}
