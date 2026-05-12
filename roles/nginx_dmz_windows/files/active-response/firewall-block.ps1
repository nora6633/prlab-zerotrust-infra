# Wazuh Active Response — block source IP at Windows Firewall (rule 100211, level 10).
# Reads JSON from stdin per Wazuh AR protocol; supports add/delete commands.

$ErrorActionPreference = 'Stop'
$logPath = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'

function Write-ARLog($msg) {
    "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') firewall-block: $msg" |
        Out-File -FilePath $logPath -Append -Encoding ASCII
}

try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { Write-ARLog 'no stdin'; exit 1 }

    $payload = $raw | ConvertFrom-Json
    $cmd     = $payload.command
    $srcip   = $payload.parameters.alert.data.srcip
    if (-not $srcip) { $srcip = $payload.parameters.alert.srcip }
    if (-not $srcip) { Write-ARLog 'no srcip in alert'; exit 1 }

    $ruleName = "Wazuh-AR-Block-$srcip"

    if ($cmd -eq 'add') {
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Description "Auto-blocked by Wazuh AR (rule 100211 HTTP flood)" `
                -Direction Inbound `
                -Action Block `
                -RemoteAddress $srcip | Out-Null
            Write-ARLog "added block rule for $srcip"
        } else {
            Write-ARLog "rule for $srcip already exists"
        }
    }
    elseif ($cmd -eq 'delete') {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule
        Write-ARLog "removed block rule for $srcip"
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
