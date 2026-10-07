# Wazuh Active Response - deny write access to the simulated removable disk
# (C:\SimulatedUSB) via an NTFS deny ACE. Manual/API-triggered only (mirrors
# the DDoS ip-limit-* design in roles/wazuh_ddos_rules): this command has no
# <rules_id>/<level> in ossec.conf, so it never fires automatically off an
# alert match - Shuffle calls it via PUT /active-response only after the
# score_alert node returns ESCALATE_AND_CONTAIN (score >= 60).
#
# Deliberately no auto-release/timer (unlike ip-limit.ps1's 5-minute
# self-unblock): this is a data-exfiltration containment action, not a rate
# limit, so lifting it needs a human decision. "delete" removes the deny ACE
# if/when someone decides to unblock (e.g. via the Wazuh Active Response API
# with the "delete" command, or by running this script directly on the agent).
#
# Reads the AR payload from STDIN, one line only (not to EOF): wazuh-execd
# pipes the JSON as a single newline-terminated line but does not reliably
# close its end of the stdin pipe afterward - reading to EOF hangs forever
# (confirmed for this exact agent in ip-limit.ps1's header comment; same
# upstream Wazuh bug, wazuh/wazuh#25784/#25915). ReadLine() returns as soon
# as it sees the newline, sidestepping it entirely.

$TargetPath = "C:\SimulatedUSB"
$LogPath = "C:\Program Files (x86)\ossec-agent\active-response\bin\block-usb-write.log"

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

    $Obj = $Payload | ConvertFrom-Json
    $Command = $Obj.command
    $TriggerFile = $Obj.parameters.alert.data.file
    if ([string]::IsNullOrWhiteSpace($TriggerFile)) {
        $TriggerFile = "(unknown)"
    }

    switch ($Command) {
        "add" {
            # Idempotency check: an already-denied Everyone ACE means a
            # redundant ESCALATE_AND_CONTAIN re-dispatch is a no-op instead
            # of stacking duplicate deny entries. icacls prints inheritance
            # flags between the principal and the DENY/permission flags
            # (e.g. "Everyone:(OI)(CI)(DENY)(W)") - confirmed live that an
            # anchored "Everyone:\(DENY\)" pattern never matches that real
            # output, so this check always fell through and every repeat
            # dispatch stacked another duplicate DENY ACE instead of
            # skipping.
            $existing = icacls $TargetPath 2>$null
            if ($existing -match "Everyone:.*\(DENY\)") {
                Write-Log "[SKIP] $TargetPath already write-denied - not re-adding (triggered by: $TriggerFile)."
                exit 0
            }
            Write-Log "[START] Blocking write access to $TargetPath (triggered by file: $TriggerFile)."
            icacls $TargetPath /deny "Everyone:(OI)(CI)W" | Out-Null
            Write-Log "[SUCCESS] Write access to $TargetPath denied for Everyone. Manual unblock required (see delete command)."
        }
        "delete" {
            icacls $TargetPath /remove:d "Everyone" | Out-Null
            Write-Log "[RELEASE] Write-deny removed from $TargetPath. Access restored to normal."
        }
        default {
            Write-Log "[ERROR] Unknown command: '$Command'."
        }
    }
} catch {
    Write-Log "[CRITICAL ERROR] $($_.Exception.Message)"
}
