# Wazuh Active Response — block a source IP on ports 80/443 only, via netsh
# advfirewall. Manual/API-triggered only (ddos-plan.txt Part 3): this command
# has no <rules_id>/<level> in ossec.conf, so it never fires automatically off
# an alert match — Shuffle calls it via PUT /active-response after the N5
# scoring node returns AUTO_BLOCK.
#
# Self-contained 5-minute auto-release: this script blocks, sleeps 300s, then
# unblocks itself in the SAME invocation, rather than relying on Wazuh's own
# <timeout> to re-invoke it with "delete" later. Because of this, the
# ip-limit-windows <active-response> block in ossec.conf must NOT also set
# <timeout> (see inject_active_response.py.j2) — that would make Wazuh
# independently re-invoke this script with "delete" 5 minutes after "add" too,
# racing this script's own self-delete (harmless — `netsh ... delete rule` on
# an already-removed rule just no-ops — but redundant, and it also changes the
# ar.conf-registered command name that Shuffle has to call by exact string).
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
    $Payload = $RawArgs.Trim('"')
    if ([string]::IsNullOrWhiteSpace($Payload) -or $Payload -eq '""') {
        Write-Log "[ERROR] Empty payload after trim."
        exit 0
    }

    # Regex extraction of the target IP rather than JSON parsing: the AR body
    # Shuffle sends is just {"command":"...","arguments":["<ip>"],
    # "alert":{"data":{"srcip":"<ip>"}}} — the attacker IP is the only IPv4
    # address present, so grabbing the first match is safe for this payload
    # shape (if the payload ever grows to include other IP-bearing fields —
    # e.g. agent.ip — this would need to become a real JSON parse instead).
    $TargetIP = "Unknown"
    $IPPattern = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    if ($Payload -match $IPPattern) {
        $TargetIP = $Matches[0]
    } else {
        Write-Log "[ERROR] Valid IP not found."
        exit 0
    }

    $RuleName = "Wazuh-DDoS-Limit-$TargetIP"
    Write-Log "[START] Protecting against DDoS from IP: $TargetIP. Mitigating via Windows Netsh Firewall for 5 mins."

    netsh advfirewall firewall add rule name=$RuleName dir=in action=block remoteip=$TargetIP protocol=TCP localport=80,443 | Out-Null
    Write-Log "[SUCCESS] Firewall Rule '$RuleName' applied successfully. Blocked high-frequency web ports for this IP."

    Start-Sleep -Seconds 300

    netsh advfirewall firewall delete rule name=$RuleName | Out-Null
    Write-Log "[RELEASE] 5 minutes up. Firewall Rule '$RuleName' removed. IP $TargetIP restored to normal."
} catch {
    Write-Log "[CRITICAL ERROR] $($_.Exception.Message)"
}
