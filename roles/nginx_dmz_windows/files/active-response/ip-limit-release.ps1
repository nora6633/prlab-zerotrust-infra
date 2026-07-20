# Delayed-release helper for ip-limit.ps1. Launched as a DETACHED background
# process (Start-Process, no -Wait) by the "add" path so that invocation can
# return immediately instead of blocking for the full 5 minutes — see
# ip-limit.ps1's header comment for why an in-process Start-Sleep caused
# invocations of the same ar.conf command to serialize and starve out fresh
# blocks for other IPs.
#
# Self-managed rather than relying on Wazuh's own <timeout>-driven "delete"
# re-invocation: confirmed live that Wazuh's execd never actually re-dispatches
# a "delete" for active-responses that were triggered manually via the API
# (no <rules_id>/<level> bound) even with <timeout> configured — a 6-minute
# window with no delete for a real test block proved this out. ip-limit.sh
# (Linux) has the identical <timeout>300 configuration and has NEVER logged a
# single "unblocked" line in this environment's history, confirming the same
# gap exists there too (separate, pre-existing issue — not fixed here).
#
# Runs as its own OS process (not a PowerShell job tied to the parent's
# session), so it survives the "add" invocation's own exit.

param(
    [Parameter(Mandatory = $true)][string]$RuleName,
    [Parameter(Mandatory = $true)][string]$TargetIP,
    [Parameter(Mandatory = $true)][string]$LogPath,
    [int]$DelaySeconds = 300
)

Start-Sleep -Seconds $DelaySeconds

netsh advfirewall firewall delete rule name=$RuleName | Out-Null

$CurrentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$CurrentTime] [RELEASE] $DelaySeconds seconds up. Firewall Rule '$RuleName' removed. IP $TargetIP restored to normal." | Out-File -FilePath $LogPath -Append -Encoding utf8 | Out-Null
