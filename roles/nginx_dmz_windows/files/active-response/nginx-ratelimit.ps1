# Wazuh Active Response — enable nginx rate limiting (rule 100210, level 8).
# Writes a one-line `limit_req` directive into limit-active.conf and reloads nginx.

$ErrorActionPreference = 'Stop'
$logPath  = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$confPath = 'C:\nginx\conf\limit-active.conf'
$nginxExe = 'C:\nginx\nginx.exe'
$nginxDir = 'C:\nginx'

function Write-ARLog($msg) {
    "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') nginx-ratelimit: $msg" |
        Out-File -FilePath $logPath -Append -Encoding ASCII
}

try {
    $raw = [Console]::In.ReadToEnd()
    $payload = $raw | ConvertFrom-Json
    $cmd = $payload.command

    if ($cmd -eq 'add') {
        Set-Content -Path $confPath -Value 'limit_req zone=arratelimit burst=20 nodelay;' -Encoding ASCII
        & $nginxExe -p $nginxDir -s reload 2>&1 | Out-Null
        Write-ARLog 'rate limiting enabled (10r/s, burst 20)'
    }
    elseif ($cmd -eq 'delete') {
        Set-Content -Path $confPath -Value '# disabled' -Encoding ASCII
        & $nginxExe -p $nginxDir -s reload 2>&1 | Out-Null
        Write-ARLog 'rate limiting disabled'
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
