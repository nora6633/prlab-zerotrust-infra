# ============================================================
# SOC Lab - Windows DMZ Setup Script
# Deploys: Wazuh Agent + OWASP Juice Shop
# Run as Administrator on the Windows DMZ machine
# ============================================================

param(
    [string]$WazuhManagerIP  = "192.168.5.15",
    [string]$AgentName       = "dmz-windows",
    [string]$WazuhVersion    = "4.9.2"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "[!] $msg" -ForegroundColor Red }

# ── 0. Privilege check ───────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Please run this script as Administrator."
    exit 1
}

# ── 1. Install Chocolatey (if needed) ───────────────────────
Write-Step "Checking Chocolatey..."
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Step "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    Write-OK "Chocolatey installed."
} else {
    Write-OK "Chocolatey already installed."
}

# ── 2. Install Docker Desktop ────────────────────────────────
Write-Step "Checking Docker..."
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Step "Installing Docker Desktop..."
    choco install docker-desktop -y --no-progress
    Write-OK "Docker Desktop installed. A reboot may be required."
    Write-Host "  If Docker is not running after this script, reboot and re-run." -ForegroundColor Yellow
} else {
    Write-OK "Docker already installed: $(docker --version)"
}

# Wait for Docker daemon
Write-Step "Waiting for Docker daemon..."
$timeout = 60
$elapsed = 0
while ($elapsed -lt $timeout) {
    try {
        docker info 2>&1 | Out-Null
        Write-OK "Docker daemon is running."
        break
    } catch {
        Start-Sleep -Seconds 5
        $elapsed += 5
    }
}
if ($elapsed -ge $timeout) {
    Write-Err "Docker daemon did not start in time. Please ensure Docker Desktop is running and re-run the script."
    exit 1
}

# ── 3. Deploy OWASP Juice Shop ───────────────────────────────
Write-Step "Deploying OWASP Juice Shop on port 3000..."
$existing = docker ps -aq --filter "name=juice-shop" 2>&1
if ($existing) {
    Write-Host "  Removing existing juice-shop container..."
    docker rm -f juice-shop 2>&1 | Out-Null
}
docker run -d `
    --name juice-shop `
    --restart unless-stopped `
    -p 3000:3000 `
    bkimminich/juice-shop:latest
Write-OK "Juice Shop deployed -> http://${env:COMPUTERNAME}:3000  (or http://10.8.0.17:3000)"

# ── 4. Download Wazuh Agent MSI ──────────────────────────────
Write-Step "Downloading Wazuh Agent v${WazuhVersion}..."
$msiName = "wazuh-agent-${WazuhVersion}-1.msi"
$msiUrl  = "https://packages.wazuh.com/4.x/windows/${msiName}"
$msiPath = "$env:TEMP\${msiName}"

if (-not (Test-Path $msiPath)) {
    Write-Host "  Downloading from $msiUrl ..."
    (New-Object System.Net.WebClient).DownloadFile($msiUrl, $msiPath)
    Write-OK "Downloaded to $msiPath"
} else {
    Write-OK "MSI already cached at $msiPath"
}

# ── 5. Install Wazuh Agent ───────────────────────────────────
Write-Step "Installing Wazuh Agent..."
$installArgs = @(
    "/i", $msiPath,
    "WAZUH_MANAGER=`"$WazuhManagerIP`"",
    "WAZUH_AGENT_NAME=`"$AgentName`"",
    "WAZUH_REGISTRATION_SERVER=`"$WazuhManagerIP`"",
    "/quiet",
    "/norestart",
    "/l*v", "$env:TEMP\wazuh-install.log"
)

$proc = Start-Process msiexec -ArgumentList $installArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Err "Wazuh Agent installation failed (exit code $($proc.ExitCode)). Check $env:TEMP\wazuh-install.log"
    exit 1
}
Write-OK "Wazuh Agent installed."

# ── 6. Start and enable Wazuh Agent service ──────────────────
Write-Step "Starting Wazuh Agent service..."
Start-Sleep -Seconds 3
$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($svc) {
    Set-Service -Name "WazuhSvc" -StartupType Automatic
    if ($svc.Status -ne "Running") {
        Start-Service -Name "WazuhSvc"
    }
    Start-Sleep -Seconds 5
    $svc.Refresh()
    Write-OK "WazuhSvc status: $($svc.Status)"
} else {
    Write-Err "WazuhSvc not found after install - check $env:TEMP\wazuh-install.log"
}

# ── 7. Open firewall for Wazuh & Juice Shop ──────────────────
Write-Step "Configuring Windows Firewall..."
netsh advfirewall firewall add rule name="Wazuh Agent Out" dir=out action=allow protocol=TCP remoteport=1514,1515 remoteip=$WazuhManagerIP 2>&1 | Out-Null
netsh advfirewall firewall add rule name="Juice Shop In" dir=in action=allow protocol=TCP localport=3000 2>&1 | Out-Null
Write-OK "Firewall rules added."

# ── 8. Summary ───────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  DMZ Windows Setup Complete" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Juice Shop  : http://10.8.0.17:3000"
Write-Host "  Wazuh Agent : connecting to $WazuhManagerIP"
Write-Host ""
Write-Host "  Verify agent on SOC (Ubuntu):"
Write-Host "    sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
Write-Host ""
