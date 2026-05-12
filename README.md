# SOC Lab Infrastructure

Ansible-orchestrated, Docker Compose-based SOC lab across three hosts. Fill in three IP addresses, run two playbooks, and all services are deployed and wired together automatically.

---

## Architecture
<img width="2252" height="844" alt="image" src="https://github.com/user-attachments/assets/16eac631-446d-48bb-85fc-bcee39264b8a" />

```
┌─────────────────────────────────────────────────────────────────┐
│ External Host  (Linux OR Windows DMZ)                           │
│   • OWASP Juice Shop  (port 3000)  — intentionally vulnerable   │
│   • Wazuh Agent       (host mode)  — monitors this host         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ agent registration / alerts
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ SOC Host                                                        │
│   • Wazuh Server   (port 443)   — SIEM / EDR                   │
│     └─ on alert (level ≥ 7) → custom-shuffle.py                │
│   • Shuffle        (port 3001)  — SOAR                          │
│     └─ webhook → HTTP POST to DFIR-IRIS API                     │
│   • DFIR-IRIS      (port 4444)  — case management               │
└─────────────────────────────────────────────────────────────────┘
                               ▲ agent registration / alerts
                               │
┌─────────────────────────────────────────────────────────────────┐
│ LAN Host                                                        │
│   • FreeIPA    (port 8443)  — LDAP / Kerberos identity          │
│   • Nextcloud  (port 8888)  — file storage                      │
│   • Mailcow    (port 443)   — mail server suite                 │
│   • Wazuh Agent (host mode) — monitors this host                │
└─────────────────────────────────────────────────────────────────┘
```

### Alert Pipeline

```
Wazuh Manager
  → /var/ossec/integrations/custom-shuffle  (Python script, level ≥ 7)
    → Shuffle webhook  http://<SOC_IP>:5001/api/v1/hooks/<webhook-id>
      → HTTP action: POST https://<SOC_IP>:4444/api/v1/cases/add
        → DFIR-IRIS case created automatically
```

---

## Project Structure

```
.
├── inventory/
│   └── hosts.ini                        ← fill in the 3 host IPs here
├── group_vars/
│   ├── all.yml                          ← shared vars (IPs derived from inventory)
│   ├── soc.yml                          ← Shuffle / IRIS passwords & API keys
│   ├── lan.yml                          ← FreeIPA / Nextcloud / Mailcow passwords
│   └── external.yml
├── roles/
│   ├── common/                          ← Docker CE install (Ubuntu 24.04)
│   ├── wazuh_server/                    ← Wazuh single-node + integration setup
│   ├── wazuh_agent/                     ← Wazuh agent container
│   ├── juice_shop/                      ← OWASP Juice Shop
│   ├── shuffle/                         ← Shuffle SOAR + workflow template
│   ├── dfir_iris/                       ← DFIR-IRIS case management
│   ├── freeipa/                         ← FreeIPA identity server
│   ├── nextcloud/                       ← Nextcloud + MariaDB
│   ├── mailcow/                         ← Mailcow mail server suite
│   ├── nginx_dmz_windows/               ← nginx reverse proxy + AR scripts (Windows)
│   └── wazuh_ddos_rules/                ← custom decoder/rules + AR config injection
├── windows-dmz/
│   └── setup-dmz.ps1                    ← manual PowerShell fallback (no Ansible)
├── site.yml                             ← deploy all services (Linux external)
├── deploy_windows_dmz.yml               ← deploy external host as Windows DMZ
├── deploy_soc_remaining.yml             ← resume partial SOC deploy (Shuffle + IRIS)
├── deploy_ddos_response.yml             ← DDoS scenario: nginx + AR (rate-limit + block)
└── configure_integration.yml            ← wire Wazuh → Shuffle → IRIS
```

---

## Host Specifications

| Host | Services | Min RAM | Recommended RAM | Min CPU | Disk |
|---|---|---|---|---|---|
| **SOC** | Wazuh server (manager + indexer + dashboard) + Shuffle (backend + OpenSearch) + DFIR-IRIS | 8 GB | 16 GB | 4 cores | 50 GB |
| **LAN** | FreeIPA + Nextcloud + Mailcow + Wazuh agent | 4 GB | 8 GB | 2 cores | 50 GB |
| **External (Linux)** | Juice Shop + Wazuh agent | 1 GB | 2 GB | 1 core | 20 GB |
| **External (Windows DMZ)** | Juice Shop (NSSM) + Wazuh agent (MSI) | 2 GB | 4 GB | 2 cores | 30 GB |

> The SOC host is the most resource-intensive — it runs two separate OpenSearch instances (Wazuh indexer + Shuffle's OpenSearch), each needing at least 1 GB JVM heap, on top of Wazuh manager, dashboard, and DFIR-IRIS. 8 GB is the floor; 16 GB is recommended for a stable lab.

---

## Prerequisites

- Ansible ≥ 2.14 on the control node
- SSH key access to all 3 hosts
- Target hosts: Ubuntu 24.04, min 4 GB RAM each (SOC host: 8 GB recommended)
- Passwordless sudo on all 3 hosts (Ansible uses `become: true` throughout)

Grant passwordless sudo to the ansible user on each host:

```bash
echo '<your-user> ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/<your-user>
```

Install required Ansible collections:

```bash
ansible-galaxy collection install community.docker community.general
```

For the Windows DMZ option additionally install:

```bash
ansible-galaxy collection install ansible.windows community.windows chocolatey.chocolatey
pip install pywinrm
```

The Windows target must have WinRM enabled and reachable on TCP/5985:

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted $true   # lab only
```

---

## Usage

### 1. Set host IPs

**Option A — environment variables (recommended):**

```bash
export EXTERNAL_HOST_IP=10.8.0.12
export SOC_HOST_IP=10.8.0.13
export LAN_HOST_IP=10.8.0.14
export ANSIBLE_USER=ubuntu           # optional, default: ubuntu
export ANSIBLE_SSH_KEY=~/.ssh/id_rsa # optional, default: ~/.ssh/id_rsa
```

Then use the dynamic inventory script for all playbook commands:

```bash
ansible-playbook -i inventory/hosts.py site.yml
```

**Option B — static file:**

Edit `inventory/hosts.ini` directly and use `-i inventory/hosts.ini`.

All service configs (Wazuh agent → manager IP, Shuffle webhook URLs, etc.) are derived automatically from these three IPs — no other files need to be touched for a basic deployment.

### 2. Change secrets

**Required before deploy** — edit `group_vars/soc.yml`:

| Variable | Description |
|---|---|
| `shuffle_default_apikey` | Shuffle API key (min 36 chars) |
| `iris_adm_api_key` | DFIR-IRIS admin API key (min 36 chars); embedded into the Shuffle workflow so Shuffle can call the IRIS API |
| `iris_admin_password` | DFIR-IRIS web UI password |
| `iris_secret_key` | Flask secret key (min 32 chars) |

Also review `group_vars/lan.yml` for FreeIPA, Nextcloud, and Mailcow passwords.

Optionally change the domain (default `example.lab`) in `group_vars/all.yml`.

### 3. Deploy all services

```bash
ansible-playbook -i inventory/hosts.ini site.yml
```

This runs four plays in order:
1. **all** — install Docker CE on every host
2. **soc** — Wazuh server, Shuffle, DFIR-IRIS
3. **external** — Wazuh agent, Juice Shop
4. **lan** — Wazuh agent, FreeIPA, Nextcloud, Mailcow

**Windows DMZ external host?** Skip the `external` play in `site.yml` and run the dedicated Windows playbook instead — it installs Juice Shop as a Windows service via NSSM and the Wazuh agent via MSI, configures the firewall, and registers the agent with the manager:

```bash
ansible-playbook -i inventory/hosts.ini deploy_windows_dmz.yml
```

**SOC deploy failed mid-way?** Re-run only the parts that haven't completed (skips Wazuh server, runs Shuffle + DFIR-IRIS):

```bash
ansible-playbook -i inventory/hosts.ini deploy_soc_remaining.yml
```

> No Ansible at all on the Windows side? Run `windows-dmz/setup-dmz.ps1` directly on the DMZ host as Administrator — it does the same install via Chocolatey + Docker Desktop.

### 4. Wire up the alert pipeline

```bash
ansible-playbook -i inventory/hosts.ini configure_integration.yml
```

This playbook:
- Imports the pre-built Shuffle workflow (Wazuh webhook → IRIS case creation)
- Copies `custom-shuffle.py` into the Wazuh manager container
- Injects the `<integration>` block into `ossec.conf`
- Restarts the Wazuh manager

### 5. (Optional) Deploy DDoS auto-response scenario

Adds an nginx reverse proxy in front of Juice Shop on the Windows DMZ host and wires Wazuh + Active Response to react to HTTP floods:

```bash
ansible-playbook -i inventory/hosts.ini deploy_ddos_response.yml
```

What gets deployed:

| Layer | What | Where |
|---|---|---|
| Ingress | nginx :80 → Juice Shop :3000 (NSSM service) | Windows DMZ |
| Detection | nginx access.log → Wazuh agent → custom decoder + rules 100210/100211 | manager |
| Response (level 8) | `nginx-ratelimit.ps1` writes `limit_req` snippet, reloads nginx | Windows DMZ |
| Response (level 10) | `firewall-block.ps1` adds `New-NetFirewallRule` blocking source IP for 600s | Windows DMZ |

Test it from any host with [`wrk`](https://github.com/wg/wrk) installed (`brew install wrk`):

```bash
# 100 conns × 4 threads × 30s — easily exceeds rule 100211's 100 req / 10 s
wrk -t4 -c100 -d30s http://<WINDOWS_DMZ_IP>/
```

Watch the chain trigger:

```bash
# alerts on the manager
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log
# AR script log on the agent
# (PowerShell on the Windows DMZ host)
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Wait
# firewall rules added by AR
Get-NetFirewallRule -DisplayName "Wazuh-AR-Block-*"
```

Expected: rule 100210 fires first (rate limit on), then 100211 fires and the source IP is blocked at the Windows firewall for 10 minutes.

---

## Service Endpoints

| Service | Host | URL |
|---|---|---|
| Wazuh Dashboard | SOC | `https://<SOC_IP>` |
| Shuffle | SOC | `http://<SOC_IP>:3001` |
| DFIR-IRIS | SOC | `https://<SOC_IP>:4444` |
| Juice Shop (direct) | External (Linux or Windows DMZ) | `http://<EXTERNAL_IP>:3000` |
| Juice Shop (via nginx, after DDoS scenario deploy) | Windows DMZ | `http://<WINDOWS_DMZ_IP>/` |
| FreeIPA | LAN | `https://<LAN_IP>:8443` |
| Nextcloud | LAN | `http://<LAN_IP>:8888` |
| Mailcow | LAN | `https://<LAN_IP>` |

Default Wazuh dashboard credentials: `admin` / `SecretPassword` (Wazuh default; change via Wazuh API post-deploy).

---

## How the Shuffle Workflow Works

The pre-built workflow (`roles/shuffle/templates/wazuh_iris_workflow.json.j2`) has two nodes:

1. **Webhook trigger** — listens at `http://<SOC_IP>:5001/api/v1/hooks/<trigger-id>`. The Wazuh integration script POSTs the full alert JSON here for every alert at level ≥ `wazuh_alert_min_level` (default: 7).

2. **HTTP action** — POSTs to the DFIR-IRIS `/api/v1/cases/add` endpoint, mapping Wazuh fields to IRIS case fields:
   - Case name: `Wazuh: <rule.description>`
   - Description: rule ID, agent name, alert level, source IP
   - SOC ID: `W-<alert_id>`

The workflow is imported automatically by `configure_integration.yml` using the `shuffle_default_apikey`.

---

## Customisation

| What | Where |
|---|---|
| Wazuh alert level threshold | `wazuh_alert_min_level` in `group_vars/soc.yml` |
| IRIS case fields mapping | `roles/shuffle/templates/wazuh_iris_workflow.json.j2` |
| Domain name | `domain` in `group_vars/all.yml` |
| IRIS version | `iris_version` in `group_vars/soc.yml` |
| Wazuh version | `wazuh_version` in `group_vars/all.yml` |
| Deploy directory on hosts | `deploy_base_dir` in `group_vars/all.yml` (default `/opt/soc-infra`) |
