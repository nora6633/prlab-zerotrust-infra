# SOC Lab Infrastructure

Ansible-orchestrated, Docker Compose-based SOC lab across three hosts. Fill in three IP addresses, run two playbooks, and all services are deployed and wired together automatically.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ External Host                                                   │
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
│   └── mailcow/                         ← Mailcow mail server suite
├── site.yml                             ← deploy all services
└── configure_integration.yml           ← wire Wazuh → Shuffle → IRIS
```

---

## Prerequisites

- Ansible ≥ 2.14 on the control node
- SSH key access to all 3 hosts
- Target hosts: Ubuntu 24.04, min 4 GB RAM each (SOC host: 8 GB recommended)

Install required Ansible collections:

```bash
ansible-galaxy collection install community.docker community.general
```

---

## Usage

### 1. Set host IPs

Edit `inventory/hosts.ini`:

```ini
[external]
external-host ansible_host=<EXTERNAL_HOST_IP> ansible_user=ubuntu

[soc]
soc-host ansible_host=<SOC_HOST_IP> ansible_user=ubuntu

[lan]
lan-host ansible_host=<LAN_HOST_IP> ansible_user=ubuntu

[all:vars]
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

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

### 4. Wire up the alert pipeline

```bash
ansible-playbook -i inventory/hosts.ini configure_integration.yml
```

This playbook:
- Imports the pre-built Shuffle workflow (Wazuh webhook → IRIS case creation)
- Copies `custom-shuffle.py` into the Wazuh manager container
- Injects the `<integration>` block into `ossec.conf`
- Restarts the Wazuh manager

---

## Service Endpoints

| Service | Host | URL |
|---|---|---|
| Wazuh Dashboard | SOC | `https://<SOC_IP>` |
| Shuffle | SOC | `http://<SOC_IP>:3001` |
| DFIR-IRIS | SOC | `https://<SOC_IP>:4444` |
| Juice Shop | External | `http://<EXTERNAL_IP>:3000` |
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
