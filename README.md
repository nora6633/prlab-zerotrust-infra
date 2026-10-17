# SOC Lab Infrastructure

> Scenario 3 (insider-threat, `insider-threat-test/`) lives on the `scenario3` branch, not `main`. Clone with `git clone -b scenario3 <repo>` if you need it.

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
│   ├── shuffle/                         ← Shuffle SOAR + workflow templates (IRIS + DDoS)
│   ├── dfir_iris/                       ← DFIR-IRIS case management
│   ├── freeipa/                         ← FreeIPA identity server
│   ├── nextcloud/                       ← Nextcloud + MariaDB
│   ├── mailcow/                         ← Mailcow mail server suite
│   ├── nginx_dmz_windows/               ← nginx reverse proxy + AR scripts (Windows)
│   └── wazuh_ddos_rules/                ← custom decoder/rules + AR config injection
├── windows-dmz/
│   └── setup-dmz.ps1                    ← manual PowerShell fallback (no Ansible)
├── dmz-ubuntu/                          ← Dockerfile + compose for a container standing in for
│   └── docker-compose.yaml                the Linux "external" host (single-machine topology
│                                           only - see "Single machine simulating 3 hosts" below)
├── ubuntu-lan/                          ← same, standing in for the "lan" host
│   └── docker-compose.yaml
├── bootstrap_scenario_hosts.yml         ← creates dmz-ubuntu/ + ubuntu-lan/ containers (run
│                                           this first if using the single-machine topology)
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

**Single-machine sizing, measured on a test VM** — the table above is for the 3-separate-real-hosts topology; the numbers below are from a single VM running scenario 3 (`--limit soc-host,dmz-ubuntu`, skipping the optional `lan` play), the only scenario actually tested end-to-end this way:

| | Scenario 3 only (`--limit soc-host,dmz-ubuntu`) | Full deploy (incl. `lan` play) |
|---|---|---|
| RAM | **Measured** ≈7.4 GiB (`docker stats` summed across SOC containers + `dmz-ubuntu` + the `lan` container's own base footprint). Whole-VM `free -h` at the same snapshot (19GiB VM): 6.1 GiB used. | **Not measured** (Nextcloud/Mailcow/FreeIPA never reached a stable fully-up state together to snapshot — see FreeIPA note below). The 3-hosts table above's LAN-host figure (4GB min / 8GB recommended) is the closest reference, not re-verified for this topology. |
| Disk | **Estimated** ≈20-29GB (outer images ~15.1GB + outer volumes 11.74GB, most of which is likely inflated by repeated testing and not representative of a fresh deploy (unverified) + non-`lan` container layers ~2.5GB) — arithmetic on measured components, not a from-scratch test. | **No usable number** — this test VM's disk hit 100% (96GB/96GB), but ~60GB of that traced to a specific bug (see FreeIPA note below), not representative steady-state usage. Budget generously and monitor if you run this play. |

Only a ~19GiB VM was actually tested — nothing smaller. 12GiB is a reasonable first value to try, not a verified minimum.

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

### Fresh host/VM setup

If you're starting from a brand new machine/VM with nothing installed yet, here's the exact sequence that's been verified to work end to end. All commands below are for Ubuntu 24.04.

**Clone.** This repo's own `git remote` is configured over SSH for the maintainer's own push access - that URL will fail with `Host key verification failed` on a machine with no SSH key registered against it. Use the HTTPS form instead (works with no authentication, since this repo is public):

```bash
git clone -b scenario3 https://github.com/nora6633/prlab-zerotrust-infra.git
cd prlab-zerotrust-infra
```

**Ansible, and the collections this repo's roles need:**

```bash
sudo apt-get update
sudo apt-get install -y ansible git python3-pip
ansible-galaxy collection list | grep -i docker   # confirm community.docker is already present
```

The Ubuntu `ansible` apt package already bundles `community.docker` and `community.general` - the separate `ansible-galaxy collection install` step mentioned earlier in this doc is only needed if you installed a bare `ansible-core` via pip instead.

**Docker CE + the Compose v2 plugin.** `bootstrap_scenario_hosts.yml` (and every service role) needs `docker compose` as a subcommand, not the standalone `docker-compose` binary - Ubuntu's own `docker.io` apt package does **not** include it.

⚠️ **This removes `docker.io`/`docker-compose`/`containerd`/`runc` first - only do this on a genuinely fresh machine/VM.** If the host already has containers or data you need to keep, don't paste this blindly; adapt it (or install Docker CE alongside what's there) instead.

```bash
sudo apt-get remove -y docker.io docker-doc docker-compose podman-docker containerd runc
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
# The group change above doesn't apply to your current shell/session - log
# out and back in, or run `newgrp docker`, before `docker`/`docker compose`
# work without `sudo`.
docker compose version   # should print a version, not "unknown command: compose"
```

⚠️ Switching from `docker.io` to `docker-ce` like this can leave `dockerd` in a crash-restart loop for a few seconds (`systemctl status docker` shows `Start request repeated too quickly`), apparently from a stale `iptables` lock held by the just-removed daemon. If `docker compose version` above fails to connect to the daemon, this clears it:

```bash
sudo pkill -9 dockerd
sudo systemctl reset-failed docker
sudo systemctl start docker
```

### Single machine simulating 3 hosts vs. 3 real hosts

The Architecture diagram above describes 3 logically separate hosts (External/SOC/LAN). Nothing about the roles themselves requires that — `site.yml` just targets whatever `inventory/hosts.ini` groups resolve to. In practice this lab is commonly run **on a single physical machine**, with each "host" actually being a separate Docker container/bridge network on that one machine, and `inventory/hosts.ini`'s `ansible_host` values pointing at those containers' bridge IPs rather than separate real machines. If that's your setup:

- The `soc` group's `ansible_host` is the Docker host's own address (same machine Ansible runs on), with `ansible_connection=local`.
- `external`/`lan` point at container IPs on their own bridge networks, not separate VMs.
- **`dmz-ubuntu`'s address is fixed and known in advance: `dmz-ubuntu/docker-compose.yaml` declares `ipv4_address: 172.23.0.2` on its `default` network** (plus `172.30.0.2` on `scenario3-link`, used by scenario 3's Linux AR target). Put `172.23.0.2` directly into `inventory/hosts.ini`'s `dmz-ubuntu` entry — no need to inspect anything for this one.
- **`ubuntu-lan` has no fixed address at all** — its `docker-compose.yaml` declares no `networks:` block with a static IP, so `docker compose up` creates a fresh bridge network and assigns whatever IP is free. This means a chicken-and-egg problem writing `hosts.ini`: you can't know the real IP until after the container exists, and the container doesn't exist until `bootstrap_scenario_hosts.yml` runs. The sequence:
  ```bash
  # 1. Put a placeholder in hosts.ini's lan-host entry for now, then:
  ansible-playbook -i inventory/hosts.ini bootstrap_scenario_hosts.yml

  # 2. The running container is named "lan" (from its docker-compose.yaml's
  #    service name), NOT "ubuntu-lan" (the directory name) - find its real IP:
  docker inspect lan --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'

  # 3. Put that IP into hosts.ini's lan-host entry before running site.yml.
  ```
  **Taking the scenario-3-only path (`--limit soc-host,dmz-ubuntu`)? Skip all three steps above.** The lateral-movement target IP inside scenario 3's own attack script is fixed at `insider_threat_lan_link_ip` (`172.30.0.3` in `group_vars/all.yml`, the `scenario3-link` network address) — unrelated to `hosts.ini`'s `lan-host` entry. You only need the bootstrap/inspect/refill dance above if you're also running the optional `lan` play (FreeIPA/Nextcloud/Mailcow), which does connect to `lan-host` over SSH for real.
- **`dmz-ubuntu` and `lan` both run their own *nested* Docker daemon** — this matters for anything you try to debug on them. `roles/juice_shop` (on `dmz-ubuntu`) and `roles/freeipa`/`roles/nextcloud`/`roles/mailcow` (on `lan`) all run `docker compose up -d` *over Ansible's SSH connection, inside the target container itself* — not on the VM/physical host's own Docker. This means:
  - `docker ps -a` run on the VM/host **never** shows Juice Shop, FreeIPA, Nextcloud, or Mailcow — you have to go one level deeper:
    ```bash
    docker exec dmz-ubuntu docker ps -a --format '{{.Names}}\t{{.Status}}'
    docker exec lan docker ps -a --format '{{.Names}}\t{{.Status}}'
    ```
  - The pre-pull / save-transfer-load advice in [§ 3 Deploy all services](#3-deploy-all-services) only reaches the VM/host's **outer** Docker daemon — `docker load` there does nothing for images these nested services need. To get a saved image into the **inner** `lan` (or `dmz-ubuntu`) daemon instead, pipe the save directly into a `docker exec`, skipping the intermediate `.tar` file entirely (verified working against `lan`'s nested daemon on a test VM). Note `dmz-ubuntu`'s own nested Docker daemon doesn't exist until `site.yml`'s first play (`all` — "Install Docker on all hosts") has run against it — see the timing note under § 3 method 2 below:
    ```bash
    docker save <image> | docker exec -i lan docker load
    # or, for dmz-ubuntu's own Juice Shop image:
    docker save <image> | docker exec -i dmz-ubuntu docker load
    ```
- **`dmz-ubuntu/` and `ubuntu-lan/` (their Dockerfile + `docker-compose.yaml`) are not deployed by `site.yml` or any other role in this repo** — if you're using these containers as stand-ins for the external/LAN hosts, prepare the following *before* running anything:

  **`group_vars/soc.yml` and `inventory/hosts.ini` ship with the maintainer's own real environment's values, not a blank template.** `git clone` copies whatever is currently committed - both files are tracked (not gitignored), and on the maintainer's own machine they're additionally marked `git update-index --skip-worktree`, which only suppresses `git status`/`git diff` noise *on that one machine* and has no effect at all on what a fresh clone receives. If you're cloning this fresh, you will get the maintainer's own hostnames/IPs/credentials, not an empty form - overwrite both files with your own values before doing anything else:

  ```bash
  cp group_vars/soc.yml.example group_vars/soc.yml
  cp inventory/hosts.ini.example inventory/hosts.ini
  # Optional, but recommended if you intend to keep working in this clone and
  # don't want your own real values to accidentally get committed later:
  git update-index --skip-worktree group_vars/soc.yml inventory/hosts.ini
  ```

  See [§ Change secrets](#2-change-secrets) below for which `soc.yml` values need a real value before first deploy vs. which are fine to leave as-is.

  `dmz-ubuntu/Dockerfile` and `ubuntu-lan/Dockerfile` both `COPY` an `authorized_keys` file at build time - it's gitignored, so a fresh clone doesn't have one and the image build fails outright without it. This generates an ed25519 keypair, **not** the RSA key `hosts.ini.example`'s `ansible_ssh_private_key_file` points at by default - update that line in your `hosts.ini` to match (done below), rather than generating an RSA key just to match the example file:

  ```bash
  ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519
  cp ~/.ssh/id_ed25519.pub dmz-ubuntu/authorized_keys
  cp ~/.ssh/id_ed25519.pub ubuntu-lan/authorized_keys
  ```

  Ansible's own SSH connections to these containers will fail on first contact (`Host key verification failed`) unless `hosts.ini`'s `[all:vars]` sets this (matching what `insider-threat-test/run_attack.sh` already assumes), and `ansible_ssh_private_key_file` must point at the key you just generated above, not `hosts.ini.example`'s default `~/.ssh/id_rsa`:

  ```ini
  [all:vars]
  ansible_ssh_private_key_file=~/.ssh/id_ed25519
  ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
  ```

  With that done, the full order for a from-scratch scenario-3 deployment is:
  ```bash
  # 1. Fill in group_vars/soc.yml FIRST (see group_vars/soc.yml.example) - every
  #    CHANGE_ME must be replaced before running configure_integration.yml, or
  #    the placeholder gets permanently baked into a live Shuffle workflow
  #    (see note below).
  #    dmz_ubuntu_agent_id/dmz_windows_agent_id CANNOT be filled in yet at this
  #    point - they're assigned by Wazuh at agent registration time, which
  #    hasn't happened. Leave them as CHANGE_ME for now and come back after step 2.

  ansible-playbook -i inventory/hosts.ini bootstrap_scenario_hosts.yml
  ansible-playbook -i inventory/hosts.ini site.yml

  # 2. Agents are now registered - look up the real IDs and fill them into
  #    group_vars/soc.yml before continuing (don't assume example values like
  #    "007" - a fresh single-agent lab typically registers as "001"):
  #    docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

  ansible-playbook -i inventory/hosts.ini configure_integration.yml                  # imports IRIS/DDoS/USB-DLP workflows - run this even if you only want scenario 3, see note below
  ansible-playbook -i inventory/hosts.ini deploy_insider_threat_response.yml          # only if using insider-threat-test/
  ansible-playbook -i inventory/hosts.ini configure_insider_threat_integration.yml    # only if using insider-threat-test/

  # 3. configure_insider_threat_integration.yml just imported the insider-threat
  #    Shuffle workflow, but does NOT write its assigned IDs back into
  #    group_vars/soc.yml - Shuffle re-generates these on every import.
  #    These two IDs aren't read by run_attack.sh or the helper scripts
  #    (set_force_off_hours.sh/update_shuffle_workflow_ip.sh look up the
  #    live value instead), so it's fine to leave them as CHANGE_ME. To
  #    look them up by hand anyway:
  #    curl -H "Authorization: Bearer <shuffle_default_apikey>" http://<soc-ip>:5001/api/v1/workflows
  #    -> match by name "Wazuh Insider-Threat Auto-Response", use its "id" for
  #       shuffle_insider_threat_workflow_id and its triggers[0].id for
  #       shuffle_insider_threat_webhook_trigger_id
  ```
  `bootstrap_scenario_hosts.yml` creates the `dmz-ubuntu_default` and `scenario3-link` networks (both declared `external: true` in `dmz-ubuntu/docker-compose.yaml` — yes, both, even if you only want the plain DDoS/Juice-Shop use of this host and have no interest in scenario 3; see the playbook's own header comment) and builds/starts both containers. It's idempotent - safe to re-run, never recreates an already-running container or touches its volumes. Confirm the subnet it picks matches what `inventory/hosts.ini` expects to SSH into (`docker network inspect dmz-ubuntu_default`).

  ⚠️ **`configure_insider_threat_integration.yml` cannot run standalone** despite scoping itself to "scenario 3 only" - it looks up the *currently active* IRIS/DDoS/USB-DLP Shuffle trigger IDs (deliberately without re-importing them) to wire the shared `custom-shuffle` forwarding script, so those three workflows must already exist. Run `configure_integration.yml` at least once first.

  ⚠️ **Any value baked into a Shuffle workflow or `custom-shuffle.py` at import time is frozen from that point on** - Shuffle stores imported workflow JSON as a static document, it does not re-read `group_vars/soc.yml` later. If you edit `wazuh_indexer_password`, `wazuh_api_password`, `wazuh_server_ip`, `dmz_ubuntu_agent_id`, `dmz_windows_agent_id`, `iris_adm_api_key`, `abuseipdb_api_key`, or `shuffle_default_apikey` *after* already running `configure_integration.yml`/`configure_insider_threat_integration.yml`, the already-imported workflow keeps using the old value - the fix doesn't take effect until you delete that specific workflow in Shuffle and re-run the playbook that imports it. Both playbooks now assert on startup that none of their required values are still `CHANGE_ME`/empty, to catch this before it silently gets baked in - but that only protects the *first* import, not a later edit to an already-deployed value. In particular: if you deploy scenario 3 first and only add the Windows agent later, `dmz_windows_agent_id` was still `CHANGE_ME` when the DDoS/USB-DLP workflows were imported, and filling it in afterward does not retroactively fix them - delete both workflows in Shuffle and re-run `configure_integration.yml` for the real agent ID to take effect.

  ⚠️ Both Dockerfiles bake in a `dev` account with a hardcoded, lab-only password (an SSH key is also baked in and preferred for actual access) — change or remove that password before using either Dockerfile outside a throwaway lab.
- If a scenario's own setup (e.g. `insider-threat-test/`) requires host-level `auditd`, that specifically needs a real machine or VM for the `soc` host - it cannot run inside a container (no access to the kernel audit netlink socket). See `insider-threat-test/README.md`'s prerequisites.

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

`ANSIBLE_SSH_KEY` only feeds `inventory/hosts.py` (confirmed in that script - its default really is `~/.ssh/id_rsa`, not a doc error). It has **no effect** on the single-machine/scenario-3 path below ("Fresh host/VM setup" + "Single machine simulating 3 hosts"), which uses `-i inventory/hosts.ini` directly throughout - that path's own key comes from `hosts.ini`'s `ansible_ssh_private_key_file` instead (set to `~/.ssh/id_ed25519` there, matching the keypair generated in that section). It also has no effect on `insider-threat-test/run_attack.sh`, which uses a third, separate keypair of its own (`secrets/insider_threat_test_key`, auto-generated idempotently by the `insider_threat_agent_linux` role - nothing to set up manually). If you *are* using Option A's dynamic inventory with an ed25519 key instead of RSA, set `ANSIBLE_SSH_KEY=~/.ssh/id_ed25519` to match.

**Option B — static file:**

Edit `inventory/hosts.ini` directly and use `-i inventory/hosts.ini`.

All service configs (Wazuh agent → manager IP, Shuffle webhook URLs, etc.) are derived automatically from these three IPs — no other files need to be touched for a basic deployment.

### 2. Change secrets

**`group_vars/soc.yml` is not gitignored - it's a tracked file with real values currently committed to history (clean that up / rotate those values before treating this repo as shareable).** Copy `group_vars/soc.yml.example` to `group_vars/soc.yml` and `inventory/hosts.ini.example` to `inventory/hosts.ini` for a fresh checkout, and run `git update-index --skip-worktree group_vars/soc.yml inventory/hosts.ini` before filling in your own values so they don't get committed.

None of `soc.yml`'s ~28 variables have an Ansible-level default (no `defaults/main.yml`, no `| default(...)` anywhere) - every one of them must have *some* string or template rendering fails outright. Whether that string needs to be a real, working value, or whether the `.example` placeholder is fine to leave as-is, differs per variable:

**Choose a real value before first deploy - the respective container adopts it as its actual credential at boot** (confirmed in `roles/shuffle/templates/docker-compose.yml.j2` / `roles/dfir_iris/templates/docker-compose.yml.j2` - these are plain container env vars, nothing generates them after the fact and writes them back):

| Variable | Description |
|---|---|
| `shuffle_admin_username` / `shuffle_admin_password` | Shuffle UI login |
| `shuffle_default_apikey` | Shuffle API key (min 36 chars) |
| `iris_adm_api_key` | DFIR-IRIS admin API key (min 36 chars); embedded into the Shuffle workflow so Shuffle can call the IRIS API |
| `iris_admin_password` | DFIR-IRIS web UI password |
| `iris_secret_key` | Flask secret key (min 32 chars) |
| `iris_db_password`, `iris_rabbitmq_user` / `iris_rabbitmq_password` | IRIS's own Postgres/RabbitMQ credentials |

⚠️ **`wazuh_api_user` / `wazuh_api_password` and `wazuh_indexer_user` / `wazuh_indexer_password` are two pairs that look like the above but AREN'T - do not change these from the `.example` values, which are deliberately filled in with the matching upstream defaults, not `CHANGE_ME`.** `roles/wazuh_server/templates/wazuh.yml.j2` hardcodes the Wazuh dashboard's `wazuh-wui` API credential as a literal string (confirmed: Wazuh's own upstream `wazuh-docker` single-node default), and that same project's `docker-compose.yml` (cloned verbatim by `roles/wazuh_server/tasks/main.yml`) separately hardcodes its own `INDEXER_PASSWORD` the same way - neither is actually set from `soc.yml`, despite both having an entry here. But the DDoS/USB-DLP/insider-threat Shuffle workflows *do* build their Basic Auth headers for calling the Wazuh API and indexer from `soc.yml`'s copies of these four values. If you "secure" these per the usual instinct, every Active Response dispatch and indexer history lookup in those workflows silently starts failing auth against the real manager/indexer, because nothing changed the manager's/indexer's actual password to match. Leave these as the `.example` values - if you do need to rotate them for a non-lab deployment, change the hardcoded copy in `wazuh.yml.j2` (and the upstream `wazuh-docker` compose for the indexer one) at the same time, not just here.

**Fine to leave as the `.example` placeholder, no known functional impact either way:**

| Variable | Why |
|---|---|
| `iris_version` | Already a real, working image tag |
| `wazuh_alert_min_level` | Numeric threshold; the `.example` default (7) is what this repo's own rule design assumes |
| `wazuh_manager_host_conf` | Path template, correct as long as `deploy_base_dir` matches your install |
| `soc_notify_email` | **Dead variable - grepped the whole repo, nothing reads it.** Originally meant for a NOTIFY_SOC email step that was never wired up. |

**Scenario-specific** (only matters if you're deploying that particular add-on scenario - see each scenario's own setup notes):

| Variable | Scenario |
|---|---|
| `abuseipdb_api_key`, `shuffle_ddos_workflow_id` / `shuffle_ddos_webhook_trigger_id` | DDoS |
| `shuffle_usb_dlp_workflow_id` / `shuffle_usb_dlp_webhook_trigger_id` | USB-DLP |
| `shuffle_insider_threat_workflow_id` / `shuffle_insider_threat_webhook_trigger_id` | Insider-threat (`insider-threat-test/`) |
| `dmz_windows_agent_id` | DDoS + USB-DLP (Windows AR target) |
| `dmz_ubuntu_agent_id` | DDoS + Insider-threat (Linux AR target) |
| `wazuh_indexer_url`/`user`/`password` | DDoS + Insider-threat only (USB-DLP uses a Shuffle cache instead of querying the indexer) |

⚠️ **`configure_integration.yml` requires `abuseipdb_api_key` to be set even if you only want scenario 3 (insider-threat) and have no interest in DDoS.** This playbook unconditionally imports the IRIS/DDoS/USB-DLP workflows every time it runs — there's no flag to import only some of them — so its pre-flight assert checks `abuseipdb_api_key` regardless of which scenario you actually care about. If you don't plan to use DDoS: **any non-empty value that is not literally the string `CHANGE_ME` satisfies the assert** (e.g. `scenario3-unused`) — the assert never validates that the key is a real, working AbuseIPDB credential, only that it isn't the literal placeholder. Keep in mind this placeholder gets baked into the DDoS workflow's AbuseIPDB-lookup node at import time (same "frozen at import" caveat as the warning box below) — if you later want real DDoS functionality, you must delete that workflow in Shuffle and re-run `configure_integration.yml` after setting a real key, filling it in afterward does not retroactively fix the already-imported copy.

**Genuinely only knowable after a first deploy** (Shuffle re-generates UUIDs on import; agent IDs are assigned at registration time - leave the `.example` placeholder for the very first run, then fill in for real): `shuffle_workflow_id`/`shuffle_webhook_trigger_id` and all the other `shuffle_*_workflow_id`/`*_webhook_trigger_id` pairs (the insider-threat pair can be left as-is — see step 3 above), `dmz_windows_agent_id`, `dmz_ubuntu_agent_id`.

Also review `group_vars/lan.yml` for FreeIPA, Nextcloud, and Mailcow passwords.

Optionally change the domain (default `example.lab`) in `group_vars/all.yml`.

> ⚠️ **Do not run `site.yml` against a machine that already has a working deployment on it using a *different* `soc.yml` than what's currently live.** `docker compose up -d` (used by every service role here) recreates any container whose rendered config changed - if your `soc.yml` differs from what the running containers were last deployed with, this will restart Wazuh/Shuffle/IRIS etc. with new credentials that may not match what's already inside their databases/volumes. **Confirmed live, not just a theoretical risk**: changing `iris_db_password` in `soc.yml` and re-running `site.yml` after DFIR-IRIS had already initialized with the old value recreated `iriswebapp_app`/`iriswebapp_worker` with the new password, while Postgres (a stateful service - its own init scripts only run once, against an empty data directory) kept the old one - every subsequent app connection failed with `password authentication failed for user "iris"` until the affected volume was removed and the service reinitialized from scratch. No `--force-recreate`/`-v` flags are used, so this does not delete a volume outright by itself - but a credential mismatch like this makes the existing data inaccessible through the app layer just the same, which is practically no better.
>
> This can happen to **any** of these services' own stateful data, not just IRIS's Postgres - each one's first-boot init is a one-time event, and a container recreate afterward only changes what the *new* container's env vars say, never what's already stored inside the volume:
>
> | Service | Volume | Driven by (in `soc.yml`) |
> |---|---|---|
> | DFIR-IRIS Postgres | `dfir-iris_iris-db-data` | `iris_db_password`, `iris_admin_password`, `iris_secret_key` |
> | DFIR-IRIS RabbitMQ | `dfir-iris_iris-rabbitmq-data` | `iris_rabbitmq_password` |
> | Shuffle (admin user + API key, stored in its OpenSearch backing store) | `shuffle_shuffle-opensearch-data` | `shuffle_admin_password`, `shuffle_default_apikey` |
> | Wazuh indexer | `single-node_wazuh-indexer-data` | *not* driven by `soc.yml`'s `wazuh_indexer_password` at all - the upstream `wazuh-docker` compose hardcodes its own value, see the note on `wazuh_api_password`/`wazuh_indexer_password` above |
>
> If you need to change one of these values after the first deploy, remove that specific volume (`docker compose down` the relevant stack first, then `docker volume rm <name>`, **not** `-v` on the whole stack, which would take out volumes you didn't mean to touch) and re-run `site.yml` to let it reinitialize clean.

### 3. Deploy all services

```bash
ansible-playbook -i inventory/hosts.ini site.yml
```

This runs four plays in order:
1. **all** — install Docker CE on every host
2. **soc** — Wazuh server, Shuffle, DFIR-IRIS
3. **external** — Wazuh agent, Juice Shop
4. **lan** — Wazuh agent, FreeIPA, Nextcloud, Mailcow (**optional** — see below)

**The `lan` play (FreeIPA/Nextcloud/Mailcow) isn't needed by scenarios 1–3** — none of their roles, scripts, or Shuffle workflows reference `lan-host` as a Wazuh agent or dependency. That said, **scenario 3 is the only one actually run end-to-end via `--limit soc-host,dmz-ubuntu`** — the other two have their own caveats if you want to use this exact limit:
- **Scenario 1 (DDoS)** has a Linux-DMZ path (`deploy_dmz_ubuntu_nginx.yml` + `deploy_ddos_response.yml`'s `soc` play) fully covered by `--limit soc-host,dmz-ubuntu`, plus a separate Windows-DMZ Active Response path (`deploy_ddos_response.yml`'s second play, `roles/nginx_dmz_windows`) that isn't.
- **Scenario 2 (USB-DLP) requires a Windows DMZ host** — `deploy_usb_dlp_response.yml`'s second play targets `dmz-windows` specifically via `roles/usb_dlp_agent_windows`, and there's no Linux equivalent. `--limit soc-host,dmz-ubuntu` excludes Windows entirely, so it does not cover scenario 2 on its own.

A dry-run shows the `lan` play dropping to zero hosts under the limit (nothing actually executed):
```bash
ansible-playbook -i inventory/hosts.ini site.yml --limit soc-host,dmz-ubuntu --list-hosts
#   play #1 (all): hosts (2): dmz-ubuntu, soc-host
#   play #2 (soc): hosts (1): soc-host
#   play #3 (external): hosts (1): dmz-ubuntu
#   play #4 (lan): hosts (0):            <- correctly empty
```
To actually skip it, add `--limit soc-host,dmz-ubuntu` to the real `ansible-playbook -i inventory/hosts.ini site.yml` command. `site.yml` has no tags defined (`--tags` won't do anything here), so `--limit` against the relevant host names is the only lever available.

**If you do want the `lan` play (FreeIPA/Nextcloud/Mailcow), budget for it separately — it's the least reliable, least documented part of this repo:**
- It needs its own stable outbound network access and meaningfully more disk than scenarios 1–3 alone (Mailcow's upstream project alone declares 18 of its own container images).
- `roles/mailcow/tasks/main.yml`'s `git clone` of `mailcow-dockerized` has **no pinned version** (no `version:`/tag/commit) — it tracks whatever that upstream project's default branch HEAD is at the moment you run it, so its own image list, versions, and behavior can all change out from under this repo without warning, and are not reproducible between two runs on different days.
- FreeIPA is currently known to fail outright in this containerized environment (server-side install completes, but the image's own client-side `ipa-client-install` step fails with a Kerberos/SPNEGO error, root cause not identified). It loops `restart: unless-stopped` indefinitely. This is non-fatal to the rest of the play — `roles/freeipa/tasks/main.yml`'s own wait task is deliberately `failed_when: false` (up to ~15 minutes of retries) specifically so it doesn't block Nextcloud/Mailcow — but expect `site.yml` to sit through that wait if you include this play.

  ⚠️ **This restart loop is not just a time cost — on a test VM it grew `lan`'s own container disk footprint to ~67GB.** Likely cause (reasoned from what was observed, not directly proven): `roles/common` sets nested Docker's storage driver to `vfs` (no layer deduplication), and each FreeIPA crash/restart cycle appears to leave behind a new, never-reclaimed ~0.9-1.4GB copy of its root filesystem — over a day of uptime, dozens of these accumulated to tens of GB. If you hit this, you can stop the loop:
  ```bash
  docker exec lan docker stop freeipa
  ```
  This specific command and its effect were not re-verified live after the disk filled up (the same disk-full state blocks `docker exec` into `lan` at all). Reasoning from the role's own task definition rather than a live test: `roles/freeipa/tasks/main.yml` deploys via a plain `docker compose up -d` (no `--no-recreate`), so a stopped/`docker update --restart=no` container will likely get recreated — and the restart loop will resume — the next time `site.yml` or this role runs again, since compose will see the live config drift from `restart: unless-stopped` and reconcile it. Treat `docker stop`/`docker update --restart=no` as a temporary mitigation between runs, not a permanent fix.

**Windows DMZ external host?** Skip the `external` play in `site.yml` and run the dedicated Windows playbook instead — it installs Juice Shop as a Windows service via NSSM and the Wazuh agent via MSI, configures the firewall, and registers the agent with the manager:

```bash
ansible-playbook -i inventory/hosts.ini deploy_windows_dmz.yml
```

**SOC deploy failed mid-way?** Re-run only the parts that haven't completed (skips Wazuh server, runs Shuffle + DFIR-IRIS):

```bash
ansible-playbook -i inventory/hosts.ini deploy_soc_remaining.yml
```

> No Ansible at all on the Windows side? Run `windows-dmz/setup-dmz.ps1` directly on the DMZ host as Administrator — it does the same install via Chocolatey + Docker Desktop.

**Docker Hub / ghcr.io pull failures.** The `soc` play alone pulls several multi-GB images (Wazuh manager/indexer/dashboard, Shuffle frontend/backend/orborus + OpenSearch, DFIR-IRIS app/nginx/db + RabbitMQ). On a slow or flaky connection, `docker compose up -d` inside these roles can fail partway through with `read: connection reset by peer` - confirmed to be general network/registry flakiness, not something these roles do wrong (retrying the same `ansible-playbook` command resumes from already-pulled layers, since neither Docker nor these roles delete a partial pull). Three ways to deal with it, roughly in order of effort:

1. **Just retry.** Re-run the same `ansible-playbook -i inventory/hosts.ini site.yml` command. Layers already fully downloaded are not re-fetched.
2. **Pre-pull before running Ansible at all**, so the whole multi-image pull isn't riding on one `docker compose up -d` call's retry budget. **The list below is scoped to the scenario 3 path** (`--limit soc-host,dmz-ubuntu`, skipping the optional `lan` play entirely — see above) — cross-checked by grepping every `image:` line across `roles/*/templates/*.j2`, the upstream `wazuh-docker` compose, and this repo's own `dmz-ubuntu` Dockerfile, split by which Docker daemon actually needs to pull it, since (see [§ Single machine simulating 3 hosts](#single-machine-simulating-3-hosts-vs-3-real-hosts) above) `dmz-ubuntu` runs its own *nested* Docker daemon, separate from the VM/host's own. **Sizes below are approximate, taken from `docker images` on the day this was tested — they'll drift as images get updated upstream, treat them as a rough budget, not an exact figure:**

   **VM/host's own (outer) Docker — `soc` play:**
   ```bash
   docker pull wazuh/wazuh-manager:4.9.2            # ~2.0GB
   docker pull wazuh/wazuh-indexer:4.9.2            # ~4.2GB
   docker pull wazuh/wazuh-dashboard:4.9.2          # ~1.8GB
   docker pull wazuh/wazuh-certs-generator:0.0.2    # ~218MB - NOT in the upstream wazuh-docker compose templated by this repo; pulled on-demand by wazuh-docker's own generate-indexer-certs.yml the first time wazuh_server's role runs it. Missing this one specifically is what makes the very first site.yml run fail with no obvious image name to go chase.
   docker pull ghcr.io/shuffle/shuffle-frontend:latest   # ~275MB
   docker pull ghcr.io/shuffle/shuffle-backend:latest    # ~188MB
   docker pull ghcr.io/shuffle/shuffle-orborus:latest    # ~163MB
   docker pull ghcr.io/shuffle/shuffle-worker:latest     # ~173MB - a core Shuffle component alongside frontend/backend/orborus, easy to miss since it's not in roles/shuffle/templates/docker-compose.yml.j2 at all (Shuffle's own orborus container spawns it)
   docker pull opensearchproject/opensearch:2.12.0       # ~2.2GB
   docker pull ghcr.io/dfir-iris/iriswebapp_app:v2.4.18   # ~1.9GB - both iriswebapp_app AND iriswebapp_worker use this same image, just a different command - no separate pull needed for the worker
   docker pull ghcr.io/dfir-iris/iriswebapp_nginx:v2.4.18 # ~313MB
   docker pull ghcr.io/dfir-iris/iriswebapp_db:v2.4.18    # ~381MB - DFIR-IRIS's own Postgres image, not a vanilla postgres:xx
   docker pull rabbitmq:3-management                      # ~392MB - the plain upstream Docker Hub image, not ghcr.io-hosted
   ```
   ⚠️ The `ghcr.io/shuffle/*:latest` images are **not version-pinned** - whatever you pull here may not match the exact build this doc was last verified against. If something Shuffle-related behaves differently than described elsewhere in this README, check `docker image inspect <image> --format '{{.Created}}'` before assuming it's a bug in these roles.

   **Shuffle also pulls additional app images *at workflow-execution time*, not at deploy time** — confirmed present on a test VM after running the DDoS/insider-threat workflows a few times: `frikky/shuffle:app_sdk`, `frikky/shuffle:shuffle-tools_1.2.0`, `frikky/shuffle:http_1.4.0`, `frikky/shuffle:email_1.3.0`, `frikky/shuffle:shuffle-subflow_1.1.0`, `frikky/shuffle:shufflehealthcheck_1.1.0`, `frikky/shuffle:tenzir`. The exact tags above are what was observed on the day this was tested and may change later - there's no fixed, pinned list to point at. If your network is unreliable, pre-pulling these on the outer Docker daemon avoids the first workflow execution being the moment you discover a pull failure:
   ```bash
   docker pull frikky/shuffle:app_sdk
   docker pull frikky/shuffle:shuffle-tools_1.2.0
   docker pull frikky/shuffle:http_1.4.0
   docker pull frikky/shuffle:email_1.3.0
   docker pull frikky/shuffle:shuffle-subflow_1.1.0
   docker pull frikky/shuffle:shufflehealthcheck_1.1.0
   docker pull frikky/shuffle:tenzir
   ```

   **Locally-built images' own base layer:**
   ```bash
   docker pull ubuntu:24.04   # dmz-ubuntu/Dockerfile and ubuntu-lan/Dockerfile both FROM this - pulled automatically by `docker compose build`, but worth having cached up front
   ```

   **`dmz-ubuntu`'s own nested Docker — `external` play (Juice Shop):** `dmz-ubuntu/Dockerfile` does not install Docker itself (confirmed by reading it — only systemd/ssh/python3/sudo); Docker CE inside `dmz-ubuntu` is installed by `roles/common`, i.e. `site.yml`'s first play (`all` — "Install Docker on all hosts"). This means `docker exec dmz-ubuntu docker ...` does not work yet right after `bootstrap_scenario_hosts.yml` — only after `site.yml` has gotten through its first play for `dmz-ubuntu`. In practice, pre-loading before the `external` play even tries to pull Juice Shop isn't something you can cleanly do standalone; the straightforward path is: run `site.yml`, and if the Juice Shop pull in the `external` play fails, load the image into `dmz-ubuntu`'s now-existing nested daemon and re-run `site.yml` (per method 1 above — already-done work isn't redone):
   ```bash
   docker pull bkimminich/juice-shop:latest   # size not checked
   docker save bkimminich/juice-shop:latest | docker exec -i dmz-ubuntu docker load
   ```
3. **Pull on a machine with a working connection, then import on the target** (what was actually necessary in testing, when the pulling machine's own network was the bottleneck - not specific to any of these images or to Docker/Ansible):
   ```bash
   # On the machine that CAN reach the registry, for images the VM/host's own
   # (outer) daemon needs:
   docker save -o wazuh-manager.tar wazuh/wazuh-manager:4.9.2
   # ...repeat per image, then copy the .tar file(s) to the target host, then:
   docker load -i wazuh-manager.tar
   ```
   Confirm the loaded image's ID matches the source machine's (`docker image inspect <image> --format '{{.Id}}'`) before trusting it's the exact same build.

   For the image the **nested** `dmz-ubuntu` daemon needs (Juice Shop), `docker load` alone doesn't help — see method 2 above for the `docker save | docker exec -i dmz-ubuntu docker load` piping approach and its timing caveat (nested Docker doesn't exist there until `site.yml`'s first play has run). If you're also deploying the optional `lan` play, the same technique applies to its nested daemon (`docker exec -i lan docker load`) for FreeIPA/Nextcloud/Mailcow's images — see the warning about that play above for why this doc doesn't give those a fixed image list.

**Long-running commands (`site.yml` especially can take 20+ minutes with these many images).** As a precaution, avoid plain `nohup CMD &` in a terminal you might disconnect from — if the session underneath it closes, the backgrounded process can be torn down along with it before it finishes. `tmux`/`screen`, or `sudo systemd-run` for a one-off transient unit that isn't tied to any login session, are both safer for anything you intend to let run unattended:
```bash
sudo systemd-run --unit=site-deploy --uid=$(id -u) --gid=$(id -g) \
  --working-directory="$PWD" \
  -p StandardOutput=append:/tmp/site-deploy.log -p StandardError=inherit \
  -- "$(which ansible-playbook)" -i inventory/hosts.ini site.yml
```
`--uid`/`--gid` matter — without them `systemd-run` runs the command as `root`, which has its own home directory (no SSH key, no `~/.ansible` state) rather than the user whose key/config you set all this up under.

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

Adds an nginx reverse proxy in front of Juice Shop on the DMZ host(s) and wires Wazuh detection rules + Active Response scripts for HTTP floods and Slowloris. Design follows `ddos-plan.txt`.

```bash
# Windows DMZ + SOC-side rules/AR:
ansible-playbook -i inventory/hosts.ini deploy_ddos_response.yml

# Linux DMZ (dmz-ubuntu) nginx + AR script:
ansible-playbook -i inventory/hosts.ini deploy_dmz_ubuntu_nginx.yml
```

What gets deployed:

| Layer | What | Where |
|---|---|---|
| Ingress | nginx :80 → Juice Shop :3000 | dmz-windows (NSSM) / dmz-ubuntu (systemd) |
| Detection | nginx access.log → Wazuh agent → rules 100200/100211/100220 → 100210/100212/100213/100221/100222 | manager |
| Response | Wazuh Active Response `ip-limit-windows` / `ip-limit-linux` — netsh / iptables block on ports 80/443, 5-min auto-release. **Not bound to any rule** — dispatched only by the Shuffle workflow below (§6) after scoring | dmz-windows / dmz-ubuntu |

The rule chain (`roles/wazuh_ddos_rules/files/local_rules_ddos.xml`) mirrors `ddos-plan.txt`'s design, adapted to this ruleset's actual built-in rules (31108 fires for plain GET/HEAD floods here, not 31103 — verified with `wazuh-logtest`; the decoder names the status field `id`, not `http_status`):

```
31108 (built-in: ignored URLs 2xx/3xx, level 0)
  → 100200 (level 1, promote so frequency counts)
    → 100210 (level 8, freq 100/10s)   — "watch" tier, forwarded to Shuffle
      → 100213 (level 12, freq 50/30s of 100210) — confirmed DDoS, escalate

31101 (built-in: 400-class error) --id 408--> 100211 (level 1, promote)
  → 100212 (level 10, freq 50/30s)    — Slowloris, forwarded to Shuffle

31101 (built-in: 400-class error, 4xx excl. 408) → 100220 (level 1, promote)
  → 100221 (level 8, freq 100/10s)    — "watch" tier, forwarded to Shuffle
    → 100222 (level 12, freq 50/30s of 100221) — confirmed error-flood, escalate
```

`100220` explicitly excludes 408 (`<id negate="yes">^408$</id>`) so the same log line never double-alerts on both this branch and the Slowloris one above — verified live with `wazuh-logtest` (a synthetic `404` line lands on `100220` only, a synthetic `408` line lands on `100211` only).

**Resolved — a heavy enough flood crashed the backend (5xx) instead of triggering 100213/100222, which none of these chains covered**: live testing against dmz-ubuntu with `run_attack.sh`'s `auto_block` flood consistently produced ~35-40% `HTTP 500`s (nginx logs `recv() failed (104: Connection reset by peer)` reading from the Juice Shop upstream on `127.0.0.1:3000` — the Node.js backend itself getting overwhelmed), not 2xx/4xx. Neither `100200`/`100210`/`100213` (2xx/3xx via `31108`) nor `100211`/`100220` (4xx via `31101`) match 5xx at all, so this — the one case where the flood actually succeeded at degrading the service — was completely invisible to detection. Added a third chain mirroring the same shape, off the built-in `31120` ("Web server 500 error code", itself a sibling of `31101` under `31100` filtered to `id ^50`, so no overlap):
```
31120 (built-in: 500-class error) → 100230 (level 1, promote)
  → 100231 (level 8, freq 100/10s)    — "watch" tier, forwarded to Shuffle
    → 100232 (level 12, freq 50/30s of 100231) — confirmed 5xx error-flood, escalate
```
Verified live: after adding this chain, the same flood that previously produced zero DDoS-relevant alerts on the ubuntu side now correctly fires `100232` (confirmed) alongside whatever `100213`/`100222` it also happens to trigger.

The `custom-shuffle` integration script (`roles/wazuh_server/templates/custom-shuffle.py.j2`) forwards **every** alert to the legacy IRIS webhook, but only rule IDs `100210`/`100212`/`100213`/`100221`/`100222`/`100231`/`100232` to the DDoS webhook — the per-request base tags (`100200`/`100211`/`100220`/`100230`) fire once per HTTP request and would flood Shuffle/AbuseIPDB for zero decision value.

**Resolved — a real flood's alert volume broke Shuffle's webhook dispatch entirely (unrelated to rule coverage)**: a frequency rule like `100210` re-fires on every matching event once its threshold crosses — hundreds/thousands of times over one flood — and `custom-shuffle` was forwarding every single one as a separate webhook POST. `custom-shuffle.py.j2` now debounces per `(srcip, rule_id)` (`DEBOUNCE_SECONDS`, filesystem markers under `/tmp/custom-shuffle-debounce/`) so a sustained flood generates a handful of forwarded calls instead of hundreds — keyed on rule_id too, not just srcip, since an srcip-only debounce let the noisy `100210` starve out the much rarer but decision-critical `100213`/`100222`/`100232` entirely (verified live: first version of this fix produced debounce markers only for `100210`, never for the escalation rules, and Shuffle received nothing for that srcip). See below for the actual root cause this was masking.

**Resolved — dmz-windows never reached rule 100213 under real flood load**: earlier testing found rule `100213` (needs 50× `100210` in 30s) simply never fired against dmz-windows no matter how heavy the flood, capping every real test at LOG_ONLY. Root-caused to two stacked throughput bottlenecks, both now fixed by default (`deploy_windows_dmz.yml` / `windows-dmz/docker-compose.yml`):
1. The Windows VM only gets 2 vCPUs by default (`dockurr/windows`) — under flood load nginx and the Wazuh agent starved each other for CPU, and the agent logged `Target 'agent' message queue is full (1024). Log lines may be lost.` Fixed by bumping `CPU_CORES` to 4 in `windows-dmz/docker-compose.yml` (host has plenty to spare) and `logcollector.queue_size` from the default 1024 to 220000.
2. Once CPU stopped being the bottleneck, nginx could generate events faster than the agent's own `<client_buffer>` rate limiter allows to leave the agent — hard-capped at 1000 events/sec (Wazuh's documented maximum, not further raisable), so the buffer itself started flooding and dropping newest events (`Agent buffer is flooded: Producing too many events.`). Fixed by disabling `client_buffer` entirely (`<disabled>yes</disabled>`) — removes the leaky-bucket cap, agent sends as fast as it can.

Verified live after both fixes: `100213` fired 37-40 times per `run_attack.sh windows auto_block` run, with a real Windows Firewall block landing each time (`Get-NetFirewallRule -DisplayName 'Wazuh-DDoS-Limit-*'`). If you're running an older checkout, re-run `deploy_windows_dmz.yml` to pick up both fixes (idempotent — safe to re-run against an already-deployed host).

**Resolved — Shuffle silently dropped almost every DDoS/IRIS webhook execution, independent of load**: real floods stopped resulting in any block at all, even though Wazuh detected them correctly and `custom-shuffle` forwarded them successfully (manager API returned `200` every time). `shuffle-backend` logged `[ERROR] HOOKS: No start node for hook <id> - running with workflow default` on nearly every webhook call, and the resulting execution had `last_node: ""` and zero results — the workflow DAG never actually ran. Initially suspected as a concurrency race in Shuffle's webhook-to-workflow resolution under bursty load (the debounce fix above was built around that theory, and does help as defense-in-depth), but the real root cause turned out to be static, not load-related: Shuffle stores each webhook trigger as its own document in a separate OpenSearch `hooks` index (distinct from the `workflow` document itself), and that document's `start` field — the ID of the first action node to run — was simply empty (`"start": ""`) on both the DDoS and IRIS hooks. Neither the workflow-level `start` field (correctly set to `dedupe_check` / `iris-create-case`) nor the trigger's `isStartNode` flag on the workflow object is what the webhook dispatcher actually reads; it reads this separate hook document's own `start` field, which raw-JSON import via `POST /api/v1/workflows` never populates. **Fix**: re-register both hooks via the existing `POST /api/v1/hooks/new` endpoint (used in `configure_integration.yml`) with an explicit `"start": "<first-action-id>"` field, then restart `shuffle-backend` once to pick it up. Verified live: `0` "No start node" errors afterward (previously 1000+ per flood), and a real flood's `100213`/`100232` alerts correctly drove the full chain through to a real `netsh`/`iptables` block on both platforms.

**Resolved — Windows AR command invocations serialized, silently failing to block the CURRENT attacker**: an earlier version of `ip-limit.ps1` blocked via `netsh advfirewall firewall add rule ... action=block remoteip=<ip> protocol=TCP localport=80,443`, then `Start-Sleep -Seconds 300`, then deleted the same rule by name — all inside one script invocation. Invocations of the same `ar.conf` command serialize on the Windows agent, so a second dispatch for a *different* IP arriving while an earlier one was still mid-`Start-Sleep` did not run concurrently — it queued behind the sleeping invocation. Confirmed live: a manual `PUT /active-response` dispatch for a fresh IP sat queued for 1m41s behind an unrelated, already-running block before it even started. Under `run_attack.sh both auto_block` (dmz-ubuntu's and dmz-windows' alerts can still be in flight close together, or a backlog from earlier testing can already occupy the slot), this meant the CURRENT attacker's block could be delayed indefinitely — Windows never actually blocked the right IP in time, while Ubuntu (iptables `add`/`delete` are near-instant, no serialization) always did.

An intermediate fix moved Windows to Wazuh's own `<timeout>`-driven `add`/`delete` re-invocation (mirroring `ip-limit-linux`, renaming the registered `ar.conf` command to `ip-limit-windows300`) — this made `add` return instantly (no more queuing), but **broke auto-release entirely**: confirmed live that Wazuh's execd never actually re-dispatches `delete` for active-responses triggered manually via the API (no `<rules_id>`/`<level>` bound, per `ddos-plan.txt` Part 3) — a test block sat firewalled for 6+ minutes with zero delete dispatch, well past its 300s `<timeout>`. `ip-limit.sh` (Linux) has the identical `<timeout>300</timeout>` config and has never once logged an "unblocked" line in this environment's history either — the same gap exists on Linux, just unnoticed until this investigation (separate, pre-existing issue, not fixed here).

**Final fix**: `ip-limit.ps1`'s `add` path now applies the block, then launches a new helper (`ip-limit-release.ps1`) as a **detached background process** (`Start-Process -WindowStyle Hidden`, no `-Wait`) that sleeps 300s and deletes the rule independently, and returns immediately itself. This keeps `add` near-instant (fixing the original serialization bug) while self-managing the release (fixing the broken-timeout regression) instead of depending on Wazuh's `<timeout>` re-dispatch, which doesn't happen for API-manual commands. `ossec.conf`'s `<timeout>300</timeout>` on `ip-limit-windows` is left in place for parity with `ip-limit-linux` (harmless — it's simply inert for manual dispatch) rather than reverting the `ip-limit-windows300` command name yet again. Verified live: two back-to-back dispatches for different IPs both landed within ~1s of each other (no queuing), and both firewall rules were confirmed removed by the background process exactly 300s later (`[RELEASE] 300 seconds up ...` in `ip-limit.log`) — with the parent AR invocation having returned long before that.

**Resolved — AUTO_BLOCK branch fired even when the real decision was NOTIFY_SOC (degraded-evidence downgrade)**: the workflow's branch conditions matched on whether the *entire* `score_alert` JSON output contained the bare word `AUTO_BLOCK`/`NOTIFY_SOC`/`LOG_ONLY`, not just the `action` field. `ddos_score_alert.py`'s safety valve — never auto-block on degraded evidence, downgrade to `NOTIFY_SOC` instead — logged this into `evidence` as `"...downgraded from AUTO_BLOCK..."`, which itself contains the substring `AUTO_BLOCK`. That made the AUTO_BLOCK branch fire *alongside* NOTIFY_SOC on every degraded-evidence downgrade: confirmed live (AbuseIPDB's daily quota was exhausted, so every score->=70 alert took this path) that `wazuh_auth` and `wazuh_ar_block_windows` both ran for executions whose real, intended decision was NOTIFY_SOC. **Fix**: branch conditions in `wazuh_ddos_workflow.json.j2` now match the exact `"action": "AUTO_BLOCK"` / `"NOTIFY_SOC"` / `"LOG_ONLY"` key-value substring (relying on `json.dumps`' default `": "` separator), which the evidence text can never coincidentally reproduce; `ddos_score_alert.py`'s downgrade message was also reworded to say "an automatic block" instead of the literal word, as defense-in-depth. Verified live across 23 real executions from a `run_attack.sh both auto_block` run (all hitting the degraded-evidence path due to the exhausted AbuseIPDB quota): every `NOTIFY_SOC` execution correctly skipped `wazuh_auth`/`wazuh_ar_block_windows`/`wazuh_ar_block_linux`, with only `notify_soc` running — and confirmed algebraically that a genuine, non-degraded `AUTO_BLOCK` output still contains the exact `"action": "AUTO_BLOCK"` key-value pair and can't collide with the other two branches.

Test it with [`wrk`](https://github.com/wg/wrk) or `ab`:

```bash
wrk -t4 -c100 -d30s http://<DMZ_IP>/
```

Watch alerts firing:

```bash
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log | grep -E "1002(10|12|13|21|22)"
```

**Active Response is manual/API-dispatch only** (`ddos-plan.txt` Part 3: detection and enforcement are deliberately decoupled so Shuffle's scoring node — not a rule match — decides). Trigger it via the Wazuh API:

```bash
TOKEN=$(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' -X POST "https://<SOC_IP>:55000/security/user/authenticate?raw=true")
curl -sk -X PUT "https://<SOC_IP>:55000/active-response?agents_list=<AGENT_ID>" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"command":"ip-limit-linux300","arguments":["<ATTACKER_IP>"],"alert":{"data":{"srcip":"<ATTACKER_IP>"}}}'
# Use "ip-limit-windows300" for a Windows agent instead — add returns
# instantly and self-releases via a detached background process (NOT
# Wazuh's <timeout>, which never actually re-dispatches delete for
# manually-triggered commands — see the AR-serialization note above).
```

Or invoke the script directly on the agent (bypasses Wazuh entirely — useful to prove the script works in isolation):

```bash
# dmz-ubuntu:
echo '{"command":"add","parameters":{"alert":{"data":{"srcip":"<ATTACKER_IP>"}}}}' | \
  sudo /var/ossec/active-response/bin/ip-limit.sh
```
```powershell
# dmz-windows, as Administrator:
'{"command":"add","parameters":{"alert":{"data":{"srcip":"<ATTACKER_IP>"}}}}' | \
  & "C:\Program Files (x86)\ossec-agent\active-response\bin\ip-limit.cmd"
```

**Resolved — AR dispatch reliability**: earlier revisions of this doc described this as flaky/unreliable on both platforms (manager always accepted the API call, but the agent inconsistently — sometimes never — actually ran the script). Root-caused during a live debug session: **it wasn't a manager→agent delivery problem at all**. `wazuh-execd`'s debug log showed it always received and started executing the AR command; the actual bug was in `ip-limit.sh`/`ip-limit.ps1` themselves — both read stdin to EOF (`INPUT_JSON=$(cat)` / `[Console]::In.ReadToEnd()`), but `wazuh-execd` does not reliably close its end of the stdin pipe after writing the payload. This is a confirmed, unresolved upstream Wazuh bug (Wazuh 4.8.0/4.9.0/4.9.2 — see [wazuh/wazuh#25784](https://github.com/wazuh/wazuh/issues/25784) "Active Response gets stuck after first execution" and [wazuh/wazuh#25915](https://github.com/wazuh/wazuh/discussions/25915)): the read-to-EOF call blocks forever, permanently wedging that child process (`ps` showed a stuck `cat`/`.NET ReadToEnd` holding a pipe whose write end `wazuh-execd` itself never closed), and once wedged, subsequent AR requests on that agent got stuck behind it too — exactly matching the "works once, then stuck until restart" pattern observed throughout testing.

**Fix**: both scripts now read exactly one line (`IFS= read -r INPUT_JSON` / `[Console]::In.ReadLine()`) instead of reading to EOF, matching Wazuh's own documented AR stdin protocol ("read up to the newline character"). Verified live after the fix: 5 rapid back-to-back AR calls to dmz-ubuntu and 4 to dmz-windows all executed correctly with no hangs (previously ~50% failure rate on Linux, 0% success across every attempt on Windows). If you're running an older checkout, redeploy via `deploy_dmz_ubuntu_nginx.yml` / `deploy_ddos_response.yml` to pick up the fixed scripts.

**Cleanup after demo:** both blocks self-release after 5 minutes on their own (Linux via Wazuh's `<timeout>` re-invoking `ip-limit.sh` with `delete`, Windows via `ip-limit.ps1`'s own `Start-Sleep 300` — see above) — only needed if you want to clear a block early:

```bash
# dmz-ubuntu
sudo iptables -D INPUT -s <ATTACKER_IP> -p tcp -m multiport --dports 80,443 -j DROP
```
```powershell
# dmz-windows
Get-NetFirewallRule -DisplayName "Wazuh-DDoS-Limit-*" | Remove-NetFirewallRule
```

### 6. (Optional) DDoS SOAR workflow — cache-dedupe → enrich → score → decide

Sits on top of the Wazuh detection from §5. Design follows `ddos-plan.txt` Part 4-5, adapted to real Shuffle app semantics (verified live against the running Shuffle backend — see below) and swapping the plan's PAN-OS firewall for a direct call to the Wazuh Active Response API, since this lab has no PA appliance:

```
webhook (rule 100210/100212/100213 only — filtered upstream by custom-shuffle)
   │
   ▼
dedupe_check (get_cache_value "blocked:$srcip")
   │
   └─[found == false]──┬─→ abuseipdb_query ─┐
                        └─→ wazuh_history ───┴─→ score_alert (Python, pure)
                                                        │
                        ┌───────────────────────────────┼───────────────────────────────┐
                        ▼                                ▼                                ▼
            AUTO_BLOCK (score>=70,               NOTIFY_SOC (40-69, or            LOG_ONLY (score<40)
             no degraded evidence)                degraded-evidence downgrade)
            wazuh_auth → wazuh_ar_block_{windows,linux}  notify_soc (IRIS alert)    iris_log_alert
              (branch on $exec.agent.name)               │                         (plain alert,
              → set_dedupe_cache                         │                          no case)
                        └────────────┬─────────────────┘
                                     ▼
                              iris_record_case (IRIS case)
```

**Scoring (3 dimensions)** in `roles/shuffle/files/ddos_score_alert.py` — exactly `ddos-plan.txt` Part 4's design:

| Dimension | Trigger | Points (cap) |
|---|---|---|
| Rule level | `level >= 12` / `>= 10` | +40 / +25 (cap 40) |
| 24h history (same srcip, Wazuh indexer) | `>= 20` / `>= 5` alerts | +30 / +20 (cap 30) |
| AbuseIPDB confidence | `>= 80` / `>= 50` | +70 / +40 (cap 70) |

Decision bands: `>=70` AUTO_BLOCK, `40-69` NOTIFY_SOC, `<40` LOG_ONLY. A degraded dimension (AbuseIPDB/indexer query returned non-200, tracked via each HTTP node's real `.status`, not just a body-parse failure) is recorded in `degraded[]`; if that would have produced AUTO_BLOCK, the safety valve downgrades it to NOTIFY_SOC instead, so a human sees the evidence gap rather than the machine silently blocking on incomplete information.

**Cache dedupe** (`dedupe_check`/`set_dedupe_cache` nodes, per `ddos-plan.txt`'s closing mitigation): during a real flood the same attacker fires 100210 repeatedly, so re-querying AbuseIPDB and re-issuing AR blocks for an IP that's already blocked wastes API quota and produces duplicate cases. Verified live against Shuffle Tools' `get_cache_value`: a missing key returns `{"found": false, ...}` (not an error), and `set_cache_value` under the same key afterward flips it to `{"found": true, "value": "blocked", ...}` — the branch condition checks `$dedupe_check.found` for exactly this.

**Shuffle variable-substitution quirk (why some fields are hardcoded/rerouted)**: found and worked around during this build, verified with throwaway probe workflows against the live Shuffle backend. Dot-path field extraction from an `execute_python` node's JSON stdout (e.g. `$score_alert.srcip`) into a *downstream* node's URL/body reliably resolves to an empty string — confirmed with `execution_delay` set on the consumer, so it isn't a timing race. Separately, `$exec.agent.name`/`$exec.agent.id` (from the webhook trigger payload, not a Python node) resolves fine on unconditional edges but unreliably on a node that is the *direct destination of a conditional branch* — sometimes returns the whole parent object instead of the leaf, non-deterministically. Branch *conditions* themselves (`$score_alert` / `$dedupe_check.found`, evaluated as whole-value "contains" checks rather than field extraction) were reliable in every test. Net effect on this workflow: `notify_soc`/`iris_log_alert` don't reference `agent.name` in their body text, and `wazuh_ar_block_windows`/`wazuh_ar_block_linux` get their target agent ID from `dmz_windows_agent_id`/`dmz_ubuntu_agent_id` (rendered by Ansible at import time) instead of `$exec.agent.id` — the field that decides which agent gets blocked shouldn't depend on an unreliable substitution.

**Pre-flight — set these in `group_vars/soc.yml` before importing:**

| Variable | Where to get |
|---|---|
| `abuseipdb_api_key` | https://www.abuseipdb.com/account/api (free tier OK) |
| `wazuh_api_user` / `wazuh_api_password` | Same credential the Wazuh dashboard uses (`wazuh.yml.j2`); default is `wazuh-wui` / the value baked into that template |
| `wazuh_indexer_user` / `wazuh_indexer_password` | Wazuh single-node compose defaults are `admin` / `SecretPassword` |
| `iris_adm_api_key` | DFIR-IRIS web UI → My Settings → API Key |
| `dmz_windows_agent_id` / `dmz_ubuntu_agent_id` | `docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l` — hardcoded into the AUTO_BLOCK nodes at template time rather than read from the alert at runtime (see note below) |

**Deploy** (re-runs `configure_integration.yml` which imports BOTH the IRIS workflow and this DDoS workflow, and re-templates `custom-shuffle` with the live trigger IDs):

```bash
ansible-playbook -i inventory/hosts.ini configure_integration.yml
```

**Test the workflow without firing real Wazuh alerts**:

```bash
curl -X POST http://<SOC_IP>:5001/api/v1/hooks/webhook_<shuffle_ddos_webhook_trigger_id> \
  -H "Content-Type: application/json" \
  -d '{"id":"test-001","timestamp":"2026-05-19T22:00:00.000+0000","rule":{"id":"100213","level":12,"description":"Confirmed DDoS"},"agent":{"id":"007","name":"dmz-ubuntu"},"data":{"srcip":"203.0.113.5"}}'
```

Watch in Shuffle UI → Workflows → "Wazuh DDoS Auto-Response" → Runs, or poll `GET /api/v1/workflows/<id>/executions`. Each node's `result` field shows its input/output — useful for confirming the scoring decision and evidence without touching the UI.

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
