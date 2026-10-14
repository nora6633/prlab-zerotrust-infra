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

### Single machine simulating 3 hosts vs. 3 real hosts

The Architecture diagram above describes 3 logically separate hosts (External/SOC/LAN). Nothing about the roles themselves requires that — `site.yml` just targets whatever `inventory/hosts.ini` groups resolve to. In practice this lab is commonly run **on a single physical machine**, with each "host" actually being a separate Docker container/bridge network on that one machine, and `inventory/hosts.ini`'s `ansible_host` values pointing at those containers' bridge IPs rather than separate real machines. If that's your setup:

- The `soc` group's `ansible_host` is the Docker host's own address (same machine Ansible runs on), with `ansible_connection=local`.
- `external`/`lan` point at container IPs on their own bridge networks, not separate VMs.
- **`dmz-ubuntu/` and `ubuntu-lan/` (their Dockerfile + `docker-compose.yaml`) are not deployed by `site.yml` or any other role in this repo** — if you're using these containers as stand-ins for the external/LAN hosts, run `bootstrap_scenario_hosts.yml` first, before anything else:
  ```bash
  ansible-playbook -i inventory/hosts.ini bootstrap_scenario_hosts.yml
  ansible-playbook -i inventory/hosts.ini site.yml
  ansible-playbook -i inventory/hosts.ini deploy_insider_threat_response.yml          # only if using insider-threat-test/
  ansible-playbook -i inventory/hosts.ini configure_insider_threat_integration.yml    # only if using insider-threat-test/
  ```
  `bootstrap_scenario_hosts.yml` creates the `dmz-ubuntu_default` and `scenario3-link` networks (both declared `external: true` in `dmz-ubuntu/docker-compose.yaml` — yes, both, even if you only want the plain DDoS/Juice-Shop use of this host and have no interest in scenario 3; see the playbook's own header comment) and builds/starts both containers. It's idempotent - safe to re-run, never recreates an already-running container or touches its volumes. Confirm the subnet it picks matches what `inventory/hosts.ini` expects to SSH into (`docker network inspect dmz-ubuntu_default`).

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

⚠️ **`wazuh_api_user` / `wazuh_api_password` are the one pair that looks like the above but ISN'T - do not change these from the `.example` defaults.** `roles/wazuh_server/templates/wazuh.yml.j2` hardcodes the Wazuh dashboard's `wazuh-wui` API credential as a literal string (it's Wazuh's own upstream `wazuh-docker` single-node default, cloned verbatim by `roles/wazuh_server/tasks/main.yml` - nothing in this repo sets it from `soc.yml`). But the DDoS/USB-DLP/insider-threat Shuffle workflows *do* build their Basic Auth header for calling the Wazuh API from `soc.yml`'s `wazuh_api_user`/`wazuh_api_password`. If you "secure" these per the usual instinct, every Active Response dispatch in those three workflows silently starts failing auth against the real manager, because nothing changed the manager's actual password to match. Leave these as the `.example` values. The same is suspected for `wazuh_indexer_user`/`wazuh_indexer_password` (same lack of any template that sets them from `soc.yml`), but that one isn't confirmed by a found hardcoded-template the way the API password is - treat it the same way (leave as `.example`) until proven otherwise.

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

**Genuinely only knowable after a first deploy** (Shuffle re-generates UUIDs on import; agent IDs are assigned at registration time - leave the `.example` placeholder for the very first run, then fill in for real): `shuffle_workflow_id`/`shuffle_webhook_trigger_id` and all the other `shuffle_*_workflow_id`/`*_webhook_trigger_id` pairs, `dmz_windows_agent_id`, `dmz_ubuntu_agent_id`.

Also review `group_vars/lan.yml` for FreeIPA, Nextcloud, and Mailcow passwords.

Optionally change the domain (default `example.lab`) in `group_vars/all.yml`.

> ⚠️ **Do not run `site.yml` against a machine that already has a working deployment on it using a *different* `soc.yml` than what's currently live.** `docker compose up -d` (used by every service role here) recreates any container whose rendered config changed - if your `soc.yml` differs from what the running containers were last deployed with, this will restart Wazuh/Shuffle/IRIS etc. with new credentials that may not match what's already inside their databases/volumes. This hasn't been tested end-to-end in this repo (no `--force-recreate` or `-v` flags are used, so it shouldn't delete volumes outright) - treat this as a reasoned risk from reading the roles, not a confirmed-safe-or-unsafe operation either way.

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
