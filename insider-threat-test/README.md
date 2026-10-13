# 情境三：高風險可疑行為（Insider Threat）測試指南

對應雛型手冊「情境三 高風險可疑行為」章節、報告書「系統測試與效能評估」章節 4.1~4.3 的子情境 A/B/C，加上本輪驗收新增的補充子情境 D。完整的設計偏差與已知限制請見 [`DEVIATIONS.md`](./DEVIATIONS.md)，本檔只處理「怎麼跑」。

## 前置條件

1. **Docker host 本身必須是真實機器或 VM，不能是巢狀容器。** `insider_threat_host_audit` role 會自動在 `soc` 主機（inventory 裡 `ansible_connection=local` 的那台）安裝並設定 auditd，但 auditd 需要 kernel audit netlink 權限，容器內無法取得（見 DEVIATIONS #3）——這也是為什麼 dmz-ubuntu 本身是容器、auditd 卻裝在 Docker host 上，再把 `/var/log/audit` 唯讀 bind mount 進容器的原因。
2. **`wazuh_server_ip` 必須是所有 agent（dmz-ubuntu / dmz-windows / lan-host）都能連到的位址。** 這個值是從 `inventory/hosts.ini` 的 `soc-host` `ansible_host` 自動推導（`group_vars/all.yml`），不需要另外設定，但要確認 DMZ/LAN 側實際連得到這個 IP 的 1514/1515（agent 通訊）、55000（API）、5001（Shuffle）、9200（indexer）。**之後要換這個 IP 的話請見本檔最後「變更 `wazuh_server_ip` 的影響範圍」。**
3. **Wazuh 版本固定在 4.9.2**（`group_vars/all.yml` 的 `wazuh_version`）。AR 派送機制與 `wazuh-execd` payload 格式的細節（見 DEVIATIONS #24：execd 頂層 `command` 欄位恆為 `"add"`，真正意圖在 `parameters.extra_args`）是針對這個版本實測確認的——換 Wazuh 版本後要重新驗證 `host-isolate.sh` 的解析邏輯還成立。
4. **跑之前先確認 Shuffle 的 `workflow` OpenSearch index alias 沒有分裂。** DEVIATIONS #16 記錄過一次 `workflow` alias 分裂成 `workflow-000001`/`workflow-000002` 兩個底層 index，導致所有 webhook（含情境一二）完全失效。健康檢查指令見本檔最後「Shuffle alias 健康檢查」一節。
5. **`group_vars/soc.yml` / `inventory/hosts.ini` 已從對應的 `.example` 複製並填好真實值**（這兩個檔案本身不會進版控）。需要填的變數：
   - `inventory/hosts.ini.example` → `hosts.ini`：各主機的 `ansible_host`/`ansible_user`（dmz-windows 還需要 `ansible_password`）
   - `group_vars/soc.yml.example` → `soc.yml`：`wazuh_api_user`/`wazuh_api_password`、`wazuh_indexer_user`/`wazuh_indexer_password`、`shuffle_default_apikey`、`iris_adm_api_key`、`dmz_ubuntu_agent_id`（這個要等 agent 註冊後用 `agent_control -l` 查到才能填）、各 workflow/webhook trigger id（要等對應 playbook 第一次 import 後才知道）
   - `group_vars/all.yml`（這個會進版控，不用複製，但情境三特有的這幾個變數可能要依環境調整）：`insider_threat_accounts`（測試帳號與 UID，whitelist 標記）、`insider_threat_v5_force_off_hours`（預設 `false`，平時維持 `false`，只在驗收/測試時用 `set_force_off_hours.sh` 暫時切換，見下方）
6. **`secrets/insider_threat_test_key` SSH keypair 已產生**，公鑰已經透過 `insider_threat_agent_linux` role 部署到 dmz-ubuntu 的 `ubuntu`/`it.prlab` 帳號（`run_attack.sh` 用這把 key 以各帳號身份登入下指令）。

## 部署順序

1. `site.yml` + `deploy_windows_dmz.yml` / `deploy_dmz_ubuntu_nginx.yml`（情境一二既有基礎設施；跑完後 dmz-ubuntu / lan-host 都要已經是已註冊的 Wazuh agent）
2. ```
   ansible-playbook -i inventory/hosts.ini deploy_insider_threat_response.yml
   ```
   內部依序是 `insider_threat_host_audit`（host 端 auditd）→ `wazuh_insider_threat_rules`（manager 規則 + AR command 註冊）→ `insider_threat_network`（`network` tag）→ `insider_threat_agent_linux`（測試帳號、AR 腳本、wodle backstop）。

   **`network` tag 在第一次部署時必須執行，不是可以隨意跳過的選項**：這個 tag 會建立 `scenario3-link` 橋接網路，並對應到 dmz-ubuntu 的 docker-compose.yaml 新增 `/var/log/audit:ro` bind mount 與 `scenario3-link` 外部網路宣告（compose 檔是 host-local 檔案、不在本 repo 裡，這一步改動是操作者手動編輯 + `docker compose up -d`），**會讓 dmz-ubuntu 容器短暫中斷重啟**。
   - **跳過的後果**：一旦 dmz-ubuntu 的 docker-compose.yaml 已經宣告 `scenario3-link` 為 `external: true` 網路，若還沒執行這個 tag（網路還不存在），之後任何 `docker compose up -d` 都會直接失敗（`network scenario3-link declared as external, but could not be found`），容器完全起不來。
   - **已存在時重跑是否安全**：角色本身對網路建立用的是 `community.docker.docker_network` + `state: present`（標準 Ansible 冪等模組）、對 lan-host 的掛載也是先 `docker inspect` 檢查有沒有掛上才決定要不要 `docker network connect`——程式碼結構上設計成冪等，且 DEVIATIONS #11 記錄過確實需要在 `docker compose down && up` 之後重跑這個角色才能把網路重新接上（這本身就是一次「重跑有效」的既有佐證）。但這次驗收過程中我沒有刻意對同一個環境連續重跑這個 tag 兩次來現場驗證冪等性，如實標示：**冪等性是根據程式碼設計＋既有記錄判斷的，不是本輪新鮮驗證過的**。
3. ```
   ansible-playbook -i inventory/hosts.ini configure_insider_threat_integration.yml
   ```
   **不要用 `configure_integration.yml`**——那是情境一二共用的舊劇本，對 Shuffle 的 `/api/v1/workflows` 做無條件 POST，import API 本身不是 upsert，每次執行都會疊加一個新的重複 workflow（本 repo 其他三個 workflow 已經各自疊了 6~7 個重複，散在 Shuffle 的 `hooks`/`workflow` 系列 OpenSearch index 裡未清理）。`configure_insider_threat_integration.yml` 是特地為情境三另外寫的、有 idempotent 判斷（`insider_threat_existing | length == 0` 才會 import）的獨立劇本，不會重複建立。
4. `deploy_insider_threat_response.yml` 跑完後，到 manager 容器內用 `agent_control -l` 查 dmz-ubuntu 的真實 agent id，填入 `soc.yml` 的 `dmz_ubuntu_agent_id`（如果還沒填——這個 id 是 Wazuh 動態指派的，沒辦法事先知道）。

## `run_attack.sh` 用法

```
insider-threat-test/run_attack.sh [A|B|C|D|all] [--reset]
```

- `A`／`B`／`C`：報告書原始三個子情境（資料竊取／憑證竊取+橫向移動／白名單日常維運）。
- `D`：**補充項目，不屬於報告書原測試**（見 DEVIATIONS #26）——白名單帳號 `it.prlab` 跑完整攻擊鏈到 `nc 4444`，用來驗證「白名單帳號即使推進到 C2 階段也不會被 AUTO_BLOCK」。`D` 必須明確指定，`all` 不包含 `D`，且 `D` 只應該在 A/B/C 都跑完之後才執行。
- `all`：依序跑 A → B → C，子情境之間自動等待 `GAP_SECONDS`（預設140秒，避開已知無法觸發的複合規則100410的120秒關聯視窗，見 DEVIATIONS #23），也會自動在每個子情境前做 `--reset`。
- `--reset`：先清除 dmz-ubuntu 上殘留的攻擊產物檔案、強制解除任何殘留的 AR 隔離、清空這三個測試帳號在 Wazuh indexer 裡過去24小時的告警歷史（固定的安全條件過濾，命中數超過200筆會拒絕執行，見腳本內 `clear_indexer_history` 的註解）。

  **單獨跑 A/B/C/D 時，每個子情境之間都必須帶 `--reset`，不是可省略的保險步驟**：A 和 B 用的都是 `ubuntu` 這個帳號，`progression_calc` 重建攻擊鏈時是以 `auid`（帳號）為 key 去查 24 小時歷史——如果 A 跑完沒清歷史就接著跑 B，B 的第一個指令（`whoami`）在查詢時會看到 A 殘留的 ssh/tar/nc 等事件，V2 的攻擊鏈深度會被 A 的歷史污染，分數不會是 B 單獨跑出來該有的分數。`all` 模式已經在每個子情境前自動做這件事，只有手動單獨跑 A/B/C/D 時才需要自己記得帶。

同一個子情境**內部**每個指令之間，腳本會等待 `STEP_GAP_SECONDS`（預設19秒，可用環境變數覆寫）——這是因為 `progression_calc` 重建攻擊鏈要查 Wazuh indexer 的歷史告警，而從指令執行到該筆告警能被同一種查詢查到，實測 auditd→agent→manager→filebeat→indexer 整條鏈路平均延遲10秒、最長15.26秒（見 DEVIATIONS #27）；指令發得太快，後面的事件會查不到前面剛發生、還沒被索引的事件，導致攻擊鏈深度被低估、分數算低。

### 切換 `force_off_hours`

```
insider-threat-test/set_force_off_hours.sh on   # 驗收/測試前開
insider-threat-test/set_force_off_hours.sh off  # 驗收後務必還原
```

這個開關決定信心評分 V5 維度是否強制視為離峰，**不是** `run_attack.sh` 的參數，是 Shuffle 上 `score_alert` 節點程式碼裡的一個常數。因為 Shuffle 的 workflow import API 不是 upsert，改 `group_vars/all.yml` 的 `insider_threat_v5_force_off_hours` 再重新執行 `configure_insider_threat_integration.yml` **不會生效**（那個劇本已存在就不會再 import）。`set_force_off_hours.sh` 改用 `PUT /api/v1/workflows/{id}` 直接改寫既有 workflow 裡 `score_alert` 節點的 `code` 參數，只動這一個欄位，執行前後都會印出 workflow 總數與 insider-threat workflow 數並要求兩者一致，任何一步失敗就直接中止、不留下半改狀態。**驗收/測試跑完後一定要 `off` 還原**，否則 V5 會一直被強制視為離峰，不反映真實事件時間。

## 各子情境預期結果

以下是用 `force_off_hours=true`（A/B/D）、`false` 與 `true` 各一次（C）跑出來的實測結果（驗收重跑，2026-10-13）：

| 子情境 | 最高風險事件 | 攻擊鏈深度 | V1/V2/V3/V5 | 總分 | 決策 | AR / 隔離 |
|---|---|---|---|---|---|---|
| A | `nc 4444`（100403, level 10） | 4 | 25/30/20/10 | 85 | **AUTO_BLOCK** | 觸發，~120~135秒後自動解除 |
| B | `nc 4444`（100403, level 10） | 4 | 25/30/20/10 | 85 | **AUTO_BLOCK** | 觸發，~120~135秒後自動解除 |
| C（false） | `tar`（100407, level 5） | 3 | 0/30/0/10 | 40 | LOG_ONLY | 不觸發 |
| C（true） | `tar`（100407, level 5） | 3 | 0/30/0/10 | 40 | LOG_ONLY | 不觸發 |
| D（補充） | `nc 4444`（100403, level 10） | 4 | 25/30/0/10 | 65 | NOTIFY_SOC | 不觸發 |

C 的 V5 在 `false` 模式下仍是10分：純粹是因為跑測當下真實當地時間剛好落在離峰時段（18:xx），不是開關失效——但這不影響 C 的判定結果，因為 C 的分數上限（白名單+無高風險事件）本來就到不了50分門檻。V5 的精確定義見下方「離峰時段定義」。

## 已知限制

完整清單見 [`DEVIATIONS.md`](./DEVIATIONS.md)，特別需要注意的幾項：

- **#2**：AR 隔離是 **blackhole 靜默丟棄**，不是終止連線——既有連線不會收到 FIN/RST，白名單外的連線只是新封包立即被丟，資料會堆在對方的本地重傳佇列裡；解除隔離後，這些堆積的資料會一次性全部補送達（實測在 listener 端單次 `recv` 收到 80+ 筆堆積資料）。如果驗收時有長連線（例如已建立的 ssh session）橫跨隔離開始/解除的時間點，不要預期連線會斷開重建，它會在解除後突然收到一大批延遲資料。
- **#9**：白名單帳號理論上在 rule_level≥12 的情境下仍可能被 AUTO_BLOCK，但目前規則集沒有任何 level≥12 的事件來源，實測（子情境D）確認白名單帳號目前不會被 AUTO_BLOCK。
- **#23**：複合規則 100410（原設計用來偵測「120秒內同主機3個以上 insider_threat 指標」並直接觸發隔離）在目前 Wazuh 4.9.2 + merged-event 的環境下無法可靠觸發，維持原樣未修，不影響其他7條規則。
- **#25**：`host-isolate.sh` 的 setsid 計時器（sleeper）偶爾會無聲失效，原因未查明，但有15秒輪詢的 wodle 機制作為真正的保證解除手段，隔離時長上限仍是120~135秒。
- **#27**：同一子情境內指令發太快會導致攻擊鏈深度被低估（已用 `STEP_GAP_SECONDS` 緩解，見上方「`run_attack.sh` 用法」）。

### 離峰時段定義

V5 的「離峰」定義在 `roles/shuffle/files/insider_threat_score.py.j2`：事件時間（`$exec.timestamp`，即該筆 Wazuh alert 自己的事件時間，不是 Shuffle 節點執行當下的時鐘）轉換成 **UTC+8 當地時間**後，落在 **00:00–07:59 或 18:00–23:59** 算離峰（+10分），**08:00–17:59** 算上班時間（+0分）。

### 手動解除隔離 / 隔離卡住 / agent 離線時的處置

正常情況下優先用 `run_attack.sh --reset`（內部呼叫 Wazuh API 送 `delete`），或直接：

```
# 1. 確認目前是否真的被隔離
docker exec dmz-ubuntu iptables -L WAZUH_ISOLATE -n
docker exec dmz-ubuntu cat /var/run/host-isolate-deadline   # 看預定解除時間
```

如果 API 路徑送不出去（例如 dmz-ubuntu 的 `wazuh-agent` 本身掛掉、沒辦法接收 manager 推下來的 AR 指令），已實測確認可以**直接繞過 API/execd**，在容器內本機呼叫腳本本體：

```
docker exec dmz-ubuntu /var/ossec/active-response/bin/host-isolate.sh --release manual
```

這條路徑只依賴 Docker host 能 `docker exec` 進 dmz-ubuntu，完全不需要 `wazuh-agent` 或 manager 端 API 正常運作，是隔離卡住時的最後手段。執行後用上面的 `iptables -L` 再確認一次 chain 真的消失。

### 變更 `wazuh_server_ip` 的影響範圍

`wazuh_server_ip` 改了之後（即改 `inventory/hosts.ini` 的 `soc-host` `ansible_host`），以下幾處**不會**自動跟著更新，需要逐項處理：

1. **各 agent 的 `ossec.conf`**（`<client><server><address>`）：agent 不會自動重新指向新 IP，需要重新跑對應的 agent 部署 playbook（`deploy_windows_dmz.yml`/`deploy_dmz_ubuntu_nginx.yml`/`deploy_insider_threat_response.yml`）讓 agent 設定檔重新模板化＋重啟 `wazuh-agent`。驗證：`docker exec dmz-ubuntu grep -A1 '<server>' /var/ossec/etc/ossec.conf` 要顯示新 IP，且 `/var/ossec/bin/wazuh-control status` 顯示 agent 連線正常。
2. **manager 上的 `custom-shuffle` 整合腳本**：這個檔案每次執行 `configure_integration.yml`/`configure_insider_threat_integration.yml` 都會用目前的 `wazuh_server_ip` 重新模板化＋複製進 manager 容器＋重啟 manager，所以只要重跑對應劇本就會自動更新，不需要額外手動處理。
3. **已經匯入過的 Shuffle workflow 自己內部節點的 URL**（`wazuh_auth`、`wazuh_ar_isolate_host`、`wazuh_history_query`、`escalate_iris_alert`/`iris_log_alert` 等）：**這些不會自動更新**——Shuffle 在 import 當下把 `{{ wazuh_server_ip }}` 的渲染結果存成死值寫進它自己的資料庫，之後 `wazuh_server_ip` 改變並不會讓已存在的 workflow 跟著變（這是 DEVIATIONS #16 已經記錄過的已知問題，情境一二三的 workflow 都受影響）。要修正需要用跟 `set_force_off_hours.sh` 一樣的手法：`GET` 該 workflow、找出含舊 IP 的節點參數、替換成新 IP、`PUT` 寫回去（絕對不要用 import API 重新匯入，會造成重複）。驗證：抓下該 workflow 的 JSON，grep 裡面還有沒有舊 IP 字串。

### Shuffle alias 健康檢查

`shuffle-opensearch` 本身停用了安全外掛（`DISABLE_SECURITY_PLUGIN=true`），不需要帳密：

```
docker exec shuffle-opensearch curl -s http://localhost:9200/_alias/workflow
```

回應裡最外層只應該有**一個** index 名稱（例如 `{"workflow-000002": {...}}`）。如果看到兩個以上的 index 同時掛在 `workflow` 這個 alias 下，就是 DEVIATIONS #16 記錄過的那種分裂狀態，所有 webhook（含情境一二）都會失效，需要照該項記錄的方式 reindex 合併。

### IRIS 測試 alert 的累積

每跑一次子情境，情境三的每個告警（不管是 LOG_ONLY/NOTIFY_SOC/AUTO_BLOCK）幾乎都會各自在 DFIR-IRIS 建一筆新 alert（`iris_log_alert`/`notify_soc_review`/`escalate_iris_alert`，視分數走不同節點），這些測試用 alert 會持續累積、不會自動清除。**不要自動清理**——是否要清、要留哪些當證據由人決定；如果要人工清，先在 IRIS UI 確認 alert 的建立時間與 `run_attack.sh` 的測試時段對得上，且**絕對不要刪到既有的（非本情境三測試產生的）alert**。
