# 情境三：高風險可疑行為（Insider Threat）測試指南

對應雛型手冊「情境三 高風險可疑行為」章節、報告書「系統測試與效能評估」章節 4.1~4.3 的子情境 A/B/C，加上本輪驗收新增的補充子情境 D。完整的設計偏差與已知限制請見 [`DEVIATIONS.md`](./DEVIATIONS.md)，本檔只處理「怎麼跑」。

**先讀過 repo 根目錄的 [`README.md`](../README.md)**——那份才是整個 lab（Wazuh/Shuffle/IRIS 等基礎設施）的部署入口，本檔完全假設 `site.yml` 等基礎部署已經跑過。特別是根目錄 README 的「Single machine simulating 3 hosts vs. 3 real hosts」一節（單機 Docker 模擬 3 台主機時 `dmz-ubuntu`/`ubuntu-lan` 容器要手動建立，沒有任何 Ansible role 會自動建）跟「Change secrets」一節（`soc.yml` 全部變數的分類、`wazuh_api_password` 不能亂改的原因）。

## 環境假設（明確列出，不要假設）

- **作業系統：Ubuntu 24.04**（根目錄 README 的 Prerequisites 寫的目標版本；本檔沒有獨立測試過其他版本）。
- **Docker host 本身必須是真實機器或 VM，不能是巢狀容器**（見下方第1點，auditd 需要 kernel 權限）。
- **`wazuh_server_ip` 一定要改成你自己環境的位址**，不能照抄本 repo 任何既有的值——這個值是從 `inventory/hosts.ini` 推導出來的，不是寫死的常數。
- 單機模擬 3 台主機的拓樸細節、`soc.yml` 變數意義，請見根目錄 README，本檔不重複。

## 前置條件

1. **Docker host 本身必須是真實機器或 VM，不能是巢狀容器。** `insider_threat_host_audit` role 會自動在 `soc` 主機（inventory 裡 `ansible_connection=local` 的那台）安裝並設定 auditd，但 auditd 需要 kernel audit netlink 權限，容器內無法取得（見 DEVIATIONS #3）——這也是為什麼 dmz-ubuntu 本身是容器、auditd 卻裝在 Docker host 上，再把 `/var/log/audit` 唯讀 bind mount 進容器的原因。
2. **`wazuh_server_ip` 必須是所有 agent（dmz-ubuntu / dmz-windows / lan-host）都能連到的位址。** 這個值是從 `inventory/hosts.ini` 的 `soc-host` `ansible_host` 自動推導（`group_vars/all.yml`），不需要另外設定，但要確認 DMZ/LAN 側實際連得到這個 IP 的 1514/1515（agent 通訊）、55000（API）、5001（Shuffle）、9200（indexer）。**之後要換這個 IP 的話請見本檔最後「變更 `wazuh_server_ip` 的影響範圍」。**
3. **Wazuh 版本固定在 4.9.2**（`group_vars/all.yml` 的 `wazuh_version`）。AR 派送機制與 `wazuh-execd` payload 格式的細節（見 DEVIATIONS #24：execd 頂層 `command` 欄位恆為 `"add"`，真正意圖在 `parameters.extra_args`）是針對這個版本實測確認的——換 Wazuh 版本後要重新驗證 `host-isolate.sh` 的解析邏輯還成立。
4. **跑之前先確認 Shuffle 的 `workflow` OpenSearch index alias 沒有分裂。** DEVIATIONS #16 記錄過一次 `workflow` alias 分裂成 `workflow-000001`/`workflow-000002` 兩個底層 index，導致所有 webhook（含情境一二）完全失效。健康檢查指令見本檔最後「Shuffle alias 健康檢查」一節。
5. **`group_vars/soc.yml` / `inventory/hosts.ini` 已從對應的 `.example` 複製並填好真實值。**

   ⚠️ **這兩個檔案其實是被 git 追蹤的**（不是 gitignore），clone 下來就已經有內容——目前是用 `git update-index --skip-worktree` 讓本機對它們的修改不會出現在 `git status`/`git diff`/`git commit` 裡，但這**不等於**沒進版控，git 歷史裡原本就留著曾經提交過的內容。**在你用自己的真實值蓋掉這兩個檔案之前，先執行**：
   ```
   git update-index --skip-worktree group_vars/soc.yml inventory/hosts.ini
   ```
   （如果 clone 下來的副本還沒被標記成 skip-worktree，上面這行要先做，否則你填入的真實值會被 git 當成一般修改，一個 `git add -A` 或 `git commit -a` 就會把你的憑證提交進去。）這只是暫時的緩解措施，比較正確的長期做法是 repo 擁有者把這兩個檔案改成 `git rm --cached` 移出版控、加進 `.gitignore`，但那需要處理既有 git 歷史裡已經提交過的內容，由 repo 擁有者決定要不要做、怎麼做。

   需要填的變數：
   - `inventory/hosts.ini.example` → `hosts.ini`：各主機的 `ansible_host`/`ansible_user`（dmz-windows 還需要 `ansible_password`）
   - `group_vars/soc.yml.example` → `soc.yml`：**完整的 28 個欄位分類（哪些必填、哪些可以留佔位值、哪些是部署後才知道）請見根目錄 README 的「Change secrets」一節，不在這裡重複**。情境三直接會用到的是 `wazuh_api_user`/`wazuh_api_password`（⚠️ **這兩個不要改，原因見根目錄README——Wazuh manager 的 `wazuh-wui` 密碼是寫死在 `wazuh.yml.j2` 裡的官方預設值，改了 soc.yml 這裡不會讓 manager 真的換密碼，AR 會認證失敗**）、`wazuh_indexer_user`/`wazuh_indexer_password`、`dmz_ubuntu_agent_id`（agent 註冊後用 `agent_control -l` 查）、`shuffle_insider_threat_workflow_id`/`_webhook_trigger_id`（情境三 workflow 第一次 import 後才知道）
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
3. **已經匯入過的 Shuffle workflow 自己內部節點的 URL**（`wazuh_auth`、`wazuh_ar_block_*`、`wazuh_ar_isolate_host`、`wazuh_history`/`wazuh_history_query`、`escalate_iris_alert`/`iris_log_alert`/`notify_soc*` 等）：**這些不會自動更新**——Shuffle 在 import 當下把 `{{ wazuh_server_ip }}` 的渲染結果存成死值寫進它自己的資料庫，之後 `wazuh_server_ip` 改變並不會讓已存在的 workflow 跟著變（這是 DEVIATIONS #16 已經記錄過的已知問題，情境一二三的 workflow 都受影響過）。

   修正用 `scripts/update_shuffle_workflow_ip.sh`（跟 `set_force_off_hours.sh` 同一手法：只用 `PUT` 改既有 workflow 裡命中的欄位，絕對不透過 import API，不會造成重複）：
   ```
   # 1. 先備份全部 workflow（gitignored，不進版控）
   mkdir -p secrets/shuffle-backups/$(date -u +%Y%m%dT%H%M%SZ)
   # （或參考這個腳本開發時用的手法，對 /api/v1/workflows 逐一 GET 存成 <id>.json）

   # 2. 先 dry-run 看命中清單，不會改任何東西
   scripts/update_shuffle_workflow_ip.sh <舊IP> <新IP> --dry-run

   # 3. 確認範圍後逐一 --apply（建議一次只動一個 workflow id，每次跑完立刻重新
   #    dry-run 確認該 workflow 命中數變 0，且 hook 的 start/trigger status 沒變）
   scripts/update_shuffle_workflow_ip.sh <舊IP> <新IP> --apply --only <workflow_id>

   # 如果某次 --apply 後發現不對，用備份還原（同樣先 dry-run 看會還原哪些再 --apply）
   scripts/update_shuffle_workflow_ip.sh --restore <備份目錄> --dry-run
   scripts/update_shuffle_workflow_ip.sh --restore <備份目錄> --apply --only <workflow_id>
   ```
   腳本會自動判斷「哪個是 hook 真正指向的那個版本」（直接讀 manager 上目前部署的 `custom-shuffle.py` 裡的 trigger id，不是猜的），在輸出裡標 `[ACTIVE]`。**只對 active 版本套用就夠了**——其他重複版本是 DEVIATIONS #16 提過、還沒清理的孤兒 workflow，不影響任何功能，修它們的 IP 純粹是為了「萬一以後 hook 不小心被切去指到其中一個」的保險，不是必要項目。2026-10-13 的一次實際套用只動了 IRIS/DDoS/USB-DLP 三個 active workflow（詳見 DEVIATIONS），17個孤兒版本的舊IP維持原樣。
4. **workflow 節點裡的 `agents_list`（Active Response 要打給哪個 agent id，例如 `wazuh_ar_block_windows`/`wazuh_ar_block_linux`/`wazuh_ar_isolate_host` 的 `006`/`007`）：跟 IP 是完全一樣的問題**——這些也是 import 當下從 `soc.yml` 的 `dmz_windows_agent_id`/`dmz_ubuntu_agent_id`（情境一/二/三共用同一組 id）寫死進 URL 字串的，agent 重新註冊、Wazuh 重新分配 id 時，這些節點**不會自動跟著變**。`scripts/update_shuffle_workflow_ip.sh` 其實不是只處理 IP——它做的是任意字串的精確比對+替換，所以同一支腳本、同一套流程可以直接拿來改 agent id，把上面指令裡的 `<舊IP> <新IP>` 換成 `<舊agent_id> <新agent_id>` 即可，不需要另外的工具：
   ```
   scripts/update_shuffle_workflow_ip.sh <舊agent_id> <新agent_id> --dry-run
   scripts/update_shuffle_workflow_ip.sh <舊agent_id> <新agent_id> --apply --only <workflow_id>
   ```
   換 agent id 時要特別小心命中清單裡標 `[ACTIVE]` 的那個是不是真的對應到你要換的那個 agent——同一個 `agents_list` 字串（例如 `006`）如果剛好也是別的東西的編號，字串比對不會知道語意，套用前務必先看過 dry-run 的命中清單（哪個 workflow、哪個節點、哪個欄位）再決定要不要 `--apply`。

### Shuffle alias 健康檢查

`shuffle-opensearch` 本身停用了安全外掛（`DISABLE_SECURITY_PLUGIN=true`），不需要帳密：

```
docker exec shuffle-opensearch curl -s http://localhost:9200/_alias/workflow
```

回應裡最外層只應該有**一個** index 名稱（例如 `{"workflow-000002": {...}}`）。如果看到兩個以上的 index 同時掛在 `workflow` 這個 alias 下，就是 DEVIATIONS #16 記錄過的那種分裂狀態，所有 webhook（含情境一二）都會失效，需要照該項記錄的方式 reindex 合併。

### IRIS 測試 alert 的累積

每跑一次子情境，情境三的每個告警（不管是 LOG_ONLY/NOTIFY_SOC/AUTO_BLOCK）幾乎都會各自在 DFIR-IRIS 建一筆新 alert（`iris_log_alert`/`notify_soc_review`/`escalate_iris_alert`，視分數走不同節點），這些測試用 alert 會持續累積、不會自動清除。**不要自動清理**——是否要清、要留哪些當證據由人決定；如果要人工清，先在 IRIS UI 確認 alert 的建立時間與 `run_attack.sh` 的測試時段對得上，且**絕對不要刪到既有的（非本情境三測試產生的）alert**。
