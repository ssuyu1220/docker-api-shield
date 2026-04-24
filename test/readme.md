# 自動化測試說明

## 簡介
本 `test` 資料夾是為了提供使用者自動測試的範例，內容檔案包含了
* `test_script.sh`：自動化測試程式
* `payload/`：內含多個用於測試，有各種情況的 payload

---

## 執行方法
1. 賦予測試執行權限

```bash
chmod +x test_script.bash
```

2. 進入程式設定測試目標

```bash
# 約在第九行
TARGET="https://127.0.0.1:2375"
```
3. 執行：

```bash
./test_script.sh
```

## 檔案結構
* `test_script.sh`： 自動化測試主程式。
* `payloads/`： 存放各種測試情境的 JSON Payload。
    * `valid_create.json`： 合法建立容器
    * `exec_normal.json`：執行合法指令 `ls -la /var/log`
    * `atk_etc_bind.json`：掛載敏感路徑 `/etc:`
    * `atk_sock.json`：掛載 `docker.sock`
    * `atk_cap_add.json`：給予過高 (最高) 權限 ("CapAdd": ["SYS_ADMIN"])
    * `atk_priv.json`：給予過高 (最高) 權限 ("Privileged": true)
    * `atk_host_net.json`：佔用實體主機網路
    * `atk_root_bind.json`： 掛載主機根目錄 ("NetworkMode": "host")
    * `atk_trivy_vuln.json`： 包含高風險漏洞的映像檔
    * `exec_obfuscated_chain.json`： 執行帶有加密混淆的指令鏈
---



---

## 測試階段說明

### Phase 1: 合法流量測試 (Positive Testing)
* **目的**: 驗證正常操作
* **驗證項目**: 
    * `GET /_ping`: 基本連通性
    * `GET /containers/json`: 讀取容器列表
    * **合法建立**: 建立標準 Alpine 容器（預期回傳 `201` 或 `404`）
    * **合法指令執行**: 正常 ls 指令（預期回傳 `201` 或 `404`）

### Phase 2: 惡意 Create 靜態攔截 (Static Analysis)
* **目的**: 攔截具有高風險配置的容器建立請求
* **驗證項目**: 
    * **Root Bind**: 嚴禁掛載主機 `/`
    * **Bind Socket**: 嚴禁掛 `docker.sock`
    * **Privileged**: 攔截特權模式開啟
    * **Host Net**: 禁止占用本機網路
    * **/etc Bind**: 嚴禁掛載敏感目錄 `/etc`
    * **Cap Add**: 攔截注入 `SYS_ADMIN` 權限
    * **Trivy**: 不可包含嚴重漏洞的 image

### Phase 3: 惡意 Exec 動態行為攔截 (Behavioral Analysis)
* **目的**: 攔截進入容器後的惡意指令執行
* **驗證項目**: 
    * **Decode-to-Shell**: 執行包含 base64 編碼混淆的執行鏈

---
## 測試結果注意事項
* **404 狀態碼**: 在測試中，若收到 404 代表請求已成功穿透 WAF 到達 Docker，但 Docker 找不到該容器，也可能為正常現象

---

## 結果驗證方式

### 1. 終端機即時反饋
程式會根據 HTTP 狀態碼輸出結果：
* **[PASS]**: 符合預期（該擋的有擋住，該放行的有放行）。
* **[FAIL]**: 不符合預期（需檢查 OPA 規則或 Envoy 緩衝設定）。

### 2. 資料庫日誌 (Security Logs)
可使用以下指令進入資料庫查看詳細的內容：
```bash
sudo docker exec -it postgres psql -U root -d crypto_db -c "SELECT * FROM security_logs;"
```

### 3. Grafana
打開瀏覽器訪問 Grafana，查看攔截狀況，可配合 LLM 協助分析的功能確認攔截原因 。



