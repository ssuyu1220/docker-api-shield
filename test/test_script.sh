#!/bin/bash

# ========================================================
# Docker API Shield 自動化攻防測試腳本 (完全體)
# 涵蓋靜態設定防禦 (Create) 與 動態行為防禦 (Exec)
# ========================================================

# 設定目標位址
TARGET="https://127.0.0.1:2375"

# 顏色設定
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}==============================================${NC}"
echo -e "${CYAN}   🚀 啟動 Docker API Shield 全面攻防驗證   ${NC}"
echo -e "${CYAN}==============================================${NC}\n"

# 核心測試函數 (支援讀取外部 Payload 檔案)
run_test() {
    local test_name=$1
    local expected_code=$2
    local method=$3
    local path=$4
    local payload=$5

    echo -e "🧪 ${YELLOW}測試項目: ${test_name}${NC} (預期 HTTP ${expected_code})"

    if [ -n "$payload" ]; then
        # 有 payload 的請求 (使用 -d "@payloads/...")
        actual_code=$(curl -k -s -o /dev/null -w "%{http_code}" -X "$method" -H "Content-Type: application/json" -d "$payload" "${TARGET}${path}")
    else
        # 沒有 payload 的請求 (如 GET)
        actual_code=$(curl -k -s -o /dev/null -w "%{http_code}" -X "$method" "${TARGET}${path}")
    fi

    if [ "$actual_code" == "$expected_code" ]; then
        echo -e "   ${GREEN}[PASS] ✅ 測試通過! (實際收到 ${actual_code})${NC}"
    else
        echo -e "   ${RED}[FAIL] ❌ 測試失敗! (實際收到 ${actual_code})${NC}"
    fi
    echo "------------------------------------------------"
}

# ==========================================
# 🟢 階段一：合法流量測試 (預期放行 200/201)
# ==========================================
echo -e "${YELLOW}>>> [Phase 1] 測試合法白名單通道...${NC}"

run_test "合法讀取: /_ping" "200" "GET" "/_ping" ""
run_test "合法讀取: 獲取容器列表" "200" "GET" "/containers/json" ""
# Docker API 建立容器成功會回傳 201 Created
run_test "合法建立: 標準 Alpine 容器" "201" "POST" "/containers/create?name=valid_test" "@payloads/valid_create.json"
run_test "合法 Exec: 正常 ls 指令" "201" "POST" "/containers/victim/exec" "@payloads/exec_normal.json"

echo ""

# ==========================================
# 🔴 階段二：惡意 Create 攻擊測試 (預期阻擋 403)
# ==========================================
echo -e "${YELLOW}>>> [Phase 2] 測試靜態配置越權攔截 (Create API)...${NC}"

run_test "惡意建立: 掛載主機根目錄 (Root Bind)" "403" "POST" "/containers/create?name=atk_root" "@payloads/atk_root_bind.json"
run_test "惡意建立: 竊取 docker.sock" "403" "POST" "/containers/create?name=atk_sock" "@payloads/atk_sock.json"
run_test "惡意建立: 啟動特權容器 (Privileged)" "403" "POST" "/containers/create?name=atk_priv" "@payloads/atk_priv.json"
run_test "惡意建立: 劫持主機網路 (Host Net)" "403" "POST" "/containers/create?name=atk_net" "@payloads/atk_host_net.json"
run_test "惡意建立: 掛載敏感目錄 (/etc)" "403" "POST" "/containers/create?name=atk_etc" "@payloads/atk_etc_bind.json"
run_test "惡意建立: 注入 SYS_ADMIN 權限" "403" "POST" "/containers/create?name=atk_cap" "@payloads/atk_cap_add.json"
run_test "惡意建立: 包含嚴重漏洞的映像檔 (Trivy)" "403" "POST" "/containers/create?name=atk_vuln_img" "@payloads/atk_trivy_vuln.json"

echo ""

# ==========================================
# ⚡ 階段三：惡意 Exec 行為測試 (預期阻擋 403)
# ==========================================
echo -e "${YELLOW}>>> [Phase 3] 測試動態行為指令攔截 (Exec API)...${NC}"

run_test "惡意 Exec: 加密執行鏈 (Decode-to-Shell)" "403" "POST" "/containers/victim/exec" "@payloads/exec_obfuscated_chain.json"

echo ""
echo -e "${CYAN}==============================================${NC}"
echo -e "${CYAN}  🎉 所有攻防測試執行完畢！${NC}"
echo -e "${CYAN}  👉 可前往 Grafana 查看阻擋日誌${NC}"
echo -e "${CYAN}  👉 或使用 sudo docker exec -it postgres psql -U root -d crypto_db -c "SELECT * FROM security_logs" 確認資料庫內容;${NC}"
echo -e "${CYAN}==============================================${NC}\n"