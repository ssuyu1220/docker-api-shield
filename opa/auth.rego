package docker.guard

import future.keywords.if
import future.keywords.contains

# 注意：這裡改成 logic_allow，只做計算，不直接給 Envoy 用
default logic_allow := false

# =======================
# 1. 小工具：Log 發送器
# =======================
log_result(code, denys) := true if {
    url := "http://db_pass:5000/save-to-db"
    client_ip := object.get(input.attributes.request.http.headers, "x-forwarded-for", "unknown")
    raw_payload := object.get(input.attributes.request.http, "body", "")
    ja3_fingerprint := object.get(input.attributes.request.http.headers, "x-ja3-fingerprint", "unknown")
    # 發送 POST (副作用)
    print("======== [OPA DEBUG] START ========")
    print("Deny Report:", deny)
    print("======== [OPA DEBUG] END ========")
    response := http.send({
        "method": "POST",
        "url": url,
        "headers": {"Content-Type": "application/json"},
        "body": {
            "client_ip": client_ip, 
            "ja3_fingerprint": ja3_fingerprint,
            "path": input.attributes.request.http.path,
            "response_code": code,
            "deny_report": denys,
            "original_packet": raw_payload
        },
        "timeout": "1s"
    })
    response.status_code != 0
}


# =======================
# 2. 資料解析 & 變數 (維持原樣)
# =======================

crypto_analysis := payload if {
    # 1. 讀取 Header (這是一串 Base64)
    b64_raw := input.attributes.request.http.headers["x-crypto-json"]
    
    # 2. 【關鍵】先解碼 Base64 變成字串
    json_str := base64.decode(b64_raw)
    
    # 3. 再解析 JSON
    payload := json.unmarshal(json_str)
    print("======== [OPA DEBUG] START ========")
    print("clear json:", json_str)
    print("======== [OPA DEBUG] END ========")
}

has_crypto if { crypto_analysis.signals }

req_method := input.attributes.request.http.method
normalized_path := p if {
  p := input.attributes.request.http.headers["x-original-path"]
} else := p if {
  p := input.attributes.request.http.path
} else := ""

# =======================
# 3. 規則定義 (維持原樣)
# =======================

is_read_only if {
    req_method == "GET"
    {"/_ping", "/version", "/info", "/containers/json"}[normalized_path]
}

is_create if {
    req_method == "POST"
    contains(normalized_path, "/containers/create")
}

# =======================
# 4. 阻擋規則 (維持原樣，但不需要在這裡寫 Log)
# =======================

deny contains "DENY: bind mount is not allowed" if {
    has_crypto; crypto_analysis.signals.has_any_bind_mount == true
}

deny contains "DENY: host root bind is not allowed" if {
    has_crypto; crypto_analysis.signals.has_host_root_bind == true
}

deny contains "DENY: docker.sock bind is not allowed" if {
    has_crypto; crypto_analysis.signals.has_docker_sock_bind == true
}

deny contains "DENY: privileged container is not allowed" if {
    has_crypto; crypto_analysis.signals.privileged == true
}

deny contains "DENY: obfuscated command detected" if {
    has_crypto; crypto_analysis.signals.has_obfuscated_base64_blob == true
}

deny contains "DENY: host network mode is not allowed" if {
    has_crypto
    crypto_analysis.signals.uses_host_network == true
}

deny contains "DENY: sensitive host path bind is not allowed" if {
    has_crypto
    crypto_analysis.signals.has_sensitive_bind == true
}

deny contains "DENY: adding capabilities (cap_add) is not allowed" if {
    has_crypto
    crypto_analysis.signals.has_cap_add == true
}

deny contains "DENY: decode-to-shell chain detected" if {
    has_crypto
    crypto_analysis.signals.decode_to_shell == true
}

deny contains "DENY: image has vulnerabilities" if {
    has_crypto
    crypto_analysis.signals.img_critical_count + crypto_analysis.signals.img_high_count > 0
}

# =======================
# 5. 邏輯計算 (改名為 logic_allow)
# =======================
# 這裡只負責算「過」還是「不過」，不做任何動作

# 通道 1：建立容器
logic_allow if {
    has_crypto
    count(deny) == 0
}

# 通道 2：Read Only
logic_allow if {
    is_read_only
    count(deny) == 0
}

# ========================================================
# 6. 【總出口】 最終決策 + Log (你想要的部分)
# ========================================================

# 這是 Envoy 真正會讀取的變數
# 它會先去讀上面的 logic_allow 算出 true/false，然後根據結果發送 Log
allow := result if {
    
    # 1. 取得計算結果 (如果 logic_allow 沒過，這裡就會是 false)
    result := logic_allow
    
    # 2. 決定 Log 代碼
    code := {true: "200", false: "403"}[result]
    
    # 3. 執行 Log (只會在最後執行這一次)
    log_result(code, deny)
}