package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
	"os/exec"
)

/*
This service analyzes a Docker "containers/create" request body (JSON) and returns
structured security signals suitable for OPA policy decisions.

It DOES NOT execute anything; it only inspects configuration and command strings.
*/

type DockerCreateBody struct {
	Image      string          `json:"Image"`
	Cmd        []string        `json:"Cmd"`
	Entrypoint json.RawMessage `json:"Entrypoint"` // can be string or []string
	Tty        *bool           `json:"Tty,omitempty"`
	HostConfig HostConfig      `json:"HostConfig"`
}

type DockerExecBody struct {
	Cmd        []string        `json:"Cmd"`
	Tty        *bool           `json:"Tty,omitempty"`
	Privileged *bool 		   `json:"Privileged"`
	//User	   []string		   `json:"User"`
	//Env		   []string		   `json:"Env"`
}

type HostConfig struct {
	Binds         []string `json:"Binds"`
	Privileged    *bool    `json:"Privileged,omitempty"`
	NetworkMode   string   `json:"NetworkMode,omitempty"`
	CapAdd        []string `json:"CapAdd,omitempty"`
	CapDrop       []string `json:"CapDrop,omitempty"`
	RestartPolicy any      `json:"RestartPolicy,omitempty"`
}

type AnalyzeResponse struct {
	Signals  Signals  `json:"signals"`
	DecodedSnippets []string `json:"decoded_snippets,omitempty"`
}

type Signals struct {
	Action 					string `json:"action"`
	HasAnyBindMount         bool `json:"has_any_bind_mount"`
	HasHostRootBind         bool `json:"has_host_root_bind"`      // e.g. "/:/hostroot:rw"
	HasDockerSockBind       bool `json:"has_docker_sock_bind"`    // "/var/run/docker.sock:..."
	HasSensitiveBind        bool `json:"has_sensitive_bind"`      // /etc, /root, /proc, /sys, etc.
	Privileged              bool `json:"privileged"`
	UsesHostNetwork         bool `json:"uses_host_network"`
	HasCapAdd               bool `json:"has_cap_add"`
	HasNormalizeStage       bool `json:"has_normalize_stage"`
	HasDecodeStage          bool `json:"has_decode_stage"`
	HasPipeToShell          bool `json:"has_pipe_to_shell"`
	HasObfuscatedBase64Blob bool `json:"has_obfuscated_base64_blob"`
	DecodeToShell           bool `json:"decode_to_shell"`
	ImgCriticalCount		int  `json:"img_critical_count"`
	ImgHighCount			int  `json:"img_high_count"`
}

type TrivyReport struct {
    // 雖然外層有很多欄位 (SchemaVersion, CreatedAt...)，我們都不用寫
    // 只需定義 Results
    Results []struct {
        Target          string `json:"Target"` 
        // 這裡也是，只定義我們在意的 Vulnerabilities
        Vulnerabilities []struct {
            ID       string `json:"VulnerabilityID"`
            Severity string `json:"Severity"`
        } `json:"Vulnerabilities"`
    } `json:"Results"`
}

// --- Regex: behavior signals ---
var rePipeToShell = regexp.MustCompile(`(?i)(\|\s*(sh|bash)\b)|\b(sh|bash)\s+-c\b`)
var reBase64Decode = regexp.MustCompile(`(?i)\b(base64\s+(-d|--decode)\b|openssl\s+base64\s+-d\b)`)
var reNormalize = regexp.MustCompile(`(?i)\b(tr\s+-d\b|sed\s+['"]?s/\[\^?[A-Za-z0-9\+\/=\\]\]\*?/\/*.*?/g['"]?)`)

// Candidate blob (includes URL-safe - _)
var reB64Candidate = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)
var reKeepB64Chars = regexp.MustCompile(`[^A-Za-z0-9+/=_-]+`)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/analyze", analyzeDispatcherHandler)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})


	addr := ":8082"
	log.Printf("crypto-service listening on %s", addr)
	
	// 使用 limitBody 限制 Payload 大小，防止 DoS
	if err := http.ListenAndServe(addr, limitBody(mux, 1<<20 /*1MB*/)); err != nil {
		log.Fatal(err)
	}
}

func analyzeDispatcherHandler(w http.ResponseWriter, r *http.Request) {
    // 1. 從 Header 讀取 Envoy 傳過來的原始路徑
    originalPath := r.Header.Get("x-original-path")
    
    log.Printf("[INFO] Dispatching request for path: %s", originalPath)

    // 2. 根據路徑關鍵字進行分流
    // 注意：Docker API 的路徑可能會包含版本號，如 /v1.41/containers/...
    // 所以我們用 Contains 來寬鬆比對
    if strings.Contains(originalPath, "/exec") {
        // 交給 Exec 專家處理
        analyzeDockerExecHandler(w, r)
        return
    }

    if strings.Contains(originalPath, "/create") {
        // 交給 Create 專家處理
        analyzeDockerCreateHandler(w, r)
        return
    }

    // 3. 如果都不是，回傳錯誤或略過
    log.Printf("[WARN] Unknown path: %s", originalPath)
    http.Error(w, "Unknown Docker API path", http.StatusBadRequest)
}

func analyzeDockerCreateHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("[INFO] Received CREATE request from %s", r.RemoteAddr)

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var body DockerCreateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Printf("[ERROR] Invalid JSON: %v", err)
		http.Error(w, "Invalid Docker create JSON body", http.StatusBadRequest)
		return
	}

	// Extract Entrypoint
	entry := parseEntrypoint(body.Entrypoint)
	cmdStr := joinCmd(body.Cmd)
	entryStr := strings.Join(entry, " ")
	allExecText := strings.TrimSpace(strings.Join([]string{cmdStr, entryStr}, " "))

	// Log minimal details about the request
	log.Printf("[INFO] Analyzing Image: %s, Cmd: %s", body.Image, truncate(cmdStr, 50))

	// Bind signals
	bindSignals := analyzeBinds(body.HostConfig.Binds)

	// Privileged / host network / caps
	priv := body.HostConfig.Privileged != nil && *body.HostConfig.Privileged
	hostNet := strings.EqualFold(strings.TrimSpace(body.HostConfig.NetworkMode), "host")
	hasCapAdd := len(body.HostConfig.CapAdd) > 0

	// Command-behavior signals
	hasNorm := reNormalize.MatchString(allExecText)
	hasDecode := reBase64Decode.MatchString(allExecText)
	hasPipe := rePipeToShell.MatchString(allExecText)
	hasObf := hasObfuscatedB64(allExecText)

	decodeToShell := hasPipe && (hasDecode || hasObf)

	criticalCount, highCount := trivyscanner(body.Image)

	sig := Signals{
		Action:       			 "create",
		HasAnyBindMount:         bindSignals.HasAnyBindMount,
		HasHostRootBind:         bindSignals.HasHostRootBind,
		HasDockerSockBind:       bindSignals.HasDockerSockBind,
		HasSensitiveBind:        bindSignals.HasSensitiveBind,
		Privileged:              priv,
		UsesHostNetwork:         hostNet,
		HasCapAdd:               hasCapAdd,
		HasNormalizeStage:       hasNorm,
		HasDecodeStage:          hasDecode,
		HasPipeToShell:          hasPipe,
		HasObfuscatedBase64Blob: hasObf,
		DecodeToShell:           decodeToShell,
		ImgCriticalCount:		 criticalCount,
		ImgHighCount:			 highCount,	 
	}

	decoded := tryDecodeSomeSnippets(allExecText, 3)
	log.Printf("[INFO] Critical vulnerabilities=%v, High vulnerabilities=%v", criticalCount, highCount)

	log.Printf("[INFO] Analysis Complete. Risks: Obfuscated=%v, Privileged=%v, HostRoot=%v", 
		hasObf, priv, bindSignals.HasHostRootBind)

	resp := AnalyzeResponse{
		Signals:  sig,
		DecodedSnippets: decoded,
	}

	writeJSON(w, resp)
}

func analyzeDockerExecHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("[INFO] Received Exec request from %s", r.RemoteAddr)

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var body DockerExecBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Printf("[ERROR] Invalid JSON: %v", err)
		http.Error(w, "Invalid Docker exec JSON body", http.StatusBadRequest)
		return
	}

	// Extract Entrypoint
	cmdStr := joinCmd(body.Cmd)	

	// Privileged / host network / caps
	priv := body.Privileged != nil && *body.Privileged

	// Command-behavior signals
	hasNorm := reNormalize.MatchString(cmdStr)
	hasDecode := reBase64Decode.MatchString(cmdStr)
	hasPipe := rePipeToShell.MatchString(cmdStr)
	hasObf := hasObfuscatedB64(cmdStr)

	decodeToShell := hasPipe && (hasDecode || hasObf)
	

	sig := Signals{
		Action:       			 "exec",
		Privileged:              priv,
		HasNormalizeStage:       hasNorm,
		HasDecodeStage:          hasDecode,
		HasPipeToShell:          hasPipe,
		HasObfuscatedBase64Blob: hasObf,
		DecodeToShell:           decodeToShell,
	}

	decoded := tryDecodeSomeSnippets(cmdStr, 3)


	log.Printf("[INFO] Analysis Complete. Risks: Obfuscated=%v, Privileged=%v", 
		hasObf, priv)

	resp := AnalyzeResponse{
		Signals:  sig,
		DecodedSnippets: decoded,
	}

	writeJSON(w, resp)
}

// --- Helper Types & Functions ---

type bindAnalysis struct {
	HasAnyBindMount   bool
	HasHostRootBind   bool
	HasDockerSockBind bool
	HasSensitiveBind  bool
}

func analyzeBinds(binds []string) bindAnalysis {
	ba := bindAnalysis{
		HasAnyBindMount: len(binds) > 0,
	}
	for _, b := range binds {
		parts := strings.Split(b, ":")
		if len(parts) < 2 {
			continue
		}
		src := strings.TrimSpace(parts[0])
		dst := strings.TrimSpace(parts[1])

		if src == "/" || strings.HasPrefix(src, "/:") {
			ba.HasHostRootBind = true
		}
		if strings.Contains(src, "/var/run/docker.sock") || strings.Contains(dst, "/var/run/docker.sock") {
			ba.HasDockerSockBind = true
		}
		if isSensitiveHostPath(src) {
			ba.HasSensitiveBind = true
		}
	}
	return ba
}

func isSensitiveHostPath(src string) bool {
	src = strings.TrimSpace(src)
	sensitivePrefixes := []string{
		"/etc", "/root", "/proc", "/sys", "/var/run", "/var/lib/docker", "/home",
	}
	for _, p := range sensitivePrefixes {
		if src == p || strings.HasPrefix(src, p+"/") {
			return true
		}
	}
	return false
}


func joinCmd(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}
	return strings.Join(cmd, " ")
}

func parseEntrypoint(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return []string{s}
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr
	}
	return nil
}

// --- Obfuscation Detection Logic ---

func hasObfuscatedB64(text string) bool {
	cands := reB64Candidate.FindAllString(text, -1)
	for _, c := range cands {
		clean := cleanB64(c)
		if len(clean) < 16 {
			continue
		}
		dec, ok := decodeB64Lenient(clean)
		if !ok {
			continue
		}
		if looksPrintable(dec) {
			return true
		}
	}
	return false
}

func tryDecodeSomeSnippets(text string, max int) []string {
	var out []string
	cands := reB64Candidate.FindAllString(text, -1)
	seen := 0
	for _, c := range cands {
		if seen >= max {
			break
		}
		clean := cleanB64(c)
		if len(clean) < 24 {
			continue
		}
		dec, ok := decodeB64Lenient(clean)
		if !ok {
			continue
		}
		if looksPrintable(dec) {
			out = append(out, truncate(dec, 300))
			seen++
		}
	}
	return out
}

func cleanB64(s string) string {
	s = reKeepB64Chars.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

func decodeB64Lenient(s string) (string, bool) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), true
	}
	s2 := strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s2); err == nil {
		return string(b), true
	}
	return "", false
}

func looksPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range s {
		total++
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			printable++
		case r >= 32 && r <= 126:
			printable++
		default:
			return false
		}
	}
	return total >= 8 && printable*100/total >= 85
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func trivyscanner(s string) (int, int) {
	cmd := exec.Command("trivy", "image", "--format", "json", "-q", s)
	outputBytes, err := cmd.Output() 
	if err != nil {
		fmt.Printf("執行 Trivy 失敗: %v\n", err)
		return -1,-1
	}

	var report TrivyReport
	if err := json.Unmarshal(outputBytes, &report); err != nil {
		fmt.Printf("解析 JSON 失敗: %v\n", err)
		return -1, -1
	}

	criticalCount := 0
	highCount := 0
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == "CRITICAL" {
				criticalCount++
			}
			if vuln.Severity == "HIGH" {
				highCount++
			}
		}
	}
	return criticalCount, highCount
}
// --- HTTP Helpers ---

func writeJSON(w http.ResponseWriter, v any) {
    // 改成 text/plain，因為我們要回傳 Base64 字串
    w.Header().Set("Content-Type", "text/plain")
    
    // 轉成 JSON bytes
    b, err := json.Marshal(v)
    if err != nil {
        log.Printf("[ERROR] Failed to encode JSON: %v", err)
        http.Error(w, fmt.Sprintf("encode error: %v", err), http.StatusInternalServerError)
        return
    }
    
    // 轉成 Base64 字串，確保 Header 裡面沒有特殊符號
    b64 := base64.StdEncoding.EncodeToString(b)
    
    w.Write([]byte(b64))
}

func limitBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}