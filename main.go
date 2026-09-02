// Package main 實作小型 GitHub webhook 接收器：以 HMAC-SHA256 驗證
// X-Hub-Signature-256，將 payload 動態轉為 WEBHOOK_PARAM_* 環境變數，
// 然後非同步執行部署腳本。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json" // 解析動態 JSON 必備
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// server 封裝 Webhook 伺服器的可設定參數，以便單元測試注入。
type server struct {
	secret       string
	deployScript string
	runDeploy    func(params map[string]interface{})
	debug        bool
}

// isDebugEnabled 判斷是否啟用 DEBUG 模式，支援多種常見真值。
func isDebugEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func main() {
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	deployScript := os.Getenv("WEBHOOK_SCRIPT_PATH")
	if webhookSecret == "" || deployScript == "" {
		log.Fatal("錯誤: 請設定 WEBHOOK_SECRET 和 WEBHOOK_SCRIPT_PATH 環境變數")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:9000"
	}

	s := newServer(webhookSecret, deployScript)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           s.loggingMiddleware(s.routes()),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("動態 Webhook 伺服器已啟動，監聽於 http://%s/action/webhook\n", listenAddr)
	if s.debug {
		log.Println("[DEBUG] DEBUG 模式已啟用：所有請求將被記錄")
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newServer(secret, deployScript string) *server {
	return &server{
		secret:       secret,
		deployScript: deployScript,
		debug:        isDebugEnabled(),
		runDeploy: func(params map[string]interface{}) {
			executeDeploy(deployScript, params)
		},
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/action/webhook", s.handleWebhook)
	return mux
}

// loggingResponseWriter 包裝 ResponseWriter 以捕捉狀態碼與寫入位元組數。
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// loggingMiddleware 為每個請求記錄存取日誌，僅在 DEBUG 啟用時生效。
func (s *server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.debug {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lw, r)
		duration := time.Since(start)
		log.Printf("[DEBUG] %s %s %s -> %d %dB %s UA:%q",
			r.RemoteAddr, r.Method, r.URL.Path, lw.status, lw.bytes, duration, r.UserAgent())
	})
}

func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if s.debug {
		log.Printf("[DEBUG] webhook 請求: method=%s path=%s remote=%s contentLength=%d",
			r.Method, r.URL.Path, r.RemoteAddr, r.ContentLength)
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	signatureHeader := r.Header.Get("X-Hub-Signature-256")
	if signatureHeader == "" {
		http.Error(w, "Missing Signature", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = r.Body.Close() }()

	gotSignature := strings.TrimPrefix(signatureHeader, "sha256=")

	if s.debug {
		log.Printf("[DEBUG] webhook 簽名驗證: body=%dB sigPrefix=%.8s", len(body), gotSignature)
	}

	if !verifySignature(body, gotSignature, s.secret) {
		http.Error(w, "Invalid Signature", http.StatusForbidden)
		log.Println("警告: 收到無效的簽名請求！")
		return
	}

	// 💡 【核心修改】使用 map[string]interface{} 動態接收所有欄位
	var dynamicPayload map[string]interface{}
	if err := json.Unmarshal(body, &dynamicPayload); err != nil {
		http.Error(w, "Bad Request (Invalid JSON)", http.StatusBadRequest)
		return
	}

	if s.debug {
		log.Printf("[DEBUG] webhook payload 已解析: keys=%d", len(dynamicPayload))
	}

	// 轉發給非同步部署程序
	go s.runDeploy(dynamicPayload)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Deployment triggered successfully with dynamic params."))
}

func verifySignature(payload []byte, gotSignature string, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(gotSignature), []byte(expectedSignature))
}

// 💡 【核心修改】動態將 JSON 的 Key 轉為環境變數傳入腳本
func executeDeploy(script string, params map[string]interface{}) {
	log.Println("開始執行部署腳本...")
	cmd := exec.Command("bash", script)

	// 先抓取 VPS 系統原本的環境變數
	envMapping := os.Environ()

	// 動態把 JSON 裡面的所有欄位轉換成大寫的環境變數（例如：tag -> WEBHOOK_PARAM_TAG）
	for key, value := range params {
		envKey := fmt.Sprintf("WEBHOOK_PARAM_%s", strings.ToUpper(key))
		envValue := fmt.Sprintf("%v", value) // 強制轉為字串
		envMapping = append(envMapping, envKey+"="+envValue)
		if isDebugEnabled() {
			log.Printf(" -> 注入環境變數: %s=%s\n", envKey, envValue)
		}
	}

	cmd.Env = envMapping
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("部署腳本執行失敗: %v\n", err)
		return
	}
	log.Println("部署腳本執行成功！")
}
