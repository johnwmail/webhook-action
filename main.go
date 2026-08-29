// Package main 實作小型 GitHub webhook 接收器：以 HMAC-SHA256 驗證
// X-Hub-Signature-256，將 payload 動態轉為 DEPLOY_PARAM_* 環境變數，
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
}

func main() {
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	deployScript := os.Getenv("DEPLOY_SCRIPT_PATH")
	if webhookSecret == "" || deployScript == "" {
		log.Fatal("錯誤: 請設定 WEBHOOK_SECRET 和 DEPLOY_SCRIPT_PATH 環境變數")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:9000"
	}

	s := newServer(webhookSecret, deployScript)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("動態 Webhook 伺服器已啟動，監聽於 http://%s/action/webhook\n", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newServer(secret, deployScript string) *server {
	return &server{
		secret:       secret,
		deployScript: deployScript,
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

func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
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

	// 動態把 JSON 裡面的所有欄位轉換成大寫的環境變數（例如：tag -> DEPLOY_PARAM_TAG）
	for key, value := range params {
		envKey := fmt.Sprintf("DEPLOY_PARAM_%s", strings.ToUpper(key))
		envValue := fmt.Sprintf("%v", value) // 強制轉為字串
		envMapping = append(envMapping, envKey+"="+envValue)
		log.Printf(" -> 注入環境變數: %s=%s\n", envKey, envValue)
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
