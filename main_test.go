package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-secret"

func signPayload(payload []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// captureLog 捕捉 log 輸出以便斷言 DEBUG 日誌。
func captureLog(fn func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

func TestVerifySignature(t *testing.T) {
	payload := []byte(`{"ref":"refs/tags/v1.0.0"}`)
	valid := signPayload(payload)
	got := strings.TrimPrefix(valid, "sha256=")

	if !verifySignature(payload, got, testSecret) {
		t.Error("verifySignature() = false, want true for a valid signature")
	}

	if verifySignature(payload, "0000000000000000", testSecret) {
		t.Error("verifySignature() = true, want false for a wrong signature")
	}

	if verifySignature(payload, got, "another-secret") {
		t.Error("verifySignature() = true, want false for a wrong secret")
	}
}

func TestHandleWebhookMethodNotAllowed(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	req := httptest.NewRequest(http.MethodGet, "/action/webhook", nil)
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleWebhookMissingSignature(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleWebhookInvalidSignature(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(`{}`))
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandleWebhookInvalidJSON(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	body := `{"tag": "v1.0.0"`
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", signPayload([]byte(body)))
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleWebhookSuccessTriggersDeploy(t *testing.T) {
	deployed := make(chan map[string]interface{}, 1)
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	s.runDeploy = func(params map[string]interface{}) {
		deployed <- params
	}

	body := []byte(`{"tag":"v1.0.0","ref":"refs/heads/main","actor":"octocat"}`)
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Hub-Signature-256", signPayload(body))
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	select {
	case params := <-deployed:
		if params["tag"] != "v1.0.0" || params["actor"] != "octocat" {
			t.Errorf("deployed params = %v, want tag/actor to be forwarded", params)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runDeploy was not invoked within the timeout")
	}
}

func TestExecuteDeployPassesParamsAsEnv(t *testing.T) {
	script := filepath.Join(t.TempDir(), "deploy.sh")
	scriptContent := `#!/usr/bin/env bash
echo "TAG=$WEBHOOK_PARAM_TAG"
echo "REF=$WEBHOOK_PARAM_REF"
`
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatal(err)
	}

	params := map[string]interface{}{
		"tag": "v1.0.0",
		"ref": "refs/tags/v1.0.0",
	}

	logged := captureLog(func() {
		executeDeploy(script, params)
	})

	for _, want := range []string{"[script:out] TAG=v1.0.0", "[script:out] REF=refs/tags/v1.0.0"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %q, got:\n%s", want, logged)
		}
	}
}

func TestExecuteDeployLogsStderr(t *testing.T) {
	script := filepath.Join(t.TempDir(), "deploy.sh")
	scriptContent := `#!/usr/bin/env bash
echo "to-stdout"
printf 'to-stderr-no-newline' >&2
` // stderr 無尾換行，測試 flush 殘餘內容
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatal(err)
	}

	logged := captureLog(func() {
		executeDeploy(script, map[string]interface{}{})
	})

	if !strings.Contains(logged, "[script:out] to-stdout") {
		t.Errorf("log missing stdout line, got:\n%s", logged)
	}
	if !strings.Contains(logged, "[script:err] to-stderr-no-newline") {
		t.Errorf("log missing flushed stderr line, got:\n%s", logged)
	}
}

func TestLineLoggerBuffersPartialLines(t *testing.T) {
	l := &lineLogger{prefix: "[x]"}
	logged := captureLog(func() {
		_, _ = l.Write([]byte("hello wo"))
		_, _ = l.Write([]byte("rld\nsecond"))
		l.flush()
	})
	if !strings.Contains(logged, "[x] hello world") {
		t.Errorf("跨 Write 的行应被重组，got:\n%s", logged)
	}
	if !strings.Contains(logged, "[x] second") {
		t.Errorf("flush 应输出无换行残余，got:\n%s", logged)
	}
}

func TestExecuteDeployFailingScript(t *testing.T) {
	script := filepath.Join(t.TempDir(), "deploy.sh")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// 執行失敗時 executeDeploy 不吐錯誤，只記錄 log；確認其安然返回。
	executeDeploy(script, map[string]interface{}{})
}

func TestServerRoutes(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	req := httptest.NewRequest(http.MethodPost, "/unknown", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d for unknown route", rec.Code, http.StatusNotFound)
	}
}

// --- DEBUG 相關測試 ---

func TestIsDebugEnabled(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"yes", true},
		{"YES", true},
		{"on", true},
		{"ON", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"", false},
		{"  true  ", true}, // 帶空白應被 trim
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("DEBUG", tc.env)
			if got := isDebugEnabled(); got != tc.want {
				t.Errorf("isDebugEnabled() with DEBUG=%q = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

func TestNewServerDebugFlag(t *testing.T) {
	t.Setenv("DEBUG", "true")
	s := newServer(testSecret, "/does/not/exist")
	if !s.debug {
		t.Error("newServer debug = false, want true when DEBUG=true")
	}
	t.Setenv("DEBUG", "false")
	s2 := newServer(testSecret, "/does/not/exist")
	if s2.debug {
		t.Error("newServer debug = true, want false when DEBUG=false")
	}
}

func TestLoggingMiddlewareDebugEnabled(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = true
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := s.loggingMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/action/webhook", nil)
	req.Header.Set("User-Agent", "test-agent")
	rec := httptest.NewRecorder()

	logged := captureLog(func() {
		handler.ServeHTTP(rec, req)
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(logged, "[DEBUG]") {
		t.Errorf("未找到 DEBUG 日誌，got: %q", logged)
	}
	if !strings.Contains(logged, "GET") || !strings.Contains(logged, "/action/webhook") {
		t.Errorf("日誌應包含方法與路徑，got: %q", logged)
	}
	if !strings.Contains(logged, "200") {
		t.Errorf("日誌應包含狀態碼 200，got: %q", logged)
	}
}

func TestLoggingMiddlewareDebugDisabledSilent(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := s.loggingMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/action/webhook", nil)
	rec := httptest.NewRecorder()

	logged := captureLog(func() {
		handler.ServeHTTP(rec, req)
	})

	if logged != "" {
		t.Errorf("DEBUG 關閉時不應有日誌，got: %q", logged)
	}
}

func TestLoggingMiddlewareLogsEveryAccessIncluding404(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = true
	handler := s.loggingMiddleware(s.routes())

	// 送往不存在的路徑，應 404 並仍被記錄
	req := httptest.NewRequest(http.MethodPost, "/unknown", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	logged := captureLog(func() {
		handler.ServeHTTP(rec, req)
	})

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(logged, "[DEBUG]") || !strings.Contains(logged, "/unknown") {
		t.Errorf("404 請求亦應被 DEBUG 記錄，got: %q", logged)
	}
	if !strings.Contains(logged, "404") {
		t.Errorf("日誌應包含 404 狀態碼，got: %q", logged)
	}
}

func TestLoggingMiddlewareLogsAllStatusCodes(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = true
	handler := s.loggingMiddleware(s.routes())

	cases := []struct {
		name string
		req  *http.Request
		want int
	}{
		{
			name: "405 Method Not Allowed",
			req:  httptest.NewRequest(http.MethodGet, "/action/webhook", nil),
			want: http.StatusMethodNotAllowed,
		},
		{
			name: "401 Missing Signature",
			req:  httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(`{}`)),
			want: http.StatusUnauthorized,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			logged := captureLog(func() {
				handler.ServeHTTP(rec, tc.req)
			})
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if !strings.Contains(logged, "[DEBUG]") {
				t.Errorf("應有 DEBUG 日誌，got: %q", logged)
			}
		})
	}
}

func TestHandleWebhookDebugLogs(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = true
	s.runDeploy = func(_ map[string]interface{}) {}

	body := []byte(`{"tag":"v1.0.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Hub-Signature-256", signPayload(body))
	rec := httptest.NewRecorder()

	logged := captureLog(func() {
		s.handleWebhook(rec, req)
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(logged, "[DEBUG]") {
		t.Errorf("DEBUG 模式下 handleWebhook 應有日誌，got: %q", logged)
	}
}

func TestHandleWebhookDebugDisabledNoExtraLog(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	s.debug = false
	// 捕捉 handleWebhook 本身的 DEBUG 日誌（不經 middleware）
	body := []byte(`{"tag":"v1.0.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Hub-Signature-256", signPayload(body))
	s.runDeploy = func(_ map[string]interface{}) {}
	rec := httptest.NewRecorder()

	logged := captureLog(func() {
		s.handleWebhook(rec, req)
	})

	if strings.Contains(logged, "[DEBUG]") {
		t.Errorf("DEBUG 關閉時 handleWebhook 不應輸出 [DEBUG]，got: %q", logged)
	}
}
