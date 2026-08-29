package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
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
	req := httptest.NewRequest(http.MethodGet, "/action/webhook", nil)
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleWebhookMissingSignature(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
	req := httptest.NewRequest(http.MethodPost, "/action/webhook", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleWebhookInvalidSignature(t *testing.T) {
	s := newServer(testSecret, "/does/not/exist")
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
echo "TAG=$DEPLOY_PARAM_TAG"
echo "REF=$DEPLOY_PARAM_REF"
`
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatal(err)
	}

	params := map[string]interface{}{
		"tag": "v1.0.0",
		"ref": "refs/tags/v1.0.0",
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	executeDeploy(script, params)
	os.Stdout = oldStdout
	_ = w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"TAG=v1.0.0", "REF=refs/tags/v1.0.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("script output missing %q, got:\n%s", want, got)
		}
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
	req := httptest.NewRequest(http.MethodPost, "/unknown", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d for unknown route", rec.Code, http.StatusNotFound)
	}
}
