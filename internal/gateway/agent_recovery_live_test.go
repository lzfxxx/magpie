package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/provider"
)

// Run explicitly with MAGPIE_LIVE_CODEX_BIN, MAGPIE_LIVE_CODEX_HOME, and
// MAGPIE_LIVE_HOME. It spends one short native Codex turn on the signed-in account.
func TestLiveCodexEncryptedAgentHandoff(t *testing.T) {
	bin, home, codexHome := os.Getenv("MAGPIE_LIVE_CODEX_BIN"), os.Getenv("MAGPIE_LIVE_HOME"), os.Getenv("MAGPIE_LIVE_CODEX_HOME")
	if bin == "" || home == "" || codexHome == "" {
		t.Skip("live Codex environment not set")
	}
	var mu sync.Mutex
	var childRequests [][]byte
	var agentStatus int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		childRequests = append(childRequests, append([]byte(nil), body...))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(
			`data: {"type":"response.created","response":{"id":"resp_live_fake","object":"response","status":"in_progress","output":[]}}`,
			`data: {"type":"response.output_item.done","output_index":0,"item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"PONG-LIVE-AGENT"}]}}`,
			`data: {"type":"response.completed","response":{"id":"resp_live_fake","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"PONG-LIVE-AGENT"}]}],"usage":{"input_tokens":20,"output_tokens":4}}}`))
	}))
	defer up.Close()
	if err := provider.Save(provider.Provider{ID: "fake", Name: "Fake", Key: "fake", Models: []string{"m1"}, Responses: up.URL + "/v1"}); err != nil {
		t.Fatal(err)
	}
	var encrypted bool
	s := New()
	handler := s.Handler()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAgent := false
		if r.Method == http.MethodPost && r.URL.Path == CodexPath+"/responses" {
			body, err := codexBody(r)
			if err != nil {
				http.Error(w, "could not decode test request", 400)
				return
			}
			isAgent = bytes.Contains(body, []byte(`"model":"fake/m1"`))
			if isAgent && bytes.Contains(body, []byte("gAAAAA")) {
				mu.Lock()
				encrypted = true
				mu.Unlock()
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		if isAgent {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
			mu.Lock()
			agentStatus = rec.Code
			mu.Unlock()
			for k, values := range rec.Header() {
				w.Header()[k] = values
			}
			w.WriteHeader(rec.Code)
			w.Write(rec.Body.Bytes())
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	baseURL := gateway.URL + CodexPath
	cmd := exec.CommandContext(ctx, bin, "exec", "--ignore-user-config", "--ephemeral", "--sandbox", "read-only", "--skip-git-repo-check",
		"-C", t.TempDir(), "-m", "gpt-6-sol", "-c", fmt.Sprintf("openai_base_url=%q", baseURL),
		"-c", "features.multi_agent_v2=true", "Spawn one worker subagent on model fake/m1 with fork_turns=none. Tell it to reply PONG-LIVE-AGENT. Wait for it and then reply with its exact result. Do not use any other tools.")
	cmd.Env = append(os.Environ(), "HOME="+home, "CODEX_HOME="+codexHome)
	output, err := cmd.CombinedOutput()
	mu.Lock()
	gotEncrypted, children, status := encrypted, append([][]byte(nil), childRequests...), agentStatus
	mu.Unlock()
	gotPayload, gotCiphertext := false, false
	for _, child := range children {
		var request struct {
			Input []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"input"`
		}
		if json.Unmarshal(child, &request) == nil {
			for _, item := range request.Input {
				for i, part := range item.Content {
					if strings.Contains(part.Text, "Message Type: NEW_TASK") && strings.Contains(part.Text, "Payload:") && i+1 < len(item.Content) && strings.Contains(item.Content[i+1].Text, "PONG-LIVE-AGENT") {
						gotPayload = true
					}
				}
			}
		}
		gotCiphertext = gotCiphertext || bytes.Contains(child, []byte("gAAAAA"))
	}
	if !gotEncrypted || !gotPayload || gotCiphertext {
		t.Errorf("handoff: encrypted=%v status=%d requests=%d childSawPayload=%v childSawCiphertext=%v", gotEncrypted, status, len(children), gotPayload, gotCiphertext)
	}
	if err != nil || !strings.Contains(string(output), "PONG-LIVE-AGENT") {
		t.Errorf("Codex turn: %v; expected response seen=%v", err, strings.Contains(string(output), "PONG-LIVE-AGENT"))
	}
}
