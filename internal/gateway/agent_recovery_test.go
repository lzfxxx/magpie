package gateway

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/provider"
)

func recoveryBearer(expiry time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"test"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://auth.openai.com", "aud": "https://api.openai.com/v1",
		"client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "exp": expiry.Unix(),
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "acct-1"},
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

func recoveryHeaders() http.Header {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+recoveryBearer(time.Now().Add(time.Hour)))
	h.Set("chatgpt-account-id", "acct-1")
	h.Set("originator", "codex_cli_rs")
	return h
}

func recoveryInput(kind, task string) string {
	header := "Message Type: " + kind + "\n"
	if task != "" {
		header += "Task name: " + task + "\n"
	}
	header += "Sender: /root\nPayload:\n"
	b, _ := json.Marshal(map[string]any{
		"model": "fake/m1", "stream": true,
		"input": []any{map[string]any{
			"type": "agent_message", "author": "/root", "recipient": "/root/worker",
			"content": []any{
				map[string]string{"type": "input_text", "text": header},
				map[string]string{"type": "encrypted_content", "encrypted_content": "gAAAAATest_ciphertext=="},
			},
		}},
	})
	return string(b)
}

func recoveryReply(payload string) string {
	args, _ := json.Marshal(map[string]string{"payload": payload})
	call, _ := json.Marshal(map[string]any{"type": "function_call", "name": agentRecoveryTool, "arguments": string(args)})
	return sse(
		`data: {"type":"response.output_item.done","item":`+string(call)+`}`,
		`data: {"type":"response.completed","response":{"status":"completed","output":[]}}`,
	)
}

func TestCodexEncryptedAgentRecovery(t *testing.T) {
	for _, kind := range []string{"NEW_TASK", "MESSAGE", "FOLLOWUP_TASK", "FINAL_ANSWER"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			h := recoveryHeaders()
			chatgpt(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"models":[{"slug":"fallback","visibility":"list"},{"slug":"gpt-5.6-sol","visibility":"list"}]}`)
					return
				}
				calls++
				if r.URL.Path != "/backend-api/codex/responses" || r.Header.Get("Authorization") != h.Get("Authorization") || r.Header.Get("chatgpt-account-id") != "acct-1" {
					t.Errorf("wrong relay target or credential: %s %v", r.URL.Path, r.Header)
				}
				var q struct {
					Model      string           `json:"model"`
					Input      []map[string]any `json:"input"`
					ToolChoice map[string]any   `json:"tool_choice"`
				}
				if json.NewDecoder(r.Body).Decode(&q) != nil || q.Model != preferredAgentRecoveryModel || len(q.Input) != 1 || q.Input[0]["type"] != "agent_message" || q.ToolChoice["name"] != agentRecoveryTool {
					t.Errorf("incorrect relay envelope: %+v", q)
				}
				io.WriteString(w, recoveryReply("Check the changed files."))
			})
			body := recoveryInput(kind, "/root/worker")
			if kind == "FINAL_ANSWER" {
				body = recoveryInput(kind, "")
			}
			if kind == "NEW_TASK" {
				body = strings.Replace(body, "Sender: /root\\n", "Agent type: worker\\nSender: /root\\n", 1)
			}
			s := New()
			for i := 0; i < 2; i++ {
				out, err := s.recoverCodexAgentInput(t.Context(), h, []byte(body))
				if err != nil {
					t.Fatal(err)
				}
				r, err := parseResponses(out)
				if err != nil || len(r.Messages) != 1 || !strings.Contains(text(r.Messages[0].Parts), "Check the changed files.") {
					t.Fatalf("recovered request: %+v, %v", r, err)
				}
				if strings.Contains(string(out), "gAAAAA") {
					t.Fatal("ciphertext reached the target model")
				}
			}
			if calls != 1 {
				t.Errorf("replay bought %d recoveries; want one", calls)
			}
		})
	}
}

func TestCodexEncryptedAgentRecoveryReachesModelAndCompaction(t *testing.T) {
	f := &fake{t: t, reply: sse(
		`data: {"type":"response.created","response":{"id":"r1"}}`,
		`data: {"type":"response.completed","response":{"id":"r1","status":"completed","output":[],"usage":{"input_tokens":3,"output_tokens":1}}}`,
	)}
	setup(t, provider.Responses, f)
	relays := 0
	chatgpt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"models":[{"slug":"fallback","visibility":"list"}]}`)
			return
		}
		relays++
		var request struct {
			Model string `json:"model"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		if request.Model != "fallback" {
			t.Errorf("recovery chose %q", request.Model)
		}
		args, _ := json.Marshal(map[string]string{"payload": "Check the changed files."})
		b, _ := json.Marshal(map[string]any{"type": "response.function_call_arguments.done", "item_id": "fc_1", "arguments": string(args)})
		added := `data: {"type":"response.output_item.added","item":{"type":"function_call","name":"relay_agent_payload","id":"fc_1"}}`
		io.WriteString(w, sse(added, "data: "+string(b), `data: {"type":"response.completed","response":{"status":"completed","output":[]}}`))
	})
	s := New()
	for _, compact := range []bool{false, true} {
		body := recoveryInput("NEW_TASK", "/root/worker")
		if compact {
			var q map[string]json.RawMessage
			json.Unmarshal([]byte(body), &q)
			var items []json.RawMessage
			json.Unmarshal(q["input"], &items)
			items = append(items, json.RawMessage(`{"type":"compaction_trigger"}`))
			q["input"], _ = json.Marshal(items)
			bodyBytes, _ := json.Marshal(q)
			body = string(bodyBytes)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", CodexPath+"/responses", strings.NewReader(body))
		req.Header = recoveryHeaders()
		s.Handler().ServeHTTP(rec, req)
		if compact {
			// The compaction mock has no summary, but it must still receive
			// the same recovered handoff before it reaches that failure.
			if rec.Code != 502 {
				t.Fatalf("compaction status: %d %s", rec.Code, rec.Body.String())
			}
		} else if rec.Code != 200 {
			t.Fatalf("turn status: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(string(f.got), "Check the changed files.") || strings.Contains(string(f.got), "gAAAAA") {
			t.Fatalf("model saw the wrong handoff: %s", f.got)
		}
	}
	if relays != 1 {
		t.Errorf("turn and compaction used %d relays, want one", relays)
	}
}

func TestCodexEncryptedAgentRecoveryFailsClosed(t *testing.T) {
	f := &fake{t: t, reply: sse(`data: {"choices":[{"delta":{"content":"unexpected"}}]}`)}
	setup(t, provider.Chat, f)
	relayCalls := 0
	chatgpt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"models":[{"slug":"fallback","visibility":"list"}]}`)
			return
		}
		relayCalls++
		io.WriteString(w, sse(`data: {"type":"response.completed","response":{"status":"completed","output":[]}}`))
	})
	for _, tc := range []struct {
		name string
		h    http.Header
		body string
		want int
	}{
		{"missing bearer", http.Header{}, recoveryInput("NEW_TASK", "/root/worker"), 401},
		{"expired bearer", func() http.Header {
			h := recoveryHeaders()
			h.Set("Authorization", "Bearer "+recoveryBearer(time.Now().Add(-time.Hour)))
			return h
		}(), recoveryInput("NEW_TASK", "/root/worker"), 401},
		{"invalid output", recoveryHeaders(), recoveryInput("NEW_TASK", "/root/worker"), 502},
		{"wrong message boundary", recoveryHeaders(), strings.Replace(recoveryInput("NEW_TASK", "/root/worker"), "Payload:", "No payload:", 1), 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", CodexPath+"/responses", strings.NewReader(tc.body))
			req.Header = tc.h
			New().Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want || f.calls != 0 {
				t.Fatalf("status %d, target calls %d, body %s", rec.Code, f.calls, rec.Body.String())
			}
		})
	}
	if relayCalls != 1 {
		t.Errorf("unadmitted/malformed envelopes made %d relays; want one", relayCalls)
	}
}

func TestCodexEncryptedAgentRecoveryCoalescesConcurrentRequests(t *testing.T) {
	var relays atomic.Int32
	chatgpt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"models":[{"slug":"fallback","visibility":"list"}]}`)
			return
		}
		relays.Add(1)
		time.Sleep(50 * time.Millisecond)
		io.WriteString(w, recoveryReply("One shared payload"))
	})
	s := New()
	h := recoveryHeaders()
	body := []byte(recoveryInput("NEW_TASK", "/root/worker"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := s.recoverCodexAgentInput(t.Context(), h, body)
			if err != nil || !strings.Contains(string(out), "One shared payload") {
				t.Errorf("concurrent recovery: %s, %v", out, err)
			}
		}()
	}
	wg.Wait()
	if got := relays.Load(); got != 1 {
		t.Fatalf("bought %d concurrent relays, want one", got)
	}
}

func TestCodexEncryptedAgentRecoveryBacksOffOnRateLimit(t *testing.T) {
	var relays int
	chatgpt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"models":[{"slug":"fallback","visibility":"list"}]}`)
			return
		}
		relays++
		w.WriteHeader(429)
	})
	s := New()
	for range 2 {
		_, err := s.recoverCodexAgentInput(t.Context(), recoveryHeaders(), []byte(recoveryInput("NEW_TASK", "/root/worker")))
		if err == nil || recoveryStatus(err) != 429 {
			t.Fatalf("rate limit error: %v", err)
		}
	}
	if relays != 1 {
		t.Fatalf("bought %d rate-limited relays, want one", relays)
	}
}
