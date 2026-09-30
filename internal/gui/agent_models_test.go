package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/settings"
)

// The Agents page's model list for an agent: every model it may be shown,
// the one it's set to marked and never taken out.
func TestAgentModelsAPI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"magpie/relay/m1\"\n"), 0o600)
	if err := provider.Save(provider.Provider{ID: "relay", Name: "Relay", Key: "k", Chat: "http://127.0.0.1:1/v1", Models: []string{"m1", "m2", "m3"}}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	agentModelsAPI(mux)
	call := func(method, body string) (out struct {
		Models []agentModelJSON
		Count  *modelCountJSON
	}) {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, "/api/agent-models/codex", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("%s %d %s", method, w.Code, w.Body)
		}
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	find := func(ms []agentModelJSON, id string) agentModelJSON {
		for _, m := range ms {
			if m.ID == id {
				return m
			}
		}
		t.Fatalf("no %s in %+v", id, ms)
		return agentModelJSON{}
	}
	got := call("GET", "")
	if m := find(got.Models, "relay/m1"); !m.InUse || m.Hidden || m.Group != "Relay" {
		t.Fatalf("%+v", m)
	}
	if m := find(got.Models, "relay/m2"); m.InUse || m.Hidden {
		t.Fatalf("%+v", m)
	}
	// the one in use stays whatever is asked
	got = call("POST", `{"hidden":["relay/m1","relay/m2"]}`)
	if saved := settings.Load().HiddenModels["codex"]; !slices.Equal(saved, []string{"relay/m2"}) {
		t.Fatalf("saved %v", saved)
	}
	if !find(got.Models, "relay/m2").Hidden || find(got.Models, "relay/m1").Hidden ||
		got.Count == nil || got.Count.Shown != got.Count.Listed-1 {
		t.Fatalf("%+v %+v", got.Models, got.Count)
	}
	if c := modelCount("codex"); *c != *got.Count {
		t.Fatalf("count %+v, answered %+v", c, got.Count)
	}
	got = call("POST", `{"hidden":[]}`)
	if got.Count.Shown != got.Count.Listed {
		t.Fatalf("%+v", got.Count)
	}
}

func TestAgentModelsNativeWithProviderOff(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	dir := filepath.Join(home, ".codex")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("model = \"relay/m1\"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "auth.json"), []byte(`{"auth_mode":"chatgpt","tokens":{"access_token":"x","id_token":"h.e30.s"}}`), 0o600)
	os.WriteFile(filepath.Join(dir, "models_cache.json"), []byte(`{"models":[{"slug":"gpt-a","visibility":"list"},{"slug":"gpt-b","visibility":"list"}]}`), 0o600)
	if err := provider.Save(provider.Provider{ID: "codex", Off: true, Models: []string{"gpt-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := provider.Save(provider.Provider{ID: "relay", Name: "Relay", Key: "k", Chat: "http://127.0.0.1:1/v1", Models: []string{"m1"}}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	agentModelsAPI(mux)
	call := func(method, body string) (out struct {
		Models []agentModelJSON
		Count  *modelCountJSON
	}) { t.Helper(); w := httptest.NewRecorder(); mux.ServeHTTP(w, httptest.NewRequest(method, "/api/agent-models/codex", strings.NewReader(body))); if w.Code != 200 {
		t.Fatalf("%s: %d %s", method, w.Code, w.Body)
	}; if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}; return }
	assertNative := func(ms []agentModelJSON, hidden bool) {
		t.Helper()
		n := 0
		for _, m := range ms {
			if strings.HasPrefix(m.ID, "codex/") {
				n++
				if m.Hidden != hidden {
					t.Fatalf("native state: %+v", m)
				}
			}
		}
		if n != 2 {
			t.Fatalf("native models unavailable with sharing off: %+v", ms)
		}
	}
	assertNative(call("GET", "").Models, false)
	got := call("POST", `{"hidden":["codex/gpt-a","codex/gpt-b"]}`)
	assertNative(got.Models, true)
	assertNative(call("GET", "").Models, true)
	if got.Count.Shown != 1 || got.Count.Listed != 3 {
		t.Fatalf("count: %+v", got.Count)
	}
	assertNative(call("POST", `{"hidden":[]}`).Models, false)
}
