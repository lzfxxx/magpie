package gui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yetone/magpie/internal/agent"
	"github.com/yetone/magpie/internal/provider"
)

// Which of the catalog an agent's lists show, picked one model at a time
// on the Agents page (settings.HiddenModels): the line under an agent's
// name counts them, and opens the list to pick in.

// modelCountJSON is how many models an agent's lists show, of those its
// visibility gives it.
type modelCountJSON struct {
	Shown  int `json:"shown"`
	Listed int `json:"listed"`
}

// agentModelJSON is a model an agent may be shown, as the list draws it.
type agentModelJSON struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group string   `json:"group"` // its provider's name, or "Routing groups"
	Icon  string   `json:"icon,omitempty"`
	Icons []string `json:"icons,omitempty"`
	// Logo is its maker's: known by the model's family, or its provider's
	// when that is the maker; "" when neither says
	Logo    string `json:"logo,omitempty"`
	Context int    `json:"context,omitempty"`
	Hidden  bool   `json:"hidden,omitempty"`
	// InUse: the agent is set to it, so it can't be taken out
	InUse bool `json:"inUse,omitempty"`
}

// takesCatalog reports whether an agent picks among magpie's catalog: some
// option of a field of its is a catalog entry.
func takesCatalog(fields []fieldJSON) bool {
	for _, f := range fields {
		for _, o := range f.Options {
			if o.Ref != "" {
				return true
			}
		}
	}
	return false
}

// Native ChatGPT models belong to Codex's own picker even when the
// subscription is switched off for other agents.
func agentModelsListed(id string) []provider.Entry {
	listed, _ := provider.ListedFor(id)
	if id != "codex" {
		return listed
	}
	out := make([]provider.Entry, 0, len(listed))
	for _, e := range listed {
		if e.Group == "" && e.Provider.Account != nil && e.Provider.Account.Agent == "codex" {
			continue
		}
		out = append(out, e)
	}
	return append(out, provider.CodexNativeEntries()...)
}

func modelCount(id string) *modelCountJSON {
	listed := agentModelsListed(id)
	off := provider.HiddenModels(id)
	c := &modelCountJSON{Listed: len(listed)}
	for _, e := range listed {
		if !off[e.ID] {
			c.Shown++
		}
	}
	return c
}

// usedBy reports whether one of the agent's values is the entry: its id,
// with a prefix the agent's files give it (magpie/…), or, for the agent's
// own account, the vendor's model id alone.
func usedBy(a *agent.Agent, vals map[string]string, e provider.Entry) bool {
	for _, v := range vals {
		if v == "" {
			continue
		}
		if v == e.ID || strings.HasSuffix(v, "/"+e.ID) {
			return true
		}
		if acc := e.Provider.Account; e.Group == "" && acc != nil && acc.Agent == a.ID && v == e.Model {
			return true
		}
	}
	return false
}

func agentModelList(a *agent.Agent) []agentModelJSON {
	listed := agentModelsListed(a.ID)
	off := provider.HiddenModels(a.ID)
	vals := a.Values()
	out := []agentModelJSON{}
	for _, e := range listed {
		m := agentModelJSON{ID: e.ID, Name: e.Name, Group: e.Provider.Name, Icon: e.Provider.Icon, Context: e.Context,
			Hidden: off[e.ID], InUse: usedBy(a, vals, e)}
		if m.Name == "" {
			m.Name = e.Model
		}
		m.Logo = agent.ModelIcon(e.Model)
		if e.Group != "" {
			// a group's first member says nothing of the others: known by
			// the name it was given, or its id
			m.Group, m.Icons = agent.RoutingGroups, e.Icons
			if m.Logo = agent.ModelIcon(m.Name); m.Logo == "" {
				m.Logo = agent.ModelIcon(e.Group)
			}
		} else if m.Logo == "" {
			if p := provider.Preset(e.Provider.Preset); p != nil && p.Kind == provider.KindVendor {
				m.Logo = e.Provider.Icon
			}
		}
		out = append(out, m)
	}
	return out
}

func agentModelsAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/agent-models/{id}", func(rw http.ResponseWriter, r *http.Request) {
		a, err := agent.Find(r.PathValue("id"))
		if err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, map[string]any{"models": agentModelList(a)})
	})
	// hidden is every entry to take out of the agent's lists; the others
	// are shown, and one the agent is set to is kept in whatever is asked
	mux.HandleFunc("POST /api/agent-models/{id}", func(rw http.ResponseWriter, r *http.Request) {
		var in struct{ Hidden []string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		a, err := agent.Find(r.PathValue("id"))
		if err != nil {
			fail(rw, err)
			return
		}
		used := map[string]bool{}
		for _, m := range agentModelList(a) {
			used[m.ID] = m.InUse
		}
		var hidden []string
		for _, id := range in.Hidden {
			if !used[id] {
				hidden = append(hidden, id)
			}
		}
		if err := provider.SetHiddenModels(a.ID, hidden); err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, map[string]any{"models": agentModelList(a), "count": modelCount(a.ID)})
	})
}
