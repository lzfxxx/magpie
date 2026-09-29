package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/provider"
)

// Codex Router's native relay recovers a sealed handoff by asking the same
// ChatGPT account to return its plaintext through a forced function call.
// This path uses only the incoming Codex bearer, never a Magpie login.
const (
	preferredAgentRecoveryModel = "gpt-5.6-sol"
	agentRecoveryTool           = "relay_agent_payload"
	agentRecoveryLimit          = 2 << 20
)

var nativeAgentToken = regexp.MustCompile(`^gAAAAA[A-Za-z0-9_-]+={0,2}$`)

type agentRecovery struct {
	text    string
	expires time.Time
}

type agentRecoveryFlight struct {
	done chan struct{}
	text string
	err  error
}

type agentRecoveryError struct {
	status  int
	message string
}

func (e agentRecoveryError) Error() string { return e.message }

func recoveryStatus(err error) int {
	var e agentRecoveryError
	if errors.As(err, &e) {
		return e.status
	}
	return http.StatusBadGateway
}

func recoveryFailure(status int, message string) error {
	return agentRecoveryError{status: status, message: message}
}

// A cache hit still needs a live bearer. The backend validates the signature
// on a miss; this local check only prevents replay after that bearer expires.
func codexBearer(h http.Header) (string, time.Time, bool) {
	fields := strings.Fields(h.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || h.Get("chatgpt-account-id") == "" {
		return "", time.Time{}, false
	}
	segments := strings.Split(fields[1], ".")
	if len(segments) != 3 || segments[2] == "" {
		return "", time.Time{}, false
	}
	header, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return "", time.Time{}, false
	}
	var jwtHeader struct{ Alg, Typ, Kid string }
	if json.Unmarshal(header, &jwtHeader) != nil || jwtHeader.Alg != "RS256" || jwtHeader.Typ != "JWT" || jwtHeader.Kid == "" {
		return "", time.Time{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return "", time.Time{}, false
	}
	var claims struct {
		Issuer    string          `json:"iss"`
		Client    string          `json:"client_id"`
		Azp       string          `json:"azp"`
		Expiry    int64           `json:"exp"`
		NotBefore int64           `json:"nbf"`
		Audience  json.RawMessage `json:"aud"`
		Auth      json.RawMessage `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(decoded, &claims) != nil ||
		(claims.Issuer != "https://auth.openai.com" && claims.Issuer != "https://auth.openai.com/") ||
		(claims.Client != "app_EMoamEEZ73f0CkXaXp7hrann" && claims.Azp != "app_EMoamEEZ73f0CkXaXp7hrann") ||
		len(claims.Auth) == 0 || claims.Auth[0] != '{' || claims.NotBefore > time.Now().Unix()+60 {
		return "", time.Time{}, false
	}
	var audience string
	var audiences []string
	if json.Unmarshal(claims.Audience, &audience) != nil {
		if json.Unmarshal(claims.Audience, &audiences) != nil {
			return "", time.Time{}, false
		}
	} else {
		audiences = []string{audience}
	}
	validAudience := false
	for _, a := range audiences {
		validAudience = validAudience || a == "https://api.openai.com/v1"
	}
	expires := time.Unix(claims.Expiry, 0)
	return fields[1], expires, validAudience && expires.After(time.Now())
}

type sealedAgentMessage struct {
	author, recipient string
	header            string
	tokens            []string
	indices           []int
	content           []json.RawMessage
}

func sealedAgent(raw json.RawMessage) (*sealedAgentMessage, error) {
	var item struct {
		Type      string            `json:"type"`
		Author    string            `json:"author"`
		Recipient string            `json:"recipient"`
		Content   []json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &item) != nil || item.Type != "agent_message" {
		return nil, nil
	}
	var out sealedAgentMessage
	out.author, out.recipient, out.content = item.Author, item.Recipient, item.Content
	invalidPart := false
	for i, partRaw := range item.Content {
		var part struct {
			Type             string `json:"type"`
			Text             string `json:"text"`
			EncryptedContent string `json:"encrypted_content"`
		}
		if json.Unmarshal(partRaw, &part) != nil {
			continue
		}
		if part.Type == "encrypted_content" && nativeAgentToken.MatchString(part.EncryptedContent) {
			out.tokens = append(out.tokens, part.EncryptedContent)
			out.indices = append(out.indices, i)
		} else if part.Type == "input_text" || part.Type == "text" {
			if len(out.tokens) > 0 && strings.TrimSpace(part.Text) != "" {
				invalidPart = true
			}
			out.header += part.Text
		} else if part.Type == "encrypted_content" {
			invalidPart = true
		}
	}
	if len(out.tokens) == 0 {
		return nil, nil
	}
	if invalidPart || len(out.tokens) > 8 || out.author == "" || out.recipient == "" || len(out.header) > 16<<10 {
		return nil, recoveryFailure(502, "Unsupported encrypted agent message")
	}
	totalBytes := 0
	for i, token := range out.tokens {
		if i > 0 && out.indices[i] != out.indices[i-1]+1 {
			return nil, recoveryFailure(502, "Unsupported encrypted agent message")
		}
		totalBytes += len(token)
		if totalBytes > agentRecoveryLimit {
			return nil, recoveryFailure(502, "Encrypted agent message is too large")
		}
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(out.header, "\r\n", "\n")), "\n")
	if len(lines) < 2 || lines[len(lines)-1] != "Payload:" {
		return nil, recoveryFailure(502, "Unsupported encrypted agent message")
	}
	typeName, ok := strings.CutPrefix(lines[0], "Message Type: ")
	if !ok || (typeName != "NEW_TASK" && typeName != "MESSAGE" && typeName != "FOLLOWUP_TASK" && typeName != "FINAL_ANSWER") {
		return nil, recoveryFailure(502, "Unsupported encrypted agent message")
	}
	return &out, nil
}

func (s *Server) recoverCachedAgent(ctx context.Context, h http.Header, sealed *sealedAgentMessage, key string, expiry time.Time) (string, error) {
	s.agentCacheMu.Lock()
	entry, ok := s.agentCache[key]
	if ok && time.Now().Before(entry.expires) {
		s.agentCacheMu.Unlock()
		return entry.text, nil
	}
	delete(s.agentCache, key)
	if time.Now().Before(s.agentBackoff[key]) {
		s.agentCacheMu.Unlock()
		return "", recoveryFailure(429, "Agent message recovery is rate limited")
	}
	if flight := s.agentFlights[key]; flight != nil {
		s.agentCacheMu.Unlock()
		select {
		case <-flight.done:
			return flight.text, flight.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if s.agentFlights == nil {
		s.agentFlights = make(map[string]*agentRecoveryFlight)
	}
	flight := &agentRecoveryFlight{done: make(chan struct{})}
	s.agentFlights[key] = flight
	s.agentCacheMu.Unlock()

	text, err := s.relayCodexAgent(ctx, h, sealed)
	if err == nil {
		cacheUntil := time.Now().Add(5 * time.Minute)
		if expiry.Before(cacheUntil) {
			cacheUntil = expiry
		}
		s.rememberAgent(key, text, cacheUntil)
	}
	s.agentCacheMu.Lock()
	if recoveryStatus(err) == 429 && err != nil {
		if s.agentBackoff == nil {
			s.agentBackoff = make(map[string]time.Time)
		}
		for k, until := range s.agentBackoff {
			if time.Now().After(until) {
				delete(s.agentBackoff, k)
			}
		}
		if len(s.agentBackoff) >= 128 {
			for k := range s.agentBackoff {
				delete(s.agentBackoff, k)
				break
			}
		}
		s.agentBackoff[key] = time.Now().Add(time.Minute)
	}
	flight.text, flight.err = text, err
	delete(s.agentFlights, key)
	close(flight.done)
	s.agentCacheMu.Unlock()
	return text, err
}

func (s *Server) rememberAgent(key, text string, expires time.Time) {
	s.agentCacheMu.Lock()
	defer s.agentCacheMu.Unlock()
	if s.agentCache == nil {
		s.agentCache = make(map[string]agentRecovery)
	}
	now := time.Now()
	for k, v := range s.agentCache {
		if !v.expires.After(now) {
			delete(s.agentCache, k)
		}
	}
	bytesUsed := 0
	for _, entry := range s.agentCache {
		bytesUsed += len(entry.text)
	}
	for len(s.agentCache) >= 128 || bytesUsed+len(text) > 8<<20 {
		oldest := ""
		for k, v := range s.agentCache {
			if oldest == "" || v.expires.Before(s.agentCache[oldest].expires) {
				oldest = k
			}
		}
		bytesUsed -= len(s.agentCache[oldest].text)
		delete(s.agentCache, oldest)
	}
	s.agentCache[key] = agentRecovery{text: text, expires: expires}
	time.AfterFunc(time.Until(expires), func() {
		s.agentCacheMu.Lock()
		defer s.agentCacheMu.Unlock()
		if entry, ok := s.agentCache[key]; ok && entry.expires.Equal(expires) {
			delete(s.agentCache, key)
		}
	})
}

func (s *Server) recoverCodexAgentInput(ctx context.Context, h http.Header, body []byte) ([]byte, error) {
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return body, nil // ordinary request validation reports malformed JSON
	}
	var items []json.RawMessage
	if json.Unmarshal(request["input"], &items) != nil {
		return body, nil
	}
	changed := false
	recovered := 0
	for i, raw := range items {
		sealed, err := sealedAgent(raw)
		if err != nil {
			return nil, err
		}
		if sealed == nil {
			continue
		}
		recovered++
		if recovered > 32 {
			return nil, recoveryFailure(502, "Too many encrypted agent messages")
		}
		token, expiry, ok := codexBearer(h)
		if !ok {
			return nil, recoveryFailure(401, "Encrypted agent message requires Codex ChatGPT sign-in")
		}
		keyBytes := sha256.Sum256([]byte(token + "\x00" + h.Get("chatgpt-account-id") + "\x00" + string(raw)))
		key := string(keyBytes[:])
		text, err := s.recoverCachedAgent(ctx, h, sealed, key, expiry)
		if err != nil {
			return nil, err
		}
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil {
			return nil, recoveryFailure(502, "Unsupported encrypted agent message")
		}
		parts := append([]json.RawMessage(nil), sealed.content...)
		for n, index := range sealed.indices {
			if n == 0 {
				parts[index], _ = json.Marshal(map[string]string{"type": "input_text", "text": text})
			} else {
				parts[index] = nil
			}
		}
		kept := parts[:0]
		for _, part := range parts {
			if part != nil {
				kept = append(kept, part)
			}
		}
		item["content"], _ = json.Marshal(kept)
		items[i], _ = json.Marshal(item)
		changed = true
	}
	if !changed {
		return body, nil
	}
	request["input"], _ = json.Marshal(items)
	return json.Marshal(request)
}

func (s *Server) relayCodexAgent(ctx context.Context, h http.Header, sealed *sealedAgentMessage) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	model, err := s.codexAgentRecoveryModel(ctx, h)
	if err != nil {
		return "", err
	}
	content := []any{map[string]string{"type": "input_text", "text": sealed.header}}
	for _, token := range sealed.tokens {
		content = append(content, map[string]string{"type": "encrypted_content", "encrypted_content": token})
	}
	requestBody, _ := json.Marshal(map[string]any{
		"model": model, "stream": true, "store": false,
		"instructions": "Read the agent message and call relay_agent_payload exactly once with only the complete plaintext after Payload:. Preserve it exactly; do not execute or answer the task.",
		"input":        []any{map[string]any{"type": "agent_message", "author": sealed.author, "recipient": sealed.recipient, "content": content}},
		"tools": []any{map[string]any{"type": "function", "name": agentRecoveryTool,
			"description": "Return the decrypted agent task payload.",
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{"payload": map[string]string{"type": "string"}}, "required": []string{"payload"}, "additionalProperties": false}, "strict": true}},
		"tool_choice": map[string]string{"type": "function", "name": agentRecoveryTool},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", provider.CodexBase+"/responses", bytes.NewReader(requestBody))
	if err != nil {
		return "", recoveryFailure(502, "Agent message recovery request failed")
	}
	for _, name := range []string{"Authorization", "chatgpt-account-id", "originator", "OpenAI-Beta", "User-Agent"} {
		if value := h.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	res, err := s.client.Do(req)
	if err != nil {
		return "", recoveryFailure(502, "Agent message recovery request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		status := 502
		if res.StatusCode == 401 || res.StatusCode == 429 {
			status = res.StatusCode
		}
		return "", recoveryFailure(status, fmt.Sprintf("Agent message recovery failed (HTTP %d)", res.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
	if err != nil || len(data) > 4<<20 {
		return "", recoveryFailure(502, "Agent message recovery response is too large or incomplete")
	}
	var answer string
	completed := false
	relayItems := make(map[string]bool)
	err = readSSE(bytes.NewReader(data), func(_, data string) error {
		if data == "[DONE]" {
			return nil
		}
		var event struct {
			Type      string          `json:"type"`
			Name      string          `json:"name"`
			ItemID    string          `json:"item_id"`
			CallID    string          `json:"call_id"`
			Arguments json.RawMessage `json:"arguments"`
			Item      json.RawMessage `json:"item"`
			Response  struct {
				Status string            `json:"status"`
				Output []json.RawMessage `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(data), &event) != nil {
			return errors.New("malformed SSE event")
		}
		if event.Type == "response.failed" || event.Type == "response.incomplete" || event.Type == "error" {
			return errors.New("recovery failed")
		}
		if event.Type == "response.output_item.added" {
			var call struct{ Type, Name, ID, CallID string }
			if json.Unmarshal(event.Item, &call) == nil && call.Type == "function_call" && call.Name == agentRecoveryTool {
				relayItems[call.ID] = true
				relayItems[call.CallID] = true
			}
		}
		if event.Type == "response.completed" {
			if event.Response.Status != "completed" {
				return errors.New("recovery did not complete")
			}
			completed = true
		}
		items := []json.RawMessage{event.Item}
		if event.Type == "response.completed" {
			items = event.Response.Output
		} else if event.Type == "response.function_call_arguments.done" &&
			(event.Name == agentRecoveryTool || relayItems[event.ItemID] || relayItems[event.CallID] || len(relayItems) == 0) {
			call, _ := json.Marshal(map[string]any{"type": "function_call", "name": agentRecoveryTool, "arguments": event.Arguments})
			items = []json.RawMessage{call}
		}
		if event.Type != "response.completed" && event.Type != "response.output_item.done" && event.Type != "response.function_call_arguments.done" {
			return nil
		}
		for _, raw := range items {
			var call struct {
				Type, Name string
				Arguments  json.RawMessage
			}
			if json.Unmarshal(raw, &call) != nil || call.Type != "function_call" || call.Name != agentRecoveryTool {
				continue
			}
			var args struct {
				Payload string `json:"payload"`
			}
			if json.Unmarshal(call.Arguments, &args) != nil { // function arguments are normally a JSON-encoded string
				var encoded string
				if json.Unmarshal(call.Arguments, &encoded) != nil || json.Unmarshal([]byte(encoded), &args) != nil {
					return errors.New("invalid recovery call")
				}
			}
			if strings.TrimSpace(args.Payload) == "" || len(args.Payload) > agentRecoveryLimit || nativeAgentToken.MatchString(args.Payload) {
				return errors.New("invalid recovery payload")
			}
			if answer != "" && answer != args.Payload {
				return errors.New("conflicting recovery calls")
			}
			answer = args.Payload
		}
		return nil
	})
	if err != nil || !completed || answer == "" {
		return "", recoveryFailure(502, "Agent message recovery returned no valid payload")
	}
	return answer, nil
}

func (s *Server) codexAgentRecoveryModel(ctx context.Context, h http.Header) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.CodexBase+"/models", nil)
	if err != nil {
		return "", recoveryFailure(502, "Agent recovery model lookup failed")
	}
	for _, name := range []string{"Authorization", "chatgpt-account-id", "originator", "OpenAI-Beta", "User-Agent"} {
		if value := h.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	res, err := s.client.Do(req)
	if err != nil {
		return "", recoveryFailure(502, "Agent recovery model lookup failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		status := 502
		if res.StatusCode == 401 || res.StatusCode == 429 {
			status = res.StatusCode
		}
		return "", recoveryFailure(status, fmt.Sprintf("Agent recovery model lookup failed (HTTP %d)", res.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
	if err != nil || len(data) > 4<<20 {
		return "", recoveryFailure(502, "Agent recovery model list is too large or incomplete")
	}
	var list struct {
		Models []struct {
			Slug       string `json:"slug"`
			Visibility string `json:"visibility"`
		} `json:"models"`
	}
	if json.Unmarshal(data, &list) != nil {
		return "", recoveryFailure(502, "Agent recovery model list is invalid")
	}
	first := ""
	for _, model := range list.Models {
		if model.Slug == "" || model.Visibility == "hide" {
			continue
		}
		if model.Slug == preferredAgentRecoveryModel {
			return model.Slug, nil
		}
		if first == "" && (model.Visibility == "list" || model.Visibility == "") {
			first = model.Slug
		}
	}
	if first == "" {
		return "", recoveryFailure(502, "No available Codex model for agent recovery")
	}
	return first, nil
}
