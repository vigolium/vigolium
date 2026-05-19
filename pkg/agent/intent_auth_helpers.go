package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"gopkg.in/yaml.v3"
)

type sessionConfigYAML struct {
	Sessions []sessionEntryYAML `yaml:"sessions"`
}

type sessionEntryYAML struct {
	Name    string            `yaml:"name"`
	Role    string            `yaml:"role,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Login   *loginFlowYAML    `yaml:"login,omitempty"`
}

type loginFlowYAML struct {
	URL         string            `yaml:"url"`
	Method      string            `yaml:"method,omitempty"`
	ContentType string            `yaml:"content_type,omitempty"`
	Body        string            `yaml:"body,omitempty"`
	Type        string            `yaml:"type,omitempty"`
	TokenPath   string            `yaml:"token_path,omitempty"`
	Expect      *expectYAML       `yaml:"expect,omitempty"`
	Extract     []extractRuleYAML `yaml:"extract,omitempty"`
}

type expectYAML struct {
	Status       []int  `yaml:"status,omitempty"`
	BodyContains string `yaml:"body_contains,omitempty"`
}

type extractRuleYAML struct {
	Source  string `yaml:"source"`
	Name    string `yaml:"name,omitempty"`
	Path    string `yaml:"path,omitempty"`
	ApplyAs string `yaml:"apply_as,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
	Group   int    `yaml:"group,omitempty"`
}

func resolveIntentCredentialSets(raw string, sets []agenttypes.IntentCredentialSet) []agenttypes.IntentCredentialSet {
	if len(sets) > 0 {
		return append([]agenttypes.IntentCredentialSet(nil), sets...)
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return parseCredentialSetsFromString(raw)
}

func parseCredentialSetsFromString(raw string) []agenttypes.IntentCredentialSet {
	var out []agenttypes.IntentCredentialSet
	parts := strings.Split(raw, ",")
	assignedPrimary := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		role := ""
		lower := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lower, "compare "):
			role = "compare"
			part = strings.TrimSpace(part[len("compare "):])
		case strings.HasPrefix(lower, "with "):
			part = strings.TrimSpace(part[len("with "):])
		}
		user, pass, ok := strings.Cut(part, "/")
		if !ok {
			continue
		}
		user = strings.TrimSpace(user)
		pass = strings.TrimSpace(pass)
		if user == "" || pass == "" {
			continue
		}
		if role == "" {
			if !assignedPrimary {
				role = "primary"
				assignedPrimary = true
			} else {
				role = "compare"
			}
		}
		out = append(out, agenttypes.IntentCredentialSet{
			Name:     user,
			Role:     role,
			Username: user,
			Password: pass,
		})
	}
	return out
}

func applyIntentCredentialsToSessionConfig(base *AgentSessionConfig, sets []agenttypes.IntentCredentialSet) *AgentSessionConfig {
	if base == nil || len(base.Sessions) == 0 || len(sets) == 0 {
		return base
	}
	out := cloneAgentSessionConfig(base)
	for _, set := range sets {
		idx := matchCredentialSession(out, set)
		if idx < 0 {
			continue
		}
		entry := &out.Sessions[idx]
		if entry.Name == "" {
			entry.Name = firstNonEmpty(set.Name, set.Username, set.Role)
		}
		if entry.Role == "" {
			entry.Role = set.Role
		}
		if entry.Login != nil {
			entry.Login.Body = replaceLoginBodyCredentials(entry.Login.Body, entry.Login.ContentType, set)
		}
	}
	return out
}

func WriteAuthConfigYAML(sessionDir string, cfg *AgentSessionConfig) (string, error) {
	if sessionDir == "" {
		return "", fmt.Errorf("session dir is required")
	}
	if cfg == nil || len(cfg.Sessions) == 0 {
		return "", nil
	}
	yamlData, err := yaml.Marshal(convertSessionConfig(cfg))
	if err != nil {
		return "", fmt.Errorf("failed to marshal session config: %w", err)
	}
	authPath := filepath.Join(sessionDir, "auth-config.yaml")
	if err := os.WriteFile(authPath, yamlData, 0o644); err != nil {
		return "", fmt.Errorf("failed to write auth config: %w", err)
	}
	return authPath, nil
}

func convertSessionConfig(cfg *AgentSessionConfig) sessionConfigYAML {
	result := sessionConfigYAML{}
	for _, s := range cfg.Sessions {
		entry := sessionEntryYAML{
			Name:    s.Name,
			Role:    s.Role,
			Headers: s.Headers,
		}
		if s.Login != nil {
			login := &loginFlowYAML{
				URL:         s.Login.URL,
				Method:      s.Login.Method,
				ContentType: s.Login.ContentType,
				Body:        s.Login.Body,
				Type:        s.Login.Type,
				TokenPath:   s.Login.TokenPath,
			}
			if s.Login.Expect != nil {
				login.Expect = &expectYAML{
					Status:       s.Login.Expect.Status,
					BodyContains: s.Login.Expect.BodyContains,
				}
			}
			for _, e := range s.Login.Extract {
				login.Extract = append(login.Extract, extractRuleYAML{
					Source:  e.Source,
					Name:    e.Name,
					Path:    e.Path,
					ApplyAs: e.ApplyAs,
					Pattern: e.Pattern,
					Group:   e.Group,
				})
			}
			entry.Login = login
		}
		result.Sessions = append(result.Sessions, entry)
	}
	return result
}

func matchCredentialSession(cfg *AgentSessionConfig, set agenttypes.IntentCredentialSet) int {
	for i := range cfg.Sessions {
		entry := cfg.Sessions[i]
		if set.Role != "" && entry.Role == set.Role {
			return i
		}
		if set.Name != "" && strings.EqualFold(entry.Name, set.Name) {
			return i
		}
	}
	if len(cfg.Sessions) == 1 {
		return 0
	}
	return -1
}

func replaceLoginBodyCredentials(body, contentType string, set agenttypes.IntentCredentialSet) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return body
	}
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(trimmed, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			replaceCredentialKeys(obj, set)
			if data, err := json.Marshal(obj); err == nil {
				return string(data)
			}
		}
	}
	values, err := url.ParseQuery(trimmed)
	if err == nil && len(values) > 0 {
		replaceCredentialValues(values, set)
		return values.Encode()
	}
	return body
}

func replaceCredentialKeys(obj map[string]any, set agenttypes.IntentCredentialSet) {
	for _, key := range []string{"username", "user", "email", "login"} {
		if _, ok := obj[key]; ok {
			obj[key] = set.Username
		}
	}
	for _, key := range []string{"password", "pass", "passwd"} {
		if _, ok := obj[key]; ok {
			obj[key] = set.Password
		}
	}
}

func replaceCredentialValues(values url.Values, set agenttypes.IntentCredentialSet) {
	for _, key := range []string{"username", "user", "email", "login"} {
		if _, ok := values[key]; ok {
			values.Set(key, set.Username)
		}
	}
	for _, key := range []string{"password", "pass", "passwd"} {
		if _, ok := values[key]; ok {
			values.Set(key, set.Password)
		}
	}
}

func cloneAgentSessionConfig(in *AgentSessionConfig) *AgentSessionConfig {
	if in == nil {
		return nil
	}
	out := &AgentSessionConfig{Sessions: make([]AgentSessionEntry, 0, len(in.Sessions))}
	for _, s := range in.Sessions {
		entry := AgentSessionEntry{
			Name:    s.Name,
			Role:    s.Role,
			Headers: cloneStringMap(s.Headers),
		}
		if s.Login != nil {
			login := *s.Login
			login.Extract = append([]AgentExtractRule(nil), s.Login.Extract...)
			if s.Login.Expect != nil {
				expect := *s.Login.Expect
				expect.Status = append([]int(nil), s.Login.Expect.Status...)
				login.Expect = &expect
			}
			entry.Login = &login
		}
		out.Sessions = append(out.Sessions, entry)
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
