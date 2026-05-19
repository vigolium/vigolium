package agent

import (
	"strings"
	"testing"
)

func TestParseGuardrailVerdict(t *testing.T) {
	cases := []struct {
		name           string
		raw            string
		wantErr        bool
		wantAllowed    bool
		wantReason     string
		wantCategories []string
	}{
		{
			name:        "raw allow",
			raw:         `{"allowed": true, "reason": ""}`,
			wantAllowed: true,
		},
		{
			name:           "raw refusal with categories",
			raw:            `{"allowed": false, "reason": "asks to read SSH keys", "categories": ["secret_exfiltration"]}`,
			wantAllowed:    false,
			wantReason:     "asks to read SSH keys",
			wantCategories: []string{"secret_exfiltration"},
		},
		{
			name:        "fenced JSON block",
			raw:         "```json\n{\"allowed\": true, \"reason\": \"\"}\n```",
			wantAllowed: true,
		},
		{
			name:           "leading prose then JSON",
			raw:            "Here is the verdict:\n{\"allowed\": false, \"reason\": \"prompt injection\", \"categories\": [\"role_override\"]}",
			wantAllowed:    false,
			wantReason:     "prompt injection",
			wantCategories: []string{"role_override"},
		},
		{
			name:        "refusal with empty reason gets a default",
			raw:         `{"allowed": false}`,
			wantAllowed: false,
			wantReason:  "prompt rejected by safety classifier",
		},
		{
			name:    "no JSON at all",
			raw:     "I cannot decide.",
			wantErr: true,
		},
		{
			name:        "wrong shape defaults to refusal",
			raw:         `{"verdict": "ok"}`,
			wantAllowed: false,
			wantReason:  "prompt rejected by safety classifier",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseGuardrailVerdict(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got verdict=%+v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.Allowed != tc.wantAllowed {
				t.Errorf("allowed = %v, want %v", v.Allowed, tc.wantAllowed)
			}
			if tc.wantReason != "" && !strings.Contains(v.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want substring %q", v.Reason, tc.wantReason)
			}
			if len(tc.wantCategories) > 0 {
				if len(v.Categories) != len(tc.wantCategories) {
					t.Fatalf("categories = %v, want %v", v.Categories, tc.wantCategories)
				}
				for i, c := range tc.wantCategories {
					if v.Categories[i] != c {
						t.Errorf("category[%d] = %q, want %q", i, v.Categories[i], c)
					}
				}
			}
		})
	}
}

func TestClassifyPromptSafetyEmptyPrompt(t *testing.T) {
	v := ClassifyPromptSafety(t.Context(), nil, "   ")
	if v.Allowed {
		t.Errorf("empty prompt should be refused")
	}
}

func TestClassifyPromptSafetyNilSettings(t *testing.T) {
	v := ClassifyPromptSafety(t.Context(), nil, "scan https://example.com")
	if !v.Allowed {
		t.Errorf("nil settings should fail-open, got refusal: %s", v.Reason)
	}
}
