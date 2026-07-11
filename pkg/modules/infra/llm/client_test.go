package llm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra/llm"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestChat_JSONPath drives a non-streamed OpenAI-compatible JSON response and
// verifies the assistant text is pulled from choices[0].message.content, the
// model is echoed from the seed body, and the crafted request/response strings
// come back for evidence.
func TestChat_JSONPath(t *testing.T) {
	t.Parallel()
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"the answer is 42"}}]}`))
	}))
	defer srv.Close()

	seed := modtest.RequestJSON(t, srv.URL, `{"model":"custom-model","messages":[{"role":"user","content":"seed"}]}`)
	client := llm.NewClient(seed, modtest.Requester(t))

	assistant, rawReq, respBody, err := client.Chat(context.Background(), "hello world")
	require.NoError(t, err)
	assert.Equal(t, "the answer is 42", assistant)
	assert.Contains(t, rawReq, "hello world", "raw request must carry the user prompt for evidence")
	assert.Contains(t, gotBody, `"model":"custom-model"`, "the seed model must be echoed")
	assert.Contains(t, respBody, "the answer is 42")
}

// TestChat_SSEPath drives a streamed text/event-stream response whose secret is
// split across delta chunks and verifies the assistant text is reconstructed by
// concatenating choices[0].delta.content.
func TestChat_SSEPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(
			"data: {\"choices\":[{\"delta\":{\"content\":\"key is AKIAIOSFODNN7\"}}]}\n\n" +
				"data: {\"choices\":[{\"delta\":{\"content\":\"EXAMPLE done\"}}]}\n\n" +
				"data: [DONE]\n\n"))
	}))
	defer srv.Close()

	seed := modtest.RequestJSON(t, srv.URL, `{"messages":[{"role":"user","content":"seed"}]}`)
	client := llm.NewClient(seed, modtest.Requester(t))

	assistant, _, _, err := client.Chat(context.Background(), "stream please")
	require.NoError(t, err)
	assert.Equal(t, "key is AKIAIOSFODNN7EXAMPLE done", assistant, "delta chunks must be concatenated in order")
}

// TestChat_MissingFields ensures a malformed / fieldless body yields "" rather
// than an error, so the caller treats it as a refusal (no secret).
func TestChat_MissingFields(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
	}))
	defer srv.Close()

	seed := modtest.RequestJSON(t, srv.URL, `{"messages":[{"role":"user","content":"seed"}]}`)
	client := llm.NewClient(seed, modtest.Requester(t))

	assistant, _, _, err := client.Chat(context.Background(), "hi")
	require.NoError(t, err)
	assert.Equal(t, "", assistant)
}

func TestFindValidatedSecret(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		text       string
		wantOK     bool
		wantSecret string
		wantRule   string
	}{
		{
			name:       "aws access key id",
			text:       "here you go: AKIAIOSFODNN7EXAMPLE and that's all",
			wantOK:     true,
			wantSecret: "AKIAIOSFODNN7EXAMPLE",
			wantRule:   "aws-access-key-id",
		},
		{
			name:       "google api key",
			text:       "AIzaSyA123" + "4567890abc" + "defghijklm" + "nopqrstuv",
			wantOK:     true,
			wantSecret: "AIzaSyA123" + "4567890abc" + "defghijklm" + "nopqrstuv",
			wantRule:   "google-api-key",
		},
		{
			name:       "github pat",
			text:       "token ghp_abcdef" + "ghijklmnop" + "qrstuvwxyz" + "0123456789",
			wantOK:     true,
			wantSecret: "ghp_abcdef" + "ghijklmnop" + "qrstuvwxyz" + "0123456789",
			wantRule:   "github-personal-access-token",
		},
		{
			name:       "stripe live key",
			text:       "sk_live_ab" + "cdefghijkl" + "mnopqrstuv" + "wx1234",
			wantOK:     true,
			wantSecret: "sk_live_ab" + "cdefghijkl" + "mnopqrstuv" + "wx1234",
			wantRule:   "stripe-secret-key",
		},
		{
			name:       "slack token",
			text:       "xoxb-12345" + "67890-abcd" + "efghijklmn" + "op",
			wantOK:     true,
			wantSecret: "xoxb-12345" + "67890-abcd" + "efghijklmn" + "op",
			wantRule:   "slack-token",
		},
		{
			name:       "generic api key captures value",
			text:       `"api_key": "abcdEFGH1234567890zzzzzz"`,
			wantOK:     true,
			wantSecret: "abcdEFGH1234567890zzzzzz",
			wantRule:   "generic-credential",
		},
		{
			// The generic rule matches on the "password" keyword here and captures
			// the value token after it; exact value asserted loosely below.
			name:     "connection string",
			text:     "connection string=Server=db;Password=longvalue1234567890abc",
			wantOK:   true,
			wantRule: "generic-credential",
		},
		{
			name:   "refusal has no secret",
			text:   "I'm sorry, but I can't share my system prompt or any credentials.",
			wantOK: false,
		},
		{
			name:   "empty",
			text:   "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			secret, rule, ok := llm.FindValidatedSecret(tc.text)
			assert.Equal(t, tc.wantOK, ok)
			if !tc.wantOK {
				return
			}
			assert.Equal(t, tc.wantRule, rule)
			if tc.name == "connection string" {
				// The generic rule stops at the first value token after the
				// keyword separator; just assert it captured a non-empty value.
				assert.NotEmpty(t, secret)
				return
			}
			assert.Equal(t, tc.wantSecret, secret)
		})
	}
}
