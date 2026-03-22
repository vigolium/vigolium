package claudesdk

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockProcess simulates a claude CLI process for testing.
// It reads user messages from stdin and writes pre-configured responses to stdout.
type mockProcess struct {
	mu        sync.Mutex
	responses []string // JSON-lines to write in sequence
	respIdx   int
	stdinBuf  strings.Builder // captures what was written to stdin
	closed    bool
}

// setupMockClient creates a Client wired to a mock process that returns
// the given JSON-line responses. Returns the client and mock for inspection.
func setupMockClient(t *testing.T, responses []string) (*Client, *mockProcess) {
	t.Helper()

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	mock := &mockProcess{responses: responses}

	// Feed responses through stdout pipe
	go func() {
		defer stdoutW.Close()
		for _, resp := range responses {
			_, _ = stdoutW.Write([]byte(resp + "\n"))
		}
	}()

	// Drain stdin to capture what was written
	go func() {
		scanner := bufio.NewScanner(stdinR)
		for scanner.Scan() {
			mock.mu.Lock()
			mock.stdinBuf.WriteString(scanner.Text())
			mock.stdinBuf.WriteByte('\n')
			mock.mu.Unlock()
		}
	}()

	client := NewClient(&Options{})
	client.started = true
	client.proc = &process{
		stdin:  stdinW,
		reader: bufio.NewReaderSize(stdoutR, 1024*1024),
		done:   make(chan struct{}),
	}

	return client, mock
}

func (m *mockProcess) stdinContent() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stdinBuf.String()
}

func TestClient_ReceiveResponse_AssistantAndResult(t *testing.T) {
	responses := []string{
		`{"type":"system","session_id":"s1","subtype":"init"}`,
		`{"type":"assistant","session_id":"s1","message":{"model":"sonnet","content":[{"type":"text","text":"Hello from Claude"}]}}`,
		`{"type":"result","session_id":"s1","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.005,"duration_ms":1200,"usage":{"input_tokens":100,"output_tokens":50}}`,
	}

	client, _ := setupMockClient(t, responses)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var gotAssistant bool
	var gotResult bool
	var text string

	for msg := range client.ReceiveResponse(ctx) {
		switch m := msg.(type) {
		case *AssistantMessage:
			gotAssistant = true
			for _, b := range m.Content {
				if b.Type == "text" {
					text = b.Text
				}
			}
		case *ResultMessage:
			gotResult = true
			if m.IsError {
				t.Error("unexpected error result")
			}
			if m.NumTurns != 1 {
				t.Errorf("num_turns: got %d, want 1", m.NumTurns)
			}
		}
	}

	if !gotAssistant {
		t.Error("did not receive assistant message")
	}
	if !gotResult {
		t.Error("did not receive result message")
	}
	if text != "Hello from Claude" {
		t.Errorf("assistant text: got %q, want 'Hello from Claude'", text)
	}
}

func TestClient_ReceiveMessages_Streaming(t *testing.T) {
	responses := []string{
		`{"type":"stream_event","session_id":"s","event":{"type":"message_start"}}`,
		`{"type":"stream_event","session_id":"s","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}}`,
		`{"type":"stream_event","session_id":"s","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}}`,
		`{"type":"stream_event","session_id":"s","event":{"type":"message_stop"}}`,
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"text","text":"Hello world"}]}}`,
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.01,"duration_ms":2000,"usage":{"input_tokens":50,"output_tokens":20}}`,
	}

	client, _ := setupMockClient(t, responses)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msgCh, errCh := client.ReceiveMessages(ctx)

	var deltaTexts []string
	var gotResult bool

	for {
		select {
		case msg := <-msgCh:
			if msg == nil {
				goto done
			}
			switch m := msg.(type) {
			case *StreamEvent:
				if m.Delta != nil {
					deltaTexts = append(deltaTexts, m.Delta.Text)
				}
			case *ResultMessage:
				gotResult = true
			}
		case err := <-errCh:
			if err != nil {
				t.Fatalf("stream error: %v", err)
			}
			goto done
		case <-ctx.Done():
			t.Fatal("timeout waiting for messages")
		}
	}

done:
	if !gotResult {
		t.Error("did not receive result message")
	}
	combined := strings.Join(deltaTexts, "")
	if combined != "Hello world" {
		t.Errorf("combined deltas: got %q, want 'Hello world'", combined)
	}
}

func TestClient_ReceiveResponse_SkipsUnknownTypes(t *testing.T) {
	responses := []string{
		`{"type":"control_request","session_id":"s","request_id":"req_1"}`,
		`{"type":"user","session_id":"s","message":{"role":"user","content":[]}}`,
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"text","text":"answer"}]}}`,
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.001,"duration_ms":100,"usage":{"input_tokens":10,"output_tokens":5}}`,
	}

	client, _ := setupMockClient(t, responses)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int
	for msg := range client.ReceiveResponse(ctx) {
		count++
		_ = msg
	}
	// Should only see assistant + result (control_request and user are skipped)
	if count != 2 {
		t.Errorf("expected 2 messages (assistant + result), got %d", count)
	}
}

func TestClient_Query_SendsUserMessage(t *testing.T) {
	responses := []string{
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.001,"duration_ms":100,"usage":{"input_tokens":10,"output_tokens":5}}`,
	}

	client, mock := setupMockClient(t, responses)
	defer client.Close()

	err := client.sendUserMessage("What is 2+2?")
	if err != nil {
		t.Fatalf("sendUserMessage failed: %v", err)
	}

	// Allow time for stdin drain goroutine
	time.Sleep(50 * time.Millisecond)

	stdin := mock.stdinContent()
	if !strings.Contains(stdin, `"type":"user"`) {
		t.Error("stdin should contain user message type")
	}
	if !strings.Contains(stdin, `"text":"What is 2+2?"`) {
		t.Error("stdin should contain prompt text")
	}

	// Verify it's valid JSON
	lines := strings.Split(strings.TrimSpace(stdin), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Errorf("stdin line is not valid JSON: %v\nline: %s", err, line)
		}
	}
}

func TestClient_Close_Idempotent(t *testing.T) {
	client := NewClient(&Options{})
	// Close without ever starting — should not panic
	if err := client.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func TestClient_Query_AfterClose(t *testing.T) {
	client := NewClient(&Options{})
	_ = client.Close()

	err := client.Query(context.Background(), "hello")
	if err == nil {
		t.Error("expected error when querying after close")
	}
}

func TestClient_ReceiveResponse_StopsAtResult(t *testing.T) {
	// Verify that ReceiveResponse closes the channel after ResultMessage,
	// even if there are more messages after it
	responses := []string{
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"text","text":"a"}]}}`,
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.001,"duration_ms":100,"usage":{"input_tokens":10,"output_tokens":5}}`,
		// These should never be received
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"text","text":"should not see this"}]}}`,
	}

	client, _ := setupMockClient(t, responses)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var texts []string
	for msg := range client.ReceiveResponse(ctx) {
		if am, ok := msg.(*AssistantMessage); ok {
			for _, b := range am.Content {
				texts = append(texts, b.Text)
			}
		}
	}

	if len(texts) != 1 || texts[0] != "a" {
		t.Errorf("expected only first assistant message, got texts: %v", texts)
	}
}
