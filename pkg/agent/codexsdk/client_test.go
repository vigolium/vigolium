package codexsdk

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCodexServer simulates a codex app-server for testing.
// It reads JSON-RPC requests from stdin, responds with pre-configured responses,
// and sends notifications at the right time.
type mockCodexServer struct {
	mu       sync.Mutex
	stdinBuf strings.Builder

	responses []mockResponse
	respIdx   int
}

type mockResponse struct {
	method        string          // documentary (unused for matching — responses consumed in order)
	result        json.RawMessage // response result (must be compact JSON — no embedded newlines)
	notifications []string        // notifications to send AFTER the response (one per line)
}

// setupMockCodexClient creates a Client wired to a mock codex app-server.
// Uses os.Pipe() for OS-level buffering to prevent deadlocks when the mock
// sends notifications while the client is writing to stdin.
func setupMockCodexClient(t *testing.T, responses []mockResponse) (*Client, *mockCodexServer) {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe (stdin) failed: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe (stdout) failed: %v", err)
	}
	t.Cleanup(func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
	})

	mock := &mockCodexServer{responses: responses}

	// Read requests from stdin, write responses + notifications to stdout
	go func() {
		scanner := bufio.NewScanner(stdinR)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			mock.mu.Lock()
			mock.stdinBuf.WriteString(line)
			mock.stdinBuf.WriteByte('\n')
			mock.mu.Unlock()

			var req struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			}
			if json.Unmarshal([]byte(line), &req) != nil {
				continue
			}

			// Skip notifications (no id)
			if req.ID == "" {
				continue
			}

			mock.mu.Lock()
			if mock.respIdx >= len(mock.responses) {
				mock.mu.Unlock()
				continue
			}
			resp := mock.responses[mock.respIdx]
			mock.respIdx++
			mock.mu.Unlock()

			// Compact the result to ensure no embedded newlines
			compacted := compactJSON(resp.result)
			respLine := fmt.Sprintf(`{"id":%q,"result":%s}`, req.ID, compacted)
			_, _ = stdoutW.Write([]byte(respLine + "\n"))

			for _, notif := range resp.notifications {
				_, _ = stdoutW.Write([]byte(notif + "\n"))
			}
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

func compactJSON(data json.RawMessage) string {
	var buf []byte
	buf, err := json.Marshal(json.RawMessage(data))
	if err != nil {
		return string(data)
	}
	return string(buf)
}

func (m *mockCodexServer) stdinContent() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stdinBuf.String()
}

// ============================================================
// Initialize
// ============================================================

func TestClient_Initialize(t *testing.T) {
	responses := []mockResponse{
		{
			method: "initialize",
			result: json.RawMessage(`{"serverInfo":{"name":"codex","version":"0.1.0"},"userAgent":"codex/0.1.0"}`),
		},
	}

	client, _ := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if resp.ServerInfo == nil {
		t.Fatal("expected serverInfo to be non-nil")
	}
	if resp.ServerInfo.Name == nil || *resp.ServerInfo.Name != "codex" {
		t.Errorf("serverInfo.name: got %v, want 'codex'", resp.ServerInfo.Name)
	}
}

func TestClient_Initialize_SendsClientInfo(t *testing.T) {
	responses := []mockResponse{
		{
			method: "initialize",
			result: json.RawMessage(`{"serverInfo":{"name":"codex"}}`),
		},
	}

	client, mock := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	stdin := mock.stdinContent()
	if !strings.Contains(stdin, `"method":"initialize"`) {
		t.Error("stdin should contain initialize request")
	}
	if !strings.Contains(stdin, `"name":"vigolium"`) {
		t.Error("stdin should contain client name 'vigolium'")
	}
	if !strings.Contains(stdin, `"method":"initialized"`) {
		t.Error("stdin should contain initialized notification")
	}
}

// ============================================================
// ThreadStart
// ============================================================

func TestClient_ThreadStart(t *testing.T) {
	responses := []mockResponse{
		{
			method: "thread/start",
			result: json.RawMessage(`{"thread":{"id":"thr_abc123","cliVersion":"0.1.0","createdAt":1700000000,"cwd":"/tmp","ephemeral":false,"modelProvider":"openai","preview":"","source":{"custom":"test"},"status":{"type":"active"},"turns":[],"updatedAt":1700000000},"model":"gpt-4.1","modelProvider":"openai","cwd":"/tmp","approvalPolicy":{},"approvalsReviewer":"user","sandbox":{"type":"danger-full-access"}}`),
		},
	}

	client, _ := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	model := "gpt-4.1"
	resp, err := client.ThreadStart(ctx, &ThreadStartParams{
		Model: &model,
	})
	if err != nil {
		t.Fatalf("ThreadStart failed: %v", err)
	}

	if resp.Thread.Id != "thr_abc123" {
		t.Errorf("thread.id: got %q, want 'thr_abc123'", resp.Thread.Id)
	}
	if resp.Model != "gpt-4.1" {
		t.Errorf("model: got %q, want 'gpt-4.1'", resp.Model)
	}
}

// ============================================================
// TurnStart + notification handling
// ============================================================

func TestClient_TurnStart(t *testing.T) {
	responses := []mockResponse{
		{method: "turn/start", result: json.RawMessage(`{"turn":{"id":"turn_xyz","status":"inProgress","items":[]}}`)},
	}

	client, mock := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.TurnStart(ctx, &TurnStartParams{
		ThreadId: "thr_abc123",
		Input: []UserInput{
			{Type: "text", Text: strPtr("Hello codex")},
		},
	})
	if err != nil {
		t.Fatalf("TurnStart failed: %v", err)
	}

	if resp.Turn.Id != "turn_xyz" {
		t.Errorf("turn.id: got %q, want 'turn_xyz'", resp.Turn.Id)
	}

	time.Sleep(50 * time.Millisecond)
	stdin := mock.stdinContent()
	if !strings.Contains(stdin, `"method":"turn/start"`) {
		t.Error("stdin should contain turn/start request")
	}
	if !strings.Contains(stdin, `"thr_abc123"`) {
		t.Error("stdin should contain threadId")
	}
	if !strings.Contains(stdin, `"Hello codex"`) {
		t.Error("stdin should contain input text")
	}
}

// ============================================================
// NextNotification
// ============================================================

func TestClient_NextNotification(t *testing.T) {
	responses := []mockResponse{
		{
			method: "initialize",
			result: json.RawMessage(`{"serverInfo":{"name":"codex"}}`),
			notifications: []string{
				`{"method":"turn/started","params":{"threadId":"thr_1","turn":{"id":"turn_1","status":"inProgress","items":[]}}}`,
			},
		},
	}

	client, _ := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	notif, err := client.NextNotification(ctx)
	if err != nil {
		t.Fatalf("NextNotification failed: %v", err)
	}

	if notif.Method != "turn/started" {
		t.Errorf("notification method: got %q, want 'turn/started'", notif.Method)
	}

	var started TurnStartedNotification
	if err := json.Unmarshal(notif.Payload, &started); err != nil {
		t.Fatalf("failed to parse notification payload: %v", err)
	}
	if started.Turn.Id != "turn_1" {
		t.Errorf("turn.id: got %q, want 'turn_1'", started.Turn.Id)
	}
}

// ============================================================
// Approval handling
// ============================================================

func TestClient_ApprovalHandling(t *testing.T) {
	handler := defaultApprovalHandler
	resp := handler("item/commandExecution/requestApproval", nil)
	if resp["decision"] != "accept" {
		t.Errorf("default approval: got %v, want 'accept'", resp["decision"])
	}

	resp = handler("item/fileChange/requestApproval", nil)
	if resp["decision"] != "accept" {
		t.Errorf("default file change approval: got %v, want 'accept'", resp["decision"])
	}
}

func TestClient_CustomApprovalHandler(t *testing.T) {
	client := NewClient(&Options{})
	defer func() { _ = client.Close() }()

	denyCalled := false
	client.SetApprovalHandler(func(method string, _ json.RawMessage) map[string]any {
		denyCalled = true
		return map[string]any{"decision": "deny"}
	})

	resp := client.approvalHandler("test", nil)
	if !denyCalled {
		t.Error("custom handler was not called")
	}
	if resp["decision"] != "deny" {
		t.Errorf("custom handler response: got %v, want 'deny'", resp["decision"])
	}
}

// ============================================================
// CollectText
// ============================================================

func TestClient_CollectText(t *testing.T) {
	responses := []mockResponse{
		{
			method: "turn/start",
			result: json.RawMessage(`{"turn":{"id":"turn_1","status":"inProgress","items":[]}}`),
			notifications: []string{
				`{"method":"item/completed","params":{"threadId":"thr_1","turnId":"turn_1","item":{"id":"item_1","type":"message","text":"Hello from Codex!"}}}`,
				`{"method":"turn/completed","params":{"threadId":"thr_1","turn":{"id":"turn_1","status":"completed","items":[{"id":"item_1","type":"message","text":"Hello from Codex!"}]}}}`,
			},
		},
	}

	client, _ := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, completed, err := client.CollectText(ctx, "thr_1", "Say hello")
	if err != nil {
		t.Fatalf("CollectText failed: %v", err)
	}

	if output != "Hello from Codex!" {
		t.Errorf("output: got %q, want 'Hello from Codex!'", output)
	}
	if completed == nil {
		t.Fatal("expected completed notification")
	}
	if completed.Turn.Id != "turn_1" {
		t.Errorf("turn.id: got %q, want 'turn_1'", completed.Turn.Id)
	}
	if completed.Turn.Status != "completed" {
		t.Errorf("turn.status: got %q, want 'completed'", completed.Turn.Status)
	}
}

// ============================================================
// StreamText
// ============================================================

func TestClient_StreamText(t *testing.T) {
	responses := []mockResponse{
		{
			method: "turn/start",
			result: json.RawMessage(`{"turn":{"id":"turn_1","status":"inProgress","items":[]}}`),
			notifications: []string{
				`{"method":"item/agentMessage/delta","params":{"threadId":"thr_1","turnId":"turn_1","itemId":"i1","delta":"Hello "}}`,
				`{"method":"item/agentMessage/delta","params":{"threadId":"thr_1","turnId":"turn_1","itemId":"i1","delta":"world"}}`,
				`{"method":"turn/completed","params":{"threadId":"thr_1","turn":{"id":"turn_1","status":"completed","items":[{"id":"i1","type":"message","text":"Hello world"}]}}}`,
			},
		},
	}

	client, _ := setupMockCodexClient(t, responses)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var streamBuf strings.Builder
	completed, err := client.StreamText(ctx, "thr_1", "Say hello", &streamBuf)
	if err != nil {
		t.Fatalf("StreamText failed: %v", err)
	}

	streamed := streamBuf.String()
	if streamed != "Hello world" {
		t.Errorf("streamed output: got %q, want 'Hello world'", streamed)
	}
	if completed == nil {
		t.Fatal("expected completed notification")
	}
}

// ============================================================
// Error handling
// ============================================================

func TestClient_RPCError(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	t.Cleanup(func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
	})

	go func() {
		scanner := bufio.NewScanner(stdinR)
		for scanner.Scan() {
			line := scanner.Text()
			var req struct {
				ID string `json:"id"`
			}
			if json.Unmarshal([]byte(line), &req) != nil || req.ID == "" {
				continue
			}
			errResp := fmt.Sprintf(`{"id":%q,"error":{"code":-32601,"message":"Method not found"}}`, req.ID)
			_, _ = stdoutW.Write([]byte(errResp + "\n"))
		}
	}()

	client := NewClient(&Options{})
	client.started = true
	client.proc = &process{
		stdin:  stdinW,
		reader: bufio.NewReaderSize(stdoutR, 1024*1024),
		done:   make(chan struct{}),
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, tsErr := client.ThreadStart(ctx, &ThreadStartParams{})
	if tsErr == nil {
		t.Fatal("expected error from ThreadStart")
	}

	if !strings.Contains(tsErr.Error(), "Method not found") {
		t.Errorf("error should contain 'Method not found', got: %v", tsErr)
	}
}

// ============================================================
// Close
// ============================================================

func TestClient_Close_Idempotent(t *testing.T) {
	client := NewClient(&Options{})
	if err := client.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func TestClient_Alive_BeforeStart(t *testing.T) {
	client := NewClient(&Options{})
	if client.Alive() {
		t.Error("expected Alive() = false before start")
	}
}
