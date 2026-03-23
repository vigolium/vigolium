package codexsdk

import (
	"encoding/json"
	"testing"
)

func TestRawMessage_MessageKind(t *testing.T) {
	tests := []struct {
		name string
		msg  rawMessage
		want string
	}{
		{
			name: "server request (has method + id)",
			msg:  rawMessage{Method: strPtr("item/commandExecution/requestApproval"), ID: strPtr("req_1")},
			want: "server_request",
		},
		{
			name: "notification (has method, no id)",
			msg:  rawMessage{Method: strPtr("turn/completed")},
			want: "notification",
		},
		{
			name: "error response (has id + error)",
			msg:  rawMessage{ID: strPtr("r1"), Error: &jsonRPCError{Code: -32601, Message: "not found"}},
			want: "error_response",
		},
		{
			name: "response (has id, no error)",
			msg:  rawMessage{ID: strPtr("r2"), Result: json.RawMessage(`{}`)},
			want: "response",
		},
		{
			name: "unknown (no method, no id)",
			msg:  rawMessage{},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.messageKind()
			if got != tt.want {
				t.Errorf("messageKind() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNotificationRegistry_ContainsKeyMethods(t *testing.T) {
	required := []string{
		"thread/started",
		"turn/started",
		"turn/completed",
		"item/agentMessage/delta",
		"item/started",
		"item/completed",
		"item/commandExecution/outputDelta",
		"item/fileChange/outputDelta",
		"error",
		"thread/tokenUsage/updated",
	}

	for _, method := range required {
		if _, ok := NotificationRegistry[method]; !ok {
			t.Errorf("NotificationRegistry missing method %q", method)
		}
	}
}

func TestRPCError_Error(t *testing.T) {
	err := &RPCError{Code: -32601, Message: "Method not found"}
	got := err.Error()
	if got != "codex RPC error -32601: Method not found" {
		t.Errorf("Error() = %q", got)
	}
}

func TestRPCError_IsServerBusy(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{-32000, true},
		{-32001, true},
		{-32099, true},
		{-32100, false},
		{-31999, false},
		{-32601, false},
	}

	for _, tt := range tests {
		err := &RPCError{Code: tt.code, Message: "test"}
		if got := err.IsServerBusy(); got != tt.want {
			t.Errorf("IsServerBusy() for code %d = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestJsonRPCRequest_Marshal(t *testing.T) {
	req := jsonRPCRequest{
		ID:     "test-123",
		Method: "thread/start",
		Params: map[string]any{"model": "gpt-4.1"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if raw["id"] != "test-123" {
		t.Errorf("id: got %v, want 'test-123'", raw["id"])
	}
	if raw["method"] != "thread/start" {
		t.Errorf("method: got %v, want 'thread/start'", raw["method"])
	}
}

func TestJsonRPCNotification_Marshal(t *testing.T) {
	notif := jsonRPCNotification{
		Method: "initialized",
		Params: nil,
	}

	data, err := json.Marshal(notif)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Should NOT have an "id" field
	if _, hasID := raw["id"]; hasID {
		t.Error("notification should not have 'id' field")
	}
	if raw["method"] != "initialized" {
		t.Errorf("method: got %v, want 'initialized'", raw["method"])
	}
}
