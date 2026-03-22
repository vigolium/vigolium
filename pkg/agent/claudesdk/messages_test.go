package claudesdk

import (
	"testing"
)

func TestParseMessage_AssistantText(t *testing.T) {
	data := `{"type":"assistant","session_id":"sess-1","message":{"model":"claude-sonnet-4-5","content":[{"type":"text","text":"Hello world"}]}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	am, ok := msg.(*AssistantMessage)
	if !ok {
		t.Fatalf("expected *AssistantMessage, got %T", msg)
	}
	if am.GetSessionID() != "sess-1" {
		t.Errorf("session ID: got %q, want sess-1", am.GetSessionID())
	}
	if am.Model != "claude-sonnet-4-5" {
		t.Errorf("model: got %q, want claude-sonnet-4-5", am.Model)
	}
	if len(am.Content) != 1 {
		t.Fatalf("content blocks: got %d, want 1", len(am.Content))
	}
	if am.Content[0].Type != "text" {
		t.Errorf("block type: got %q, want text", am.Content[0].Type)
	}
	if am.Content[0].Text != "Hello world" {
		t.Errorf("block text: got %q, want Hello world", am.Content[0].Text)
	}
}

func TestParseMessage_AssistantMultipleBlocks(t *testing.T) {
	data := `{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[
		{"type":"thinking","thinking":"Let me analyze..."},
		{"type":"text","text":"Here is the answer"},
		{"type":"tool_use","id":"tu_1","name":"Read","input":{"path":"/tmp/x"}}
	]}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	am := msg.(*AssistantMessage)
	if len(am.Content) != 3 {
		t.Fatalf("content blocks: got %d, want 3", len(am.Content))
	}

	// Thinking block should have text from "thinking" field
	if am.Content[0].Type != "thinking" || am.Content[0].Text != "Let me analyze..." {
		t.Errorf("thinking block: type=%q text=%q", am.Content[0].Type, am.Content[0].Text)
	}

	// Text block
	if am.Content[1].Type != "text" || am.Content[1].Text != "Here is the answer" {
		t.Errorf("text block: type=%q text=%q", am.Content[1].Type, am.Content[1].Text)
	}

	// Tool use block — text is empty (input is raw JSON, not extracted)
	if am.Content[2].Type != "tool_use" {
		t.Errorf("tool_use block: type=%q", am.Content[2].Type)
	}
}

func TestParseMessage_Result(t *testing.T) {
	data := `{
		"type":"result",
		"session_id":"sess-2",
		"subtype":"success",
		"is_error":false,
		"num_turns":3,
		"total_cost_usd":0.0142,
		"duration_ms":5200,
		"usage":{"input_tokens":1500,"output_tokens":800}
	}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	rm, ok := msg.(*ResultMessage)
	if !ok {
		t.Fatalf("expected *ResultMessage, got %T", msg)
	}
	if rm.GetSessionID() != "sess-2" {
		t.Errorf("session ID: got %q", rm.GetSessionID())
	}
	if rm.Subtype != "success" {
		t.Errorf("subtype: got %q", rm.Subtype)
	}
	if rm.IsError {
		t.Error("is_error should be false")
	}
	if rm.NumTurns != 3 {
		t.Errorf("num_turns: got %d, want 3", rm.NumTurns)
	}
	if rm.TotalCostUSD != 0.0142 {
		t.Errorf("total_cost_usd: got %f, want 0.0142", rm.TotalCostUSD)
	}
	if rm.DurationMS != 5200 {
		t.Errorf("duration_ms: got %d, want 5200", rm.DurationMS)
	}
	if rm.Usage.InputTokens != 1500 {
		t.Errorf("input_tokens: got %d, want 1500", rm.Usage.InputTokens)
	}
	if rm.Usage.OutputTokens != 800 {
		t.Errorf("output_tokens: got %d, want 800", rm.Usage.OutputTokens)
	}
}

func TestParseMessage_ResultError(t *testing.T) {
	data := `{"type":"result","session_id":"s","subtype":"error_max_turns","is_error":true,"num_turns":50,"total_cost_usd":1.23,"duration_ms":60000,"usage":{"input_tokens":0,"output_tokens":0}}`

	msg, _ := parseMessage([]byte(data))
	rm := msg.(*ResultMessage)
	if !rm.IsError {
		t.Error("is_error should be true")
	}
	if rm.Subtype != "error_max_turns" {
		t.Errorf("subtype: got %q", rm.Subtype)
	}
}

func TestParseMessage_StreamEventDelta(t *testing.T) {
	data := `{"type":"stream_event","session_id":"s","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	se, ok := msg.(*StreamEvent)
	if !ok {
		t.Fatalf("expected *StreamEvent, got %T", msg)
	}
	if se.EventType != "content_block_delta" {
		t.Errorf("event type: got %q", se.EventType)
	}
	if se.Delta == nil {
		t.Fatal("delta should not be nil for content_block_delta")
	}
	if se.Delta.Text != "Hello" {
		t.Errorf("delta text: got %q, want Hello", se.Delta.Text)
	}
}

func TestParseMessage_StreamEventNonDelta(t *testing.T) {
	data := `{"type":"stream_event","session_id":"s","event":{"type":"message_start"}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	se := msg.(*StreamEvent)
	if se.EventType != "message_start" {
		t.Errorf("event type: got %q", se.EventType)
	}
	if se.Delta != nil {
		t.Error("delta should be nil for non-delta events")
	}
}

func TestParseMessage_StreamEventMessageStop(t *testing.T) {
	data := `{"type":"stream_event","session_id":"s","event":{"type":"message_stop"}}`

	msg, _ := parseMessage([]byte(data))
	se := msg.(*StreamEvent)
	if se.EventType != "message_stop" {
		t.Errorf("event type: got %q", se.EventType)
	}
}

func TestParseMessage_SystemMessage(t *testing.T) {
	data := `{"type":"system","session_id":"s","subtype":"init"}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	sm, ok := msg.(*SystemMessage)
	if !ok {
		t.Fatalf("expected *SystemMessage, got %T", msg)
	}
	if sm.Subtype != "init" {
		t.Errorf("subtype: got %q, want init", sm.Subtype)
	}
}

func TestParseMessage_UnknownType(t *testing.T) {
	data := `{"type":"control_request","session_id":"s","request_id":"req_1"}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != nil {
		t.Errorf("expected nil for unknown type, got %T", msg)
	}
}

func TestParseMessage_UserType(t *testing.T) {
	data := `{"type":"user","session_id":"s","message":{"role":"user","content":[{"type":"text","text":"hello"}]}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != nil {
		t.Errorf("expected nil for user type (not consumed), got %T", msg)
	}
}

func TestParseMessage_InvalidJSON(t *testing.T) {
	data := `{not valid json}`

	_, err := parseMessage([]byte(data))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseMessage_EmptyContent(t *testing.T) {
	data := `{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[]}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	am := msg.(*AssistantMessage)
	if len(am.Content) != 0 {
		t.Errorf("expected empty content, got %d blocks", len(am.Content))
	}
}

func TestParseMessage_StreamEventDeltaNullText(t *testing.T) {
	// Delta with no text field (e.g., input_json_delta)
	data := `{"type":"stream_event","session_id":"s","event":{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta"}}}`

	msg, err := parseMessage([]byte(data))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}

	se := msg.(*StreamEvent)
	if se.Delta != nil {
		t.Error("delta should be nil when text is not present")
	}
}

func TestMessageInterface(t *testing.T) {
	// Verify all message types implement the Message interface
	messages := []Message{
		&AssistantMessage{SessionIDField: "s1"},
		&ResultMessage{SessionIDField: "s2"},
		&StreamEvent{SessionIDField: "s3"},
		&SystemMessage{SessionIDField: "s4"},
	}

	expectedTypes := []string{"assistant", "result", "stream_event", "system"}

	for i, msg := range messages {
		if msg.msgType() != expectedTypes[i] {
			t.Errorf("message[%d].msgType() = %q, want %q", i, msg.msgType(), expectedTypes[i])
		}
		if msg.GetSessionID() == "" {
			t.Errorf("message[%d].GetSessionID() is empty", i)
		}
	}
}
