package jsext

import (
	"context"
	"fmt"
	"testing"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/agent/llm"
)

// mockLLMClient is a simple Client for testing.
type mockLLMClient struct {
	fn func(req llm.CompletionRequest) (*llm.CompletionResponse, error)
}

func (m *mockLLMClient) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return m.fn(req)
}

func newMockClient(content string) *mockLLMClient {
	return &mockLLMClient{fn: func(_ llm.CompletionRequest) (*llm.CompletionResponse, error) {
		return &llm.CompletionResponse{Content: content, Model: "test-model"}, nil
	}}
}

func setupAgentTestVM(t *testing.T, client llm.Client) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	opts := APIOptions{
		ScriptID:  "test",
		LLMClient: client,
	}
	SetupAPI(vm, opts)
	return vm
}

func TestAgentAsk(t *testing.T) {
	vm := setupAgentTestVM(t, newMockClient("hello from LLM"))
	val, err := vm.RunString(`vigolium.agent.ask("what is xss?")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.String() != "hello from LLM" {
		t.Errorf("unexpected result: %q", val.String())
	}
}

func TestAgentAskWithSystemPrompt(t *testing.T) {
	var captured llm.CompletionRequest
	client := &mockLLMClient{fn: func(req llm.CompletionRequest) (*llm.CompletionResponse, error) {
		captured = req
		return &llm.CompletionResponse{Content: "ok"}, nil
	}}
	vm := setupAgentTestVM(t, client)
	_, err := vm.RunString(`vigolium.agent.ask("question", {system: "be helpful", model: "custom-model"})`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.Messages[0].Role != "system" || captured.Messages[0].Content != "be helpful" {
		t.Errorf("system message not propagated: %+v", captured.Messages)
	}
	if captured.Model != "custom-model" {
		t.Errorf("model not propagated: %q", captured.Model)
	}
}

func TestAgentChat(t *testing.T) {
	vm := setupAgentTestVM(t, newMockClient("chat response"))
	val, err := vm.RunString(`
		vigolium.agent.chat([
			{role: "system", content: "be helpful"},
			{role: "user", content: "hello"}
		])
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.String() != "chat response" {
		t.Errorf("unexpected result: %q", val.String())
	}
}

func TestAgentComplete(t *testing.T) {
	var captured llm.CompletionRequest
	client := &mockLLMClient{fn: func(req llm.CompletionRequest) (*llm.CompletionResponse, error) {
		captured = req
		return &llm.CompletionResponse{Content: "done", Model: "m", TokensIn: 5, TokensOut: 3}, nil
	}}
	vm := setupAgentTestVM(t, client)
	val, err := vm.RunString(`
		vigolium.agent.complete({
			messages: [{role: "user", content: "hi"}],
			model: "mymodel",
			max_tokens: 512,
			temperature: 0.5,
			json_schema: '{"type":"object"}'
		})
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	obj := val.ToObject(vm)
	if obj.Get("content").String() != "done" {
		t.Errorf("unexpected content: %q", obj.Get("content").String())
	}
	if obj.Get("tokens_in").ToInteger() != 5 {
		t.Errorf("unexpected tokens_in: %v", obj.Get("tokens_in"))
	}
	if captured.Model != "mymodel" {
		t.Errorf("model not propagated: %q", captured.Model)
	}
	if captured.JSONSchema != `{"type":"object"}` {
		t.Errorf("json_schema not propagated: %q", captured.JSONSchema)
	}
}

func TestAgentGeneratePayloads(t *testing.T) {
	vm := setupAgentTestVM(t, newMockClient(`{"payloads":["<script>alert(1)</script>","<img src=x onerror=alert(1)>"]}`))
	val, err := vm.RunString(`vigolium.agent.generatePayloads({type: "xss", parameter: "q", count: 2})`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr := val.Export().([]string)
	if len(arr) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(arr))
	}
}

func TestAgentAnalyzeResponse(t *testing.T) {
	vm := setupAgentTestVM(t, newMockClient(`{"vulnerable":true,"confidence":"high","evidence":"XSS reflected","details":"payload echoed"}`))
	val, err := vm.RunString(`
		vigolium.agent.analyzeResponse({
			request: "GET /?q=<script>alert(1)</script>",
			response: "<html><script>alert(1)</script></html>",
			vulnerability_type: "xss",
			payload: "<script>alert(1)</script>"
		})
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	obj := val.ToObject(vm)
	if !obj.Get("vulnerable").ToBoolean() {
		t.Errorf("expected vulnerable=true")
	}
	if obj.Get("confidence").String() != "high" {
		t.Errorf("unexpected confidence: %q", obj.Get("confidence").String())
	}
}

func TestAgentConfirmFinding(t *testing.T) {
	vm := setupAgentTestVM(t, newMockClient(`{"confirmed":true,"confidence":"high","reasoning":"clear XSS","false_positive_indicators":[]}`))
	val, err := vm.RunString(`
		vigolium.agent.confirmFinding({
			name: "Reflected XSS",
			request: "GET /?q=<script>",
			response: "<html><script>",
			matched: "<script>"
		})
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	obj := val.ToObject(vm)
	if !obj.Get("confirmed").ToBoolean() {
		t.Errorf("expected confirmed=true")
	}
}

func TestAgentAPINotSetupWhenClientNil(t *testing.T) {
	vm := sobek.New()
	opts := APIOptions{ScriptID: "test", LLMClient: nil}
	SetupAPI(vm, opts)

	val, err := vm.RunString(`typeof vigolium.agent`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.String() != "undefined" {
		t.Errorf("expected agent to be undefined when LLMClient is nil, got %q", val.String())
	}
}

func TestAgentComplete_Error(t *testing.T) {
	client := &mockLLMClient{fn: func(_ llm.CompletionRequest) (*llm.CompletionResponse, error) {
		return nil, fmt.Errorf("API rate limited")
	}}
	vm := setupAgentTestVM(t, client)
	_, err := vm.RunString(`vigolium.agent.ask("hello")`)
	if err == nil {
		t.Fatal("expected error from failing LLM client")
	}
}
