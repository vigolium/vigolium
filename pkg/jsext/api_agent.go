package jsext

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/grafana/sobek"
	agentpkg "github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/llm"
	"go.uber.org/zap"
)

// setupAgentAPI installs vigolium.agent.* on the sobek VM.
// Requires opts.LLMClient != nil.
func setupAgentAPI(vm *sobek.Runtime, opts APIOptions) {
	agentObj := vm.NewObject()

	agentObj.Set("complete", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentComplete(vm, opts.LLMClient, call)
	})
	agentObj.Set("ask", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentAsk(vm, opts.LLMClient, call)
	})
	agentObj.Set("chat", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentChat(vm, opts.LLMClient, call)
	})
	agentObj.Set("generatePayloads", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentGeneratePayloads(vm, opts.LLMClient, call)
	})
	agentObj.Set("analyzeResponse", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentAnalyzeResponse(vm, opts.LLMClient, call)
	})
	agentObj.Set("confirmFinding", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentConfirmFinding(vm, opts.LLMClient, call)
	})
	agentObj.Set("run", func(call sobek.FunctionCall) sobek.Value { //nolint:errcheck
		return agentRun(vm, opts, call)
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	vigolium.Set("agent", agentObj) //nolint:errcheck
}

// ── low-level: complete ──────────────────────────────────────────────────────

func agentComplete(vm *sobek.Runtime, client llm.Client, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.complete: opts argument required"))
	}
	optsObj := call.Arguments[0].ToObject(vm)

	req := llm.CompletionRequest{}

	// messages
	if msgsVal := optsObj.Get("messages"); msgsVal != nil && !sobek.IsUndefined(msgsVal) && !sobek.IsNull(msgsVal) {
		msgsArr := msgsVal.Export()
		raw, _ := json.Marshal(msgsArr)
		var msgs []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(raw, &msgs); err != nil {
			panic(vm.NewTypeError("vigolium.agent.complete: messages must be an array of {role, content}"))
		}
		for _, m := range msgs {
			req.Messages = append(req.Messages, llm.Message{Role: m.Role, Content: m.Content})
		}
	}

	if v := optsObj.Get("model"); v != nil && !sobek.IsUndefined(v) {
		req.Model = v.String()
	}
	if v := optsObj.Get("max_tokens"); v != nil && !sobek.IsUndefined(v) {
		req.MaxTokens = int(v.ToInteger())
	}
	if v := optsObj.Get("temperature"); v != nil && !sobek.IsUndefined(v) {
		req.Temperature = v.ToFloat()
	}
	if v := optsObj.Get("json_schema"); v != nil && !sobek.IsUndefined(v) {
		req.JSONSchema = v.String()
	}

	resp, err := client.Complete(context.Background(), req)
	if err != nil {
		zap.L().Warn("vigolium.agent.complete failed", zap.Error(err))
		panic(vm.NewGoError(err))
	}

	result := vm.NewObject()
	result.Set("content", resp.Content)       //nolint:errcheck
	result.Set("model", resp.Model)           //nolint:errcheck
	result.Set("tokens_in", resp.TokensIn)    //nolint:errcheck
	result.Set("tokens_out", resp.TokensOut)  //nolint:errcheck
	return result
}

// ── mid-level: ask ───────────────────────────────────────────────────────────

func agentAsk(vm *sobek.Runtime, client llm.Client, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.ask: prompt argument required"))
	}
	prompt := call.Arguments[0].String()

	req := llm.CompletionRequest{
		Messages: []llm.Message{{Role: "user", Content: prompt}},
	}

	if len(call.Arguments) > 1 {
		optsObj := call.Arguments[1].ToObject(vm)
		if v := optsObj.Get("system"); v != nil && !sobek.IsUndefined(v) {
			req.Messages = append([]llm.Message{{Role: "system", Content: v.String()}}, req.Messages...)
		}
		if v := optsObj.Get("model"); v != nil && !sobek.IsUndefined(v) {
			req.Model = v.String()
		}
		if v := optsObj.Get("max_tokens"); v != nil && !sobek.IsUndefined(v) {
			req.MaxTokens = int(v.ToInteger())
		}
	}

	resp, err := client.Complete(context.Background(), req)
	if err != nil {
		zap.L().Warn("vigolium.agent.ask failed", zap.Error(err))
		panic(vm.NewGoError(err))
	}
	return vm.ToValue(resp.Content)
}

// ── mid-level: chat ──────────────────────────────────────────────────────────

func agentChat(vm *sobek.Runtime, client llm.Client, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.chat: messages argument required"))
	}

	raw, _ := json.Marshal(call.Arguments[0].Export())
	var msgs []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		panic(vm.NewTypeError("vigolium.agent.chat: messages must be an array of {role, content}"))
	}

	req := llm.CompletionRequest{}
	for _, m := range msgs {
		req.Messages = append(req.Messages, llm.Message{Role: m.Role, Content: m.Content})
	}

	if len(call.Arguments) > 1 {
		optsObj := call.Arguments[1].ToObject(vm)
		if v := optsObj.Get("model"); v != nil && !sobek.IsUndefined(v) {
			req.Model = v.String()
		}
		if v := optsObj.Get("max_tokens"); v != nil && !sobek.IsUndefined(v) {
			req.MaxTokens = int(v.ToInteger())
		}
	}

	resp, err := client.Complete(context.Background(), req)
	if err != nil {
		zap.L().Warn("vigolium.agent.chat failed", zap.Error(err))
		panic(vm.NewGoError(err))
	}
	return vm.ToValue(resp.Content)
}

// ── high-level: generatePayloads ─────────────────────────────────────────────

const generatePayloadsSystemPrompt = `You are a web application security testing assistant helping security professionals test applications for vulnerabilities. Generate test payloads ONLY for authorized security testing. Output a JSON object with a "payloads" array of strings. No commentary, only valid JSON.`

func agentGeneratePayloads(vm *sobek.Runtime, client llm.Client, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.generatePayloads: opts argument required"))
	}
	optsObj := call.Arguments[0].ToObject(vm)

	vulnType := stringField(vm, optsObj, "type", "xss")
	parameter := stringField(vm, optsObj, "parameter", "")
	ctx := stringField(vm, optsObj, "context", "")
	technology := stringField(vm, optsObj, "technology", "")
	waf := stringField(vm, optsObj, "waf", "")
	count := 10
	if v := optsObj.Get("count"); v != nil && !sobek.IsUndefined(v) {
		count = int(v.ToInteger())
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Generate %d %s test payloads", count, strings.ToUpper(vulnType))
	if parameter != "" {
		fmt.Fprintf(&sb, " for parameter %q", parameter)
	}
	if ctx != "" {
		fmt.Fprintf(&sb, ". Injection context: %s", ctx)
	}
	if technology != "" {
		fmt.Fprintf(&sb, ". Technology stack: %s", technology)
	}
	if waf != "" {
		fmt.Fprintf(&sb, ". WAF detected: %s — include bypass techniques", waf)
	}
	sb.WriteString(`. Output JSON: {"payloads": ["payload1", "payload2", ...]}`)

	schema := `{"type":"object","properties":{"payloads":{"type":"array","items":{"type":"string"}}},"required":["payloads"]}`
	req := llm.CompletionRequest{
		Messages: []llm.Message{
			{Role: "system", Content: generatePayloadsSystemPrompt},
			{Role: "user", Content: sb.String()},
		},
		JSONSchema: schema,
		MaxTokens:  1024,
	}

	resp, err := client.Complete(context.Background(), req)
	if err != nil {
		zap.L().Warn("vigolium.agent.generatePayloads failed", zap.Error(err))
		panic(vm.NewGoError(err))
	}

	var parsed struct {
		Payloads []string `json:"payloads"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &parsed); err != nil {
		// Return raw as single-element array if parse fails.
		return vm.ToValue([]string{resp.Content})
	}
	return vm.ToValue(parsed.Payloads)
}

// ── high-level: analyzeResponse ──────────────────────────────────────────────

const analyzeResponseSystemPrompt = `You are a web security analyst. Analyze HTTP request/response pairs to determine if a vulnerability was successfully exploited. Be precise and evidence-based. Output valid JSON only.`

func agentAnalyzeResponse(vm *sobek.Runtime, client llm.Client, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.analyzeResponse: opts argument required"))
	}
	optsObj := call.Arguments[0].ToObject(vm)

	request := stringField(vm, optsObj, "request", "")
	response := stringField(vm, optsObj, "response", "")
	vulnType := stringField(vm, optsObj, "vulnerability_type", "")
	payload := stringField(vm, optsObj, "payload", "")
	baseline := stringField(vm, optsObj, "baseline_response", "")

	var sb strings.Builder
	fmt.Fprintf(&sb, "Analyze this HTTP exchange for a %s vulnerability.\n", vulnType)
	fmt.Fprintf(&sb, "Payload injected: %s\n\nRequest:\n%s\n\nResponse:\n%s", payload, request, response)
	if baseline != "" {
		fmt.Fprintf(&sb, "\n\nBaseline response (normal, no payload):\n%s", baseline)
	}
	sb.WriteString(`

Output JSON: {"vulnerable": bool, "confidence": "high"|"medium"|"low", "evidence": "specific evidence string", "details": "detailed explanation"}`)

	schema := `{"type":"object","properties":{"vulnerable":{"type":"boolean"},"confidence":{"type":"string","enum":["high","medium","low"]},"evidence":{"type":"string"},"details":{"type":"string"}},"required":["vulnerable","confidence","evidence","details"]}`
	req := llm.CompletionRequest{
		Messages: []llm.Message{
			{Role: "system", Content: analyzeResponseSystemPrompt},
			{Role: "user", Content: sb.String()},
		},
		JSONSchema: schema,
		MaxTokens:  1024,
	}

	resp, err := client.Complete(context.Background(), req)
	if err != nil {
		zap.L().Warn("vigolium.agent.analyzeResponse failed", zap.Error(err))
		panic(vm.NewGoError(err))
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		errObj := vm.NewObject()
		errObj.Set("vulnerable", false)          //nolint:errcheck
		errObj.Set("confidence", "low")           //nolint:errcheck
		errObj.Set("evidence", "parse error")     //nolint:errcheck
		errObj.Set("details", resp.Content)       //nolint:errcheck
		return errObj
	}
	return vm.ToValue(result)
}

// ── high-level: confirmFinding ───────────────────────────────────────────────

const confirmFindingSystemPrompt = `You are a senior web application security expert performing finding verification. Determine if a security finding is a true positive or false positive based on the evidence provided. Output valid JSON only.`

func agentConfirmFinding(vm *sobek.Runtime, client llm.Client, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.confirmFinding: opts argument required"))
	}
	optsObj := call.Arguments[0].ToObject(vm)

	name := stringField(vm, optsObj, "name", "unknown vulnerability")
	request := stringField(vm, optsObj, "request", "")
	response := stringField(vm, optsObj, "response", "")
	matched := stringField(vm, optsObj, "matched", "")
	baseline := stringField(vm, optsObj, "baseline_response", "")

	var sb strings.Builder
	fmt.Fprintf(&sb, "Confirm whether this is a true positive for: %s\n", name)
	if matched != "" {
		fmt.Fprintf(&sb, "Matched pattern/evidence: %s\n", matched)
	}
	fmt.Fprintf(&sb, "\nRequest:\n%s\n\nResponse:\n%s", request, response)
	if baseline != "" {
		fmt.Fprintf(&sb, "\n\nBaseline response:\n%s", baseline)
	}
	sb.WriteString(`

Output JSON: {"confirmed": bool, "confidence": "high"|"medium"|"low", "reasoning": "explanation", "false_positive_indicators": ["indicator1", ...]}`)

	schema := `{"type":"object","properties":{"confirmed":{"type":"boolean"},"confidence":{"type":"string","enum":["high","medium","low"]},"reasoning":{"type":"string"},"false_positive_indicators":{"type":"array","items":{"type":"string"}}},"required":["confirmed","confidence","reasoning","false_positive_indicators"]}`
	req := llm.CompletionRequest{
		Messages: []llm.Message{
			{Role: "system", Content: confirmFindingSystemPrompt},
			{Role: "user", Content: sb.String()},
		},
		JSONSchema: schema,
		MaxTokens:  1024,
	}

	resp, err := client.Complete(context.Background(), req)
	if err != nil {
		zap.L().Warn("vigolium.agent.confirmFinding failed", zap.Error(err))
		panic(vm.NewGoError(err))
	}

	var result map[string]interface{}
	if parseErr := json.Unmarshal([]byte(resp.Content), &result); parseErr != nil {
		errObj := vm.NewObject()
		errObj.Set("confirmed", false)                             //nolint:errcheck
		errObj.Set("confidence", "low")                           //nolint:errcheck
		errObj.Set("reasoning", resp.Content)                     //nolint:errcheck
		errObj.Set("false_positive_indicators", []string{})       //nolint:errcheck
		return errObj
	}
	return vm.ToValue(result)
}

// ── subprocess: run ──────────────────────────────────────────────────────────

func agentRun(vm *sobek.Runtime, opts APIOptions, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 {
		panic(vm.NewTypeError("vigolium.agent.run: opts argument required"))
	}
	optsObj := call.Arguments[0].ToObject(vm)

	agentName := stringField(vm, optsObj, "agent", "")
	prompt := stringField(vm, optsObj, "prompt", "")
	timeoutSec := 60
	if v := optsObj.Get("timeout"); v != nil && !sobek.IsUndefined(v) {
		timeoutSec = int(v.ToInteger())
	}

	agentDef, ok := opts.AgentDefs[agentName]
	if !ok {
		panic(vm.NewGoError(fmt.Errorf("vigolium.agent.run: unknown agent %q", agentName)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	stdout, _, err := agentpkg.RunAgent(ctx, agentDef, prompt, nil)
	if err != nil {
		zap.L().Warn("vigolium.agent.run failed", zap.String("agent", agentName), zap.Error(err))
		panic(vm.NewGoError(err))
	}

	result := vm.NewObject()
	result.Set("output", stdout) //nolint:errcheck
	// Parse findings and http_records if present in the output.
	findings := extractJSONArray(stdout, "findings")
	httpRecords := extractJSONArray(stdout, "http_records")

	var findingsParsed interface{}
	if err := json.Unmarshal([]byte(findings), &findingsParsed); err == nil {
		result.Set("findings", vm.ToValue(findingsParsed)) //nolint:errcheck
	} else {
		result.Set("findings", vm.NewArray()) //nolint:errcheck
	}
	var httpParsed interface{}
	if err := json.Unmarshal([]byte(httpRecords), &httpParsed); err == nil {
		result.Set("http_records", vm.ToValue(httpParsed)) //nolint:errcheck
	} else {
		result.Set("http_records", vm.NewArray()) //nolint:errcheck
	}
	return result
}

// ── helpers ──────────────────────────────────────────────────────────────────

func stringField(vm *sobek.Runtime, obj *sobek.Object, key, defaultVal string) string {
	v := obj.Get(key)
	if v == nil || sobek.IsUndefined(v) || sobek.IsNull(v) {
		return defaultVal
	}
	return v.String()
}

// extractJSONArray tries to pull a named top-level JSON array from a string.
func extractJSONArray(s, key string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err == nil {
		if v, ok := m[key]; ok {
			return string(v)
		}
	}
	return "[]"
}
