// +build ignore

// fake_codex_server.go is a standalone program that mimics the codex app-server
// JSON-RPC v2 protocol over stdio. It's used by e2e tests.
//
// Usage: go run fake_codex_server.go <response_text>
//
// It responds to initialize, thread/start, thread/resume, and turn/start.
// For turn/start it sends streaming notifications and a completed turn with
// the given response text.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type request struct {
	ID     string `json:"id"`
	Method string `json:"method"`
}

func main() {
	responseText := "Hello from fake Codex!"
	if len(os.Args) > 1 {
		responseText = os.Args[1]
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req request
		if json.Unmarshal([]byte(line), &req) != nil {
			continue
		}
		// Skip notifications (no id)
		if req.ID == "" {
			continue
		}

		switch req.Method {
		case "initialize":
			fmt.Printf(`{"id":%q,"result":{"serverInfo":{"name":"fake-codex","version":"0.0.1"},"userAgent":"fake-codex/0.0.1"}}%s`, req.ID, "\n")

		case "thread/start", "thread/resume":
			fmt.Printf(`{"id":%q,"result":{"thread":{"id":"thr_test_001","cliVersion":"0.0.1","createdAt":1700000000,"cwd":"/tmp","ephemeral":false,"modelProvider":"openai","preview":"","source":{"custom":"test"},"status":{"type":"active"},"turns":[],"updatedAt":1700000000},"model":"gpt-4.1","modelProvider":"openai","cwd":"/tmp","approvalPolicy":{},"approvalsReviewer":"user","sandbox":{"type":"danger-full-access"}}}%s`, req.ID, "\n")

		case "turn/start":
			// Response
			fmt.Printf(`{"id":%q,"result":{"turn":{"id":"turn_001","status":"inProgress","items":[]}}}%s`, req.ID, "\n")
			// Streaming delta
			text, _ := json.Marshal(responseText)
			fmt.Printf(`{"method":"item/agentMessage/delta","params":{"threadId":"thr_test_001","turnId":"turn_001","itemId":"item_001","delta":%s}}%s`, text, "\n")
			// Item completed
			fmt.Printf(`{"method":"item/completed","params":{"threadId":"thr_test_001","turnId":"turn_001","item":{"id":"item_001","type":"message","text":%s}}}%s`, text, "\n")
			// Turn completed
			fmt.Printf(`{"method":"turn/completed","params":{"threadId":"thr_test_001","turn":{"id":"turn_001","status":"completed","items":[{"id":"item_001","type":"message","text":%s}]}}}%s`, text, "\n")

		default:
			fmt.Printf(`{"id":%q,"result":{}}%s`, req.ID, "\n")
		}
	}
}
