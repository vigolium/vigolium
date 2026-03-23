// +build ignore

// fake_opencode_server.go is a standalone HTTP server that mimics the OpenCode
// REST API + SSE event stream. It's used by e2e tests.
//
// It is spawned by the opencodesdk.Client as: <binary> serve --cwd <dir>
// Port is read from the OPENCODE_BASE_URL environment variable.
// Response text is read from the FAKE_OPENCODE_RESPONSE environment variable.
//
// It implements:
//   - GET  /session                      → list sessions
//   - POST /session                      → create session
//   - POST /session/{id}/message         → send prompt
//   - POST /session/{id}/abort           → abort session
//   - POST /session/{id}/permissions/{pid} → approve permission
//   - GET  /event                        → SSE stream
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// pendingPrompt tracks a prompt that needs SSE events dispatched.
type pendingPrompt struct {
	sessionID string
	text      string
}

var (
	mu              sync.Mutex
	sessionCounter  int
	promptQueue     []pendingPrompt
	promptQueueCond = sync.NewCond(&mu)
	respText        string
)

func main() {
	// Parse port from OPENCODE_BASE_URL (e.g., "http://localhost:54321")
	listenPort := "54321"
	if baseURL := os.Getenv("OPENCODE_BASE_URL"); baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil {
			if p := u.Port(); p != "" {
				listenPort = p
			}
		}
	}

	// Response text from env var
	respText = os.Getenv("FAKE_OPENCODE_RESPONSE")
	if respText == "" {
		respText = "Hello from fake OpenCode!"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /session", handleSessionList)
	mux.HandleFunc("POST /session", handleSessionNew)
	mux.HandleFunc("POST /session/{id}/message", handlePrompt)
	mux.HandleFunc("POST /session/{id}/abort", handleAbort)
	mux.HandleFunc("POST /session/{id}/permissions/{pid}", handlePermission)
	mux.HandleFunc("GET /event", handleSSE)

	addr := ":" + listenPort
	fmt.Fprintf(os.Stderr, "fake opencode server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func handleSessionList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]any{})
}

func handleSessionNew(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	sessionCounter++
	id := fmt.Sprintf("sess_%04d", sessionCounter)
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":        id,
		"directory": r.URL.Query().Get("directory"),
		"title":     "Test Session",
		"version":   "1.0.0",
		"time":      map[string]any{"created": time.Now().Unix(), "updated": time.Now().Unix()},
	})
}

func handlePrompt(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")

	// Queue prompt for SSE dispatch
	mu.Lock()
	promptQueue = append(promptQueue, pendingPrompt{
		sessionID: sessionID,
		text:      respText,
	})
	promptQueueCond.Broadcast()
	mu.Unlock()

	// Return immediate response (the actual content comes via SSE)
	msgID := fmt.Sprintf("msg_%s_%d", sessionID, time.Now().UnixNano())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"info": map[string]any{
			"id":   msgID,
			"role": "assistant",
			"time": map[string]any{"created": time.Now().Unix()},
		},
		"parts": []any{},
	})
}

func handleAbort(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(true)
}

func handlePermission(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(true)
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ctx := r.Context()

	for {
		mu.Lock()
		for len(promptQueue) == 0 {
			// Wait using a channel to respect context cancellation.
			ch := make(chan struct{})
			go func() {
				mu.Lock()
				promptQueueCond.Wait()
				mu.Unlock()
				close(ch)
			}()
			mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-ch:
			}

			mu.Lock()
		}

		// Dequeue
		p := promptQueue[0]
		promptQueue = promptQueue[1:]
		mu.Unlock()

		// Small delay to simulate processing
		time.Sleep(10 * time.Millisecond)

		// Send message.part.updated events (split into chunks for realistic streaming)
		partID := fmt.Sprintf("part_%s_%d", p.sessionID, time.Now().UnixNano())
		chunks := splitIntoChunks(p.text, 20)
		for _, chunk := range chunks {
			event := map[string]any{
				"type": "message.part.updated",
				"properties": map[string]any{
					"delta": chunk,
					"part": map[string]any{
						"id":        partID,
						"sessionID": p.sessionID,
						"messageID": "msg_001",
						"type":      "text",
						"text":      p.text,
					},
				},
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}

		// Send session.idle to signal completion
		idleEvent := map[string]any{
			"type": "session.idle",
			"properties": map[string]any{
				"sessionID": p.sessionID,
			},
		}
		data, _ := json.Marshal(idleEvent)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
}

func splitIntoChunks(s string, maxLen int) []string {
	if len(s) <= maxLen {
		return []string{s}
	}
	var chunks []string
	for len(s) > 0 {
		end := maxLen
		if end > len(s) {
			end = len(s)
		}
		if end < len(s) {
			if idx := strings.LastIndex(s[:end], " "); idx > 0 {
				end = idx + 1
			}
		}
		chunks = append(chunks, s[:end])
		s = s[end:]
	}
	return chunks
}
