package llm

// Message represents a single chat message.
type Message struct {
	Role    string // "system", "user", or "assistant"
	Content string
}

// CompletionRequest holds parameters for a completion call.
type CompletionRequest struct {
	Messages    []Message
	Model       string  // optional override; uses config default if empty
	MaxTokens   int     // optional; uses config default if 0
	Temperature float64 // optional; uses config default if 0
	JSONSchema  string  // optional; enables structured JSON output
}

// CompletionResponse holds the result of a completion call.
type CompletionResponse struct {
	Content   string // raw text (or JSON string when JSONSchema was set)
	Model     string // model actually used
	TokensIn  int    // input tokens consumed
	TokensOut int    // output tokens generated
}
