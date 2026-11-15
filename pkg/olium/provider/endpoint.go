package provider

// Endpointer is a provider that talks HTTP to a known URL. A caller uses it
// to check the endpoint is reachable (a TCP dial) before the first model
// call; providers without one (a local CLI subprocess) skip that check.
type Endpointer interface {
	Endpoint() string
}

// Endpoint is the messages URL this provider posts to.
func (a *Anthropic) Endpoint() string { return a.baseURL }

// Endpoint is the chat-completions URL this provider posts to.
func (o *OpenAI) Endpoint() string { return o.baseURL }

// Endpoint is the Codex responses base URL.
func (c *Codex) Endpoint() string { return c.baseURL }
