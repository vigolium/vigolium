package codexsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ApprovalHandler is called when the server requests approval for a command or file change.
// The method is the JSON-RPC method (e.g., "item/commandExecution/requestApproval").
// Return a response map (e.g., {"decision": "accept"}).
type ApprovalHandler func(method string, params json.RawMessage) map[string]any

// Client manages a Codex app-server subprocess via JSON-RPC v2 over stdio.
type Client struct {
	opts            *Options
	approvalHandler ApprovalHandler
	proc            *process
	mu              sync.Mutex
	started         bool
	closed          bool

	// pendingNotifications buffers notifications received while waiting for a response.
	pendingNotifications []Notification
}

// NewClient creates a new Codex client. The subprocess is not started until Start() is called.
func NewClient(opts *Options) *Client {
	return &Client{
		opts:            opts,
		approvalHandler: defaultApprovalHandler,
	}
}

// SetApprovalHandler overrides the default approval handler.
func (c *Client) SetApprovalHandler(h ApprovalHandler) {
	c.approvalHandler = h
}

// Start spawns the codex app-server subprocess.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return nil
	}
	if c.closed {
		return fmt.Errorf("client is closed")
	}

	proc, err := startProcess(ctx, c.opts)
	if err != nil {
		return err
	}
	c.proc = proc
	c.started = true
	return nil
}

// Initialize performs the JSON-RPC initialize handshake.
// Returns the server info (serverInfo, userAgent, etc.).
func (c *Client) Initialize(ctx context.Context) (*InitializeResponse, error) {
	params := InitializeParams{
		ClientInfo: ClientInfo{
			Name:    "vigolium",
			Version: "1.0.0",
		},
		Capabilities: &InitializeCapabilities{
			ExperimentalApi: boolPtr(true),
		},
	}

	var resp InitializeResponse
	if err := c.request(ctx, "initialize", params, &resp); err != nil {
		return nil, fmt.Errorf("initialize failed: %w", err)
	}

	// Send "initialized" notification to confirm handshake
	if err := c.notify("initialized", nil); err != nil {
		return nil, fmt.Errorf("initialized notification failed: %w", err)
	}

	return &resp, nil
}

// ThreadStart creates a new thread.
func (c *Client) ThreadStart(ctx context.Context, params *ThreadStartParams) (*ThreadStartResponse, error) {
	var resp ThreadStartResponse
	if err := c.request(ctx, "thread/start", params, &resp); err != nil {
		return nil, fmt.Errorf("thread/start failed: %w", err)
	}
	return &resp, nil
}

// ThreadResume resumes an existing thread.
func (c *Client) ThreadResume(ctx context.Context, params *ThreadResumeParams) (*ThreadResumeResponse, error) {
	var resp ThreadResumeResponse
	if err := c.request(ctx, "thread/resume", params, &resp); err != nil {
		return nil, fmt.Errorf("thread/resume failed: %w", err)
	}
	return &resp, nil
}

// TurnStart starts a new turn in a thread with the given input.
func (c *Client) TurnStart(ctx context.Context, params *TurnStartParams) (*TurnStartResponse, error) {
	var resp TurnStartResponse
	if err := c.request(ctx, "turn/start", params, &resp); err != nil {
		return nil, fmt.Errorf("turn/start failed: %w", err)
	}
	return &resp, nil
}

// TurnSteer injects additional input into a running turn.
func (c *Client) TurnSteer(ctx context.Context, params *TurnSteerParams) (*TurnSteerResponse, error) {
	var resp TurnSteerResponse
	if err := c.request(ctx, "turn/steer", params, &resp); err != nil {
		return nil, fmt.Errorf("turn/steer failed: %w", err)
	}
	return &resp, nil
}

// TurnInterrupt cancels an in-flight turn.
func (c *Client) TurnInterrupt(ctx context.Context, params *TurnInterruptParams) error {
	var resp map[string]any
	return c.request(ctx, "turn/interrupt", params, &resp)
}

// NextNotification returns the next server notification, blocking until one arrives.
// It handles server-initiated requests (approvals) internally.
func (c *Client) NextNotification(ctx context.Context) (*Notification, error) {
	// Check buffer first
	if len(c.pendingNotifications) > 0 {
		n := c.pendingNotifications[0]
		c.pendingNotifications[0] = Notification{} // release reference
		c.pendingNotifications = c.pendingNotifications[1:]
		if len(c.pendingNotifications) == 0 {
			c.pendingNotifications = nil // release backing array
		}
		return &n, nil
	}

	for {
		msg, err := c.readMessage(ctx)
		if err != nil {
			return nil, err
		}

		switch msg.messageKind() {
		case "server_request":
			// Handle approval request inline
			if err := c.handleServerRequest(msg); err != nil {
				zap.L().Debug("failed to handle server request", zap.Error(err))
			}
			continue

		case "notification":
			method := ""
			if msg.Method != nil {
				method = *msg.Method
			}
			return &Notification{
				Method:  method,
				Payload: msg.Params,
			}, nil

		default:
			// Skip responses to requests we're not tracking
			continue
		}
	}
}

// StreamText sends a prompt and yields AgentMessageDelta notifications until the turn completes.
// Returns the completed turn notification.
func (c *Client) StreamText(ctx context.Context, threadID, text string, streamWriter io.Writer) (*TurnCompletedNotification, error) {
	turnResp, err := c.TurnStart(ctx, &TurnStartParams{
		ThreadId: threadID,
		Input: []UserInput{
			{Type: "text", Text: strPtr(text)},
		},
	})
	if err != nil {
		return nil, err
	}
	turnID := turnResp.Turn.Id

	for {
		notif, err := c.NextNotification(ctx)
		if err != nil {
			return nil, fmt.Errorf("notification stream error: %w", err)
		}

		switch notif.Method {
		case "item/agentMessage/delta":
			if streamWriter != nil {
				var delta AgentMessageDeltaNotification
				if json.Unmarshal(notif.Payload, &delta) == nil && delta.TurnId == turnID {
					_, _ = io.WriteString(streamWriter, delta.Delta)
				}
			}

		case "item/commandExecution/outputDelta":
			if streamWriter != nil {
				var delta CommandExecutionOutputDeltaNotification
				if json.Unmarshal(notif.Payload, &delta) == nil && delta.TurnId == turnID {
					_, _ = io.WriteString(streamWriter, delta.Delta)
				}
			}

		case "turn/completed":
			var completed TurnCompletedNotification
			if err := json.Unmarshal(notif.Payload, &completed); err == nil && completed.Turn.Id == turnID {
				return &completed, nil
			}

		case "error":
			var errNotif ErrorNotification
			if json.Unmarshal(notif.Payload, &errNotif) == nil && errNotif.TurnId == turnID {
				if !errNotif.WillRetry {
					return nil, fmt.Errorf("codex agent error: %s", errNotif.Error.Message)
				}
			}
		}
	}
}

// CollectText sends a prompt and collects the full text response (non-streaming).
// Returns the accumulated text output and the completed turn.
func (c *Client) CollectText(ctx context.Context, threadID, text string) (string, *TurnCompletedNotification, error) {
	turnResp, err := c.TurnStart(ctx, &TurnStartParams{
		ThreadId: threadID,
		Input: []UserInput{
			{Type: "text", Text: strPtr(text)},
		},
	})
	if err != nil {
		return "", nil, err
	}
	turnID := turnResp.Turn.Id

	var outputBuf strings.Builder
	for {
		notif, err := c.NextNotification(ctx)
		if err != nil {
			return outputBuf.String(), nil, err
		}

		switch notif.Method {
		case "item/completed":
			var item ItemCompletedNotification
			if json.Unmarshal(notif.Payload, &item) == nil && item.TurnId == turnID {
				if item.Item.Type == "message" && item.Item.Text != nil {
					outputBuf.WriteString(*item.Item.Text)
				}
			}

		case "turn/completed":
			var completed TurnCompletedNotification
			if err := json.Unmarshal(notif.Payload, &completed); err == nil && completed.Turn.Id == turnID {
				if outputBuf.Len() == 0 {
					for _, item := range completed.Turn.Items {
						if item.Type == "message" && item.Text != nil {
							outputBuf.WriteString(*item.Text)
						}
					}
				}
				return outputBuf.String(), &completed, nil
			}

		case "error":
			var errNotif ErrorNotification
			if json.Unmarshal(notif.Payload, &errNotif) == nil && errNotif.TurnId == turnID {
				if !errNotif.WillRetry {
					return outputBuf.String(), nil, fmt.Errorf("codex agent error: %s", errNotif.Error.Message)
				}
			}
		}
	}
}

// Close shuts down the app-server subprocess.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.proc != nil {
		c.proc.close()
	}
	return nil
}

// Alive returns true if the subprocess is still running.
func (c *Client) Alive() bool {
	if c.proc == nil {
		return false
	}
	return c.proc.alive()
}

// --- Internal methods ---

// request sends a JSON-RPC request and waits for the response.
// It handles interleaved notifications and server requests while waiting.
func (c *Client) request(ctx context.Context, method string, params any, result any) error {
	requestID := uuid.New().String()

	req := jsonRPCRequest{
		ID:     requestID,
		Method: method,
		Params: params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := c.proc.writeLine(data); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	// Read messages until we get our response
	for {
		msg, err := c.readMessage(ctx)
		if err != nil {
			return err
		}

		switch msg.messageKind() {
		case "server_request":
			if err := c.handleServerRequest(msg); err != nil {
				zap.L().Debug("failed to handle server request during RPC wait", zap.Error(err))
			}
			continue

		case "notification":
			method := ""
			if msg.Method != nil {
				method = *msg.Method
			}
			c.pendingNotifications = append(c.pendingNotifications, Notification{
				Method:  method,
				Payload: msg.Params,
			})
			continue

		case "error_response":
			if msg.ID != nil && *msg.ID == requestID {
				return &RPCError{
					Code:    msg.Error.Code,
					Message: msg.Error.Message,
					Data:    msg.Error.Data,
				}
			}
			continue

		case "response":
			if msg.ID != nil && *msg.ID == requestID {
				if result == nil {
					return nil
				}
				return json.Unmarshal(msg.Result, result)
			}
			continue
		}
	}
}

// notify sends a JSON-RPC notification (no response expected).
func (c *Client) notify(method string, params any) error {
	notif := jsonRPCNotification{
		Method: method,
		Params: params,
	}
	data, err := json.Marshal(notif)
	if err != nil {
		return err
	}
	return c.proc.writeLine(data)
}

// readMessage reads and parses one JSONL message from the server.
// Skips empty lines and unparseable messages.
func (c *Client) readMessage(ctx context.Context) (*rawMessage, error) {
	for {
		line, err := c.proc.readLine(ctx)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			continue
		}

		var msg rawMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			zap.L().Debug("failed to parse codex message",
				zap.Error(err),
				zap.Int("lineLen", len(line)))
			continue
		}
		return &msg, nil
	}
}

// handleServerRequest processes a server-initiated request (e.g., approval) and sends back a response.
func (c *Client) handleServerRequest(msg *rawMessage) error {
	method := ""
	if msg.Method != nil {
		method = *msg.Method
	}

	var response map[string]any
	if c.approvalHandler != nil {
		response = c.approvalHandler(method, msg.Params)
	}
	if response == nil {
		response = map[string]any{}
	}

	id := ""
	if msg.ID != nil {
		id = *msg.ID
	}

	resp := map[string]any{
		"id":     id,
		"result": response,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return c.proc.writeLine(data)
}

// defaultApprovalHandler auto-accepts all approval requests.
func defaultApprovalHandler(_ string, _ json.RawMessage) map[string]any {
	return map[string]any{"decision": "accept"}
}

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }
