package claudesdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"go.uber.org/zap"
)

const msgChanBuffer = 32

// Client manages a Claude Code CLI session via JSON-lines protocol.
type Client struct {
	opts    *Options
	proc    *process
	mu      sync.Mutex
	started bool
	closed  bool
}

// NewClient creates a new client. The CLI process is not started until the
// first call to Query (lazy initialization).
func NewClient(opts *Options) *Client {
	return &Client{opts: opts}
}

// Query sends a prompt to Claude. The first call starts the CLI subprocess;
// subsequent calls send follow-up messages for multi-turn conversations.
func (c *Client) Query(ctx context.Context, prompt string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client is closed")
	}

	if !c.started {
		proc, err := startProcess(ctx, c.opts)
		if err != nil {
			return err
		}
		c.proc = proc
		c.started = true
	}

	return c.sendUserMessage(prompt)
}

// sendUserMessage writes a user message to the CLI's stdin.
func (c *Client) sendUserMessage(prompt string) error {
	msg := userMessage{
		Type: "user",
		Message: userMessageContent{
			Role: "user",
			Content: []userContentBlock{
				{Type: "text", Text: prompt},
			},
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal user message: %w", err)
	}

	return c.proc.writeLine(data)
}

// ReceiveResponse returns a channel that yields messages until a ResultMessage
// is received, then closes. This is the simple path for one-shot queries.
func (c *Client) ReceiveResponse(ctx context.Context) <-chan Message {
	ch := make(chan Message, msgChanBuffer)

	go func() {
		defer close(ch)
		for {
			msg, err := c.readNext(ctx)
			if err != nil {
				return
			}
			if msg == nil {
				continue // unknown message type, skip
			}

			select {
			case ch <- msg:
			case <-ctx.Done():
				return
			}

			if _, ok := msg.(*ResultMessage); ok {
				return
			}
		}
	}()

	return ch
}

// ReceiveMessages returns channels for all messages and errors. The message
// channel closes on EOF. This is the streaming path.
func (c *Client) ReceiveMessages(ctx context.Context) (<-chan Message, <-chan error) {
	msgCh := make(chan Message, msgChanBuffer)
	errCh := make(chan error, 1)

	go func() {
		defer close(msgCh)
		defer close(errCh)

		for {
			msg, err := c.readNext(ctx)
			if err != nil {
				if err != io.EOF {
					errCh <- err
				}
				return
			}
			if msg == nil {
				continue
			}

			select {
			case msgCh <- msg:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}
	}()

	return msgCh, errCh
}

// Close shuts down the CLI subprocess and cleans up resources.
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

// readNext reads and parses the next message from the CLI's stdout.
func (c *Client) readNext(ctx context.Context) (Message, error) {
	if c.proc == nil {
		return nil, io.EOF
	}

	line, err := c.proc.readLine(ctx)
	if err != nil {
		return nil, err
	}

	if len(line) == 0 {
		return nil, nil
	}

	msg, parseErr := parseMessage(line)
	if parseErr != nil {
		zap.L().Debug("failed to parse claude message",
			zap.Error(parseErr),
			zap.Int("lineLen", len(line)))
		return nil, nil // skip unparseable messages
	}

	return msg, nil
}

// --- Internal message types for JSON serialization ---

type userMessage struct {
	Type    string             `json:"type"`
	Message userMessageContent `json:"message"`
}

type userMessageContent struct {
	Role    string             `json:"role"`
	Content []userContentBlock `json:"content"`
}

type userContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
