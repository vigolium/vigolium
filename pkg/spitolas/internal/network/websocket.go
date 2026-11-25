package network

import (
	"context"
	"encoding/base64"
	"net/url"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// WebSocket frame directions.
const (
	FrameSent     = "sent"
	FrameReceived = "received"
)

// Payload encodings: a text frame's head is its UTF-8 text, every other
// opcode's head is base64 of its bytes (CDP hands those over base64-encoded).
const (
	PayloadText   = "text"
	PayloadBase64 = "base64"
)

// maxFrameHeadBytes bounds the payload bytes a frame keeps; maxPendingFrames
// bounds the frames buffered between flushes (a chatty socket past it loses
// frames, counted, rather than growing without bound).
const (
	maxFrameHeadBytes = 4096
	maxPendingFrames  = 4096
)

// WebSocketFrame is one frame the browser sent or received on a socket.
type WebSocketFrame struct {
	URL          string
	Host         string
	ConnectionID string // the socket's CDP request id, unique within a crawl
	Direction    string // FrameSent or FrameReceived
	// Opcode is the RFC 6455 opcode: 1 text, 2 binary, 8 close, 9 ping, 10 pong.
	Opcode          int
	PayloadLength   int // the whole payload in bytes
	PayloadHead     string
	PayloadEncoding string // PayloadText or PayloadBase64
	Truncated       bool   // PayloadHead holds less than the whole payload
	At              time.Time
}

// FrameSaver persists WebSocket frames. The capture's RecordSaver may
// implement it; one that does not stores no frames.
type FrameSaver interface {
	SaveWebSocketFrames(ctx context.Context, projectUUID string, frames []WebSocketFrame) error
}

// FrameWriter is a Writer that also accepts WebSocket frames.
type FrameWriter interface {
	WriteFrame(f WebSocketFrame)
}

// wsSocket is an open socket's URL, parsed once when the socket is created so
// each frame on it reuses the host and path.
type wsSocket struct {
	url, host, path string
}

// parseSocket parses a socket URL; false when it does not parse.
func parseSocket(raw string) (wsSocket, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return wsSocket{}, false
	}
	return wsSocket{url: raw, host: u.Hostname(), path: u.Path}, true
}

// newWebSocketFrame builds a frame from a CDP payload: payloadData is the
// text for opcode 1 and base64 for every other opcode.
func newWebSocketFrame(s wsSocket, connID, direction string, f *proto.NetworkWebSocketFrame, at time.Time) (WebSocketFrame, bool) {
	if f == nil {
		return WebSocketFrame{}, false
	}
	out := WebSocketFrame{URL: s.url, Host: s.host, ConnectionID: connID, Direction: direction,
		Opcode: int(f.Opcode), At: at}
	if out.Opcode == 1 {
		out.PayloadEncoding = PayloadText
		out.PayloadLength = len(f.PayloadData)
		out.PayloadHead = f.PayloadData
		if len(out.PayloadHead) > maxFrameHeadBytes {
			out.PayloadHead = out.PayloadHead[:textutil.CutIndex(out.PayloadHead, maxFrameHeadBytes)]
			out.Truncated = true
		}
		return out, true
	}
	out.PayloadEncoding = PayloadBase64
	raw, err := base64.StdEncoding.DecodeString(f.PayloadData)
	if err != nil {
		// Not base64 after all: keep what CDP sent, measured as text.
		out.PayloadLength = len(f.PayloadData)
		out.PayloadHead = f.PayloadData[:textutil.CutIndex(f.PayloadData, maxFrameHeadBytes)]
		out.Truncated = len(f.PayloadData) > maxFrameHeadBytes
		return out, true
	}
	out.PayloadLength = len(raw)
	head := raw
	// Base64 grows 4/3: keep the encoded head under maxFrameHeadBytes.
	if limit := maxFrameHeadBytes / 4 * 3; len(head) > limit {
		head = head[:limit]
		out.Truncated = true
	}
	out.PayloadHead = base64.StdEncoding.EncodeToString(head)
	return out, true
}

// onWebSocketCreated remembers a socket's URL by its request id.
func (c *Capture) onWebSocketCreated(e *proto.NetworkWebSocketCreated) {
	if e == nil || e.URL == "" {
		return
	}
	s, ok := parseSocket(e.URL)
	if !ok {
		// No URL to attribute its frames to: they are skipped like those of
		// a socket whose creation was not seen.
		return
	}
	c.mu.Lock()
	if c.sockets == nil {
		c.sockets = make(map[proto.NetworkRequestID]wsSocket)
	}
	c.sockets[e.RequestID] = s
	c.mu.Unlock()
}

// onWebSocketClosed forgets a socket.
func (c *Capture) onWebSocketClosed(e *proto.NetworkWebSocketClosed) {
	if e == nil {
		return
	}
	c.mu.Lock()
	delete(c.sockets, e.RequestID)
	c.mu.Unlock()
}

// onWebSocketFrame hands one in-scope frame to the writer when it stores
// frames (FrameWriter). A frame on a socket whose creation was not seen has
// no URL to attribute it to and is skipped.
func (c *Capture) onWebSocketFrame(id proto.NetworkRequestID, direction string, f *proto.NetworkWebSocketFrame) {
	fw, ok := c.writer.(FrameWriter)
	if !ok || f == nil || c.isStopped() {
		return
	}
	c.mu.Lock()
	s, known := c.sockets[id]
	c.mu.Unlock()
	if !known {
		return
	}
	if c.ScopeFilter != nil && !c.ScopeFilter(s.host, s.path) {
		return
	}
	frame, ok := newWebSocketFrame(s, string(id), direction, f, time.Now().UTC())
	if !ok {
		return
	}
	fw.WriteFrame(frame)
}

// WriteFrame buffers a frame for the flush loop when the repository stores
// frames. A frame offered after Close, or past maxPendingFrames, is dropped
// and counted.
func (w *RepositoryWriter) WriteFrame(f WebSocketFrame) {
	if _, ok := w.repo.(FrameSaver); !ok {
		return
	}
	w.frameMu.Lock()
	defer w.frameMu.Unlock()
	if w.framesClosed || len(w.frames) >= maxPendingFrames {
		w.framesDropped++
		return
	}
	w.frames = append(w.frames, f)
}

// flushFrames saves the buffered frames by deadline. Called on the flush
// loop's goroutine only.
func (w *RepositoryWriter) flushFrames(deadline time.Time) {
	saver, ok := w.repo.(FrameSaver)
	if !ok {
		return
	}
	w.frameMu.Lock()
	batch := w.frames
	w.frames = nil
	w.frameMu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	err := saver.SaveWebSocketFrames(ctx, w.projectUUID, batch)
	cancel()
	w.frameMu.Lock()
	defer w.frameMu.Unlock()
	if err != nil {
		zap.L().Warn("Failed to save WebSocket frames; frames dropped", zap.Int("count", len(batch)), zap.Error(err))
		w.framesDropped += len(batch)
		return
	}
	w.framesSaved += len(batch)
}

// closeFrames stops admitting frames; the final drain saves what is buffered.
func (w *RepositoryWriter) closeFrames() {
	w.frameMu.Lock()
	w.framesClosed = true
	w.frameMu.Unlock()
}

// FrameCounts reports the frames saved and dropped so far.
func (w *RepositoryWriter) FrameCounts() (saved, dropped int) {
	w.frameMu.Lock()
	defer w.frameMu.Unlock()
	return w.framesSaved, w.framesDropped
}
