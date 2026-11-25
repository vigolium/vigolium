package network

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

func TestNewWebSocketFrame(t *testing.T) {
	at := time.Now()
	text, ok := newWebSocketFrame(mustSocket(t, "wss://app.test/ws?x=1"), "r1", FrameSent, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: `{"op":"sub"}`}, at)
	if !ok || text.Host != "app.test" || text.PayloadEncoding != PayloadText || text.PayloadHead != `{"op":"sub"}` ||
		text.PayloadLength != 12 || text.Truncated || text.Opcode != 1 || text.ConnectionID != "r1" {
		t.Fatalf("text frame = %+v", text)
	}

	bin, ok := newWebSocketFrame(mustSocket(t, "ws://app.test/ws"), "r1", FrameReceived,
		&proto.NetworkWebSocketFrame{Opcode: 2, PayloadData: base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}, at)
	if !ok || bin.PayloadEncoding != PayloadBase64 || bin.PayloadLength != 3 || bin.PayloadHead != "AQID" {
		t.Fatalf("binary frame = %+v", bin)
	}

	big := strings.Repeat("ü", maxFrameHeadBytes)
	long, _ := newWebSocketFrame(mustSocket(t, "ws://app.test/ws"), "r1", FrameReceived, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: big}, at)
	if !long.Truncated || len(long.PayloadHead) > maxFrameHeadBytes || !strings.HasPrefix(big, long.PayloadHead) || long.PayloadLength != len(big) {
		t.Fatalf("long text: truncated=%v head=%d", long.Truncated, len(long.PayloadHead))
	}
	bigBin := make([]byte, 10000)
	lb, _ := newWebSocketFrame(mustSocket(t, "ws://app.test/ws"), "r1", FrameReceived,
		&proto.NetworkWebSocketFrame{Opcode: 2, PayloadData: base64.StdEncoding.EncodeToString(bigBin)}, at)
	if !lb.Truncated || len(lb.PayloadHead) > maxFrameHeadBytes || lb.PayloadLength != 10000 {
		t.Fatalf("long binary: truncated=%v head=%d length=%d", lb.Truncated, len(lb.PayloadHead), lb.PayloadLength)
	}
	if _, ok := parseSocket("::bad"); ok {
		t.Fatal("an unparsable socket URL yields no socket")
	}
}

func mustSocket(t *testing.T, raw string) wsSocket {
	t.Helper()
	s, ok := parseSocket(raw)
	if !ok {
		t.Fatalf("parseSocket(%q) failed", raw)
	}
	return s
}

type frameSink struct {
	NopWriter
	mu     sync.Mutex
	frames []WebSocketFrame
}

func (s *frameSink) WriteFrame(f WebSocketFrame) {
	s.mu.Lock()
	s.frames = append(s.frames, f)
	s.mu.Unlock()
}

// The capture attributes each frame to its socket's URL, keeps in-scope
// sockets only, and drops frames of sockets it never saw created or that
// closed.
func TestCaptureWebSocketFrames(t *testing.T) {
	sink := &frameSink{}
	c := &Capture{writer: sink, ScopeFilter: func(host, _ string) bool { return host == "app.test" }}
	c.onWebSocketCreated(&proto.NetworkWebSocketCreated{RequestID: "a", URL: "wss://app.test/live"})
	c.onWebSocketCreated(&proto.NetworkWebSocketCreated{RequestID: "b", URL: "wss://tracker.other/x"})
	c.onWebSocketFrame("a", FrameSent, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: "hello"})
	c.onWebSocketFrame("a", FrameReceived, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: "world"})
	c.onWebSocketFrame("b", FrameReceived, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: "beacon"})
	c.onWebSocketFrame("zz", FrameReceived, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: "orphan"})
	c.onWebSocketClosed(&proto.NetworkWebSocketClosed{RequestID: "a"})
	c.onWebSocketFrame("a", FrameReceived, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: "late"})

	if len(sink.frames) != 2 || sink.frames[0].PayloadHead != "hello" || sink.frames[0].Direction != FrameSent ||
		sink.frames[1].Direction != FrameReceived || sink.frames[1].URL != "wss://app.test/live" {
		t.Fatalf("frames = %+v", sink.frames)
	}

	// A writer that stores no frames is never handed one.
	plain := &Capture{writer: NopWriter{}}
	plain.onWebSocketCreated(&proto.NetworkWebSocketCreated{RequestID: "a", URL: "wss://app.test/live"})
	plain.onWebSocketFrame("a", FrameSent, &proto.NetworkWebSocketFrame{Opcode: 1, PayloadData: "x"})
}

type frameRecordSaver struct {
	fakeRecordSaver
	mu      sync.Mutex
	frames  []WebSocketFrame
	project string
}

func (f *frameRecordSaver) SaveWebSocketFrames(_ context.Context, projectUUID string, frames []WebSocketFrame) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.project = projectUUID
	f.frames = append(f.frames, frames...)
	return nil
}

// The repository writer saves buffered frames through a FrameSaver, the rest
// at Close, and refuses frames after Close; a saver without frame support is
// never handed one.
func TestRepositoryWriterFrames(t *testing.T) {
	saver := &frameRecordSaver{}
	w := NewRepositoryWriter(saver, "spidering", "proj-1")
	w.WriteFrame(WebSocketFrame{URL: "wss://app.test/ws", Direction: FrameSent, Opcode: 1, PayloadHead: "a"})
	w.WriteFrame(WebSocketFrame{URL: "wss://app.test/ws", Direction: FrameReceived, Opcode: 1, PayloadHead: "b"})
	_ = w.Close()
	w.WriteFrame(WebSocketFrame{URL: "wss://app.test/ws", Direction: FrameSent, Opcode: 1, PayloadHead: "late"})

	saver.mu.Lock()
	got, project := len(saver.frames), saver.project
	saver.mu.Unlock()
	if got != 2 || project != "proj-1" {
		t.Fatalf("saved %d frames for %q, want 2 for proj-1", got, project)
	}
	if saved, dropped := w.FrameCounts(); saved != 2 || dropped != 1 {
		t.Fatalf("FrameCounts = %d saved, %d dropped", saved, dropped)
	}

	plain := NewRepositoryWriter(&fakeRecordSaver{}, "spidering", "p")
	plain.WriteFrame(WebSocketFrame{URL: "wss://app.test/ws", Direction: FrameSent})
	_ = plain.Close()
	if saved, dropped := plain.FrameCounts(); saved != 0 || dropped != 0 {
		t.Fatalf("frameless saver: %d saved, %d dropped", saved, dropped)
	}
}
