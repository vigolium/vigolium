//go:build integration

package spitolas

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// wsEcho upgrades to a WebSocket (RFC 6455 handshake by hand: the module has no
// WebSocket library) and answers each text message with "echo:" + message.
func wsEcho(w http.ResponseWriter, r *http.Request) {
	h := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n")
	_ = rw.Flush()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	for {
		msg, op, err := readClientFrame(rw.Reader)
		if err != nil || op == 8 {
			return
		}
		out := append([]byte("echo:"), msg...)
		frame := []byte{0x81, byte(len(out))} // FIN + text, short payload, unmasked
		_, _ = conn.Write(append(frame, out...))
	}
}

func readClientFrame(r *bufio.Reader) ([]byte, byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	op, n := hdr[0]&0x0f, uint64(hdr[1]&0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, 0, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, 0, err
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return nil, 0, err
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return payload, op, nil
}

type frameMemSink struct {
	memSink
	mu     sync.Mutex
	frames []WebSocketFrame
}

func (s *frameMemSink) SaveWebSocketFrames(_ context.Context, _ string, frames []WebSocketFrame) error {
	s.mu.Lock()
	s.frames = append(s.frames, frames...)
	s.mu.Unlock()
	return nil
}

// TestSpiderRecordsWebSocketFrames: a page that opens a socket and sends one
// message yields both frames — sent and the echo received — with the socket
// URL, text opcode and payload.
func TestSpiderRecordsWebSocketFrames(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsEcho)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id="o"></div><script>
var s = new WebSocket('ws://' + location.host + '/ws');
s.onopen = function () { s.send('{"op":"subscribe","topic":"orders"}'); };
s.onmessage = function (e) { document.getElementById('o').textContent = e.data; };
</script></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sink := &frameMemSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := RunSpider(ctx, SpiderConfig{TargetURL: srv.URL, MaxStates: 2, MaxDepth: 1, MaxDuration: 20 * time.Second,
		Headless: true, IncludeResponseBody: true, IncludeHeaders: true}, sink); err != nil {
		t.Fatalf("RunSpider: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var sent, received bool
	for _, f := range sink.frames {
		if f.URL != "ws"+srv.URL[len("http"):]+"/ws" || f.Opcode != 1 || f.PayloadEncoding != PayloadText {
			continue
		}
		sent = sent || (f.Direction == FrameSent && f.PayloadHead == `{"op":"subscribe","topic":"orders"}`)
		received = received || (f.Direction == FrameReceived && f.PayloadHead == `echo:{"op":"subscribe","topic":"orders"}`)
	}
	if !sent || !received {
		t.Fatalf("frames = %+v; want the sent subscribe and its echo", sink.frames)
	}
}
