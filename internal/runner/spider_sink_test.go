package runner

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// The crawl's frames become websocket_frames rows field for field.
func TestToDBFrames(t *testing.T) {
	at := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	got := toDBFrames([]spitolas.WebSocketFrame{{URL: "wss://app.test/ws", Host: "app.test", ConnectionID: "r1",
		Direction: spitolas.FrameReceived, Opcode: 2, PayloadLength: 9000, PayloadHead: "AQID",
		PayloadEncoding: spitolas.PayloadBase64, Truncated: true, At: at}})
	want := database.WebSocketFrame{Source: "spidering", URL: "wss://app.test/ws", Hostname: "app.test", ConnectionID: "r1",
		Direction: database.WebSocketFrameReceived, Opcode: 2, PayloadLength: 9000, PayloadHead: "AQID",
		PayloadEncoding: database.WebSocketPayloadBase64, PayloadTruncated: true, ObservedAt: at}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("rows = %+v\nwant %+v", got, want)
	}
}
