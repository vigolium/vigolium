package database

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSaveWebSocketFrames(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	long := strings.Repeat("é", MaxWebSocketPayloadHead) // 2 bytes a rune
	frames := []WebSocketFrame{
		{URL: "wss://App.test/ws", Hostname: "App.Test", ConnectionID: "c1", Direction: WebSocketFrameSent,
			Opcode: 1, PayloadLength: 13, PayloadHead: `{"op":"sub"}`, PayloadEncoding: WebSocketPayloadText},
		{URL: "wss://app.test/ws", Hostname: "app.test", ConnectionID: "c1", Direction: WebSocketFrameReceived,
			Opcode: 1, PayloadLength: len(long), PayloadHead: long, PayloadEncoding: WebSocketPayloadText},
		{URL: "wss://other.test/ws", Hostname: "other.test", ConnectionID: "c2", Direction: WebSocketFrameReceived,
			Opcode: 2, PayloadLength: 3, PayloadHead: "AQID", PayloadEncoding: WebSocketPayloadBase64, ScanUUID: "own-scan"},
		{URL: "", Direction: WebSocketFrameSent},                         // no URL: skipped
		{URL: "wss://app.test/ws", Hostname: "app.test", Direction: "x"}, // bad direction: skipped
	}
	if err := repo.SaveWebSocketFrames(ctx, "", "scan-1", frames); err != nil {
		t.Fatal(err)
	}

	got, err := repo.ListWebSocketFrames(ctx, "", "APP.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("app.test frames = %d, want 2", len(got))
	}
	if got[0].Direction != WebSocketFrameSent || got[0].PayloadHead != `{"op":"sub"}` || got[0].ScanUUID != "scan-1" ||
		got[0].Hostname != "app.test" || got[0].ObservedAt.IsZero() || got[0].ProjectUUID == "" {
		t.Fatalf("first frame = %+v", got[0])
	}
	if !got[1].PayloadTruncated || len(got[1].PayloadHead) > MaxWebSocketPayloadHead || !strings.HasPrefix(long, got[1].PayloadHead) ||
		got[1].PayloadLength != len(long) {
		t.Fatalf("long frame: truncated=%v head=%d bytes length=%d", got[1].PayloadTruncated, len(got[1].PayloadHead), got[1].PayloadLength)
	}
	all, _ := repo.ListWebSocketFrames(ctx, "", "", 0)
	if len(all) != 3 || all[2].ScanUUID != "own-scan" || all[2].Opcode != 2 {
		t.Fatalf("all frames = %+v", all)
	}

	// The record writer stamps its own scan.
	w := NewRecordWriter(repo, RecordWriterConfig{ScanUUID: "scan-2"})
	defer w.Close()
	if err := w.SaveWebSocketFrames(ctx, "", []WebSocketFrame{{URL: "ws://x.test/", Hostname: "x.test", ConnectionID: "c",
		Direction: WebSocketFrameReceived, Opcode: 9, ObservedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	x, _ := repo.ListWebSocketFrames(ctx, "", "x.test", 1)
	if len(x) != 1 || x[0].ScanUUID != "scan-2" {
		t.Fatalf("writer frame = %+v", x)
	}
}

func TestSchemaDeclaresTable(t *testing.T) {
	if !SchemaDeclaresTable("websocket_frames") || !SchemaDeclaresTable("HTTP_RECORDS") || SchemaDeclaresTable("nope") {
		t.Fatal("SchemaDeclaresTable disagrees with the schema")
	}
}
