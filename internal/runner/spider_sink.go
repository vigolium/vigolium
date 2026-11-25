package runner

import (
	"context"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// spiderSink is the scan record writer as the crawl's store: its records, and
// its WebSocket frames into websocket_frames under the writer's scan.
type spiderSink struct {
	*database.RecordWriter
}

// SaveWebSocketFrames implements spitolas.FrameSaver.
func (s spiderSink) SaveWebSocketFrames(ctx context.Context, projectUUID string, frames []spitolas.WebSocketFrame) error {
	return s.RecordWriter.SaveWebSocketFrames(ctx, projectUUID, toDBFrames(frames))
}

// toDBFrames converts the crawl's frames to rows.
func toDBFrames(frames []spitolas.WebSocketFrame) []database.WebSocketFrame {
	out := make([]database.WebSocketFrame, 0, len(frames))
	for _, f := range frames {
		out = append(out, database.WebSocketFrame{
			Source:           "spidering",
			URL:              f.URL,
			Hostname:         f.Host,
			ConnectionID:     f.ConnectionID,
			Direction:        f.Direction,
			Opcode:           f.Opcode,
			PayloadLength:    f.PayloadLength,
			PayloadHead:      f.PayloadHead,
			PayloadEncoding:  f.PayloadEncoding,
			PayloadTruncated: f.Truncated,
			ObservedAt:       f.At,
		})
	}
	return out
}

var _ spitolas.FrameSaver = spiderSink{}
