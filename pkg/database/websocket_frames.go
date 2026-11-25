package database

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// WebSocket frame directions (WebSocketFrame.Direction).
const (
	WebSocketFrameSent     = "sent"
	WebSocketFrameReceived = "received"
)

// Payload encodings (WebSocketFrame.PayloadEncoding): a text frame's head is
// the UTF-8 text, any other opcode's head is base64 of the bytes.
const (
	WebSocketPayloadText   = "text"
	WebSocketPayloadBase64 = "base64"
)

// MaxWebSocketPayloadHead bounds the payload bytes a frame row keeps. A frame
// is evidence of a message's shape, not an archive of the stream.
const MaxWebSocketPayloadHead = 4096

// WebSocketFrame is one WebSocket frame the browser crawl observed. Frames are
// rows of their own rather than http_records: a socket is one upgrade request
// followed by an open-ended conversation, and the frames are read per socket in
// order.
type WebSocketFrame struct {
	bun.BaseModel `bun:"table:websocket_frames,alias:wsf" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	Source      string `bun:"source,nullzero" json:"source,omitempty"`
	URL         string `bun:"url,notnull" json:"url"`
	Hostname    string `bun:"hostname,notnull" json:"hostname"`
	// ConnectionID names the socket within one crawl (the browser's request
	// id for the upgrade); frames sharing it are one conversation.
	ConnectionID string `bun:"connection_id,notnull" json:"connection_id"`
	Direction    string `bun:"direction,notnull" json:"direction"`
	// Opcode is the RFC 6455 opcode: 1 text, 2 binary, 8 close, 9 ping, 10 pong.
	Opcode int `bun:"opcode,notnull" json:"opcode"`
	// PayloadLength is the whole payload's size in bytes; PayloadHead keeps at
	// most MaxWebSocketPayloadHead of them, PayloadTruncated says it was cut.
	PayloadLength    int       `bun:"payload_length,notnull" json:"payload_length"`
	PayloadHead      string    `bun:"payload_head,nullzero" json:"payload_head,omitempty"`
	PayloadEncoding  string    `bun:"payload_encoding,nullzero" json:"payload_encoding,omitempty"`
	PayloadTruncated bool      `bun:"payload_truncated,notnull" json:"payload_truncated"`
	ObservedAt       time.Time `bun:"observed_at,notnull,default:current_timestamp" json:"observed_at"`
}

// SchemaDeclaresTable reports whether this binary's schema creates table name
// (the CREATE TABLE list every writer applies on open).
func SchemaDeclaresTable(name string) bool {
	pattern := regexp.MustCompile(ddlObjectPattern)
	for _, ddl := range schemaTables {
		if m := pattern.FindStringSubmatch(ddl); m != nil && strings.EqualFold(m[1], name) {
			return true
		}
	}
	return false
}

// SaveWebSocketFrames inserts frames in one statement, stamping the project
// (the default project when empty) and, where a frame carries none, scanUUID.
// Frames without a URL or direction are skipped; heads past
// MaxWebSocketPayloadHead are cut and marked truncated.
func (r *Repository) SaveWebSocketFrames(ctx context.Context, projectUUID, scanUUID string, frames []WebSocketFrame) error {
	if r == nil || r.db == nil || len(frames) == 0 {
		return nil
	}
	project := defaultProjectUUID(projectUUID)
	now := time.Now().UTC()
	rows := make([]WebSocketFrame, 0, len(frames))
	for _, f := range frames {
		if f.URL == "" || (f.Direction != WebSocketFrameSent && f.Direction != WebSocketFrameReceived) {
			continue
		}
		f.ID = 0
		f.ProjectUUID = project
		if f.ScanUUID == "" {
			f.ScanUUID = scanUUID
		}
		f.Hostname = strings.ToLower(f.Hostname)
		if f.ObservedAt.IsZero() {
			f.ObservedAt = now
		}
		if len(f.PayloadHead) > MaxWebSocketPayloadHead {
			f.PayloadHead = f.PayloadHead[:textutil.CutIndex(f.PayloadHead, MaxWebSocketPayloadHead)]
			f.PayloadTruncated = true
		}
		rows = append(rows, f)
	}
	if len(rows) == 0 {
		return nil
	}
	_, err := r.db.NewInsert().Model(&rows).Exec(ctx)
	return err
}

// ListWebSocketFrames returns a project's frames in capture order, for one
// host when hostname is set, at most limit (0 = all).
func (r *Repository) ListWebSocketFrames(ctx context.Context, projectUUID, hostname string, limit int) ([]WebSocketFrame, error) {
	var out []WebSocketFrame
	q := r.db.NewSelect().Model(&out).Where("project_uuid = ?", defaultProjectUUID(projectUUID)).Order("id ASC")
	if hostname != "" {
		q = q.Where("hostname = ?", strings.ToLower(hostname))
	}
	if limit > 0 {
		q = q.Limit(int64(limit))
	}
	if err := q.Scan(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// SaveWebSocketFrames persists frames for this writer's scan. Frames are rare
// beside records and arrive already batched by the capture, so they go to the
// repository directly rather than through the record shards.
func (w *RecordWriter) SaveWebSocketFrames(ctx context.Context, projectUUID string, frames []WebSocketFrame) error {
	if w == nil || w.repo == nil {
		return nil
	}
	return w.repo.SaveWebSocketFrames(ctx, projectUUID, w.cfg.ScanUUID, frames)
}
