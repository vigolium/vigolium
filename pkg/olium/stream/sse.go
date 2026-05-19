package stream

import (
	"bufio"
	"io"
	"strings"
)

// SSEEvent is a single decoded Server-Sent Events message.
type SSEEvent struct {
	Event string
	Data  string
}

// SSEReader reads an SSE byte stream and yields one SSEEvent at a time.
// Events are separated by a blank line; multi-line data: fields are joined
// with "\n" per the EventSource spec.
type SSEReader struct {
	scanner *bufio.Scanner
}

func NewSSEReader(r io.Reader) *SSEReader {
	sc := bufio.NewScanner(r)
	// Provider responses can include large tool-call argument deltas. Give the
	// scanner a generous buffer so a single SSE frame doesn't overflow.
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 8*1024*1024)
	sc.Split(bufio.ScanLines)
	return &SSEReader{scanner: sc}
}

// Next returns the next SSEEvent, or io.EOF when the stream ends.
func (r *SSEReader) Next() (*SSEEvent, error) {
	var (
		evt       SSEEvent
		dataLines []string
		gotAny    bool
	)

	for r.scanner.Scan() {
		line := r.scanner.Text()
		if line == "" {
			if gotAny {
				evt.Data = strings.Join(dataLines, "\n")
				return &evt, nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue // comment
		}

		var field, value string
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			field = line[:idx]
			value = strings.TrimPrefix(line[idx+1:], " ")
		} else {
			field = line
		}

		switch field {
		case "event":
			evt.Event = value
			gotAny = true
		case "data":
			dataLines = append(dataLines, value)
			gotAny = true
		}
	}

	if err := r.scanner.Err(); err != nil {
		return nil, err
	}
	if gotAny {
		evt.Data = strings.Join(dataLines, "\n")
		return &evt, nil
	}
	return nil, io.EOF
}
