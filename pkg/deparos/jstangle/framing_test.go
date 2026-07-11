package jstangle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

func TestLengthFramesRoundTrip(t *testing.T) {
	var stream bytes.Buffer
	for _, payload := range [][]byte{[]byte(`{"id":1}`), []byte("source bytes")} {
		if err := writeLengthFrame(&stream, payload, 1024); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}
	for _, want := range [][]byte{[]byte(`{"id":1}`), []byte("source bytes")} {
		got, err := readLengthFrame(&stream, 1024)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame = %q, want %q", got, want)
		}
	}
}

func TestLengthFrameRejectsBoundsAndTruncation(t *testing.T) {
	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 9)
	oversized.Write(header[:])
	if _, err := readLengthFrame(&oversized, 8); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}

	var truncated bytes.Buffer
	binary.BigEndian.PutUint32(header[:], 5)
	truncated.Write(header[:])
	truncated.WriteString("xx")
	if _, err := readLengthFrame(&truncated, 8); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated error = %v", err)
	}
}

func TestLengthFrameHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{}
	if err := writeLengthFrame(writer, []byte("abcdef"), 10); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got, err := readLengthFrame(&writer.Buffer, 10)
	if err != nil {
		t.Fatalf("read short-written frame: %v", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("payload = %q", got)
	}
}
