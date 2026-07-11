package jstangle

import (
	"encoding/binary"
	"fmt"
	"io"
)

const maxControlFrameBytes = 2 * 1024 * 1024

func writeLengthFrame(w io.Writer, payload []byte, maxBytes int64) error {
	if len(payload) == 0 {
		return fmt.Errorf("%w: zero-length frame", ErrIncompleteOutput)
	}
	if int64(len(payload)) > maxBytes || uint64(len(payload)) > uint64(^uint32(0)) {
		return fmt.Errorf("%w: frame=%d limit=%d", ErrOutputTooLarge, len(payload), maxBytes)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func readLengthFrame(r io.Reader, maxBytes int64) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int64(binary.BigEndian.Uint32(header[:]))
	if length <= 0 {
		return nil, fmt.Errorf("%w: zero-length frame", ErrIncompleteOutput)
	}
	if length > maxBytes {
		return nil, fmt.Errorf("%w: frame=%d limit=%d", ErrOutputTooLarge, length, maxBytes)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
