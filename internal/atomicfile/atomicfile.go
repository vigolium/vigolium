// Package atomicfile writes files atomically: content is streamed into a temp
// file in the destination directory and renamed into place only on success, so a
// failed or partial write never replaces or half-writes the destination.
package atomicfile

import (
	"bufio"
	"os"
	"path/filepath"
)

// Write atomically writes path's contents via write. It creates a temp file in
// path's directory, hands write a buffered writer, then flushes and renames the
// temp file over path on success. If write returns an error (or any I/O step
// fails) path is left untouched and the temp file is removed.
//
// write receives a *bufio.Writer so callers needing WriteByte/WriteString (e.g.
// incremental JSON array framing) can use them directly; it satisfies io.Writer
// for the common case.
func Write(path string, write func(w *bufio.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	bw := bufio.NewWriter(tmp)
	if err := write(bw); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return nil
}
