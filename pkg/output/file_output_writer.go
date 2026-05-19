package output

import (
	"bufio"
	"os"
	"sync"
)

const outputBufSize = 64 * 1024 // 64 KiB write buffer

// fileWriter is a concurrent file based output writer with buffered I/O.
type fileWriter struct {
	file *os.File
	buf  *bufio.Writer
	mu   sync.Mutex
}

// newFileOutputWriter creates a new buffered writer for a file
func newFileOutputWriter(file string, resume bool) (*fileWriter, error) {
	var output *os.File
	var err error
	if resume {
		output, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		output, err = os.Create(file)
	}
	if err != nil {
		return nil, err
	}
	return &fileWriter{
		file: output,
		buf:  bufio.NewWriterSize(output, outputBufSize),
	}, nil
}

// Write appends data + newline to the buffer. The buffer is flushed to
// disk automatically when it reaches 64 KiB, or explicitly on Close().
func (w *fileWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n, err := w.buf.Write(data)
	if err != nil {
		return n, err
	}
	if err := w.buf.WriteByte('\n'); err != nil {
		return n, err
	}
	return n + 1, nil
}

// Close flushes the buffer, syncs the file, and closes the handle.
func (w *fileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.buf.Flush(); err != nil {
		_ = w.file.Close()
		return err
	}
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	return w.file.Close()
}
