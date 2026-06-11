package output

type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter creates a new MultiWriter instance
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (mw *MultiWriter) Close() {
	for _, writer := range mw.writers {
		writer.Close()
	}
}
func (mw *MultiWriter) Write(event *ResultEvent) error {
	for _, writer := range mw.writers {
		if err := writer.Write(event); err != nil {
			return err
		}
	}
	return nil
}

func (mw *MultiWriter) WriteFileOnly(event *ResultEvent) error {
	for _, writer := range mw.writers {
		if err := writer.WriteFileOnly(event); err != nil {
			return err
		}
	}
	return nil
}

// ShowsFindingsOnStdout reports whether any underlying writer renders findings to
// stdout in human-readable form (see StandardWriter.ShowsFindingsOnStdout).
func (mw *MultiWriter) ShowsFindingsOnStdout() bool {
	for _, writer := range mw.writers {
		if s, ok := writer.(interface{ ShowsFindingsOnStdout() bool }); ok && s.ShowsFindingsOnStdout() {
			return true
		}
	}
	return false
}
