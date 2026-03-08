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
