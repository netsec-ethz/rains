package borat

import (
	"bytes"
	"io"
)

// DebugWriter wraps a writer and provides functionality to
// dump what was written to the writer.
type DebugWriter struct {
	buf        *bytes.Buffer
	underlying io.Writer
}

// NewDebugWriter creates a DebugWriter instance.
func NewDebugWriter(underlying io.Writer) *DebugWriter {
	return &DebugWriter{
		buf:        bytes.NewBuffer(make([]byte, 0)),
		underlying: underlying,
	}
}

// Write will write the provided byte slice to the buffer and
// the underlying writer. If there is an error writing to the
// buffer, the underlying sink will not be written to and the
// error returned.
func (dw *DebugWriter) Write(p []byte) (int, error) {
	if n, err := dw.buf.Write(p); err != nil {
		return n, err
	}
	return dw.underlying.Write(p)
}

// RetrieveReset returns the current buffer and resets it for
// future writing. Note that the buffer is unchanged, writing
// to the buffer will overwrite the buffer's underlying bytes.
func (dw *DebugWriter) RetrieveReset() []byte {
	buf := dw.buf.Bytes()
	dw.buf.Reset()
	return buf
}
