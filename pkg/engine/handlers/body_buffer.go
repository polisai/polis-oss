package handlers

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
)

type hybridBuffer struct {
	threshold   int64
	size        int64
	buffer      bytes.Buffer
	file        *os.File
	tempPath    string // Track temp file path for cleanup
	transferred bool   // Track if ownership was transferred to Reader()
}

func newHybridBuffer(threshold int64) *hybridBuffer {
	if threshold <= 0 {
		threshold = 1 * 1024 * 1024 // default 1MB
	}
	hb := &hybridBuffer{threshold: threshold}
	// Set finalizer to ensure cleanup if buffer is abandoned
	runtime.SetFinalizer(hb, func(b *hybridBuffer) {
		b.Cleanup()
	})
	return hb
}

func (b *hybridBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if b.file != nil {
		n, err := b.file.Write(p)
		b.size += int64(n)
		return n, err
	}

	projected := b.size + int64(len(p))
	if projected <= b.threshold {
		n, err := b.buffer.Write(p)
		b.size += int64(n)
		return n, err
	}

	if err := b.promoteToFile(); err != nil {
		return 0, err
	}

	n, err := b.file.Write(p)
	b.size += int64(n)
	return n, err
}

func (b *hybridBuffer) promoteToFile() error {
	if b.file != nil {
		return nil
	}

	file, err := os.CreateTemp("", "proxy-dlp-body-*")
	if err != nil {
		return fmt.Errorf("dlp: failed to create temp buffer: %w", err)
	}

	// Track the temp file path for cleanup
	b.tempPath = file.Name()

	if b.buffer.Len() > 0 {
		if _, err := file.Write(b.buffer.Bytes()); err != nil {
			_ = file.Close()
			_ = os.Remove(b.tempPath)
			b.tempPath = ""
			return fmt.Errorf("dlp: failed to persist buffer: %w", err)
		}
		b.buffer.Reset()
	}

	b.file = file
	return nil
}

func (b *hybridBuffer) Reader() (io.ReadCloser, error) {
	if b.file != nil {
		if _, err := b.file.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("dlp: failed to rewind buffer: %w", err)
		}
		replay := &tempReplayBody{file: b.file, path: b.tempPath}
		// Transfer ownership to reader - clear finalizer and mark as transferred
		b.transferred = true
		b.file = nil
		b.tempPath = ""
		runtime.SetFinalizer(b, nil)
		return replay, nil
	}

	data := b.buffer.Bytes()
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *hybridBuffer) Cleanup() {
	if b.file != nil && !b.transferred {
		path := b.tempPath
		if path == "" {
			path = b.file.Name()
		}
		_ = b.file.Close()
		_ = os.Remove(path)
		b.file = nil
		b.tempPath = ""
	}
	b.buffer.Reset()
	b.size = 0
	runtime.SetFinalizer(b, nil)
}

func (b *hybridBuffer) Len() int {
	if b.size < 0 {
		return 0
	}
	return int(b.size)
}

type tempReplayBody struct {
	file *os.File
	path string
}

func (t *tempReplayBody) Read(p []byte) (int, error) {
	return t.file.Read(p)
}

func (t *tempReplayBody) Close() error {
	err := t.file.Close()
	errRemove := os.Remove(t.path)
	if err == nil {
		err = errRemove
	}
	return err
}

// Len returns the size of the file, allowing for Content-Length calculation.
func (t *tempReplayBody) Len() int {
	info, err := t.file.Stat()
	if err != nil {
		return 0
	}
	return int(info.Size())
}
