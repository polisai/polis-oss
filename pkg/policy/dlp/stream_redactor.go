package dlp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
)

// ChunkSize returns the preferred chunk size for stream processing.
func (r *StreamRedactor) ChunkSize() int {
	if r == nil {
		return defaultChunkSize
	}
	return r.chunkSize
}

// RedactStream reads from src, applies DLP redactions, and streams to dst.
func (r *StreamRedactor) RedactStream(ctx context.Context, src io.Reader, dst io.Writer) (Report, error) {
	buf := make([]byte, r.ChunkSize())

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if err := r.processChunk(ctx, buf[:n], dst); err != nil {
				if errors.Is(err, ErrBlocked) || errors.Is(err, errMaxReadExceeded) || errors.Is(err, errMaxFindingsExceeded) {
					return r.Report(), err
				}
				return Report{}, fmt.Errorf("dlp: failed to process chunk: %w", err)
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				if err := r.flush(dst); err != nil {
					return Report{}, fmt.Errorf("dlp: failed to flush tail: %w", err)
				}
				return r.Report(), nil
			}
			return Report{}, fmt.Errorf("dlp: read error: %w", readErr)
		}
	}
}

func (r *StreamRedactor) processChunk(ctx context.Context, chunk []byte, dst io.Writer) error {
	if len(chunk) == 0 {
		return nil
	}

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	if r.maxRead > 0 && r.totalRead+int64(len(chunk)) > r.maxRead {
		return errMaxReadExceeded
	}

	r.bufferRaw = append(r.bufferRaw, chunk...)
	r.totalRead += int64(len(chunk))

	baseOffset := r.totalRead - int64(len(r.bufferRaw))
	emitLen := len(r.bufferRaw) - r.overlap
	if emitLen < 0 {
		emitLen = 0
	}

	return r.emitBuffer(baseOffset, emitLen, dst, false)
}

func (r *StreamRedactor) flush(dst io.Writer) error {
	if len(r.bufferRaw) == 0 {
		return nil
	}
	baseOffset := r.totalRead - int64(len(r.bufferRaw))
	if err := r.emitBuffer(baseOffset, len(r.bufferRaw), dst, true); err != nil {
		return err
	}
	r.bufferRaw = r.bufferRaw[:0]
	return nil
}

func (r *StreamRedactor) emitBuffer(baseOffset int64, emitLen int, dst io.Writer, final bool) error {
	bufferStr := string(r.bufferRaw)
	safeEmit := emitLen

	// 1. Determine safeEmit point based on original buffer (avoid splitting matches)
	for _, rule := range r.scanner.rules {
		indices := rule.expr.FindAllStringIndex(bufferStr, -1)
		for _, idx := range indices {
			if rule.action == ActionBlock {
				r.blocked = true
			}
			// If a match crosses the emit boundary, pull back the boundary to the start of the match
			if idx[0] < safeEmit && idx[1] > safeEmit {
				safeEmit = idx[0]
			}
		}

		// Record findings that fall within the safe emit region
		for _, idx := range indices {
			if !final && idx[1] > safeEmit {
				continue
			}
			if len(r.findings) >= r.maxFindings {
				return errMaxFindingsExceeded
			}

			absStart := baseOffset + int64(idx[0])
			absEnd := baseOffset + int64(idx[1])

			r.findings = append(r.findings, Finding{
				Rule:   rule.name,
				Match:  "", // We don't store the match content to save memory/avoid PII storage
				Start:  int(absStart),
				End:    int(absEnd),
				Action: rule.action,
			})
		}
	}

	if r.blocked {
		if r.deferEmission {
			r.pending.Reset()
		}
		return ErrBlocked
	}

	if safeEmit > len(r.bufferRaw) {
		safeEmit = len(r.bufferRaw)
	}

	writer := dst
	if r.deferEmission {
		writer = &r.pending
	}

	if safeEmit > 0 {
		// 2. Extract the chunk we are safely emitting
		chunkToEmit := bufferStr[:safeEmit]
		redactedChunk := chunkToEmit

		// 3. Apply redactions ONLY to this chunk
		for _, rule := range r.scanner.rules {
			if rule.action == ActionRedact {
				redactedChunk = rule.expr.ReplaceAllStringFunc(redactedChunk, func(string) string {
					return rule.replacement
				})
				if redactedChunk != chunkToEmit {
					r.redactionsApplied = true
				}
			}
		}

		// 4. Write the redacted chunk
		if _, err := writer.Write([]byte(redactedChunk)); err != nil {
			return err
		}

		// 5. Shift the original buffer by the amount of ORIGINAL bytes consumed
		copy(r.bufferRaw, r.bufferRaw[safeEmit:])
		r.bufferRaw = r.bufferRaw[:len(r.bufferRaw)-safeEmit]
	}

	if final && r.deferEmission && !r.blocked {
		if r.pending.Len() > 0 {
			if _, err := dst.Write(r.pending.Bytes()); err != nil {
				return err
			}
			r.pending.Reset()
		}
	}

	return nil
}

// Report summarises the streaming redaction outcome.
func (r *StreamRedactor) Report() Report {
	findings := append([]Finding(nil), r.findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return findings[i].End < findings[j].End
		}
		return findings[i].Start < findings[j].Start
	})

	return Report{
		Findings:          findings,
		Redacted:          "",
		RedactionsApplied: r.redactionsApplied,
		Blocked:           r.blocked,
	}
}
