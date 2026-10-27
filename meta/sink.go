package meta

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

// Sink 是统一的输出汇。
// 封装「内存缓冲 / io.Writer / 文件 / 标准输出」四种去处，
// 并按 Encoding 对写入内容做编码（对应 CLI 的 `-hex` / `-base64`）。
//
// nil *Sink 等价于标准输出（与铜锁 CLI 的 `-out` 默认 stdout 对齐）。
//
// Sink is the unified output sink. It wraps the four ways of emitting data
// — an in-memory buffer, an io.Writer, a file and standard output — and
// encodes the written bytes according to the Encoding (mirroring the
// CLI's -hex / -base64).
//
// A nil *Sink is equivalent to standard output, matching the Tongsuo
// CLI's `-out` defaulting to stdout.
//
// Sink 不是并发安全的；调用方负责在 Close 之前完成全部写入。
//
// Sink is not safe for concurrent use; callers must finish all writes
// before Close.
type Sink struct {
	mu      sync.Mutex
	kind    sinkKind
	buf     bytes.Buffer
	writer  io.Writer
	path    string
	file    *os.File
	enc     Encoding
	encoder io.WriteCloser
	wrote   bool
	closed  bool
}

// sinkKind 区分 Sink 的四种去处。
//
// sinkKind distinguishes the four flavours of Sink.
type sinkKind int

const (
	// sinkBytes 写入内存缓冲。
	sinkBytes sinkKind = iota
	// sinkWriter 写入 io.Writer。
	sinkWriter
	// sinkFile 写入文件路径。
	sinkFile
	// sinkStdout 写入标准输出。
	sinkStdout
)

// NewBytesSink 创建写入内存缓冲的输出汇。
//
// NewBytesSink creates an output sink writing to an in-memory buffer.
func NewBytesSink() *Sink {
	return &Sink{kind: sinkBytes, enc: EncodingRaw}
}

// NewWriterSink 创建写入 io.Writer 的输出汇。
// 写入器不会被本包关闭。
//
// NewWriterSink creates an output sink writing to an io.Writer. The writer
// is not closed by this package.
func NewWriterSink(w io.Writer) *Sink {
	return &Sink{kind: sinkWriter, writer: w, enc: EncodingRaw}
}

// NewFileSink 创建写入文件路径的输出汇。
// 路径 "-" 表示标准输出。
// 文件在首次写入时创建（不存在则新建，存在则截断）。
// 构造时只校验路径非空；打开失败在首次写入或 Close 时报告。
//
// NewFileSink creates an output sink writing to a file path. The path "-"
// denotes standard output. The file is created on the first write (newly
// created if missing, truncated otherwise). The constructor only rejects
// an empty path; a failure to open is reported on the first write or on
// Close.
func NewFileSink(path string) (*Sink, error) {
	if path == "" {
		return nil, fmt.Errorf("meta: empty sink path")
	}
	if path == "-" {
		return StdoutSink(), nil
	}
	return &Sink{kind: sinkFile, path: path, enc: EncodingRaw}, nil
}

// StdoutSink 返回写入标准输出的输出汇。
//
// StdoutSink returns an output sink writing to standard output.
func StdoutSink() *Sink {
	return &Sink{kind: sinkStdout, enc: EncodingRaw}
}

// Path 返回文件汇的路径；非文件汇返回空串。
//
// Path returns the path of a file sink; it returns an empty string for
// other kinds of sink.
func (s *Sink) Path() string {
	if s == nil || s.kind != sinkFile {
		return ""
	}
	return s.path
}

// Encoding 返回当前输出编码。
//
// Encoding returns the current output encoding.
func (s *Sink) Encoding() Encoding {
	if s == nil {
		return EncodingRaw
	}
	return s.enc
}

// SetEncoding 设置输出编码。
// 必须在第一次写入之前调用；已写入数据后设置返回错误。
// 未知编码返回错误。
//
// SetEncoding sets the output encoding. It must be called before the first
// write; calling it after data has been written yields an error. An
// unknown encoding yields an error.
func (s *Sink) SetEncoding(enc Encoding) error {
	if s == nil {
		return fmt.Errorf("meta: nil sink")
	}
	switch enc {
	case EncodingRaw, EncodingHex, EncodingBase64:
	default:
		return fmt.Errorf("meta: unknown encoding %q", string(enc))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wrote {
		return fmt.Errorf("meta: cannot change encoding after writing")
	}
	s.enc = enc
	return nil
}

// Write 写入数据，按当前编码做转换。
// nil 接收者等价于标准输出。
//
// Write writes data, converting it according to the current encoding. A
// nil receiver is equivalent to standard output.
func (s *Sink) Write(p []byte) (int, error) {
	if s == nil {
		return os.Stdout.Write(p)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("meta: sink closed")
	}
	if err := s.ensureOpen(); err != nil {
		return 0, err
	}
	s.wrote = true
	switch s.enc {
	case EncodingRaw:
		return s.raw().Write(p)
	case EncodingHex:
		out := make([]byte, hex.EncodedLen(len(p)))
		hex.Encode(out, p)
		if _, err := s.raw().Write(out); err != nil {
			return 0, err
		}
		return len(p), nil
	case EncodingBase64:
		// base64 以 3 字节为组编码，跨块需保留余量，故用流式编码器。
		if s.encoder == nil {
			s.encoder = base64.NewEncoder(base64.StdEncoding, s.raw())
		}
		if _, err := s.encoder.Write(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return 0, fmt.Errorf("meta: unknown encoding %q", string(s.enc))
}

// ensureOpen 按需打开底层去处（调用方须持有锁）。
//
// ensureOpen opens the underlying destination on demand (the caller must
// hold the lock).
func (s *Sink) ensureOpen() error {
	switch s.kind {
	case sinkBytes, sinkWriter, sinkStdout:
		return nil
	case sinkFile:
		if s.file != nil {
			return nil
		}
		f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("meta: open sink %q: %w", s.path, err)
		}
		s.file = f
		return nil
	}
	return fmt.Errorf("meta: unknown sink kind")
}

// raw 返回底层写入器（调用方须持有锁）。
//
// raw returns the underlying writer (the caller must hold the lock).
func (s *Sink) raw() io.Writer {
	switch s.kind {
	case sinkBytes:
		return &s.buf
	case sinkWriter:
		return s.writer
	case sinkFile:
		if s.file != nil {
			return s.file
		}
		return io.Discard
	case sinkStdout:
		return os.Stdout
	}
	return io.Discard
}

// Bytes 返回内存汇已写入内容的副本。
// 非内存汇返回 nil。
//
// Bytes returns a copy of the content written to an in-memory sink. It
// returns nil for other kinds of sink.
func (s *Sink) Bytes() []byte {
	if s == nil || s.kind != sinkBytes {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

// Close 关闭输出汇，结束流式编码并关闭文件。
// 幂等；重复调用返回 nil。
//
// Close closes the output sink, finalising the streaming encoding and
// closing the file. It is idempotent; repeated calls return nil.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var firstErr error
	if s.encoder != nil {
		if err := s.encoder.Close(); err != nil {
			firstErr = err
		}
		s.encoder = nil
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.file = nil
	}
	return firstErr
}
