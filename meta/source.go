package meta

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrSourceConsumed 表示一次性输入源已被读取。
//
// ErrSourceConsumed reports that a single-use input source has already
// been read.
var ErrSourceConsumed = errors.New("meta: source already consumed")

// Source 是统一的输入源。
// 封装「字节 / io.Reader / 文件 / 标准输入」四种来源，
// 让上层入口（摘要、加解密、MAC、派生）只需面对一个类型。
//
// nil *Source 等价于标准输入（与铜锁 CLI 的 `-in` 默认 stdin 对齐）。
//
// Source is the unified input source. It wraps the four ways of feeding
// data — bytes, an io.Reader, a file and standard input — so that the
// upper-level entry points (digest, cipher, MAC, KDF) only deal with one
// type.
//
// A nil *Source is equivalent to standard input, matching the Tongsuo
// CLI's `-in` defaulting to stdin.
//
// 使用方必须调用 Close 关闭返回的 io.ReadCloser。
//
// Callers must close the returned io.ReadCloser.
type Source struct {
	kind   sourceKind
	data   []byte
	reader io.Reader
	path   string
	used   bool
}

// sourceKind 区分 Source 的四种来源。
//
// sourceKind distinguishes the four flavours of Source.
type sourceKind int

const (
	// sourceBytes 来自内存字节。
	sourceBytes sourceKind = iota
	// sourceReader 来自 io.Reader（一次性）。
	sourceReader
	// sourceFile 来自文件路径。
	sourceFile
	// sourceStdin 来自标准输入。
	sourceStdin
)

// NewBytesSource 以内存字节构造输入源。
// 构造时会拷贝 data，调用方后续修改不影响源内容。
//
// NewBytesSource builds an input source from in-memory bytes. The data is
// copied, so later mutation by the caller does not affect the source.
func NewBytesSource(data []byte) *Source {
	return &Source{kind: sourceBytes, data: append([]byte(nil), data...)}
}

// NewReaderSource 以 io.Reader 构造输入源。
// 该源是**一次性**的：首次 Open 后再次 Open 返回 ErrSourceConsumed。
// 读取器不会被本包关闭。
//
// NewReaderSource builds an input source from an io.Reader. The source is
// **single-use**: a second Open returns ErrSourceConsumed. The reader
// itself is not closed by this package.
func NewReaderSource(r io.Reader) *Source {
	return &Source{kind: sourceReader, reader: r}
}

// NewFileSource 以文件路径构造输入源。
// 路径 "-" 表示标准输入。
// 文件在每次 Open 时重新打开，可多次使用。
// 构造时只校验路径非空，不检查文件是否存在（错误在 Open 时报告）。
//
// NewFileSource builds an input source from a file path. The path "-"
// denotes standard input. The file is reopened on every Open, so the
// source can be used repeatedly. The constructor only rejects an empty
// path; a missing file is reported by Open.
func NewFileSource(path string) (*Source, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("meta: empty source path")
	}
	if path == "-" {
		return StdinSource(), nil
	}
	return &Source{kind: sourceFile, path: path}, nil
}

// StdinSource 返回读取标准输入的输入源。
// 该源是**一次性**的：首次 Open 后再次 Open 返回 ErrSourceConsumed。
//
// StdinSource returns an input source reading standard input. The source
// is **single-use**: a second Open returns ErrSourceConsumed.
func StdinSource() *Source {
	return &Source{kind: sourceStdin}
}

// Path 返回文件源的路径；非文件源返回空串。
//
// Path returns the path of a file source; it returns an empty string for
// other kinds of source.
func (s *Source) Path() string {
	if s == nil || s.kind != sourceFile {
		return ""
	}
	return s.path
}

// Open 打开输入源并返回读取器。
// nil 接收者等价于标准输入。
// 一次性源被重复打开时返回 ErrSourceConsumed；文件不存在时返回底层错误。
//
// Open opens the input source and returns a reader. A nil receiver is
// equivalent to standard input. Re-opening a single-use source returns
// ErrSourceConsumed; a missing file yields the underlying error.
func (s *Source) Open() (io.ReadCloser, error) {
	if s == nil {
		return io.NopCloser(os.Stdin), nil
	}
	switch s.kind {
	case sourceBytes:
		return io.NopCloser(bytes.NewReader(s.data)), nil
	case sourceReader:
		if s.used {
			return nil, ErrSourceConsumed
		}
		s.used = true
		return io.NopCloser(s.reader), nil
	case sourceFile:
		f, err := os.Open(s.path)
		if err != nil {
			return nil, fmt.Errorf("meta: open source %q: %w", s.path, err)
		}
		return f, nil
	case sourceStdin:
		if s.used {
			return nil, ErrSourceConsumed
		}
		s.used = true
		return io.NopCloser(os.Stdin), nil
	}
	return nil, fmt.Errorf("meta: unknown source kind")
}

// ReadAll 读取输入源的全部内容并关闭读取器。
// nil 接收者等价于标准输入。
//
// ReadAll reads the whole content of the input source and closes the
// reader. A nil receiver is equivalent to standard input.
func (s *Source) ReadAll() ([]byte, error) {
	r, err := s.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("meta: read source: %w", err)
	}
	return data, nil
}
