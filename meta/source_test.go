package meta

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSourceBytes 验证字节源可重复读取且内容与源一致。
//
// TestSourceBytes verifies that a bytes source can be read repeatedly and
// yields the original content.
func TestSourceBytes(t *testing.T) {
	s := NewBytesSource([]byte("hello"))
	for i := 0; i < 2; i++ {
		got, err := s.ReadAll()
		if err != nil {
			t.Fatalf("ReadAll #%d: %v", i, err)
		}
		if string(got) != "hello" {
			t.Fatalf("ReadAll #%d = %q, want %q", i, string(got), "hello")
		}
	}
}

// TestSourceBytesCopiesInput 验证字节源在构造时拷贝输入。
//
// TestSourceBytesCopiesInput verifies that a bytes source copies its
// input at construction time.
func TestSourceBytesCopiesInput(t *testing.T) {
	buf := []byte("hello")
	s := NewBytesSource(buf)
	buf[0] = 'X'
	got, err := s.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("ReadAll = %q, want %q", string(got), "hello")
	}
}

// TestSourceReaderIsSingleUse 验证读取器源是一次性的。
//
// TestSourceReaderIsSingleUse verifies that a reader source is single-use.
func TestSourceReaderIsSingleUse(t *testing.T) {
	s := NewReaderSource(strings.NewReader("hello"))
	got, err := s.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("ReadAll = %q, want %q", string(got), "hello")
	}
	if _, err := s.Open(); !errors.Is(err, ErrSourceConsumed) {
		t.Fatalf("second Open error = %v, want ErrSourceConsumed", err)
	}
}

// TestSourceFile 验证文件源可重复读取。
//
// TestSourceFile verifies that a file source can be read repeatedly.
func TestSourceFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(path, []byte("file content"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s, err := NewFileSource(path)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	if s.Path() != path {
		t.Errorf("Path = %q, want %q", s.Path(), path)
	}
	for i := 0; i < 2; i++ {
		got, err := s.ReadAll()
		if err != nil {
			t.Fatalf("ReadAll #%d: %v", i, err)
		}
		if string(got) != "file content" {
			t.Fatalf("ReadAll #%d = %q, want %q", i, string(got), "file content")
		}
	}
}

// TestSourceFileMissing 验证缺失文件在 Open 时报告错误。
//
// TestSourceFileMissing verifies that a missing file is reported when the
// source is opened.
func TestSourceFileMissing(t *testing.T) {
	s, err := NewFileSource(filepath.Join(t.TempDir(), "missing.txt"))
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	if _, err := s.ReadAll(); err == nil {
		t.Fatal("ReadAll: expected error for missing file")
	}
}

// TestSourceEmptyPath 验证空路径被拒绝。
//
// TestSourceEmptyPath verifies that an empty path is rejected.
func TestSourceEmptyPath(t *testing.T) {
	if _, err := NewFileSource("  "); err == nil {
		t.Fatal("NewFileSource: expected error for empty path")
	}
}

// TestSourceDashIsStdin 验证 "-" 路径映射到标准输入源。
//
// TestSourceDashIsStdin verifies that the "-" path maps to the standard
// input source.
func TestSourceDashIsStdin(t *testing.T) {
	s, err := NewFileSource("-")
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	if s.Path() != "" {
		t.Errorf("Path = %q, want empty", s.Path())
	}
}

// TestSinkBytes 验证内存汇按编码写出内容。
//
// TestSinkBytes verifies that an in-memory sink writes content according
// to the selected encoding.
func TestSinkBytes(t *testing.T) {
	s := NewBytesSink()
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(s.Bytes()); got != "hello" {
		t.Errorf("Bytes = %q, want %q", got, "hello")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close 必须幂等。
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSinkHex 验证 hex 编码的内存汇。
//
// TestSinkHex verifies a hex-encoded in-memory sink.
func TestSinkHex(t *testing.T) {
	s := NewBytesSink()
	if err := s.SetEncoding(EncodingHex); err != nil {
		t.Fatalf("SetEncoding: %v", err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(s.Bytes()); got != "68656c6c6f" {
		t.Errorf("Bytes = %q, want %q", got, "68656c6c6f")
	}
}

// TestSinkBase64Chunked 验证 base64 编码跨多次写入与一次性写入结果一致。
//
// TestSinkBase64Chunked verifies that base64 encoding across several
// writes yields the same result as a single write.
func TestSinkBase64Chunked(t *testing.T) {
	one := NewBytesSink()
	if err := one.SetEncoding(EncodingBase64); err != nil {
		t.Fatalf("SetEncoding: %v", err)
	}
	if _, err := one.Write([]byte("hello world")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := one.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	chunked := NewBytesSink()
	if err := chunked.SetEncoding(EncodingBase64); err != nil {
		t.Fatalf("SetEncoding: %v", err)
	}
	for _, part := range []string{"hel", "lo ", "world"} {
		if _, err := chunked.Write([]byte(part)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := chunked.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(one.Bytes(), chunked.Bytes()) {
		t.Fatalf("chunked base64 = %q, want %q", chunked.Bytes(), one.Bytes())
	}
}

// TestSinkEncodingAfterWriteRejected 验证写入后改编码被拒绝。
//
// TestSinkEncodingAfterWriteRejected verifies that changing the encoding
// after a write is rejected.
func TestSinkEncodingAfterWriteRejected(t *testing.T) {
	s := NewBytesSink()
	if _, err := s.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.SetEncoding(EncodingHex); err == nil {
		t.Fatal("SetEncoding after write: expected error")
	}
}

// TestSinkUnknownEncodingRejected 验证未知编码被拒绝。
//
// TestSinkUnknownEncodingRejected verifies that an unknown encoding is
// rejected.
func TestSinkUnknownEncodingRejected(t *testing.T) {
	s := NewBytesSink()
	if err := s.SetEncoding(Encoding("rot13")); err == nil {
		t.Fatal("SetEncoding: expected error for unknown encoding")
	}
}

// TestSinkFile 验证文件汇把内容写到磁盘。
//
// TestSinkFile verifies that a file sink writes its content to disk.
func TestSinkFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.bin")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if s.Path() != path {
		t.Errorf("Path = %q, want %q", s.Path(), path)
	}
	if _, err := s.Write([]byte("file sink")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "file sink" {
		t.Errorf("file content = %q, want %q", string(data), "file sink")
	}
}

// TestSinkWriter 验证 writer 汇把内容交给底层写入器。
//
// TestSinkWriter verifies that a writer sink hands its content to the
// underlying writer.
func TestSinkWriter(t *testing.T) {
	var buf bytes.Buffer
	s := NewWriterSink(&buf)
	if _, err := s.Write([]byte("writer sink")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.String() != "writer sink" {
		t.Errorf("writer content = %q, want %q", buf.String(), "writer sink")
	}
	if s.Bytes() != nil {
		t.Error("Bytes on a writer sink should be nil")
	}
}
