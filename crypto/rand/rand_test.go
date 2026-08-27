package rand

import (
	"bytes"
	"testing"
)

// TestRead 验证 Read 填充缓冲区并返回正确长度。
func TestRead(t *testing.T) {
	buf := make([]byte, 32)
	n, err := Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) {
		t.Fatalf("read %d bytes, want %d", n, len(buf))
	}
	if bytes.Equal(buf, make([]byte, 32)) {
		t.Fatal("read all-zero random bytes")
	}
}

// TestBytes 验证 Bytes 返回指定长度。
func TestBytes(t *testing.T) {
	b, err := Bytes(64)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 64 {
		t.Fatalf("got %d bytes, want 64", len(b))
	}
}

// TestIndependent 验证两次随机抽取结果不同。
func TestIndependent(t *testing.T) {
	a, err := Bytes(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Bytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two random draws are equal")
	}
}

// TestNegative 验证负长度返回错误。
func TestNegative(t *testing.T) {
	if _, err := Bytes(-1); err == nil {
		t.Fatal("expected error for negative length")
	}
}

// TestEmpty 验证空缓冲区行为。
func TestEmpty(t *testing.T) {
	if n, err := Read(nil); err != nil || n != 0 {
		t.Fatalf("Read(nil) = %d, %v", n, err)
	}
}
