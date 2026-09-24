package rand

import (
	"bytes"
	"io"
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

// TestIndependent 验证两次随机抽取结果不同（统计意义上的几乎必然不同）。
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
		t.Fatal("two random draws are equal (CSPRNG broken)")
	}
}

// TestNegative 验证负长度返回错误。
func TestNegative(t *testing.T) {
	if _, err := Bytes(-1); err == nil {
		t.Fatal("expected error for negative length")
	}
}

// TestEmpty 验证空缓冲区 Read 不调用底层 CSPRNG。
func TestEmpty(t *testing.T) {
	if n, err := Read(nil); err != nil || n != 0 {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := Read([]byte{}); err != nil || n != 0 {
		t.Fatalf("Read([]byte{}) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestZero 验证 Bytes(0) 返回空切片（不调用底层 CSPRNG）。
func TestZero(t *testing.T) {
	b, err := Bytes(0)
	if err != nil {
		t.Fatalf("Bytes(0) err = %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("Bytes(0) length = %d, want 0", len(b))
	}
}

// TestReaderImplements 编译期断言：Reader() 返回 io.Reader。
func TestReaderImplements(t *testing.T) {
	var _ io.Reader = Reader()
}

// TestReaderFill 验证 Reader().Read 等价于 Read。
func TestReaderFill(t *testing.T) {
	buf := make([]byte, 32)
	n, err := Reader().Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) {
		t.Fatalf("Reader.Read wrote %d, want %d", n, len(buf))
	}
	if bytes.Equal(buf, make([]byte, 32)) {
		t.Fatal("Reader.Read returned all-zero bytes")
	}
}

// TestReaderStream 验证 io.Copy 把 Reader 的输出搬运到 bytes.Buffer。
func TestReaderStream(t *testing.T) {
	const want = 256
	r := Reader()
	buf := make([]byte, want)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if n != want {
		t.Fatalf("ReadFull wrote %d, want %d", n, want)
	}
	if bytes.Equal(buf, make([]byte, want)) {
		t.Fatal("ReadFull returned all-zero bytes")
	}
	// 两次 ReadFull 应该得到不同的随机流
	r2 := Reader()
	buf2 := make([]byte, want)
	if _, err := io.ReadFull(r2, buf2); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(buf, buf2) {
		t.Fatal("two ReadFull calls returned equal bytes (CSPRNG broken)")
	}
}

// BenchmarkRead 测量 1024 字节随机数读取吞吐。
func BenchmarkRead(b *testing.B) {
	buf := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBytes 测量 Bytes(1024) 一次性分配+填充的吞吐。
func BenchmarkBytes(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Bytes(1024); err != nil {
			b.Fatal(err)
		}
	}
}
