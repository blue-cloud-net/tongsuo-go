package core

import (
	"bytes"
	"testing"
)

// TestMemBIO 验证 MemBIO 读写往返。
func TestMemBIO(t *testing.T) {
	bio, err := NewMemBIO()
	if err != nil {
		t.Fatalf("NewMemBIO: %v", err)
	}
	defer bio.Close()

	data := []byte("hello BIO")
	if err := bio.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := bio.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Bytes mismatch: got %q want %q", got, data)
	}
	// 第二次读取应为空（已读至末尾）
	got2, _ := bio.Bytes()
	if len(got2) != 0 {
		t.Fatalf("second Bytes should be empty, got %q", got2)
	}
}

// TestMemBIOAppendMultiple 验证多次写入追加到 BIO。
func TestMemBIOAppendMultiple(t *testing.T) {
	bio, _ := NewMemBIO()
	defer bio.Close()
	for i := 0; i < 5; i++ {
		if err := bio.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	got, _ := bio.Bytes()
	want := []byte{0, 1, 2, 3, 4}
	if !bytes.Equal(got, want) {
		t.Fatalf("Bytes mismatch: got %x want %x", got, want)
	}
}

// TestMemBIOCloseIdempotent 验证 Close 幂等。
func TestMemBIOCloseIdempotent(t *testing.T) {
	bio, err := NewMemBIO()
	if err != nil {
		t.Fatalf("NewMemBIO: %v", err)
	}
	bio.Close()
	bio.Close() // 第二次调用不应 panic
}

// TestMemBIOClosedOperations 验证关闭后操作返回错误。
func TestMemBIOClosedOperations(t *testing.T) {
	bio, _ := NewMemBIO()
	bio.Close()
	if err := bio.Write([]byte("x")); err == nil {
		t.Fatal("Write on closed should error")
	}
	if _, err := bio.Bytes(); err == nil {
		t.Fatal("Bytes on closed should error")
	}
}

// TestMemBINilDataWrite 验证 nil/零长度写入是 no-op。
func TestMemBINilDataWrite(t *testing.T) {
	bio, _ := NewMemBIO()
	defer bio.Close()
	if err := bio.Write(nil); err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if err := bio.Write([]byte{}); err != nil {
		t.Fatalf("Write(empty): %v", err)
	}
}

// TestLoadPKCS12InvalidDER 验证畸形 DER 加载返回错误。
func TestLoadPKCS12InvalidDER(t *testing.T) {
	if _, err := LoadPKCS12DER([]byte("not p12")); err == nil {
		t.Fatal("garbage DER should error")
	}
	if _, err := LoadPKCS12DER(nil); err == nil {
		t.Fatal("nil DER should error")
	}
}

// TestLoadPKCS7InvalidDER 验证畸形 DER 加载返回错误。
func TestLoadPKCS7InvalidDER(t *testing.T) {
	if _, err := LoadPKCS7DER([]byte("not p7")); err == nil {
		t.Fatal("garbage DER should error")
	}
	if _, err := LoadPKCS7DER(nil); err == nil {
		t.Fatal("nil DER should error")
	}
}

// TestNewPKCS7SignedData 验证创建签名数据。
func TestNewPKCS7SignedData(t *testing.T) {
	p7, err := NewPKCS7SignedData()
	if err != nil {
		t.Fatalf("NewPKCS7SignedData: %v", err)
	}
	defer p7.Close()
	der, err := p7.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	if len(der) < 10 {
		t.Fatalf("empty PKCS#7 too short: %d bytes", len(der))
	}
}

// TestPKCS7Close 验证 PKCS7.Close 幂等。
func TestPKCS7Close(t *testing.T) {
	p7, err := NewPKCS7SignedData()
	if err != nil {
		t.Fatalf("NewPKCS7SignedData: %v", err)
	}
	if err := p7.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p7.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
