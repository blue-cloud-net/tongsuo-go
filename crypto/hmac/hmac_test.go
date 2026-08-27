package hmac

import (
	"bytes"
	stdhmac "crypto/hmac"
	stdsha256 "crypto/sha256"
	stdsha384 "crypto/sha512"
	"hash"
	"testing"
)

// TestHmacSHA256CrossStdlib 与 Go 标准库 hmac+sha256 对随机数据逐字节比对。
func TestHmacSHA256CrossStdlib(t *testing.T) {
	key := []byte("secret-hmac-key")
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("tongsuo-hmac"), 10),
	} {
		got := SumSHA256(key, data)
		mac := stdhmac.New(stdsha256.New, key)
		_, _ = mac.Write(data)
		if !bytes.Equal(got, mac.Sum(nil)) {
			t.Fatalf("hmac-sha256 mismatch for len %d", len(data))
		}
	}
}

// TestHmacSHA384CrossStdlib 与 Go 标准库 hmac+sha384 交叉验证。
func TestHmacSHA384CrossStdlib(t *testing.T) {
	key := []byte("secret-hmac-key")
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("tongsuo-hmac-384"), 10),
	} {
		got := SumSHA384(key, data)
		mac := stdhmac.New(stdsha384.New384, key)
		_, _ = mac.Write(data)
		if !bytes.Equal(got, mac.Sum(nil)) {
			t.Fatalf("hmac-sha384 mismatch for len %d", len(data))
		}
	}
}

// TestStreaming 验证流式写入与 Sum 后继续写入。
func TestStreaming(t *testing.T) {
	key := []byte("k")
	h := NewSHA256(key)
	h.Write([]byte("abc"))
	h.Write([]byte("def"))
	one := h.Sum(nil)

	h2 := NewSHA256(key)
	h2.Write([]byte("abcdef"))
	if !bytes.Equal(one, h2.Sum(nil)) {
		t.Fatal("streaming mismatch")
	}

	// Sum 后继续写入
	h.Write([]byte("ghi"))
	want := NewSHA256(key)
	want.Write([]byte("abcdefghi"))
	if !bytes.Equal(h.Sum(nil), want.Sum(nil)) {
		t.Fatal("write-after-sum mismatch")
	}
}

// TestReset 验证 Reset 后结果一致。
func TestReset(t *testing.T) {
	key := []byte("k")
	h := NewSHA256(key)
	h.Write([]byte("data"))
	first := h.Sum(nil)
	h.Reset()
	h.Write([]byte("data"))
	if !bytes.Equal(first, h.Sum(nil)) {
		t.Fatal("reset mismatch")
	}
}

// TestHashInterface 验证实现 hash.Hash。
func TestHashInterface(t *testing.T) {
	var _ hash.Hash = NewSHA256([]byte("k"))
}

// TestDifferentKeys 验证不同密钥产生不同结果。
func TestDifferentKeys(t *testing.T) {
	a := SumSHA256([]byte("key-a"), []byte("data"))
	b := SumSHA256([]byte("key-b"), []byte("data"))
	if bytes.Equal(a, b) {
		t.Fatal("different keys produced equal HMAC")
	}
}
