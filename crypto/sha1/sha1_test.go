package sha1

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"testing"
)

func TestSumVectors(t *testing.T) {
	vectors := []struct{ in, want string }{
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
	}
	for _, v := range vectors {
		want, _ := hex.DecodeString(v.want)
		got := Sum([]byte(v.in))
		if !bytes.Equal(got[:], want) {
			t.Fatalf("Sum(%q) = %x, want %x", v.in, got, want)
		}
	}
}

// TestCrossStdlib 与 Go 标准库 crypto/sha1 对随机数据逐字节比对。
func TestCrossStdlib(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("tongsuo-sha1"), 10),
	} {
		got := Sum(data)
		want := sha1.Sum(data)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("sha1 mismatch for len %d", len(data))
		}
	}
}

func TestHashInterface(t *testing.T) {
	var _ hash.Hash = New()
	h := New()
	h.Write([]byte("abc"))
	want := Sum([]byte("abc"))
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("hash.Hash mismatch")
	}
}
