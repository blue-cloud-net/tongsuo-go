package md5

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"hash"
	"testing"
)

func TestSumVectors(t *testing.T) {
	vectors := []struct{ in, want string }{
		{"", "d41d8cd98f00b204e9800998ecf8427e"},
		{"abc", "900150983cd24fb0d6963f7d28e17f72"},
	}
	for _, v := range vectors {
		want, _ := hex.DecodeString(v.want)
		got := Sum([]byte(v.in))
		if !bytes.Equal(got[:], want) {
			t.Fatalf("Sum(%q) = %x, want %x", v.in, got, want)
		}
	}
}

// TestCrossStdlib 与 Go 标准库 crypto/md5 对随机数据逐字节比对。
func TestCrossStdlib(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("tongsuo-md5"), 10),
	} {
		got := Sum(data)
		want := md5.Sum(data)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("md5 mismatch for len %d", len(data))
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
