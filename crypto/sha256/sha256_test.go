package sha256

import (
	"bytes"
	stdsha256 "crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

func TestSumVectors(t *testing.T) {
	vectors := []struct{ in, want string }{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, v := range vectors {
		want, _ := hex.DecodeString(v.want)
		got := Sum([]byte(v.in))
		if !bytes.Equal(got[:], want) {
			t.Fatalf("Sum(%q) = %x, want %x", v.in, got, want)
		}
	}
}

// TestCrossStdlib 与 Go 标准库 crypto/sha256 对随机数据逐字节比对。
func TestCrossStdlib(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("tongsuo-sha256"), 10),
		bytes.Repeat([]byte{0x00}, 100),
	} {
		got := Sum(data)
		want := stdsha256.Sum256(data)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("sha256 mismatch for len %d", len(data))
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
