package sha512

import (
	"bytes"
	stdsha512 "crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

func TestSumVectors(t *testing.T) {
	vectors := []struct{ in, want string }{
		{"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
	}
	for _, v := range vectors {
		want, _ := hex.DecodeString(v.want)
		got := Sum([]byte(v.in))
		if !bytes.Equal(got[:], want) {
			t.Fatalf("Sum(%q) = %x, want %x", v.in, got, want)
		}
	}
}

// TestCrossStdlib 与 Go 标准库 crypto/sha512 对随机数据逐字节比对。
func TestCrossStdlib(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("tongsuo-sha512"), 10),
		bytes.Repeat([]byte{0xff}, 200),
	} {
		got := Sum(data)
		want := stdsha512.Sum512(data)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("sha512 mismatch for len %d", len(data))
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
