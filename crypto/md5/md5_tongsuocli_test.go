//go:build tongsuocli

package md5

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLICompare 与铜锁 openssl dgst -md5 对比随机数据摘要。
func TestCLICompare(t *testing.T) {
	data := []byte("tongsuo-go md5 cli compare test data")
	got := Sum(data)

	out, err := testutil.RunOpenSSL([]string{"dgst", "-md5"}, data)
	if err != nil {
		t.Fatalf("openssl dgst: %v", err)
	}
	fields := bytes.Fields(out)
	if len(fields) < 2 {
		t.Fatalf("unexpected openssl output: %q", out)
	}
	hexStr := strings.TrimSpace(string(fields[len(fields)-1]))
	want, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("parse hex: %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("cli mismatch: got %x want %x", got, want)
	}
}