//go:build tongsuocli

package hmac

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIHmacSM3 与铜锁 openssl dgst -sm3 -hmac 对比 HMAC-SM3。
func TestCLIHmacSM3(t *testing.T) {
	key := []byte("tongsuo-hmac-key")
	data := []byte("tongsuo-go hmac sm3 cli compare")

	out, err := testutil.RunOpenSSL([]string{"dgst", "-sm3", "-hmac", string(key)}, data)
	if err != nil {
		t.Fatalf("openssl dgst: %v", err)
	}
	fields := bytes.Fields(out)
	if len(fields) < 2 {
		t.Fatalf("unexpected openssl output: %q", out)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(fields[len(fields)-1])))
	if err != nil {
		t.Fatalf("parse hex: %v", err)
	}
	got := SumSM3(key, data)
	if !bytes.Equal(got, want) {
		t.Fatalf("hmac-sm3 cli mismatch: got %x want %x", got, want)
	}
}
