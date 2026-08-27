//go:build tongsuocli

package sm3

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLICompare 与铜锁 openssl dgst -sm3 对比随机数据摘要。
// 运行方式：go test -tags tongsuocli ./crypto/sm3
func TestCLICompare(t *testing.T) {
	data := []byte("tongsuo-go tongsuocli compare test data")
	got := Sum(data)

	out, err := testutil.RunOpenSSL([]string{"dgst", "-sm3"}, data)
	if err != nil {
		t.Fatalf("openssl dgst: %v", err)
	}
	// 输出形如 "SM3(stdin)= <hex>"
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
