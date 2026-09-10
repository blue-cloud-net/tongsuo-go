//go:build tongsuocli

package rand

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLICompare 验证 Read 产生的随机字节与 openssl rand -hex 等长且有效。
func TestCLICompare(t *testing.T) {
	sizes := []int{8, 16, 32, 64, 128}
	for _, n := range sizes {
		got := make([]byte, n)
		if _, err := Read(got); err != nil {
			t.Fatalf("Read(%d): %v", n, err)
		}
		// 直接调用 openssl rand -hex (n) → 应得到 2n 个 hex 字符
		out, err := testutil.RunOpenSSL([]string{"rand", "-hex", intToStr(n)}, nil)
		if err != nil {
			t.Fatalf("openssl rand -hex %d: %v", n, err)
		}
		hexStr := strings.TrimSpace(string(out))
		cliBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("parse hex: %v", err)
		}
		if len(cliBytes) != n {
			t.Fatalf("cli length = %d, want %d", len(cliBytes), n)
		}
		// 我们不验证内容相等（两者都是随机），仅验证长度与全零不出现
		allZero := true
		for _, b := range got {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatalf("Read(%d) produced all zeros", n)
		}
		_ = bytes.HasPrefix // avoid unused
	}
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}