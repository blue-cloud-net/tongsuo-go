//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。覆盖 tongsuo mac HMAC-<digest> 子命令的 Go 侧对拍。

package mac_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/mac"
)

// digestFor 把 mac 算法名映射到 openssl mac 的 -digest 参数。
//
// digestFor maps a mac algorithm name to the openssl -digest flag.
func digestFor(name string) string {
	// 名称形如 "HMAC-SM3"，去掉前缀
	const prefix = "HMAC-"
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	return strings.TrimPrefix(name, prefix)
}

// TestHMACAgainstCLI 对每种 HMAC-* 用铜锁 CLI 逐字节比对。
func TestHMACAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key, _ := hex.DecodeString("0001020304050607")
	data := []byte("abc")

	for _, name := range mac.Names() {
		t.Run(name, func(t *testing.T) {
			// 构造 CLI 调用：tongsuo mac -digest <digest> -macopt hexkey:<key> HMAC
			keyHex := hex.EncodeToString(key)
			digest := digestFor(name)
			args := []string{"mac", "-digest", digest, "-macopt", "hexkey:" + keyHex, "HMAC"}
			out, err := testutil.RunOpenSSL(args, data)
			if err != nil {
				t.Fatalf("openssl mac %s failed: %v", name, err)
			}
			cliTag := strings.TrimSpace(string(out))

			got, err := mac.Sum(name, key, data, nil)
			if err != nil {
				t.Fatalf("mac.Sum(%q) error: %v", name, err)
			}
			gotHex := hex.EncodeToString(got)
			if !strings.EqualFold(gotHex, cliTag) {
				t.Errorf("mac.Sum(%q) = %s, CLI = %s", name, gotHex, cliTag)
			}
		})
	}
}

// TestHMACByNameAgainstCLI 额外验证按名 SumHMAC* 与 CLI 一致（含大小写变体）。
func TestHMACByNameAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key, _ := hex.DecodeString("0001020304050607")
	data := []byte("abc")

	for _, name := range mac.Names() {
		t.Run(name, func(t *testing.T) {
			digest := digestFor(name)
			keyHex := hex.EncodeToString(key)
			args := []string{"mac", "-digest", digest, "-macopt", "hexkey:" + keyHex, "HMAC"}
			out, err := testutil.RunOpenSSL(args, data)
			if err != nil {
				t.Fatalf("openssl mac %s failed: %v", name, err)
			}
			cliTag := strings.ToLower(strings.TrimSpace(string(out)))

			got, err := mac.Sum(strings.ToLower(name), key, data, nil)
			if err != nil {
				t.Fatalf("mac.Sum(lower %q) error: %v", name, err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != cliTag {
				t.Errorf("lowercase mac.Sum(%q) = %s, CLI = %s", name, gotHex, cliTag)
			}
		})
	}
}
