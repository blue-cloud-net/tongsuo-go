//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。对 7 种摘要算法逐字节比对：本库类型化/按名入口 vs 铜锁 openssl dgst。

package digest_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/digest"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// cliFlag 把算法名映射为 openssl dgst 的命令行开关。
//
// cliFlag maps an algorithm name to its openssl dgst command-line flag.
func cliFlag(name string) string {
	switch name {
	case "SM3":
		return "-sm3"
	case "MD5":
		return "-md5"
	case "SHA1":
		return "-sha1"
	case "SHA224":
		return "-sha224"
	case "SHA256":
		return "-sha256"
	case "SHA384":
		return "-sha384"
	case "SHA512":
		return "-sha512"
	}
	return ""
}

// TestDigestAgainstCLI 对每种算法分别用空输入与 "abc" 与铜锁 CLI 逐字节比对。
func TestDigestAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	inputs := []struct {
		label string
		data  []byte
	}{
		{"empty", nil},
		{"abc", []byte("abc")},
		{"block-aligned", []byte(strings.Repeat("abcd", 16))},
	}

	for _, name := range digest.Names() {
		flag := cliFlag(name)
		if flag == "" {
			t.Fatalf("no CLI flag mapped for %q", name)
		}
		for _, in := range inputs {
			t.Run(name+"/"+in.label, func(t *testing.T) {
				out, err := testutil.RunOpenSSL([]string{"dgst", flag, "-hex"}, in.data)
				if err != nil {
					t.Fatalf("openssl dgst %s failed: %v", flag, err)
				}
				fields := strings.Fields(strings.TrimSpace(string(out)))
				if len(fields) == 0 {
					t.Fatalf("empty output from openssl dgst %s", flag)
				}
				wantHex := fields[len(fields)-1]

				got, err := digest.Sum(name, in.data)
				if err != nil {
					t.Fatalf("digest.Sum(%q) error: %v", name, err)
				}
				if gotHex := hex.EncodeToString(got); gotHex != wantHex {
					t.Errorf("digest.Sum(%q) = %s, CLI = %s", name, gotHex, wantHex)
				}
			})
		}
	}
}

// TestDigestTypedAgainstCLI 验证类型化 Sum* 入口与 CLI 一致（覆盖 7 种算法）。
func TestDigestTypedAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	data := []byte("abc")
	for _, name := range digest.Names() {
		flag := cliFlag(name)
		t.Run(name, func(t *testing.T) {
			out, err := testutil.RunOpenSSL([]string{"dgst", flag, "-hex"}, data)
			if err != nil {
				t.Fatalf("openssl dgst %s failed: %v", flag, err)
			}
			fields := strings.Fields(strings.TrimSpace(string(out)))
			wantHex := fields[len(fields)-1]

			got, err := digest.Sum(name, data)
			if err != nil {
				t.Fatalf("digest.Sum(%q) error: %v", name, err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != wantHex {
				t.Errorf("%s = %s, CLI = %s", name, gotHex, wantHex)
			}
		})
	}
}
