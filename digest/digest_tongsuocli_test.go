//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。对 7 种摘要算法逐字节比对：本库类型化/按名入口 vs 铜锁 openssl dgst。

package digest_test

import (
	"encoding/hex"
	"strconv"
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
	case "SHA256-192":
		return "-sha256-192"
	case "SHA512-224":
		return "-sha512-224"
	case "SHA512-256":
		return "-sha512-256"
	case "SHA3-224":
		return "-sha3-224"
	case "SHA3-256":
		return "-sha3-256"
	case "SHA3-384":
		return "-sha3-384"
	case "SHA3-512":
		return "-sha3-512"
	case "KECCAK-224":
		return "-keccak-224"
	case "KECCAK-256":
		return "-keccak-256"
	case "KECCAK-384":
		return "-keccak-384"
	case "KECCAK-512":
		return "-keccak-512"
	}
	return ""
}

// cliNames 返回可用于定长 dgst 对拍的算法名：跳过 XOF（SHAKE 需 -xoflen）
// 与当前铜锁构建不提供的算法。
//
// cliNames returns the names usable with a fixed-length dgst comparison:
// XOF algorithms (SHAKE needs -xoflen) and algorithms missing from the
// current Tongsuo build are skipped.
func cliNames() []string {
	var out []string
	for _, n := range digest.Names() {
		if cliFlag(n) == "" || !digest.Available(n) {
			continue
		}
		out = append(out, n)
	}
	return out
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

	for _, name := range cliNames() {
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
	for _, name := range cliNames() {
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

// TestSHAKEAgainstCLI 验证 SHAKE128 / SHAKE256 与铜锁 CLI 的
// `dgst -shakeXXX -xoflen N` 逐字节一致。
//
// TestSHAKEAgainstCLI verifies SHAKE128 / SHAKE256 match the Tongsuo CLI
// invocation `dgst -shakeXXX -xoflen N` byte for byte.
func TestSHAKEAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	cases := []struct {
		name   string
		flag   string
		sumFn  func([]byte, int) ([]byte, error)
		outLen int
	}{
		{"SHAKE128", "-shake128", digest.SumSHAKE128, 32},
		{"SHAKE256", "-shake256", digest.SumSHAKE256, 64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !digest.Available(c.name) {
				t.Skipf("%s unavailable in this Tongsuo build", c.name)
			}
			data := []byte("tongsuo-go xof")
			out, err := testutil.RunOpenSSL([]string{"dgst", c.flag, "-xoflen", strconv.Itoa(c.outLen), "-hex"}, data)
			if err != nil {
				t.Fatalf("openssl dgst %s failed: %v", c.flag, err)
			}
			fields := strings.Fields(strings.TrimSpace(string(out)))
			if len(fields) < 2 {
				t.Fatalf("unexpected dgst output: %q", out)
			}
			wantHex := fields[len(fields)-1]

			got, err := c.sumFn(data, c.outLen)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != wantHex {
				t.Errorf("%s = %s, CLI = %s", c.name, gotHex, wantHex)
			}
		})
	}
}
