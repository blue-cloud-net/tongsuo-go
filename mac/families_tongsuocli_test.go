//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。覆盖 CMAC / GMAC / KMAC-128 / KMAC-256 / SIPHASH / POLY1305 / EIA3
// 与铜锁 `openssl mac` 子命令的逐字节对拍。
//
// 对拍要点：
//   - CLI 的 `-macopt` 与 provider 的 OSSL_PARAM 一一对应（cipher / hexiv /
//     hexkey / custom / size），因此本文件的参数名必须与实现保持一致；
//   - CLI 默认输出十六进制文本（不带 -binary），比较前统一小写。

package mac_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/mac"
)

// runMAC 调用 `openssl mac` 并返回小写的十六进制标签文本。
//
// runMAC invokes `openssl mac` and returns the lower-case hex tag text.
func runMAC(t *testing.T, args []string, stdin []byte) string {
	t.Helper()
	out, err := testutil.RunOpenSSL(args, stdin)
	if err != nil {
		t.Fatalf("openssl mac %v: %v", args, err)
	}
	return strings.ToLower(strings.TrimSpace(string(out)))
}

// TestCMACAgainstCLI 逐字节对拍 CMAC（SM4 / AES-128 / AES-192 / AES-256）。
//
// TestCMACAgainstCLI compares CMAC byte-for-byte with the CLI for SM4 and
// all three AES key sizes.
func TestCMACAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	data := []byte("cmac cli parity")
	tests := []struct {
		cipher  string
		keyLen  int
		cliName string
	}{
		{"SM4", 16, "SM4-CBC"},
		{"AES-128", 16, "AES-128-CBC"},
		{"AES-192", 24, "AES-192-CBC"},
		{"AES-256", 32, "AES-256-CBC"},
	}
	for _, tt := range tests {
		t.Run(tt.cipher, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x11}, tt.keyLen)
			cli := runMAC(t, []string{
				"mac",
				"-macopt", "cipher:" + tt.cliName,
				"-macopt", "hexkey:" + hex.EncodeToString(key),
				"CMAC",
			}, data)
			got, err := mac.CMAC(tt.cipher, key, data)
			if err != nil {
				t.Fatalf("CMAC: %v", err)
			}
			if hex.EncodeToString(got) != cli {
				t.Fatalf("CMAC(%s) = %x, CLI = %s", tt.cipher, got, cli)
			}
		})
	}
}

// TestGMACAgainstCLI 逐字节对拍 GMAC（SM4 / AES-128 / AES-256）。
//
// TestGMACAgainstCLI compares GMAC byte-for-byte with the CLI for SM4 and
// two AES key sizes.
func TestGMACAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	data := []byte("gmac cli parity")
	iv := bytes.Repeat([]byte{0x22}, 12)
	tests := []struct {
		cipher  string
		keyLen  int
		cliName string
	}{
		{"SM4", 16, "SM4-GCM"},
		{"AES-128", 16, "AES-128-GCM"},
		{"AES-256", 32, "AES-256-GCM"},
	}
	for _, tt := range tests {
		t.Run(tt.cipher, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x33}, tt.keyLen)
			cli := runMAC(t, []string{
				"mac",
				"-macopt", "cipher:" + tt.cliName,
				"-macopt", "hexkey:" + hex.EncodeToString(key),
				"-macopt", "hexiv:" + hex.EncodeToString(iv),
				"GMAC",
			}, data)
			got, err := mac.GMAC(tt.cipher, key, iv, nil, data)
			if err != nil {
				t.Fatalf("GMAC: %v", err)
			}
			if hex.EncodeToString(got) != cli {
				t.Fatalf("GMAC(%s) = %x, CLI = %s", tt.cipher, got, cli)
			}
		})
	}
}

// TestKMACAgainstCLI 逐字节对拍 KMAC-128 / KMAC-256。
//
// TestKMACAgainstCLI compares KMAC-128 / KMAC-256 byte-for-byte with the
// CLI.
func TestKMACAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	data, _ := hex.DecodeString("00010203")
	custom := []byte("cli parity")

	tests := []struct {
		name    string
		cliName string
		outLen  int
		fn      func([]byte, []byte, []byte, int) ([]byte, error)
	}{
		{"KMAC-128", "KMAC-128", 32, mac.KMAC128},
		{"KMAC-256", "KMAC-256", 64, mac.KMAC256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := runMAC(t, []string{
				"mac",
				"-macopt", "hexkey:" + hex.EncodeToString(key),
				"-macopt", "custom:" + string(custom),
				"-macopt", "size:" + itoa(tt.outLen),
				tt.cliName,
			}, data)
			got, err := tt.fn(key, data, custom, tt.outLen)
			if err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if hex.EncodeToString(got) != cli {
				t.Fatalf("%s = %x, CLI = %s", tt.name, got, cli)
			}
		})
	}
}

// TestSipHashAgainstCLI 逐字节对拍 SipHash（默认 16 字节与 size:8 两种）。
//
// TestSipHashAgainstCLI compares SipHash byte-for-byte with the CLI, for
// both the default 16-byte output and size:8.
func TestSipHashAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	data := []byte("siphash cli parity")

	cli := runMAC(t, []string{
		"mac",
		"-macopt", "hexkey:" + hex.EncodeToString(key),
		"SIPHASH",
	}, data)
	got, err := mac.SipHash(key, data)
	if err != nil {
		t.Fatalf("SipHash: %v", err)
	}
	if hex.EncodeToString(got) != cli {
		t.Fatalf("SipHash = %x, CLI = %s", got, cli)
	}

	cli8 := runMAC(t, []string{
		"mac",
		"-macopt", "hexkey:" + hex.EncodeToString(key),
		"-macopt", "size:8",
		"SIPHASH",
	}, data)
	got8, err := mac.Sum("SIPHASH", key, data, &mac.Options{OutputLen: 8})
	if err != nil {
		t.Fatalf("Sum(SIPHASH, size 8): %v", err)
	}
	if hex.EncodeToString(got8) != cli8 {
		t.Fatalf("SIPHASH size 8 = %x, CLI = %s", got8, cli8)
	}
}

// TestPoly1305AgainstCLI 逐字节对拍 Poly1305。
//
// TestPoly1305AgainstCLI compares Poly1305 byte-for-byte with the CLI.
func TestPoly1305AgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key, _ := hex.DecodeString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	data := []byte("Cryptographic Forum Research Group")

	cli := runMAC(t, []string{
		"mac",
		"-macopt", "hexkey:" + hex.EncodeToString(key),
		"POLY1305",
	}, data)
	got, err := mac.Poly1305(key, data)
	if err != nil {
		t.Fatalf("Poly1305: %v", err)
	}
	if hex.EncodeToString(got) != cli {
		t.Fatalf("Poly1305 = %x, CLI = %s", got, cli)
	}
}

// TestEIA3AgainstCLI 逐字节对拍 EIA3。
//
// TestEIA3AgainstCLI compares EIA3 byte-for-byte with the CLI.
func TestEIA3AgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key, _ := hex.DecodeString("47054125561eb2dda94059da05097850")
	count, _ := hex.DecodeString("561eb2dda0")
	data, _ := hex.DecodeString("000000000000000000000000")

	cli := runMAC(t, []string{
		"mac",
		"-macopt", "hexkey:" + hex.EncodeToString(key),
		"-macopt", "hexiv:" + hex.EncodeToString(count),
		"EIA3",
	}, data)
	got, err := mac.EIA3(key, count, data)
	if err != nil {
		t.Fatalf("EIA3: %v", err)
	}
	if hex.EncodeToString(got) != cli {
		t.Fatalf("EIA3 = %x, CLI = %s", got, cli)
	}
}

// itoa 是 strconv.Itoa 的本地短别名（避免为单个调用引入 import）。
//
// itoa is a local short alias of strconv.Itoa.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
