//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。覆盖 0.5.0 新增算法中 `openssl enc` 支持的部分：
// AES-192 的 ECB / CBC / CTR 与 ChaCha20 流密码。
//
// SM4-CCM / SM4-XTS / ChaCha20-Poly1305 不走 `enc`（它不支持 AEAD 与
// XTS），其逐字节正确性由标准向量测试锁定（RFC 8998、GB/T 17964-2021、
// RFC 7539）。

package sym_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// TestAES192AgainstCLI 逐字节对拍 AES-192 的 ECB / CBC / CTR。
//
// TestAES192AgainstCLI compares AES-192 ECB / CBC / CTR byte-for-byte with
// the CLI.
func TestAES192AgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key := bytes.Repeat([]byte{0x24}, sym.AES192KeySize)
	iv := bytes.Repeat([]byte{0x11}, sym.BlockSize)
	data := []byte("aes-192 cli parity payload, longer than one block")

	tests := []struct {
		name    string
		cliName string
		useIV   bool
	}{
		{"AES-192-ECB", "-aes-192-ecb", false},
		{"AES-192-CBC", "-aes-192-cbc", true},
		{"AES-192-CTR", "-aes-192-ctr", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"enc", tt.cliName, "-K", hex.EncodeToString(key)}
			if tt.useIV {
				args = append(args, "-iv", hex.EncodeToString(iv))
			}
			out, err := testutil.RunOpenSSL(args, data)
			if err != nil {
				t.Fatalf("openssl enc %s: %v", tt.cliName, err)
			}

			useIV := iv
			if !tt.useIV {
				useIV = nil
			}
			got, err := sym.Encrypt(tt.name, key, useIV, data, nil)
			if err != nil {
				t.Fatalf("sym.Encrypt(%s): %v", tt.name, err)
			}
			if !bytes.Equal(got, out) {
				t.Fatalf("%s = %x, CLI = %x", tt.name, got, out)
			}

			// 解密方向同样对拍。
			back, err := testutil.RunOpenSSL(append(args, "-d"), got)
			if err != nil {
				t.Fatalf("openssl enc -d %s: %v", tt.cliName, err)
			}
			if !bytes.Equal(back, data) {
				t.Fatalf("%s CLI decrypt = %q, want %q", tt.name, back, data)
			}
		})
	}
}

// TestChaCha20AgainstCLI 逐字节对拍 ChaCha20 流密码。
//
// TestChaCha20AgainstCLI compares ChaCha20 byte-for-byte with the CLI.
func TestChaCha20AgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	key := bytes.Repeat([]byte{0x5a}, sym.ChaCha20KeySize)
	iv := bytes.Repeat([]byte{0x37}, sym.ChaCha20IVSize)
	data := []byte("chacha20 cli parity payload")

	args := []string{"enc", "-chacha20", "-K", hex.EncodeToString(key), "-iv", hex.EncodeToString(iv)}
	out, err := testutil.RunOpenSSL(args, data)
	if err != nil {
		t.Fatalf("openssl enc -chacha20: %v", err)
	}
	got, err := sym.EncryptChaCha20(key, iv, data)
	if err != nil {
		t.Fatalf("EncryptChaCha20: %v", err)
	}
	if !bytes.Equal(got, out) {
		t.Fatalf("ChaCha20 = %x, CLI = %x", got, out)
	}

	back, err := sym.DecryptChaCha20(key, iv, got)
	if err != nil {
		t.Fatalf("DecryptChaCha20: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Fatalf("ChaCha20 round trip = %q, want %q", back, data)
	}
}
