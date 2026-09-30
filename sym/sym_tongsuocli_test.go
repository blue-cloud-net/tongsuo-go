//go:build tongsuocli

package sym

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestSymEncryptAllCLI 用铜锁 openssl CLI 逐字节对拍本包所有「算法-模式」的一次性加解密。
// 这是 commit 9 的综合冒烟测试：覆盖 AES-128 / AES-256 × ECB / CBC / CTR，以及 SM4 × ECB / CBC。
func TestSymEncryptAllCLI(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)

	cases := []struct {
		name    string
		key     []byte
		iv      []byte
		plain   string
		cliArgs []string
	}{
		// AES-128-ECB
		{"AES-128-ECB", []byte("0123456789abcdef"), nil,
			"Hello, sym!",
			[]string{"enc", "-aes-128-ecb", "-K", "30313233343536373839616263646566", "-nosalt"}},
		// AES-128-CBC
		{"AES-128-CBC", []byte("0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym!",
			[]string{"enc", "-aes-128-cbc", "-K", "30313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"}},
		// AES-128-CTR
		{"AES-128-CTR", []byte("0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym!",
			[]string{"enc", "-aes-128-ctr", "-K", "30313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"}},
		// AES-256-ECB
		{"AES-256-ECB", []byte("0123456789abcdef0123456789abcdef"), nil,
			"Hello, sym!",
			[]string{"enc", "-aes-256-ecb", "-K", "3031323334353637383961626364656630313233343536373839616263646566", "-nosalt"}},
		// AES-256-CBC
		{"AES-256-CBC", []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym!",
			[]string{"enc", "-aes-256-cbc", "-K", "3031323334353637383961626364656630313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"}},
		// SM4-ECB
		{"SM4-ECB", []byte("0123456789abcdef"), nil,
			"Hello, sym!",
			[]string{"enc", "-sm4-ecb", "-K", "30313233343536373839616263646566", "-nosalt"}},
		// SM4-CBC
		{"SM4-CBC", []byte("0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym!",
			[]string{"enc", "-sm4-cbc", "-K", "30313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 加密
			ct, err := Encrypt(c.name, c.key, c.iv, []byte(c.plain), nil)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			cliOut, err := testutil.RunOpenSSL(c.cliArgs, []byte(c.plain))
			if err != nil {
				t.Fatalf("CLI %s: %v", bin, err)
			}
			if !bytes.Equal(ct, cliOut) {
				t.Errorf("encrypt mismatch:\n  got  %x\n  cli  %x", ct, cliOut)
			}

			// 解密
			pt, err := Decrypt(c.name, c.key, c.iv, ct, nil)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, []byte(c.plain)) {
				t.Errorf("decrypt = %q, want %q", pt, c.plain)
			}
		})
	}
}
