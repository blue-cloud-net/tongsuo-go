//go:build tongsuocli

package sym

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestSymNewModesCLI 用铜锁 openssl CLI 逐字节对拍新增的 AES-OFB / AES-CFB 与
// DES 家族「算法-模式」的一次性加解密。
// 单 DES 在铜锁 CLI 侧需要 legacy provider，故单 DES 不在此处直接对拍——它与
// DES-EDE3（K‖K‖K）的等价性由 TestDESSingleEqualsEDE3WithRepeatedKey 覆盖。
//
// TestSymNewModesCLI compares the new AES-OFB / AES-CFB and DES-family
// one-shot entries byte-for-byte against the Tongsuo openssl CLI. Single
// DES is not compared here because the CLI needs the legacy provider for
// it; its equivalence to DES-EDE3 with K‖K‖K is covered by
// TestDESSingleEqualsEDE3WithRepeatedKey.
func TestSymNewModesCLI(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)

	cases := []struct {
		name    string
		key     []byte
		iv      []byte
		plain   string
		cliArgs []string
	}{
		{
			"AES-128-OFB", []byte("0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym OFB!",
			[]string{"enc", "-aes-128-ofb", "-K", "30313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"},
		},
		{
			"AES-256-OFB", []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym OFB!",
			[]string{"enc", "-aes-256-ofb", "-K", "3031323334353637383961626364656630313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"},
		},
		{
			"AES-128-CFB", []byte("0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym CFB!",
			[]string{"enc", "-aes-128-cfb", "-K", "30313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"},
		},
		{
			"AES-256-CFB", []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210"),
			"Hello, sym CFB!",
			[]string{"enc", "-aes-256-cfb", "-K", "3031323334353637383961626364656630313233343536373839616263646566", "-iv", "66656463626139383736353433323130", "-nosalt"},
		},
		{
			"DES-EDE3-ECB", bytes.Repeat([]byte{0x13}, DESEDE3KeySize), nil,
			"Hello, 3DES!",
			[]string{"enc", "-des-ede3-ecb", "-K", "131313131313131313131313131313131313131313131313", "-nosalt"},
		},
		{
			"DES-EDE3-CBC", bytes.Repeat([]byte{0x13}, DESEDE3KeySize), bytes.Repeat([]byte{0x24}, DESBlockSize),
			"Hello, 3DES!",
			[]string{"enc", "-des-ede3-cbc", "-K", "131313131313131313131313131313131313131313131313", "-iv", "2424242424242424", "-nosalt"},
		},
		{
			"DES-EDE-ECB", bytes.Repeat([]byte{0x13}, DESEDEKeySize), nil,
			"Hello, 2-key 3DES!",
			[]string{"enc", "-des-ede-ecb", "-K", "13131313131313131313131313131313", "-nosalt"},
		},
		{
			"DES-EDE-CBC", bytes.Repeat([]byte{0x13}, DESEDEKeySize), bytes.Repeat([]byte{0x24}, DESBlockSize),
			"Hello, 2-key 3DES!",
			[]string{"enc", "-des-ede-cbc", "-K", "13131313131313131313131313131313", "-iv", "2424242424242424", "-nosalt"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
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

// TestSingleDESMatchesLegacyCLI 验证单 DES 的 K‖K‖K 等价实现与「真正的单 DES」
// 逐字节一致：基准由 CLI 通过 legacy provider 提供（本库运行时不加载 legacy，
// 仅在测试里用它提供基准真相）。环境无法加载 legacy 时跳过。
//
// TestSingleDESMatchesLegacyCLI verifies the K‖K‖K equivalent implementation
// of single DES is byte-identical to real single DES, using the CLI with the
// legacy provider as ground truth (the library never loads legacy itself;
// only this test does, to obtain a baseline). It skips when the environment
// cannot load legacy.
func TestSingleDESMatchesLegacyCLI(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)

	key := bytes.Repeat([]byte{0x13}, DESKeySize)
	iv := bytes.Repeat([]byte{0x24}, DESBlockSize)
	plain := []byte("Hello, 1DES!")

	cases := []struct {
		name    string
		iv      []byte
		cliArgs []string
	}{
		{
			"DES-ECB", nil,
			[]string{"enc", "-des-ecb", "-provider", "legacy", "-provider", "default",
				"-K", "1313131313131313", "-nosalt"},
		},
		{
			"DES-CBC", iv,
			[]string{"enc", "-des-cbc", "-provider", "legacy", "-provider", "default",
				"-K", "1313131313131313", "-iv", "2424242424242424", "-nosalt"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cliOut, err := testutil.RunOpenSSL(c.cliArgs, plain)
			if err != nil {
				t.Skipf("legacy provider unavailable for %s (%s): %v", c.name, bin, err)
			}
			got, err := Encrypt(c.name, key, c.iv, plain, nil)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !bytes.Equal(got, cliOut) {
				t.Errorf("K||K||K output != real single DES:\n  got  %x\n  cli  %x", got, cliOut)
			}
		})
	}
}
