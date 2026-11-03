//go:build tongsuocli

package ecdh

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"testing"
)

// TestCLIParameters 验证命名/显式参数与 CLI 逐字节一致。
//
// TestCLIParameters verifies named/explicit parameters match the CLI byte for byte.
func TestCLIParameters(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	for _, c := range []*Curve{P256(), P384(), P521(), Secp256k1()} {
		for _, explicit := range []bool{false, true} {
			flag := "named_curve"
			if explicit {
				flag = "explicit"
			}
			args := []string{"ecparam", "-name", c.ossl, "-param_enc", flag}
			want, err := testutil.RunOpenSSL(args, nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := MarshalParametersPEM(c, explicit)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s %v: %v", c.Name(), explicit, err)
			}
			parsed, err := LoadParametersPEM(want)
			if err != nil || parsed.Name() != c.Name() {
				t.Fatalf("load CLI parameters: %v", err)
			}
			if out, err := testutil.RunOpenSSLCombined([]string{"ecparam", "-check", "-noout"}, got); err != nil {
				t.Fatalf("CLI check: %s %v", out, err)
			}
		}
	}
}
