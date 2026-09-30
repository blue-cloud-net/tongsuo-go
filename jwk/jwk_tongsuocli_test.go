//go:build tongsuocli

package jwk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIInterop JWK ↔ PEM ↔ openssl pkey 互通。
func TestCLIInterop(t *testing.T) {
	dir := t.TempDir()

	// 本库 JWK → PEM → openssl pkey 可读取
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(priv) }()
	k, err := MarshalKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := k.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	pemFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(pemFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	out := testutil.MustRunOpenSSL(t, "pkey", "-in", pemFile, "-noout", "-text")
	if !bytes.Contains(out, []byte("Private-Key")) {
		t.Fatalf("openssl cannot read our JWK-derived PEM: %s", out)
	}

	// openssl genpkey → PEM → FromPEM → JWK
	genFile := filepath.Join(dir, "gen.pem")
	testutil.MustRunOpenSSL(t, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", genFile)
	genPEM, _ := os.ReadFile(genFile)
	k2, err := FromPEM(genPEM)
	if err != nil {
		t.Fatalf("FromPEM of openssl key failed: %v", err)
	}
	if k2.Kty != "RSA" || k2.N == "" || k2.E == "" {
		t.Fatalf("jwk fields: %+v", k2)
	}
	// openssl 生成的密钥经本库加载后，私钥 JWK 也应带 dp/dq/qi，
	// 覆盖"外部 PEM → 本库加载 → 私钥 JWK 含 CRT"完整互通路径。
	if k2.IsPrivate() {
		if k2.DP == "" || k2.DQ == "" || k2.QI == "" {
			t.Fatalf("RSA private JWK from openssl PEM should carry dp/dq/qi: %+v", k2)
		}
	}
}
