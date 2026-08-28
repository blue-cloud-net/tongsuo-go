//go:build tongsuocli

package jwk

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

func runOpenSSL(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// TestCLIInterop JWK ↔ PEM ↔ openssl pkey 互通。
func TestCLIInterop(t *testing.T) {
	dir := t.TempDir()

	// 本库 JWK → PEM → openssl pkey 可读取
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := Marshal(priv.Key())
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
	out := runOpenSSL(t, "pkey", "-in", pemFile, "-noout", "-text")
	if !bytes.Contains(out, []byte("Private-Key")) {
		t.Fatalf("openssl cannot read our JWK-derived PEM: %s", out)
	}

	// openssl genpkey → PEM → FromPEM → JWK
	genFile := filepath.Join(dir, "gen.pem")
	runOpenSSL(t, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", genFile)
	genPEM, _ := os.ReadFile(genFile)
	k2, err := FromPEM(genPEM)
	if err != nil {
		t.Fatalf("FromPEM of openssl key failed: %v", err)
	}
	if k2.Kty != "RSA" || k2.N == "" || k2.E == "" {
		t.Fatalf("jwk fields: %+v", k2)
	}
}
