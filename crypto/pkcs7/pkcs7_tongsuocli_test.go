//go:build tongsuocli

package pkcs7

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/x509"
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

// TestCLIInterop 本库 PKCS7 ↔ openssl crl2pkcs7 / pkcs7 互通。
func TestCLIInterop(t *testing.T) {
	c1 := makeCert(t, "cli-a.pkcs7.dev", 10)
	c2 := makeCert(t, "cli-b.pkcs7.dev", 11)
	dir := t.TempDir()

	// 本库 Build → openssl pkcs7 -print_certs 读取
	der, err := Build([]*x509.Certificate{c1, c2})
	if err != nil {
		t.Fatal(err)
	}
	p7File := filepath.Join(dir, "ours.p7b")
	if err := os.WriteFile(p7File, MarshalPEM(der), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runOpenSSL(t, "pkcs7", "-in", p7File, "-print_certs", "-noout")
	if !bytes.Contains(out, []byte("cli-a.pkcs7.dev")) || !bytes.Contains(out, []byte("cli-b.pkcs7.dev")) {
		t.Fatalf("openssl pkcs7 print_certs missing certs: %s", out)
	}

	// openssl crl2pkcs7 → 本库 Extract
	c1PEM, _ := c1.MarshalPEM()
	certFile := filepath.Join(dir, "c.pem")
	if err := os.WriteFile(certFile, c1PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	osslP7 := filepath.Join(dir, "ossl.p7b")
	runOpenSSL(t, "crl2pkcs7", "-nocrl", "-certfile", certFile, "-out", osslP7)
	osslData, _ := os.ReadFile(osslP7)
	certs, err := Extract(osslData)
	if err != nil {
		t.Fatalf("extract openssl p7b failed: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject() != "cli-a.pkcs7.dev" {
		t.Fatalf("extracted certs = %v", certs)
	}
}
