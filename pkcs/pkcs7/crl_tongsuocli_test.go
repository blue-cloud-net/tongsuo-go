//go:build tongsuocli

package pkcs7

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestCLICRLInterop 验证 CRL 双向互通：
//   - 本库 FromCRL → `openssl pkcs7 -print` 能识别为 signedData；
//   - `openssl crl2pkcs7 -in <crl.pem>` → 本库 ExtractCRLs 取回同一张 CRL。
//
// TestCLICRLInterop verifies CRL interop in both directions:
//   - the library's FromCRL output is recognised as signedData by
//     `openssl pkcs7 -print`;
//   - `openssl crl2pkcs7 -in <crl.pem>` output is read back by the
//     library's ExtractCRLs.
func TestCLICRLInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	crl := makeCRL(t, "cli-crl.pkcs7.dev")
	dir := t.TempDir()

	// 本库 → CLI
	der, err := FromCRL([]*x509.CRL{crl})
	if err != nil {
		t.Fatalf("FromCRL: %v", err)
	}
	ours := filepath.Join(dir, "ours-crl.p7b")
	if err := os.WriteFile(ours, MarshalPEM(der), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := testutil.MustRunOpenSSL(t, "pkcs7", "-in", ours, "-print", "-noout")
	if len(out) == 0 {
		t.Fatal("openssl pkcs7 -print produced no output for our container")
	}

	// CLI → 本库
	crlPEM, err := crl.MarshalPEM()
	if err != nil {
		t.Fatalf("crl.MarshalPEM: %v", err)
	}
	crlFile := filepath.Join(dir, "c.crl")
	if err := os.WriteFile(crlFile, crlPEM, 0o600); err != nil {
		t.Fatalf("write crl: %v", err)
	}
	osslP7 := filepath.Join(dir, "ossl-crl.p7b")
	testutil.MustRunOpenSSL(t, "crl2pkcs7", "-in", crlFile, "-outform", "PEM", "-out", osslP7)
	data, err := os.ReadFile(osslP7)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	crls, err := ExtractCRLs(data)
	if err != nil {
		t.Fatalf("ExtractCRLs: %v", err)
	}
	if len(crls) != 1 {
		t.Fatalf("got %d CRLs, want 1", len(crls))
	}
	if got := len(crls[0].RevokedEntries()); got != 1 {
		t.Errorf("revoked entries = %d, want 1", got)
	}
}
