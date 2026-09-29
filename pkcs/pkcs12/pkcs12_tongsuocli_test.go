//go:build tongsuocli

package pkcs12

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestCLIInterop 本库 PKCS12 ↔ openssl pkcs12 双向互通。
func TestCLIInterop(t *testing.T) {
	leaf, priv, ca := buildTestCert(t)
	dir := t.TempDir()

	// 本库 Pack → openssl pkcs12 读取并导出证书
	der, err := Pack(leaf, priv, []*x509.Certificate{ca}, "pass123", "leaf")
	if err != nil {
		t.Fatal(err)
	}
	p12File := filepath.Join(dir, "ours.p12")
	if err := os.WriteFile(p12File, der, 0o600); err != nil {
		t.Fatal(err)
	}
	exportFile := filepath.Join(dir, "exported.pem")
	// 退出码 0 即表明 MAC 校验通过、可解析（口令错误会以非零退出）。
	testutil.MustRunOpenSSL(t, "pkcs12", "-in", p12File, "-passin", "pass:pass123",
		"-nokeys", "-clcerts", "-out", exportFile)
	exported, _ := os.ReadFile(exportFile)
	if !bytes.Contains(exported, []byte("leaf.pkcs12.dev")) {
		t.Fatalf("openssl exported cert missing CN: %s", exported)
	}

	// openssl pkcs12 -export → 本库 Parse
	keyPEM, _ := priv.MarshalPrivateKeyPEM()
	certPEM, _ := leaf.MarshalPEM()
	keyFile := filepath.Join(dir, "key.pem")
	certFile := filepath.Join(dir, "cert.pem")
	os.WriteFile(keyFile, keyPEM, 0o600)
	os.WriteFile(certFile, certPEM, 0o600)
	osslP12 := filepath.Join(dir, "ossl.p12")
	testutil.MustRunOpenSSL(t, "pkcs12", "-export", "-inkey", keyFile, "-in", certFile,
		"-passout", "pass:osslpass", "-out", osslP12)
	osslDER, _ := os.ReadFile(osslP12)
	b, err := Parse(osslDER, "osslpass")
	if err != nil {
		t.Fatalf("parse openssl p12 failed: %v", err)
	}
	if b.PrivateKey != nil {
		defer func() { _ = asym.Close(b.PrivateKey) }()
	}
	if b.Certificate == nil || b.Certificate.Subject() != "leaf.pkcs12.dev" {
		t.Fatalf("parsed openssl cert = %v", b.Certificate)
	}
	gotKey, ok := keyaccess.PKey(b.PrivateKey)
	if !ok || gotKey == nil {
		t.Fatalf("parsed private key exposes no handle: %T", b.PrivateKey)
	}
	wantKey, ok := keyaccess.PKey(priv)
	if !ok || wantKey == nil {
		t.Fatalf("source private key exposes no handle: %T", priv)
	}
	if !gotKey.Equal(wantKey) {
		t.Fatal("parsed openssl key mismatch")
	}
}
