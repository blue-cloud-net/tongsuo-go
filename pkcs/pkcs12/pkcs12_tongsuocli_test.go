//go:build tongsuocli

package pkcs12

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/x509"
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
	runOpenSSL(t, "pkcs12", "-in", p12File, "-passin", "pass:pass123",
		"-nokeys", "-clcerts", "-out", exportFile)
	exported, _ := os.ReadFile(exportFile)
	if !bytes.Contains(exported, []byte("leaf.pkcs12.dev")) {
		t.Fatalf("openssl exported cert missing CN: %s", exported)
	}

	// openssl pkcs12 -export → 本库 Parse
	keyPEM, _ := priv.MarshalPEM()
	certPEM, _ := leaf.MarshalPEM()
	keyFile := filepath.Join(dir, "key.pem")
	certFile := filepath.Join(dir, "cert.pem")
	os.WriteFile(keyFile, keyPEM, 0o600)
	os.WriteFile(certFile, certPEM, 0o600)
	osslP12 := filepath.Join(dir, "ossl.p12")
	runOpenSSL(t, "pkcs12", "-export", "-inkey", keyFile, "-in", certFile,
		"-passout", "pass:osslpass", "-out", osslP12)
	osslDER, _ := os.ReadFile(osslP12)
	b, err := Parse(osslDER, "osslpass")
	if err != nil {
		t.Fatalf("parse openssl p12 failed: %v", err)
	}
	if b.PrivateKey != nil {
		defer b.PrivateKey.Close()
	}
	if b.Certificate == nil || b.Certificate.Subject() != "leaf.pkcs12.dev" {
		t.Fatalf("parsed openssl cert = %v", b.Certificate)
	}
	if !b.PrivateKey.Equal(priv.Key()) {
		t.Fatal("parsed openssl key mismatch")
	}
}
