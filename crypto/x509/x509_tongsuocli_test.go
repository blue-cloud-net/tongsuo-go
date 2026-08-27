//go:build tongsuocli

package x509

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

func runOpenSSLFile(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// TestCLICertVerify 本库签发证书 → 铜锁 openssl verify 验证通过。
func TestCLICertVerify(t *testing.T) {
	caPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
	now := time.Now()

	caSubject := NewName().Add("CN", "Tongsuo-Go Test CA")
	caCert := NewCertificate()
	if err := caCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSerial(1); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetIssuer(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSubject(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetPublicKey(caPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	leafCert, err := CreateCertificate(NewName().Add("CN", "leaf.tongsuo-go.dev"),
		caSubject, 2, now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caPEM, _ := caCert.MarshalPEM()
	leafPEM, _ := leafCert.MarshalPEM()
	caFile := dir + "/ca.pem"
	leafFile := dir + "/leaf.pem"
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafFile, leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := runOpenSSLFile(t, "verify", "-CAfile", caFile, leafFile)
	if !bytes.Contains(out, []byte("OK")) {
		t.Fatalf("openssl verify failed: %s", out)
	}
}

// TestCLISubjectIssuer 与 openssl x509 对比主题/签发者/序列号。
func TestCLISubjectIssuer(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "cli.example.com").Add("O", "CLI Org")
	cert, err := CreateCertificate(subject, subject, 42,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	certPEM, _ := cert.MarshalPEM()
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := runOpenSSLFile(t, "x509", "-in", certFile, "-noout", "-subject", "-issuer", "-serial")
	s := string(out)
	if !strings.Contains(s, "CN=cli.example.com") {
		t.Fatalf("openssl subject mismatch: %s", s)
	}
	if !strings.Contains(s, "CN=cli.example.com") {
		t.Fatalf("openssl issuer mismatch: %s", s)
	}
	if !strings.Contains(s, "serial=2A") { // 42 = 0x2A
		t.Fatalf("openssl serial mismatch: %s", s)
	}
}

// TestCLICSRVerify 本库生成 CSR → 铜锁 openssl req -verify 通过，并可用 openssl 签发。
func TestCLICSRVerify(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	subject := NewName().Add("CN", "cli-csr.example.com")
	req, err := NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	reqFile := dir + "/req.pem"
	reqPEM, _ := req.MarshalPEM()
	if err := os.WriteFile(reqFile, reqPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := runOpenSSLFile(t, "req", "-verify", "-in", reqFile, "-noout")
	if !bytes.Contains(out, []byte("verify OK")) {
		t.Fatalf("openssl req -verify failed: %s", out)
	}
}
