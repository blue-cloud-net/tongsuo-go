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

// TestCLIFingerprint 本库指纹与 openssl x509 -fingerprint -sha256 一致。
func TestCLIFingerprint(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "fp-cli.example.com")
	cert, err := CreateCertificate(subject, subject, 11,
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

	out := runOpenSSLFile(t, "x509", "-in", certFile, "-noout", "-fingerprint", "-sha256")
	parts := strings.Split(strings.TrimSpace(string(out)), "=")
	if len(parts) != 2 {
		t.Fatalf("unexpected openssl fingerprint output: %s", out)
	}
	cliFP := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(parts[1]), ":", ""))

	ourFP, err := cert.Fingerprint("sha256")
	if err != nil {
		t.Fatal(err)
	}
	if ourFP != cliFP {
		t.Fatalf("sha256 fingerprint mismatch: ours=%s openssl=%s", ourFP, cliFP)
	}
}

// TestCLIDer 本库 DER 导出/导入与 openssl 互通（-inform DER / -outform DER）。
func TestCLIDer(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "der-cli.example.com")
	cert, err := CreateCertificate(subject, subject, 12,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	derFile := dir + "/cert.der"
	if err := os.WriteFile(derFile, der, 0o600); err != nil {
		t.Fatal(err)
	}

	// openssl 可读取本库导出的 DER
	out := runOpenSSLFile(t, "x509", "-in", derFile, "-inform", "DER", "-noout", "-subject")
	if !strings.Contains(string(out), "CN=der-cli.example.com") {
		t.Fatalf("openssl DER subject mismatch: %s", out)
	}

	// openssl 导出 DER → 本库读取（字节一致）
	pemFile := dir + "/cert.pem"
	certPEM, _ := cert.MarshalPEM()
	if err := os.WriteFile(pemFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenSSLFile(t, "x509", "-in", pemFile, "-outform", "DER", "-out", dir+"/cli.der")
	cliDER, err := os.ReadFile(dir + "/cli.der")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cliDER, der) {
		t.Fatalf("DER mismatch: openssl %d bytes vs ours %d bytes", len(cliDER), len(der))
	}
	loaded, err := LoadCertificateDER(cliDER)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Subject() != "der-cli.example.com" {
		t.Fatalf("loaded DER subject = %q", loaded.Subject())
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal(err)
	}
}

// TestCLISANText 本库构建的 SAN 扩展与 openssl x509 -text 一致。
func TestCLISANText(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "san-cli.example.com")
	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(13); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuer(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddSubjectAltName("DNS:san-cli.example.com,IP:192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddKeyUsage("critical,digitalSignature,keyEncipherment"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	certPEM, _ := cert.MarshalPEM()
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := runOpenSSLFile(t, "x509", "-in", certFile, "-noout", "-text")
	s := string(out)
	if !strings.Contains(s, "DNS:san-cli.example.com") {
		t.Fatalf("openssl text missing DNS SAN: %s", s)
	}
	if !strings.Contains(s, "IP Address:192.168.1.10") {
		t.Fatalf("openssl text missing IP SAN: %s", s)
	}
	if !strings.Contains(s, "Digital Signature") || !strings.Contains(s, "Key Encipherment") {
		t.Fatalf("openssl text missing KeyUsage: %s", s)
	}
}

// TestCLICSRText 本库构建的 CSR（SAN + 挑战密码 + 多字段）与 openssl req -text 一致。
func TestCLICSRText(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	subject := NewName().Add("CN", "csr-cli.example.com").Add("O", "CLI CSR Org").Add("C", "CN")
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.SetChallengePassword("cliSecret"); err != nil {
		t.Fatal(err)
	}
	if err := req.AddSubjectAltName("DNS:csr-cli.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	reqFile := dir + "/req.pem"
	reqPEM, _ := req.MarshalPEM()
	if err := os.WriteFile(reqFile, reqPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := runOpenSSLFile(t, "req", "-text", "-noout", "-verify", "-in", reqFile)
	s := string(out)
	if !strings.Contains(s, "verify OK") {
		t.Fatalf("openssl req verify failed: %s", s)
	}
	if !strings.Contains(s, "challengePassword") || !strings.Contains(s, "cliSecret") {
		t.Fatalf("openssl req text missing challenge password: %s", s)
	}
	if !strings.Contains(s, "DNS:csr-cli.example.com") {
		t.Fatalf("openssl req text missing SAN: %s", s)
	}
	if !strings.Contains(s, "CN=csr-cli.example.com") || !strings.Contains(s, "O=CLI CSR Org") {
		t.Fatalf("openssl req text missing subject fields: %s", s)
	}
}
