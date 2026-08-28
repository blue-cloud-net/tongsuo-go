//go:build tongsuocli

package x509

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strconv"
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

// runOpenSSLInDir 在指定目录下运行铜锁 openssl（供 openssl ca 相对路径配置使用）。
func runOpenSSLInDir(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// setupCRLEnv 在临时目录搭建 openssl CA 环境并生成：
// ca.pem（CA）、leaf1.pem（已吊销）、leaf2.pem（未吊销）、crl.pem（吊销 leaf1）。
func setupCRLEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(dir+"/demoCA/newcerts", 0o700))
	must(os.WriteFile(dir+"/demoCA/index.txt", nil, 0o600))
	must(os.WriteFile(dir+"/demoCA/serial", []byte("1000\n"), 0o600))
	must(os.WriteFile(dir+"/demoCA/crlnumber", []byte("1000\n"), 0o600))
	cnf := `[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ./demoCA
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
crlnumber = $dir/crlnumber
private_key = ./ca.key
certificate = ./ca.pem
default_md = sha256
default_days = 365
default_crl_days = 30
policy = policy_any
[ policy_any ]
commonName = supplied
`
	must(os.WriteFile(dir+"/openssl.cnf", []byte(cnf), 0o600))

	runOpenSSLInDir(t, dir, "req", "-new", "-x509", "-nodes", "-keyout", "ca.key",
		"-out", "ca.pem", "-subj", "/CN=CRL Test CA", "-days", "3650")
	for _, n := range []string{"leaf1", "leaf2"} {
		runOpenSSLInDir(t, dir, "req", "-new", "-nodes", "-keyout", n+".key",
			"-out", n+".csr", "-subj", "/CN="+n+".crl.dev")
		runOpenSSLInDir(t, dir, "ca", "-batch", "-config", "openssl.cnf",
			"-in", n+".csr", "-out", n+".pem")
	}
	runOpenSSLInDir(t, dir, "ca", "-config", "openssl.cnf",
		"-revoke", "leaf1.pem", "-crl_reason", "keyCompromise")
	runOpenSSLInDir(t, dir, "ca", "-config", "openssl.cnf", "-gencrl", "-out", "crl.pem")
	return dir
}

// TestCLICrlParse 本库解析 openssl 生成的 CRL（签发者/时间窗/吊销条目与原因），并对比 openssl crl -text。
func TestCLICrlParse(t *testing.T) {
	dir := setupCRLEnv(t)
	crlPEM, err := os.ReadFile(dir + "/crl.pem")
	if err != nil {
		t.Fatal(err)
	}
	crl, err := LoadCRLPEM(crlPEM)
	if err != nil {
		t.Fatal(err)
	}

	if crl.Version() != 1 { // 0=v1，1=v2
		t.Fatalf("CRL version = %d, want 1 (v2)", crl.Version())
	}
	if crl.Issuer().Get("CN") != "CRL Test CA" {
		t.Fatalf("CRL issuer = %q", crl.Issuer().String())
	}
	if crl.LastUpdate().IsZero() {
		t.Fatal("empty LastUpdate")
	}
	if !crl.NextUpdate().After(crl.LastUpdate()) {
		t.Fatal("NextUpdate should be after LastUpdate")
	}

	entries := crl.RevokedEntries()
	if len(entries) != 1 {
		t.Fatalf("revoked entries = %d, want 1", len(entries))
	}
	if entries[0].Serial == 0 {
		t.Fatal("empty serial")
	}
	if entries[0].Reason != "keyCompromise" {
		t.Fatalf("reason = %q, want keyCompromise", entries[0].Reason)
	}
	if entries[0].RevocationDate.IsZero() {
		t.Fatal("empty revocation date")
	}

	// DER 往返
	der, err := crl.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	crl2, err := LoadCRLDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl2.RevokedEntries()) != 1 || crl2.RevokedEntries()[0].Serial != entries[0].Serial {
		t.Fatal("DER roundtrip lost revoked entries")
	}

	// 与 openssl crl -text 对比（openssl 以十六进制显示序列号）
	hexSerial := strings.ToUpper(strconv.FormatInt(entries[0].Serial, 16))
	out := runOpenSSLInDir(t, dir, "crl", "-in", "crl.pem", "-noout", "-text")
	if !strings.Contains(string(out), "Serial Number: "+hexSerial) {
		t.Fatalf("openssl crl text missing serial %s: %s", hexSerial, out)
	}
	if !strings.Contains(string(out), "Key Compromise") {
		t.Fatalf("openssl crl text missing reason: %s", out)
	}
}

// TestCLIRevocationCheck 本库吊销检查与 openssl verify -crl_check 互通。
func TestCLIRevocationCheck(t *testing.T) {
	dir := setupCRLEnv(t)
	caPEM, _ := os.ReadFile(dir + "/ca.pem")
	leaf1PEM, _ := os.ReadFile(dir + "/leaf1.pem")
	leaf2PEM, _ := os.ReadFile(dir + "/leaf2.pem")
	crlPEM, _ := os.ReadFile(dir + "/crl.pem")

	caCert, err := LoadCertificatePEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf1, err := LoadCertificatePEM(leaf1PEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := LoadCertificatePEM(leaf2PEM)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := LoadCRLPEM(crlPEM)
	if err != nil {
		t.Fatal(err)
	}

	// RevocationCheck：leaf1 被吊销，leaf2 未吊销
	if err := RevocationCheck(leaf1, []*CRL{crl}); err == nil {
		t.Fatal("leaf1 should be revoked")
	} else if !strings.Contains(err.Error(), strconv.FormatInt(leaf1.Serial(), 10)) {
		t.Fatalf("revoke error should mention serial %d: %v", leaf1.Serial(), err)
	}
	if err := RevocationCheck(leaf2, []*CRL{crl}); err != nil {
		t.Fatalf("leaf2 should not be revoked: %v", err)
	}

	// Store + SetCRLCheck + ChainVerify：leaf1 报 code 23（CERT_REVOKED）
	roots := NewStore()
	if err := roots.AddCert(caCert); err != nil {
		t.Fatal(err)
	}
	if err := roots.AddCRL(crl); err != nil {
		t.Fatal(err)
	}
	if err := roots.SetCRLCheck(); err != nil {
		t.Fatal(err)
	}
	if _, err := ChainVerify(leaf1, roots, nil); err == nil {
		t.Fatal("leaf1 verify should fail (revoked)")
	} else {
		var ve *VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("expected VerifyError, got %T: %v", err, err)
		}
		if ve.Code != 23 { // X509_V_ERR_CERT_REVOKED
			t.Fatalf("error code = %d, want 23 (certificate revoked): %v", ve.Code, err)
		}
	}
	if _, err := ChainVerify(leaf2, roots, nil); err != nil {
		t.Fatalf("leaf2 verify should pass: %v", err)
	}

	// 与 openssl verify -crl_check 结果一致（openssl 对验证失败返回退出码 2，属预期）
	cmd := exec.Command(testutil.OpenSSLBin(), "verify", "-CAfile", "ca.pem",
		"-crl_check", "-CRLfile", "crl.pem", "leaf1.pem")
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()
	if !bytes.Contains(out, []byte("certificate revoked")) {
		t.Fatalf("openssl verify -crl_check should report revoked: %s", out)
	}
}
