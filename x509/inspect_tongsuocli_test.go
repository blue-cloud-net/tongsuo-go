//go:build tongsuocli

package x509

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// buildCliEmailCert 构建一张带 rfc822Name SAN 的证书，供 CheckEmail 对拍。
//
// buildCliEmailCert builds a certificate carrying an rfc822Name SAN entry for
// the CheckEmail interop test.
func buildCliEmailCert(t *testing.T) *Certificate {
	t.Helper()
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "mail.example.com")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(0x1E971660AE8CEE19); err != nil {
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
	if err := cert.AddSubjectAltName("email:admin@mail.example.com,email:ops@mail.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestCLISerialHex 本库 SerialHex 与 openssl x509 -serial 逐字节一致。
//
// TestCLISerialHex checks that SerialHex matches `openssl x509 -serial`
// byte for byte.
func TestCLISerialHex(t *testing.T) {
	cert := buildCliEmailCert(t)
	t.Cleanup(func() { _ = cert.Close() })

	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	certPEM, _ := cert.MarshalPEM()
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := strings.TrimSpace(string(testutil.MustRunOpenSSL(t,
		"x509", "-in", certFile, "-noout", "-serial")))
	cli := strings.TrimSpace(strings.TrimPrefix(out, "serial="))
	if cli == "" {
		t.Fatalf("openssl -serial returned no value: %q", out)
	}
	if got := cert.SerialHex(); got != cli {
		t.Fatalf("SerialHex() = %q, openssl = %q", got, cli)
	}
}

// TestCLISubjectHash 本库 SubjectHash / IssuerHash 与 openssl -subject_hash /
// -issuer_hash 逐字节一致。
//
// TestCLISubjectHash checks that SubjectHash and IssuerHash match
// `openssl x509 -subject_hash` and `-issuer_hash` byte for byte.
func TestCLISubjectHash(t *testing.T) {
	caPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// CA（subject != issuer，便于区分两个 hash）
	caName := NewName().Add("CN", "Hash CA").Add("O", "Issuer Org")
	caCert, err := CreateCertificate(caName, NewName().Add("CN", "Different Root"),
		1, now.Add(-time.Hour), now.Add(365*24*time.Hour), caPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caCert.Close() })

	leaf := NewCertificate()
	if err := leaf.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetSerial(2); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetIssuer(caName); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetSubject(NewName().Add("CN", "leaf-hash.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetPublicKey(leafPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := leaf.Sign(caPriv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leaf.Close() })

	dir := t.TempDir()
	leafFile := dir + "/leaf.pem"
	leafPEM, _ := leaf.MarshalPEM()
	if err := os.WriteFile(leafFile, leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	subjOut := strings.ToLower(strings.TrimSpace(string(testutil.MustRunOpenSSL(t,
		"x509", "-in", leafFile, "-noout", "-subject_hash"))))
	if want := fmt.Sprintf("%08x", leaf.SubjectHash()); subjOut != want {
		t.Fatalf("SubjectHash() = %08x, openssl -subject_hash = %q", leaf.SubjectHash(), subjOut)
	}

	issOut := strings.ToLower(strings.TrimSpace(string(testutil.MustRunOpenSSL(t,
		"x509", "-in", leafFile, "-noout", "-issuer_hash"))))
	if want := fmt.Sprintf("%08x", leaf.IssuerHash()); issOut != want {
		t.Fatalf("IssuerHash() = %08x, openssl -issuer_hash = %q", leaf.IssuerHash(), issOut)
	}

	// CA 自身：subject 与 issuer 不同，两个 hash 必须不同
	if caCert.SubjectHash() == caCert.IssuerHash() {
		t.Error("CA subject and issuer hashes should differ")
	}
}

// TestCLICheckEmail 本库 CheckEmail 与铜锁 `openssl verify -verify_email` 结论一致。
//
// TestCLICheckEmail checks that CheckEmail agrees with the Tongsuo
// `openssl verify -verify_email` verdict.
func TestCLICheckEmail(t *testing.T) {
	caPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	caName := NewName().Add("CN", "Email CA")

	// CA 证书：必须在 Sign 之前加扩展（签名后不可变）
	caCert := NewCertificate()
	if err := caCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSerial(1); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetIssuer(caName); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSubject(caName); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetPublicKey(caPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caCert.Close() })

	leaf := NewCertificate()
	if err := leaf.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetSerial(2); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetIssuer(caName); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetSubject(NewName().Add("CN", "mail.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetPublicKey(leafPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := leaf.AddSubjectAltName("email:admin@mail.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := leaf.Sign(caPriv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leaf.Close() })

	// 本库结论
	if err := leaf.CheckEmail("admin@mail.example.com"); err != nil {
		t.Errorf("CheckEmail(match) = %v, want nil", err)
	}
	if err := leaf.CheckEmail("nobody@mail.example.com"); err == nil {
		t.Error("CheckEmail(no match) should fail")
	}

	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	leafFile := dir + "/leaf.pem"
	caPEM, _ := caCert.MarshalPEM()
	leafPEM, _ := leaf.MarshalPEM()
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafFile, leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// 铜锁结论
	out := testutil.MustRunOpenSSL(t, "verify", "-CAfile", caFile,
		"-verify_email", "admin@mail.example.com", leafFile)
	if !strings.Contains(string(out), "OK") {
		t.Errorf("openssl verify -verify_email match: %s", out)
	}
	if bad, err := testutil.RunOpenSSLCombined([]string{
		"verify", "-CAfile", caFile,
		"-verify_email", "nobody@mail.example.com", leafFile,
	}, nil); err == nil {
		t.Errorf("openssl verify -verify_email should reject: %s", bad)
	}
}
