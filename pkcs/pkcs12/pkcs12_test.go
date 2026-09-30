package pkcs12

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// buildTestCert 构建 CA 签发叶证书（RSA）。
func buildTestCert(t *testing.T) (leaf *x509.Certificate, leafPriv asym.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	now := time.Now()

	caPriv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	caSubject := x509.NewName().Add("CN", "PKCS12 Test CA")
	caCert = x509.NewCertificate()
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

	leafPriv, err = asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	leafSubject := x509.NewName().Add("CN", "leaf.pkcs12.dev")
	leaf, err = x509.CreateCertificate(leafSubject, caSubject, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, leafPriv, caCert
}

// TestPackParseRoundtrip 验证打包/解析往返（证书/私钥/CA 链一致）。
func TestPackParseRoundtrip(t *testing.T) {
	leafCert, leafPriv, caCert := buildTestCert(t)
	der, err := Pack(leafCert, leafPriv, []*x509.Certificate{caCert}, "pass123", "leaf")
	if err != nil {
		t.Fatal(err)
	}
	if len(der) == 0 {
		t.Fatal("empty PKCS12")
	}

	b, err := Parse(der, "pass123")
	if err != nil {
		t.Fatal(err)
	}
	// Bundle.PrivateKey 现在是 asym.PrivateKey（roadmap §5 E1-12）。
	if b.PrivateKey != nil {
		defer func() { _ = asym.Close(b.PrivateKey) }()
	}
	if b.Certificate == nil || b.Certificate.Subject() != "leaf.pkcs12.dev" {
		t.Fatalf("parsed cert = %v", b.Certificate)
	}
	if b.PrivateKey == nil {
		t.Fatal("parsed private key is nil")
	}
	// asym 密钥没有 Equal，改经 internal/keyaccess 取句柄后比较。
	gotKey, ok := keyaccess.PKey(b.PrivateKey)
	if !ok || gotKey == nil {
		t.Fatalf("parsed private key exposes no handle: %T", b.PrivateKey)
	}
	wantKey, ok := keyaccess.PKey(leafPriv)
	if !ok || wantKey == nil {
		t.Fatalf("source private key exposes no handle: %T", leafPriv)
	}
	if !gotKey.Equal(wantKey) {
		t.Fatal("parsed key mismatch")
	}
	if len(b.CACerts) != 1 || b.CACerts[0].Subject() != "PKCS12 Test CA" {
		t.Fatalf("parsed CA chain = %v", b.CACerts)
	}
}

// TestWrongPassword 验证错误口令解析失败。
func TestWrongPassword(t *testing.T) {
	leafCert, leafPriv, _ := buildTestCert(t)
	der, err := Pack(leafCert, leafPriv, nil, "pass123", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(der, "wrong"); err == nil {
		t.Fatal("parse with wrong password should fail")
	}
}

// TestChangePassword 验证改密往返。
func TestChangePassword(t *testing.T) {
	leafCert, leafPriv, caCert := buildTestCert(t)
	der, err := Pack(leafCert, leafPriv, []*x509.Certificate{caCert}, "oldpass", "")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ChangePassword(der, "oldpass", "newpass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(changed, "oldpass"); err == nil {
		t.Fatal("old password should no longer work")
	}
	b, err := Parse(changed, "newpass")
	if err != nil {
		t.Fatal(err)
	}
	if b.PrivateKey != nil {
		defer func() { _ = asym.Close(b.PrivateKey) }()
	}
	if b.Certificate.Subject() != "leaf.pkcs12.dev" {
		t.Fatal("changed password cert mismatch")
	}
}
