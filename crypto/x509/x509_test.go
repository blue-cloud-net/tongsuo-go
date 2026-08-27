package x509

import (
	"bytes"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
)

// TestSelfSignedCert 验证自签证书创建、字段读取、自验签与 PEM 往返。
func TestSelfSignedCert(t *testing.T) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	subject := NewName().Add("CN", "example.com").Add("O", "Example Org").Add("C", "CN")
	cert, err := CreateCertificate(subject, subject, 1001, notBefore, notAfter, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject() != "example.com" {
		t.Fatalf("subject = %q, want example.com", cert.Subject())
	}
	if cert.Issuer() != "example.com" {
		t.Fatalf("issuer = %q", cert.Issuer())
	}
	if cert.Serial() != 1001 {
		t.Fatalf("serial = %d", cert.Serial())
	}

	// 有效期读取（秒级容差）
	nb := cert.NotBefore()
	if nb.Before(notBefore.Add(-2*time.Second)) || nb.After(notBefore.Add(2*time.Second)) {
		t.Fatalf("notBefore = %v, want ~%v", nb, notBefore)
	}

	// 自签验证
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("self-verify failed: %v", err)
	}

	// PEM 往返
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pem, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatalf("bad PEM header: %q", pem[:32])
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Subject() != "example.com" {
		t.Fatalf("loaded subject = %q", loaded.Subject())
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal(err)
	}

	// 证书公钥可用于 SM2 加解密
	certPub, err := loaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sm2.Encrypt(certPub, []byte("hello cert"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sm2.Decrypt(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello cert" {
		t.Fatal("cert pubkey encrypt/decrypt mismatch")
	}
}

// TestCASignedCert 验证 CA 签发链：CA 自签，叶证书由 CA 签发。
func TestCASignedCert(t *testing.T) {
	caPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()

	now := time.Now()
	caSubject := NewName().Add("CN", "Test Root CA")
	caCert, err := CreateCertificate(caSubject, caSubject, 1,
		now.Add(-time.Hour), now.Add(2*365*24*time.Hour), caPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := caCert.Verify(caPriv.Public()); err != nil {
		t.Fatal("CA self-verify failed")
	}

	leafSubject := NewName().Add("CN", "leaf.example.com")
	leafCert, err := CreateCertificate(leafSubject, caSubject, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	if leafCert.Issuer() != "Test Root CA" {
		t.Fatalf("leaf issuer = %q", leafCert.Issuer())
	}
	if err := leafCert.Verify(caPriv.Public()); err != nil {
		t.Fatal("CA verify leaf failed")
	}

	// 错误 CA 验证失败
	other, _ := sm2.GenerateKey()
	if err := leafCert.Verify(other.Public()); err == nil {
		t.Fatal("verify with wrong CA should fail")
	}
}

// TestCSR 验证 CSR 创建、签名、PEM 往返与公钥读取。
func TestCSR(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	subject := NewName().Add("CN", "csr.example.com").Add("O", "CSR Org")
	req, err := NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Verify(); err != nil {
		t.Fatal(err)
	}

	pem, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pem, []byte("-----BEGIN CERTIFICATE REQUEST-----")) {
		t.Fatalf("bad CSR PEM: %q", pem[:32])
	}
	loaded, err := LoadCertificateRequestPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(); err != nil {
		t.Fatal("loaded CSR verify failed")
	}

	pub, err := loaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := sm2.Encrypt(pub, []byte("csr pub"))
	pt, err := sm2.Decrypt(priv, ct)
	if err != nil || string(pt) != "csr pub" {
		t.Fatal("CSR pubkey encrypt/decrypt mismatch")
	}
}

// TestLoadInvalid 验证加载非法 PEM 返回错误。
func TestLoadInvalid(t *testing.T) {
	if _, err := LoadCertificatePEM([]byte("bad")); err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
	if _, err := LoadCertificateRequestPEM([]byte("bad")); err == nil {
		t.Fatal("expected error for invalid CSR PEM")
	}
}
