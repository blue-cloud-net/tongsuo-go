package x509

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestCreateCertificateRSA 验证 RSA 密钥可签发/验证证书（自签）。
func TestCreateCertificateRSA(t *testing.T) {
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "rsa.example.com")
	cert, err := CreateCertificate(subject, subject, 20,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertificateType() != "RSA" {
		t.Fatalf("CertificateType = %q, want RSA", cert.CertificateType())
	}
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("RSA cert self-verify failed: %v", err)
	}

	// PEM 往返 + 公钥类型仍为 RSA
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := loaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(pk) }()
	if string(pk.Algorithm()) != "RSA" {
		t.Fatalf("loaded cert pubkey algorithm = %q, want RSA", pk.Algorithm())
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal("loaded RSA cert verify failed")
	}
}

// TestCreateCertificateECDSA 验证 ECDSA 密钥可签发/验证证书（自签）。
func TestCreateCertificateECDSA(t *testing.T) {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "ecdsa.example.com")
	cert, err := CreateCertificate(subject, subject, 21,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertificateType() != "EC" {
		t.Fatalf("CertificateType = %q, want EC", cert.CertificateType())
	}
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("ECDSA cert self-verify failed: %v", err)
	}
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal("loaded ECDSA cert verify failed")
	}
}

// TestCreateCertificateEd25519 验证 Ed25519 密钥可签发/验证证书（自签 + PEM 往返）。
//
// TestCreateCertificateEd25519 verifies Ed25519 self-signed certificate
// creation, signature info, PEM round-trip and verification.
func TestCreateCertificateEd25519(t *testing.T) {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "ed25519.example.com")
	cert, err := CreateCertificate(subject, subject, 40,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate Ed25519: %v", err)
	}
	if cert.CertificateType() != "ED25519" {
		t.Fatalf("CertificateType = %q, want ED25519", cert.CertificateType())
	}
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("Ed25519 self-verify failed: %v", err)
	}
	if len(cert.Signature()) != 64 {
		t.Fatalf("Ed25519 cert signature length = %d, want 64", len(cert.Signature()))
	}
	if cert.SignatureAlgorithm() != "ED25519" {
		t.Fatalf("SignatureAlgorithm = %q, want ED25519", cert.SignatureAlgorithm())
	}
	if cert.SignatureAlgorithmOID() != "1.3.101.112" {
		t.Fatalf("SignatureAlgorithmOID = %q, want 1.3.101.112", cert.SignatureAlgorithmOID())
	}

	// PEM 往返
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal("loaded Ed25519 cert verify failed")
	}
	pk, err := loaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(pk) }()
	if string(pk.Algorithm()) != "ED25519" {
		t.Fatalf("loaded pubkey algorithm = %q, want ED25519", pk.Algorithm())
	}
}

// TestCreateCertificateEd448 验证 Ed448 密钥可签发/验证证书。
func TestCreateCertificateEd448(t *testing.T) {
	priv, err := asym.GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "ed448.example.com")
	cert, err := CreateCertificate(subject, subject, 41,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate Ed448: %v", err)
	}
	if cert.CertificateType() != "ED448" {
		t.Fatalf("CertificateType = %q, want ED448", cert.CertificateType())
	}
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("Ed448 self-verify failed: %v", err)
	}
	if len(cert.Signature()) != 114 {
		t.Fatalf("Ed448 cert signature length = %d, want 114", len(cert.Signature()))
	}
	if cert.SignatureAlgorithm() != "ED448" {
		t.Fatalf("SignatureAlgorithm = %q, want ED448", cert.SignatureAlgorithm())
	}
	if cert.SignatureAlgorithmOID() != "1.3.101.113" {
		t.Fatalf("SignatureAlgorithmOID = %q, want 1.3.101.113", cert.SignatureAlgorithmOID())
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal("loaded Ed448 cert verify failed")
	}
}

// TestCASignedCertEd25519 验证 Ed25519 CA 自签 + Ed25519 CA 签 Ed25519 叶证书。
func TestCASignedCertEd25519(t *testing.T) {
	caPriv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caSubject := NewName().Add("CN", "ED25519 Root CA")
	// BasicConstraints 必须在 Sign 之前加上：Sign 之后证书即不可变
	// （x509: certificate already signed），扩展才会进入签名覆盖范围。
	caCert := NewCertificate()
	t.Cleanup(func() { _ = caCert.Close() })
	if err := caCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSerial(50); err != nil {
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
		t.Fatalf("CA sign: %v", err)
	}
	if !caCert.IsCA() {
		t.Fatal("CA cert IsCA() = false, want true")
	}
	if err := caCert.Verify(caPriv.Public()); err != nil {
		t.Fatal("CA self-verify failed")
	}

	leafCert, err := CreateCertificate(NewName().Add("CN", "leaf-ed25519.example.com"),
		caSubject, 51, now.Add(-time.Hour), now.Add(365*24*time.Hour),
		leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := leafCert.Verify(caPriv.Public()); err != nil {
		t.Fatal("CA verify leaf failed")
	}

	// CA 链验证
	roots := NewStore()
	if err := roots.AddCert(caCert); err != nil {
		t.Fatal(err)
	}
	chain, err := ChainVerify(leafCert, roots, nil)
	if err != nil {
		t.Fatalf("ChainVerify failed: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
}
