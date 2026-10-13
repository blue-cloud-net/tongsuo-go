package x509

import (
	"errors"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// makeCACert 构建一张 CA 证书（BasicConstraints CA:TRUE）。
func makeCACert(t *testing.T, priv asym.PrivateKey, cn string) *Certificate {
	t.Helper()
	now := time.Now()
	subject := NewName().Add("CN", cn)
	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(1001); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuer(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestChainVerifySelfSigned 自签证书放入信任存储后验证通过。
func TestChainVerifySelfSigned(t *testing.T) {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	subject := NewName().Add("CN", "self.example.com")
	cert, err := CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	roots := NewStore()
	if err := roots.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	chain, err := ChainVerify(cert, roots, nil)
	if err != nil {
		t.Fatalf("ChainVerify failed: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("empty chain")
	}
	if chain[0].Subject() != "self.example.com" {
		t.Fatalf("chain[0] subject = %q", chain[0].Subject())
	}

	// 未加入信任存储时自签证书验证失败
	empty := NewStore()
	if _, err := ChainVerify(cert, empty, nil); err == nil {
		t.Fatal("self-signed cert without trust anchor should fail")
	}
}

// TestChainVerifyCA CA 签发叶证书验证通过（链长 2）。
func TestChainVerifyCA(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	leafPriv, _ := asym.GenerateSM2()
	now := time.Now()
	caCert := makeCACert(t, caPriv, "Chain Root CA")

	leafSubject := NewName().Add("CN", "leaf.chain.dev")
	leafCert, err := CreateCertificate(leafSubject, caCert.SubjectName(), 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}

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
	if chain[0].Subject() != "leaf.chain.dev" {
		t.Fatalf("chain[0] = %q", chain[0].Subject())
	}
}

// TestChainVerifyForged 伪造 CA 拒绝（错误码非 0）。
func TestChainVerifyForged(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	evilPriv, _ := asym.GenerateSM2()
	leafPriv, _ := asym.GenerateSM2()
	now := time.Now()

	caCert := makeCACert(t, caPriv, "Good CA")
	evilCert := makeCACert(t, evilPriv, "Evil CA")

	leafSubject := NewName().Add("CN", "leaf.forged.dev")
	leafCert, err := CreateCertificate(leafSubject, caCert.SubjectName(), 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}

	roots := NewStore()
	if err := roots.AddCert(evilCert); err != nil {
		t.Fatal(err)
	}
	_, err = ChainVerify(leafCert, roots, nil)
	if err == nil {
		t.Fatal("verify with wrong CA should fail")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected VerifyError, got %T: %v", err, err)
	}
	if ve.Code == 0 {
		t.Fatalf("unexpected success code 0: %v", ve)
	}
}

// TestChainVerifyExpired 过期证书验证失败（错误码 10）。
func TestChainVerifyExpired(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	leafPriv, _ := asym.GenerateSM2()
	now := time.Now()
	caCert := makeCACert(t, caPriv, "Expired Root CA")

	leafSubject := NewName().Add("CN", "leaf.expired.dev")
	leafCert, err := CreateCertificate(leafSubject, caCert.SubjectName(), 2,
		now.Add(-48*time.Hour), now.Add(-24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}

	roots := NewStore()
	if err := roots.AddCert(caCert); err != nil {
		t.Fatal(err)
	}
	_, err = ChainVerify(leafCert, roots, nil)
	if err == nil {
		t.Fatal("expired cert should fail")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected VerifyError, got %T: %v", err, err)
	}
	if ve.Code != 10 { // X509_V_ERR_CERT_HAS_EXPIRED
		t.Fatalf("error code = %d, want 10 (certificate has expired): %v", ve.Code, err)
	}
}

// TestChainVerifyIntermediate Root → Intermediate → Leaf 三层链与链补全。
func TestChainVerifyIntermediate(t *testing.T) {
	rootPriv, _ := asym.GenerateSM2()
	interPriv, _ := asym.GenerateSM2()
	leafPriv, _ := asym.GenerateSM2()
	now := time.Now()

	rootSubject := NewName().Add("CN", "Chain Root CA")
	rootCert := makeCACert(t, rootPriv, "Chain Root CA")

	interSubject := NewName().Add("CN", "Chain Intermediate CA")
	interCert := NewCertificate()
	if err := interCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := interCert.SetSerial(1002); err != nil {
		t.Fatal(err)
	}
	if err := interCert.SetIssuer(rootSubject); err != nil {
		t.Fatal(err)
	}
	if err := interCert.SetSubject(interSubject); err != nil {
		t.Fatal(err)
	}
	if err := interCert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := interCert.SetPublicKey(interPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := interCert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := interCert.Sign(rootPriv); err != nil {
		t.Fatal(err)
	}

	leafSubject := NewName().Add("CN", "leaf.intermediate.dev")
	leafCert, err := CreateCertificate(leafSubject, interSubject, 1003,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), interPriv)
	if err != nil {
		t.Fatal(err)
	}

	// 仅信任根，中间证书作为 untrusted 补全链
	roots := NewStore()
	if err := roots.AddCert(rootCert); err != nil {
		t.Fatal(err)
	}
	chain, err := ChainVerify(leafCert, roots, []*Certificate{interCert})
	if err != nil {
		t.Fatalf("ChainVerify failed: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(chain))
	}
	if chain[0].Subject() != "leaf.intermediate.dev" {
		t.Fatalf("chain[0] = %q", chain[0].Subject())
	}
	if chain[1].Subject() != "Chain Intermediate CA" {
		t.Fatalf("chain[1] = %q", chain[1].Subject())
	}

	// 不提供中间证书时无法构建链
	if _, err := ChainVerify(leafCert, roots, nil); err == nil {
		t.Fatal("verify without intermediate should fail")
	}
}

// TestChainVerifyRSA 验证 RSA CA 签发 RSA 叶证书的链验证。
func TestChainVerifyRSA(t *testing.T) {
	caPriv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caSubject := NewName().Add("CN", "RSA Chain CA")
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

	leafCert, err := CreateCertificate(NewName().Add("CN", "rsa-leaf.example.com"),
		caSubject, 2, now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}

	roots := NewStore()
	if err := roots.AddCert(caCert); err != nil {
		t.Fatal(err)
	}
	chain, err := ChainVerify(leafCert, roots, nil)
	if err != nil {
		t.Fatalf("RSA chain verify failed: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
}

// TestStoreSetFlags 验证 Store.SetFlags 通用方法（传入 0 应不报错）。
func TestStoreSetFlags(t *testing.T) {
	s := NewStore()
	if err := s.SetFlags(0); err != nil {
		t.Fatalf("SetFlags(0) failed: %v", err)
	}
	if err := s.SetFlags(0x4); err != nil { // X509VFlagCRLCheck
		t.Fatalf("SetFlags(0x4) failed: %v", err)
	}
}
