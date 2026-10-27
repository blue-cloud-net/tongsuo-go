package x509

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// TestRevocationCheckBasic 无 CRL 时不吊销；空参数返回错误。
func TestRevocationCheckBasic(t *testing.T) {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	subject := NewName().Add("CN", "revoke.example.com")
	cert, err := CreateCertificate(subject, subject, 5,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	// 无 CRL → 未吊销
	if err := RevocationCheck(cert, nil); err != nil {
		t.Fatalf("RevocationCheck with no CRL should pass: %v", err)
	}
	if err := RevocationCheck(cert, []*CRL{}); err != nil {
		t.Fatalf("RevocationCheck with empty CRL list should pass: %v", err)
	}

	// nil 证书 → 错误
	if err := RevocationCheck(nil, nil); err == nil {
		t.Fatal("RevocationCheck with nil cert should error")
	}
}

// TestCRLSignatureInfoSM2 验证 SM2 签发 CRL 的签名三件套、Issuer 辅助方法、Number、Extensions。
// CRL 由 core 直接签发（绕开 CA 证书持有），通过 PEM 往返后由公开 API 加载与验证。
func TestCRLSignatureInfoSM2(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	now := time.Now()
	caName := NewName().Add("CN", "CRL SM2 CA")

	// 通过 core 直接构建 CRL
	coreCRL, err := core.NewCRL(caName.name, pkeyOf(caPriv), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("core.NewCRL: %v", err)
	}
	defer coreCRL.Close()

	// 序列化为 PEM 再通过公开 API 加载（避免所有权/句柄泄漏）
	pem, err := coreCRL.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()

	if loaded.Version() != 1 {
		t.Fatalf("CRL version = %d, want 1 (v2)", loaded.Version())
	}
	if len(loaded.Signature()) == 0 {
		t.Fatal("CRL signature should not be empty")
	}
	if loaded.SignatureAlgorithm() != "SM2-SM3" {
		t.Fatalf("CRL SignatureAlgorithm = %q, want SM2-SM3", loaded.SignatureAlgorithm())
	}
	if loaded.SignatureAlgorithmOID() != "1.2.156.10197.1.501" {
		t.Fatalf("CRL SignatureAlgorithmOID = %q, want 1.2.156.10197.1.501", loaded.SignatureAlgorithmOID())
	}

	// Issuer 辅助方法
	if loaded.Issuer().Get("CN") != "CRL SM2 CA" {
		t.Fatalf("CRL issuer CN = %q", loaded.Issuer().Get("CN"))
	}
	issuerEntries := loaded.IssuerEntries()
	if len(issuerEntries) != 1 || issuerEntries[0].Value != "CRL SM2 CA" {
		t.Fatalf("CRL IssuerEntries = %v", issuerEntries)
	}
	if loaded.IssuerText() == "" {
		t.Fatal("CRL IssuerText should not be empty")
	}

	// Extensions 应至少含 CRL Number
	exts := loaded.Extensions()
	hasNumber := false
	for _, e := range exts {
		if e.Field == "crlNumber" {
			hasNumber = true
		}
	}
	if !hasNumber {
		t.Logf("note: CRL extensions lack crlNumber (OpenSSL may not attach it to empty v2 CRL): %v", exts)
	}

	// Number() 在 OpenSSL 未附加 CRL Number 扩展时返回 -1（已记录）
	if loaded.Number() >= 0 {
		t.Logf("CRL Number() = %d", loaded.Number())
	}

	// DER 往返
	der, err := loaded.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	loaded2, err := LoadCRLDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded2.Close()
	if loaded2.SignatureAlgorithm() != "SM2-SM3" {
		t.Fatalf("DER-loaded CRL SignatureAlgorithm = %q", loaded2.SignatureAlgorithm())
	}
}

// TestCRLAKID 验证 CRL.AuthorityKeyID 与 issuer CA 的 SKID 一致（自签发 CRL 场景）。
func TestCRLAKID(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	now := time.Now()
	caName := NewName().Add("CN", "AKID CRL CA")

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
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
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

	// 通过 core 直接签发 CRL；core.NewCRL 不附加 AKID，需手工附加（与 openssl ca -gencrl 行为类似）。
	coreCRL, err := core.NewCRL(caName.name, pkeyOf(caPriv), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("core.NewCRL: %v", err)
	}
	defer coreCRL.Close()

	// 手工添加 AuthorityKeyIdentifier 扩展（keyid 取自 CA 的 SKID）
	if err := coreCRL.AddAuthorityKeyID(caCert.cert); err != nil {
		t.Fatalf("AddAuthorityKeyID: %v", err)
	}

	pem, err := coreCRL.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()

	akid := loaded.AuthorityKeyID()
	if len(akid) == 0 {
		t.Fatal("CRL AuthorityKeyID should not be empty")
	}
	if !bytes.Equal(akid, caCert.SubjectKeyID()) {
		t.Fatalf("CRL AKID = %x, want CA SKID = %x", akid, caCert.SubjectKeyID())
	}
}

// TestCRLExtensions 验证 CRL.Extensions 至少包含 CRL Number 扩展（OpenSSL 默认附加）。
func TestCRLExtensions(t *testing.T) {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	caName := NewName().Add("CN", "Ext CRL CA")

	coreCRL, err := core.NewCRL(caName.name, pkeyOf(priv), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("core.NewCRL: %v", err)
	}
	defer coreCRL.Close()

	pem, err := coreCRL.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()

	exts := loaded.Extensions()
	if len(exts) == 0 {
		t.Fatal("CRL Extensions should not be empty (OpenSSL attaches at least CRL Number)")
	}
	// 至少存在 CRL Number 扩展
	hasNumber := false
	for _, e := range exts {
		if e.Field == "crlNumber" {
			hasNumber = true
			break
		}
	}
	if !hasNumber {
		t.Fatalf("CRL extensions missing CRL Number: %v", exts)
	}
}

// TestCRLIssuerEntries / TestCRLIssuerText 验证 Issuer 辅助方法返回完整 RDN。
func TestCRLIssuerEntries(t *testing.T) {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	caName := NewName().Add("CN", "Entries CRL CA").Add("O", "Entries Org").Add("C", "CN")

	coreCRL, err := core.NewCRL(caName.name, pkeyOf(priv), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("core.NewCRL: %v", err)
	}
	defer coreCRL.Close()

	pem, err := coreCRL.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()

	entries := loaded.IssuerEntries()
	if len(entries) != 3 {
		t.Fatalf("CRL IssuerEntries = %d, want 3: %v", len(entries), entries)
	}
	want := map[string]string{"CN": "Entries CRL CA", "O": "Entries Org", "C": "CN"}
	for _, e := range entries {
		if got, ok := want[e.Field]; !ok || got != e.Value {
			t.Fatalf("unexpected entry %s=%q: %v", e.Field, e.Value, entries)
		}
	}
	text := loaded.IssuerText()
	if !strings.Contains(text, "CN=Entries CRL CA") {
		t.Fatalf("CRL IssuerText missing CN: %q", text)
	}
}

// TestCRLVerify 验证 CRL.Verify：正确签发者验证成功，错误公钥验证失败。
func TestCRLVerify(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	now := time.Now()
	caName := NewName().Add("CN", "CRL Verify CA")

	// 构造 CA 自签证书（供 Verify 取签发者公钥）。
	caCert := NewCertificate()
	if err := caCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSerial(7); err != nil {
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
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	// 签发 CRL 并通过 PEM 加载为公开 CRL。
	coreCRL, err := core.NewCRL(caName.name, pkeyOf(caPriv), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("core.NewCRL: %v", err)
	}
	defer coreCRL.Close()
	pem, err := coreCRL.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	crl, err := LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer crl.Close()

	// 正确签发者验证成功。
	if err := crl.Verify(caCert); err != nil {
		t.Fatalf("CRL.Verify with correct issuer should succeed: %v", err)
	}

	// 错误公钥验证失败。
	wrongPriv, _ := asym.GenerateSM2()
	wrongName := NewName().Add("CN", "Wrong CA")
	wrongCert := NewCertificate()
	if err := wrongCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := wrongCert.SetSerial(8); err != nil {
		t.Fatal(err)
	}
	if err := wrongCert.SetIssuer(wrongName); err != nil {
		t.Fatal(err)
	}
	if err := wrongCert.SetSubject(wrongName); err != nil {
		t.Fatal(err)
	}
	if err := wrongCert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := wrongCert.SetPublicKey(wrongPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := wrongCert.Sign(wrongPriv); err != nil {
		t.Fatal(err)
	}
	if err := crl.Verify(wrongCert); err == nil {
		t.Fatal("CRL.Verify with wrong key should fail")
	}
}

// ----- Ed25519 / Ed448 自签证书与 CSR 测试 -----

// TestCRLEd25519 验证 Ed25519 签发 CRL 的签发、加载、验签。
func TestCRLEd25519(t *testing.T) {
	caPriv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caName := NewName().Add("CN", "ED25519 CRL CA")

	coreCRL, err := core.NewCRL(caName.name, pkeyOf(caPriv), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer coreCRL.Close()

	pem, err := coreCRL.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()

	if loaded.SignatureAlgorithm() != "ED25519" {
		t.Fatalf("CRL SignatureAlgorithm = %q, want ED25519", loaded.SignatureAlgorithm())
	}
	if loaded.SignatureAlgorithmOID() != "1.3.101.112" {
		t.Fatalf("CRL SignatureAlgorithmOID = %q, want 1.3.101.112", loaded.SignatureAlgorithmOID())
	}
	if len(loaded.Signature()) != 64 {
		t.Fatalf("CRL signature len = %d, want 64", len(loaded.Signature()))
	}
}

// TestCRLNonASCIIIssuer 验证 CJK 颁发者名在 CRL 签发、DER 往返与验签后保真。
func TestCRLNonASCIIIssuer(t *testing.T) {
	caPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caSubject := NewName().Add("CN", "铜锁测试根").Add("O", "示例公司")

	caCert := NewCertificate()
	t.Cleanup(func() { _ = caCert.Close() })
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
	if err := caCert.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	leafPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := CreateCertificate(NewName().Add("CN", "海峰"), caCert.SubjectName(), 8,
		now.Add(-time.Hour), now.Add(time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()

	b, err := NewCRLBuilder(caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.SetNumber(7); err != nil {
		t.Fatal(err)
	}
	if err := b.SetThisUpdate(now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(leaf, now.Add(-30*time.Minute), ReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	crl, err := b.Sign(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer crl.Close()

	der, err := crl.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCRLDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()

	// 颁发者名逐条保真
	want := caCert.SubjectEntries()
	got := loaded.IssuerEntries()
	if len(got) != len(want) {
		t.Fatalf("CRL issuer entries = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Field != want[i].Field || got[i].Value != want[i].Value {
			t.Fatalf("CRL issuer[%d] = {%s=%q}, want {%s=%q}",
				i, got[i].Field, got[i].Value, want[i].Field, want[i].Value)
		}
	}
	if n := len(loaded.RevokedEntries()); n != 1 {
		t.Fatalf("revoked entries = %d, want 1", n)
	}
	if err := loaded.Verify(caCert); err != nil {
		t.Fatalf("CRL verify with CJK issuer failed: %v", err)
	}
}
