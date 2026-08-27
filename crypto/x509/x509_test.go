package x509

import (
	"bytes"
	"strings"
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

// buildStructuredCert 构建一张带完整 RDN/SAN/KeyUsage/EKU/SKID/BasicConstraints 的证书。
func buildStructuredCert(t *testing.T, priv *sm2.PrivateKey, cn string) *Certificate {
	t.Helper()
	now := time.Now()
	subject := NewName().
		Add("CN", cn).
		Add("O", "Struct Org").
		Add("OU", "Platform").
		Add("L", "Beijing").
		Add("ST", "Beijing").
		Add("C", "CN").
		Add("serialNumber", "12345")
	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(7); err != nil {
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
	if err := cert.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddSubjectAltName("DNS:struct.example.com,IP:192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddKeyUsage("critical,digitalSignature,keyCertSign"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtendedKeyUsage("serverAuth,clientAuth"); err != nil {
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

// TestStructuredParse 验证完整 RDN、SAN、KeyUsage、EKU、BasicConstraints、SKID、版本、类型解析。
func TestStructuredParse(t *testing.T) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert := buildStructuredCert(t, priv, "struct.example.com")

	// 完整 RDN 条目
	entries := cert.SubjectEntries()
	got := make(map[string]string)
	for _, e := range entries {
		got[e.Field] = e.Value
	}
	want := map[string]string{
		"CN": "struct.example.com", "O": "Struct Org", "OU": "Platform",
		"L": "Beijing", "ST": "Beijing", "C": "CN", "serialNumber": "12345",
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("subject field %s = %q, want %q (entries=%v)", k, got[k], v, entries)
		}
	}
	if len(entries) != len(want) {
		t.Fatalf("subject entries = %d, want %d", len(entries), len(want))
	}
	if cert.Subject() != "struct.example.com" {
		t.Fatalf("Subject CN = %q", cert.Subject())
	}
	if cert.SubjectName().Get("O") != "Struct Org" {
		t.Fatal("SubjectName().Get(O) mismatch")
	}
	if !strings.Contains(cert.SubjectText(), "CN=struct.example.com") {
		t.Fatalf("SubjectText = %q", cert.SubjectText())
	}

	// 版本 / 证书类型
	if cert.Version() != 2 {
		t.Fatalf("Version = %d, want 2", cert.Version())
	}
	if cert.CertificateType() != "SM2" {
		t.Fatalf("CertificateType = %q, want SM2", cert.CertificateType())
	}

	// SAN
	sans := cert.SAN()
	if len(sans) != 2 || sans[0] != "DNS:struct.example.com" || sans[1] != "IP:192.168.1.10" {
		t.Fatalf("SAN = %v", sans)
	}

	// KeyUsage
	ku := cert.KeyUsage()
	if len(ku) != 2 || ku[0] != "digitalSignature" || ku[1] != "keyCertSign" {
		t.Fatalf("KeyUsage = %v", ku)
	}

	// EKU
	eku := cert.ExtendedKeyUsage()
	if len(eku) != 2 || eku[0] != "serverAuth" || eku[1] != "clientAuth" {
		t.Fatalf("ExtendedKeyUsage = %v", eku)
	}

	// BasicConstraints
	if !cert.IsCA() {
		t.Fatal("IsCA should be true")
	}
	if cert.PathLen() != -1 {
		t.Fatalf("PathLen = %d, want -1", cert.PathLen())
	}

	// SKID
	if len(cert.SubjectKeyID()) == 0 {
		t.Fatal("SubjectKeyID should not be empty")
	}

	// 扩展列表包含上述扩展
	fields := make(map[string]bool)
	for _, e := range cert.Extensions() {
		fields[e.Field] = true
	}
	for _, f := range []string{"subjectAltName", "keyUsage", "extendedKeyUsage", "basicConstraints", "subjectKeyIdentifier"} {
		if !fields[f] {
			t.Fatalf("extension %q not found in %v", f, cert.Extensions())
		}
	}

	// 重载后解析结果一致
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.SAN()) != 2 || loaded.SAN()[0] != "DNS:struct.example.com" {
		t.Fatalf("loaded SAN = %v", loaded.SAN())
	}
	if !loaded.IsCA() {
		t.Fatal("loaded IsCA should be true")
	}
	if len(loaded.SubjectKeyID()) == 0 {
		t.Fatal("loaded SubjectKeyID should not be empty")
	}
	if loaded.SubjectName().Get("OU") != "Platform" {
		t.Fatal("loaded OU mismatch")
	}
}

// TestAuthorityKeyID 验证 CA 签发叶证书时 AKID 与 CA 的 SKID 一致。
func TestAuthorityKeyID(t *testing.T) {
	caPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
	now := time.Now()

	caSubject := NewName().Add("CN", "AKID Root CA")
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
	if err := caCert.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	leafSubject := NewName().Add("CN", "akid.example.com")
	leafCert := NewCertificate()
	if err := leafCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.SetSerial(2); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.SetIssuer(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.SetSubject(leafSubject); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.SetPublicKey(leafPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.AddAuthorityKeyID(caCert); err != nil {
		t.Fatal(err)
	}
	if err := leafCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	akid := leafCert.AuthorityKeyID()
	skid := caCert.SubjectKeyID()
	if len(akid) == 0 || !bytes.Equal(akid, skid) {
		t.Fatalf("leaf AKID = %x, want CA SKID = %x", akid, skid)
	}
	if len(leafCert.SubjectKeyID()) == 0 {
		t.Fatal("leaf SKID should not be empty")
	}
}

// TestFingerprint 验证指纹长度、稳定性与非法算法。
func TestFingerprint(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "fp.example.com")
	cert, err := CreateCertificate(subject, subject, 5,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	sha256, err := cert.Fingerprint("sha256")
	if err != nil {
		t.Fatal(err)
	}
	if len(sha256) != 64 {
		t.Fatalf("sha256 fingerprint length = %d, want 64", len(sha256))
	}

	sha1, err := cert.Fingerprint("sha1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sha1) != 40 {
		t.Fatalf("sha1 fingerprint length = %d, want 40", len(sha1))
	}

	sm3fp, err := cert.Fingerprint("sm3")
	if err != nil {
		t.Fatal(err)
	}
	if len(sm3fp) != 64 {
		t.Fatalf("sm3 fingerprint length = %d, want 64", len(sm3fp))
	}

	// 重载后指纹一致
	pem, _ := cert.MarshalPEM()
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := loaded.Fingerprint("sha256")
	if err != nil {
		t.Fatal(err)
	}
	if sha256 != fp2 {
		t.Fatalf("fingerprint changed after reload: %s vs %s", sha256, fp2)
	}

	// 非法算法报错
	if _, err := cert.Fingerprint("blake2"); err == nil {
		t.Fatal("expected error for unsupported fingerprint algorithm")
	}
}

// TestDERRoundtrip 验证证书与 CSR 的 DER 往返。
func TestDERRoundtrip(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "der.example.com")
	cert, err := CreateCertificate(subject, subject, 9,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if len(der) == 0 {
		t.Fatal("empty DER")
	}
	loaded, err := LoadCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Subject() != "der.example.com" {
		t.Fatalf("loaded subject = %q", loaded.Subject())
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal(err)
	}

	// PEM 与 DER 编码内容一致
	pem, _ := cert.MarshalPEM()
	pemLoaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	pemDER, err := pemLoaded.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, pemDER) {
		t.Fatal("PEM and DER marshaling mismatch")
	}

	// CSR DER 往返
	req, err := NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	reqDER, err := req.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if len(reqDER) == 0 {
		t.Fatal("empty CSR DER")
	}
	reqLoaded, err := LoadCertificateRequestDER(reqDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := reqLoaded.Verify(); err != nil {
		t.Fatal(err)
	}
}

// TestCSRAdvanced 验证 CSR 的扩展、挑战密码与多字段 Subject。
func TestCSRAdvanced(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	subject := NewName().Add("CN", "csr-adv.example.com").Add("O", "CSR Adv Org").Add("C", "CN")

	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.SetChallengePassword("s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := req.AddSubjectAltName("DNS:csr-adv.example.com,IP:10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}

	if err := req.Verify(); err != nil {
		t.Fatal(err)
	}
	if req.ChallengePassword() != "s3cret" {
		t.Fatalf("challenge password = %q, want s3cret", req.ChallengePassword())
	}

	// 扩展列表
	exts := req.Extensions()
	if len(exts) != 1 || exts[0].Field != "subjectAltName" {
		t.Fatalf("CSR extensions = %v", exts)
	}

	// 多字段 Subject
	fields := make(map[string]string)
	for _, e := range req.SubjectName().Entries() {
		fields[e.Field] = e.Value
	}
	if fields["CN"] != "csr-adv.example.com" || fields["O"] != "CSR Adv Org" || fields["C"] != "CN" {
		t.Fatalf("CSR subject fields = %v", fields)
	}

	// PEM 往返后仍可读取
	pem, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificateRequestPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(); err != nil {
		t.Fatal(err)
	}
	if loaded.ChallengePassword() != "s3cret" {
		t.Fatalf("loaded challenge password = %q", loaded.ChallengePassword())
	}
	if len(loaded.Extensions()) != 1 {
		t.Fatalf("loaded extensions = %v", loaded.Extensions())
	}
	if loaded.SubjectName().Get("O") != "CSR Adv Org" {
		t.Fatal("loaded CSR subject O mismatch")
	}
}
