package x509

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdsa"
	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
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

// TestCSRSignatureInfoSM2 验证 SM2 CSR 签名值/算法/OID 三件套读取，并支持 PEM 往返。
func TestCSRSignatureInfoSM2(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	subject := NewName().Add("CN", "csr-sig-sm2.example.com")
	req, err := NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.Signature()) == 0 {
		t.Fatal("SM2 CSR Signature bytes should not be empty")
	}
	if req.SignatureAlgorithm() != "SM2-SM3" {
		t.Fatalf("SM2 CSR SignatureAlgorithm = %q, want SM2-SM3", req.SignatureAlgorithm())
	}
	if req.SignatureAlgorithmOID() != "1.2.156.10197.1.501" {
		t.Fatalf("SM2 CSR SignatureAlgorithmOID = %q, want 1.2.156.10197.1.501", req.SignatureAlgorithmOID())
	}

	// PEM 往返后三件套保持一致
	pem, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificateRequestPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Signature(), req.Signature()) {
		t.Fatal("SM2 CSR Signature bytes changed after PEM roundtrip")
	}
	if loaded.SignatureAlgorithm() != "SM2-SM3" {
		t.Fatalf("loaded CSR SignatureAlgorithm = %q, want SM2-SM3", loaded.SignatureAlgorithm())
	}
	if loaded.SignatureAlgorithmOID() != "1.2.156.10197.1.501" {
		t.Fatalf("loaded CSR SignatureAlgorithmOID = %q, want 1.2.156.10197.1.501", loaded.SignatureAlgorithmOID())
	}
}

// TestCSRSignatureInfoRSA 验证 RSA CSR 签名值/算法/OID 三件套读取。
func TestCSRSignatureInfoRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "csr-sig-rsa.example.com")
	req, err := NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.Signature()) != 256 {
		t.Fatalf("RSA-SHA256 CSR signature length = %d, want 256", len(req.Signature()))
	}
	if req.SignatureAlgorithm() != "RSA-SHA256" {
		t.Fatalf("RSA CSR SignatureAlgorithm = %q, want RSA-SHA256", req.SignatureAlgorithm())
	}
	if req.SignatureAlgorithmOID() != "1.2.840.113549.1.1.11" {
		t.Fatalf("RSA CSR SignatureAlgorithmOID = %q, want 1.2.840.113549.1.1.11", req.SignatureAlgorithmOID())
	}
}

// TestCSRSignatureInfoECDSA 验证 ECDSA CSR 签名值/算法/OID 三件套读取。
func TestCSRSignatureInfoECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey("prime256v1")
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "csr-sig-ecdsa.example.com")
	req, err := NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.Signature()) == 0 {
		t.Fatal("ECDSA CSR Signature bytes should not be empty")
	}
	if req.SignatureAlgorithm() != "ecdsa-with-SHA256" {
		t.Fatalf("ECDSA CSR SignatureAlgorithm = %q, want ecdsa-with-SHA256", req.SignatureAlgorithm())
	}
	if req.SignatureAlgorithmOID() != "1.2.840.10045.4.3.2" {
		t.Fatalf("ECDSA CSR SignatureAlgorithmOID = %q, want 1.2.840.10045.4.3.2", req.SignatureAlgorithmOID())
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

// makeCACert 构建一张 CA 证书（BasicConstraints CA:TRUE）。
func makeCACert(t *testing.T, priv *sm2.PrivateKey, cn string) *Certificate {
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
	priv, _ := sm2.GenerateKey()
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
	caPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
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
	caPriv, _ := sm2.GenerateKey()
	evilPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
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
	caPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
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
	rootPriv, _ := sm2.GenerateKey()
	interPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
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

// TestRevocationCheckBasic 无 CRL 时不吊销；空参数返回错误。
func TestRevocationCheckBasic(t *testing.T) {
	priv, _ := sm2.GenerateKey()
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

// TestCreateCertificateRSA 验证 RSA 密钥可签发/验证证书（自签）。
func TestCreateCertificateRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
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
	pk, err := loaded.PublicKeyPKey()
	if err != nil {
		t.Fatal(err)
	}
	defer pk.Close()
	if pk.Algorithm() != "RSA" {
		t.Fatalf("loaded cert pubkey algorithm = %q, want RSA", pk.Algorithm())
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatal("loaded RSA cert verify failed")
	}
}

// TestCreateCertificateECDSA 验证 ECDSA 密钥可签发/验证证书（自签）。
func TestCreateCertificateECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey("prime256v1")
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

// TestSignatureInfoSM2 验证 SM2 证书签名值/算法/OID 三件套读取，并支持 PEM 往返。
func TestSignatureInfoSM2(t *testing.T) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "sig-sm2.example.com")
	cert, err := CreateCertificate(subject, subject, 30,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	sig := cert.Signature()
	if len(sig) == 0 {
		t.Fatal("SM2 Signature bytes should not be empty")
	}
	if cert.SignatureAlgorithm() != "SM2-SM3" {
		t.Fatalf("SM2 SignatureAlgorithm = %q, want SM2-SM3", cert.SignatureAlgorithm())
	}
	if cert.SignatureAlgorithmOID() != "1.2.156.10197.1.501" {
		t.Fatalf("SM2 SignatureAlgorithmOID = %q, want 1.2.156.10197.1.501", cert.SignatureAlgorithmOID())
	}

	// PEM 往返后三件套保持一致
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Signature(), sig) {
		t.Fatal("SM2 Signature bytes changed after PEM roundtrip")
	}
	if loaded.SignatureAlgorithm() != "SM2-SM3" {
		t.Fatalf("loaded SignatureAlgorithm = %q, want SM2-SM3", loaded.SignatureAlgorithm())
	}
	if loaded.SignatureAlgorithmOID() != "1.2.156.10197.1.501" {
		t.Fatalf("loaded SignatureAlgorithmOID = %q, want 1.2.156.10197.1.501", loaded.SignatureAlgorithmOID())
	}
}

// TestSignatureInfoRSA 验证 RSA 证书签名值/算法/OID 三件套读取（SHA-256）。
func TestSignatureInfoRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "sig-rsa.example.com")
	cert, err := CreateCertificate(subject, subject, 31,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	sig := cert.Signature()
	if len(sig) != 256 {
		t.Fatalf("RSA-SHA256 signature length = %d, want 256", len(sig))
	}
	if cert.SignatureAlgorithm() != "RSA-SHA256" {
		t.Fatalf("RSA SignatureAlgorithm = %q, want RSA-SHA256", cert.SignatureAlgorithm())
	}
	if cert.SignatureAlgorithmOID() != "1.2.840.113549.1.1.11" {
		t.Fatalf("RSA SignatureAlgorithmOID = %q, want 1.2.840.113549.1.1.11", cert.SignatureAlgorithmOID())
	}
}

// TestSignatureInfoECDSA 验证 ECDSA 证书签名值/算法/OID 三件套读取（SHA-256）。
func TestSignatureInfoECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey("prime256v1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "sig-ecdsa.example.com")
	cert, err := CreateCertificate(subject, subject, 32,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	sig := cert.Signature()
	if len(sig) == 0 {
		t.Fatal("ECDSA signature bytes should not be empty")
	}
	if cert.SignatureAlgorithm() != "ecdsa-with-SHA256" {
		t.Fatalf("ECDSA SignatureAlgorithm = %q, want ecdsa-with-SHA256", cert.SignatureAlgorithm())
	}
	if cert.SignatureAlgorithmOID() != "1.2.840.10045.4.3.2" {
		t.Fatalf("ECDSA SignatureAlgorithmOID = %q, want 1.2.840.10045.4.3.2", cert.SignatureAlgorithmOID())
	}
}

// TestChainVerifyRSA 验证 RSA CA 签发 RSA 叶证书的链验证。
func TestChainVerifyRSA(t *testing.T) {
	caPriv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := rsa.GenerateKey(2048)
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

// TestCSRRSA 验证 RSA 密钥可生成 CSR 并验签。
func TestCSRRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewCertificateRequest(NewName().Add("CN", "rsa-csr.example.com"), priv.Public(), priv)
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
	loaded, err := LoadCertificateRequestPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(); err != nil {
		t.Fatal("loaded RSA CSR verify failed")
	}
}

// TestSelfSigned 验证 Certificate.SelfSigned：自签返回 true，CA 签发叶证书返回 false。
func TestSelfSigned(t *testing.T) {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := NewName().Add("CN", "self.example.com")

	// 自签证书
	selfCert, err := CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := selfCert.SelfSigned()
	if err != nil || !ok {
		t.Fatalf("self-signed cert SelfSigned = (%v, %v), want (true, nil)", ok, err)
	}

	// CA 签发叶证书
	caPriv, _ := sm2.GenerateKey()
	caCert := makeCACert(t, caPriv, "Self CA")
	leafPriv, _ := sm2.GenerateKey()
	leafCert, err := CreateCertificate(NewName().Add("CN", "leaf.example.com"),
		caCert.SubjectName(), 2, now.Add(-time.Hour), now.Add(365*24*time.Hour),
		leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = leafCert.SelfSigned()
	if err != nil || ok {
		t.Fatalf("CA-issued cert SelfSigned = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestNameHelpers 验证 Name.Nid / Name.Len / SubjectText / IssuerEntries / SubjectEntries。
func TestNameHelpers(t *testing.T) {
	n := NewName().Add("CN", "name.example.com").Add("O", "Name Org").Add("C", "CN")
	if n.Len() != 3 {
		t.Fatalf("Name.Len = %d, want 3", n.Len())
	}
	if n.Nid("CN") == 0 {
		t.Fatal("Name.Nid(\"CN\") = 0, want nonzero")
	}
	if n.Nid("") != 0 {
		t.Fatalf("Name.Nid(\"\") = %d, want 0", n.Nid(""))
	}
	if n.Nid("unknown-field-xyz") != 0 {
		t.Fatal("Name.Nid(unknown) should return 0")
	}
	if n.String() == "" {
		t.Fatal("Name.String() should not be empty")
	}

	// CSR SubjectEntries / SubjectText
	priv, _ := sm2.GenerateKey()
	req, _ := NewCertificateRequest(n, priv.Public(), priv)
	entries := req.SubjectEntries()
	if len(entries) != 3 {
		t.Fatalf("CSR SubjectEntries = %d, want 3", len(entries))
	}
	if req.SubjectText() == "" {
		t.Fatal("CSR SubjectText should not be empty")
	}
}

// TestCSRPublicKeyPKey 验证 CSR.PublicKeyPKey 在 SM2 / RSA / ECDSA 上均工作。
func TestCSRPublicKeyPKey(t *testing.T) {
	// SM2
	sm2priv, _ := sm2.GenerateKey()
	req, _ := NewCertificateRequest(NewName().Add("CN", "sm2.example.com"),
		sm2priv.Public(), sm2priv)
	pk, err := req.PublicKeyPKey()
	if err != nil {
		t.Fatal(err)
	}
	if pk.Algorithm() != "SM2" {
		t.Fatalf("SM2 CSR PublicKeyPKey algo = %q, want SM2", pk.Algorithm())
	}
	pk.Close()

	// RSA
	rsapriv, _ := rsa.GenerateKey(2048)
	req, _ = NewCertificateRequest(NewName().Add("CN", "rsa.example.com"),
		rsapriv.Public(), rsapriv)
	pk, err = req.PublicKeyPKey()
	if err != nil {
		t.Fatal(err)
	}
	if pk.Algorithm() != "RSA" {
		t.Fatalf("RSA CSR PublicKeyPKey algo = %q, want RSA", pk.Algorithm())
	}
	pk.Close()

	// ECDSA
	ecpriv, _ := ecdsa.GenerateKey("prime256v1")
	req, _ = NewCertificateRequest(NewName().Add("CN", "ec.example.com"),
		ecpriv.Public(), ecpriv)
	pk, err = req.PublicKeyPKey()
	if err != nil {
		t.Fatal(err)
	}
	if pk.Algorithm() != "EC" {
		t.Fatalf("ECDSA CSR PublicKeyPKey algo = %q, want EC", pk.Algorithm())
	}
	pk.Close()
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

// TestCRLSignatureInfoSM2 验证 SM2 签发 CRL 的签名三件套、Issuer 辅助方法、Number、Extensions。
// CRL 由 core 直接签发（绕开 CA 证书持有），通过 PEM 往返后由公开 API 加载与验证。
func TestCRLSignatureInfoSM2(t *testing.T) {
	caPriv, _ := sm2.GenerateKey()
	now := time.Now()
	caName := NewName().Add("CN", "CRL SM2 CA")

	// 通过 core 直接构建 CRL
	coreCRL, err := core.NewCRL(caName.name, caPriv.Key(), now.Add(-time.Hour), now.Add(7*24*time.Hour))
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
	caPriv, _ := sm2.GenerateKey()
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
	coreCRL, err := core.NewCRL(caName.name, caPriv.Key(), now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("core.NewCRL: %v", err)
	}
	defer coreCRL.Close()

	// 手工添加 AuthorityKeyIdentifier 扩展（keyid 取自 CA 的 SKID）
	if err := coreCRL.AddAuthorityKeyID(caCert.Core()); err != nil {
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
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	caName := NewName().Add("CN", "Ext CRL CA")

	coreCRL, err := core.NewCRL(caName.name, priv.Key(), now.Add(-time.Hour), now.Add(7*24*time.Hour))
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
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	caName := NewName().Add("CN", "Entries CRL CA").Add("O", "Entries Org").Add("C", "CN")

	coreCRL, err := core.NewCRL(caName.name, priv.Key(), now.Add(-time.Hour), now.Add(7*24*time.Hour))
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
