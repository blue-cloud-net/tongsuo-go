package x509

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestCSR 验证 CSR 创建、签名、PEM 往返与公钥读取。
func TestCSR(t *testing.T) {
	priv, _ := asym.GenerateSM2()
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
	ct, _ := asym.Encrypt(pub, []byte("csr pub"))
	pt, err := asym.Decrypt(priv, ct)
	if err != nil || string(pt) != "csr pub" {
		t.Fatal("CSR pubkey encrypt/decrypt mismatch")
	}
}

// TestCSRSignatureInfoSM2 验证 SM2 CSR 签名值/算法/OID 三件套读取，并支持 PEM 往返。
func TestCSRSignatureInfoSM2(t *testing.T) {
	priv, _ := asym.GenerateSM2()
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
	priv, err := asym.GenerateRSA(2048)
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
	priv, err := asym.GenerateEC(asym.CurveP256)
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

// TestCSRAdvanced 验证 CSR 的扩展、挑战密码与多字段 Subject。
func TestCSRAdvanced(t *testing.T) {
	priv, _ := asym.GenerateSM2()
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

// TestCSRRSA 验证 RSA 密钥可生成 CSR 并验签。
func TestCSRRSA(t *testing.T) {
	priv, err := asym.GenerateRSA(2048)
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

// TestCSRPublicKey 验证 CSR.PublicKey 在 SM2 / RSA / ECDSA 上均返回正确的
// asym 算法标识（原 TestCSRPublicKeyPKey，随 roadmap §5 E1-9 改为 asym.PublicKey）。
func TestCSRPublicKey(t *testing.T) {
	// SM2
	sm2priv, _ := asym.GenerateSM2()
	req, _ := NewCertificateRequest(NewName().Add("CN", "sm2.example.com"),
		sm2priv.Public(), sm2priv)
	pk, err := req.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(pk.Algorithm()) != "SM2" {
		t.Fatalf("SM2 CSR PublicKey algo = %q, want SM2", pk.Algorithm())
	}
	if err := asym.Close(pk); err != nil {
		t.Fatal(err)
	}

	// RSA
	rsapriv, _ := asym.GenerateRSA(2048)
	req, _ = NewCertificateRequest(NewName().Add("CN", "rsa.example.com"),
		rsapriv.Public(), rsapriv)
	pk, err = req.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(pk.Algorithm()) != "RSA" {
		t.Fatalf("RSA CSR PublicKey algo = %q, want RSA", pk.Algorithm())
	}
	if err := asym.Close(pk); err != nil {
		t.Fatal(err)
	}

	// ECDSA
	ecpriv, _ := asym.GenerateEC(asym.CurveP256)
	req, _ = NewCertificateRequest(NewName().Add("CN", "ec.example.com"),
		ecpriv.Public(), ecpriv)
	pk, err = req.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(pk.Algorithm()) != "EC" {
		t.Fatalf("ECDSA CSR PublicKey algo = %q, want EC", pk.Algorithm())
	}
	if err := asym.Close(pk); err != nil {
		t.Fatal(err)
	}
}

// TestCSREd25519 验证 Ed25519 密钥可生成 CSR 并验签。
func TestCSREd25519(t *testing.T) {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewCertificateRequest(NewName().Add("CN", "csr-ed25519.example.com"),
		priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Verify(); err != nil {
		t.Fatalf("CSR Verify failed: %v", err)
	}
	if len(req.Signature()) != 64 {
		t.Fatalf("CSR signature length = %d, want 64", len(req.Signature()))
	}
	if req.SignatureAlgorithm() != "ED25519" {
		t.Fatalf("SignatureAlgorithm = %q, want ED25519", req.SignatureAlgorithm())
	}
	if req.SignatureAlgorithmOID() != "1.3.101.112" {
		t.Fatalf("OID = %q, want 1.3.101.112", req.SignatureAlgorithmOID())
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
		t.Fatal("loaded CSR Verify failed")
	}
}

// TestCSREd448 验证 Ed448 密钥可生成 CSR 并验签。
func TestCSREd448(t *testing.T) {
	priv, err := asym.GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewCertificateRequest(NewName().Add("CN", "csr-ed448.example.com"),
		priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Verify(); err != nil {
		t.Fatalf("CSR Verify failed: %v", err)
	}
	if len(req.Signature()) != 114 {
		t.Fatalf("CSR signature length = %d, want 114", len(req.Signature()))
	}
}

// TestCertificateToRequest 验证证书转 CSR（`openssl x509 -x509toreq` 等价）。
//
// TestCertificateToRequest verifies certificate-to-CSR conversion (the
// equivalent of `openssl x509 -x509toreq`).
func TestCertificateToRequest(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "toreq.example.com").Add("O", "Req Org")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(55); err != nil {
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
	if err := cert.AddSubjectAltName("DNS:toreq.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cert.Close() })

	req, err := cert.ToCertificateRequest(priv)
	if err != nil {
		t.Fatalf("ToCertificateRequest: %v", err)
	}
	if req.SubjectText() != cert.SubjectText() {
		t.Errorf("subject = %q, want %q", req.SubjectText(), cert.SubjectText())
	}
	if err := req.Verify(); err != nil {
		t.Errorf("CSR verify: %v", err)
	}
	// 扩展不迁移（与 openssl x509 -x509toreq 一致）
	if got := req.Extensions(); len(got) != 0 {
		t.Errorf("CSR extensions = %v, want none", got)
	}
	// PEM 往返后仍可校验
	pemBytes, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificateRequestPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(); err != nil {
		t.Errorf("loaded CSR verify: %v", err)
	}

	// nil 证书
	var nilCert *Certificate
	if _, err := nilCert.ToCertificateRequest(priv); err == nil {
		t.Error("nil certificate should fail")
	}
}

// TestCSRNonASCII 验证 CJK subject / challengePassword / 扩展值在 CSR 签名与 PEM 往返后保真。
func TestCSRNonASCII(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "海峰").Add("O", "示例公司")

	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.SetChallengePassword("口令-abc"); err != nil {
		t.Fatalf("SetChallengePassword: %v", err)
	}
	if err := req.AddExtensionByName("nsComment", "UTF8:中文注释"); err != nil {
		t.Fatalf("AddExtensionByName(nsComment): %v", err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}

	pemBytes, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificateRequestPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	// subject 逐条保真
	want := subject.Entries()
	got := loaded.SubjectEntries()
	if len(got) != len(want) {
		t.Fatalf("loaded CSR subject entries = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Field != want[i].Field || got[i].Value != want[i].Value {
			t.Fatalf("CSR subject[%d] = {%s=%q}, want {%s=%q}",
				i, got[i].Field, got[i].Value, want[i].Field, want[i].Value)
		}
	}

	// challengePassword 不再被双重编码
	if v := loaded.ChallengePassword(); v != "口令-abc" {
		t.Fatalf("ChallengePassword = %q (% x), want 口令-abc", v, v)
	}

	// nsComment 扩展以原始 UTF-8 字节承载
	var nsComment []byte
	for _, e := range loaded.Extensions() {
		if e.Field == "nsComment" {
			nsComment = e.Data
		}
	}
	if !bytes.Contains(nsComment, []byte("中文注释")) {
		t.Fatalf("nsComment Data = % x，未包含原始 UTF-8 字节 % x", nsComment, []byte("中文注释"))
	}

	if err := loaded.Verify(); err != nil {
		t.Fatalf("loaded CSR verify: %v", err)
	}
}

// TestCSRChallengePasswordInvalidUTF8 验证非法 UTF-8 口令在调用原生接口前被拒绝。
func TestCSRChallengePasswordInvalidUTF8(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(NewName().Add("CN", "csr.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	err = req.SetChallengePassword("\xff\xfe")
	if err == nil {
		t.Fatal("SetChallengePassword with invalid UTF-8 should fail")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("error = %v, want it to mention UTF-8", err)
	}
}
