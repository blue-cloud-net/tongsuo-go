package x509

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// issueTestCA 构建一张可用的签发 CA 证书（含 CA:true 与 SKID）与对应私钥。
//
// issueTestCA builds an issuing CA certificate (with CA:true and a SKID) plus
// its private key.
func issueTestCA(t *testing.T, cn string) (*Certificate, asym.PrivateKey) {
	t.Helper()
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", cn)

	ca := NewCertificate()
	if err := ca.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetSerial(1); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetIssuer(subject); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := ca.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := ca.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign(priv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ca.Close() })
	return ca, priv
}

// issueTestCSR 构建一张带多项扩展的 CSR（SAN / KU / EKU / nsComment）。
//
// issueTestCSR builds a CSR carrying several extensions (SAN / KU / EKU /
// nsComment).
func issueTestCSR(t *testing.T, cn string) *CertificateRequest {
	t.Helper()
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", cn)
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.AddExtensions(
		Extension{Nid: 85, Value: "DNS:" + cn},
		Extension{Nid: 83, Value: "critical,digitalSignature"},
		Extension{Nid: 126, Value: "serverAuth"},
		Extension{Nid: 87, Value: "critical,CA:FALSE"},
		Extension{Nid: 78, Value: "UTF8:requester-comment"},
	); err != nil {
		t.Fatal(err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return req
}

// TestIssueCertificateFromRequest 验证 CA 依据 CSR 签发证书的完整语义。
//
// TestIssueCertificateFromRequest verifies the full semantics of issuing a
// certificate from a CSR.
func TestIssueCertificateFromRequest(t *testing.T) {
	ca, caPriv := issueTestCA(t, "Issue CA")
	req := issueTestCSR(t, "leaf-issue.example.com")

	now := time.Now()
	opts := &IssueOptions{
		Serial:    100,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
	}

	// 默认不拷 CSR 扩展
	leaf, err := IssueCertificateFromRequest(req, ca, caPriv, opts)
	if err != nil {
		t.Fatalf("IssueCertificateFromRequest: %v", err)
	}
	t.Cleanup(func() { _ = leaf.Close() })

	if leaf.Issuer() != "Issue CA" {
		t.Fatalf("issuer = %q, want Issue CA", leaf.Issuer())
	}
	if leaf.Subject() != "leaf-issue.example.com" {
		t.Fatalf("subject = %q", leaf.Subject())
	}
	if leaf.Serial() != 100 {
		t.Fatalf("serial = %d, want 100", leaf.Serial())
	}
	if leaf.Version() != 2 {
		t.Fatalf("version = %d, want 2", leaf.Version())
	}
	// SKID / AKID 自动补齐：leaf 自己的 SKID + 取自 CA SKID 的 AKID
	if len(leaf.SubjectKeyID()) == 0 || len(leaf.AuthorityKeyID()) == 0 {
		t.Fatal("SKID/AKID should be added automatically")
	}
	if string(leaf.AuthorityKeyID()) != string(ca.SubjectKeyID()) {
		t.Errorf("leaf AKID %x should equal CA SKID %x",
			leaf.AuthorityKeyID(), ca.SubjectKeyID())
	}
	// 签名由 CA 私钥完成
	if err := leaf.Verify(caPriv.Public()); err != nil {
		t.Fatalf("CA verify issued cert: %v", err)
	}
	// 默认不拷 CSR 扩展
	if got := leaf.SAN(); len(got) != 0 {
		t.Errorf("SAN() = %v, want empty (CopyRequestExtensions defaults to false)", got)
	}
	if got := leaf.KeyUsage(); len(got) != 0 {
		t.Errorf("KeyUsage() = %v, want empty", got)
	}
	// CA:true 不会被请求方的 CA:FALSE 带偏
	if leaf.IsCA() {
		t.Error("issued cert should not be a CA")
	}
}

// TestIssueCopyRequestExtensions 验证 CSR 白名单扩展拷贝：白名单内的被拷，
// 白名单外的（nsComment）被丢弃，且 CA 显式指定的扩展优先。
//
// TestIssueCopyRequestExtensions verifies the CSR whitelist copy: whitelisted
// extensions are carried over, non-whitelisted ones (nsComment) are dropped,
// and the CA's explicit extensions take precedence.
func TestIssueCopyRequestExtensions(t *testing.T) {
	ca, caPriv := issueTestCA(t, "Copy CA")
	req := issueTestCSR(t, "leaf-copy.example.com")
	now := time.Now()

	opts := &IssueOptions{
		Serial:                101,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		CopyRequestExtensions: true,
	}
	leaf, err := IssueCertificateFromRequest(req, ca, caPriv, opts)
	if err != nil {
		t.Fatalf("IssueCertificateFromRequest: %v", err)
	}
	t.Cleanup(func() { _ = leaf.Close() })

	if got := leaf.SAN(); len(got) != 1 || got[0] != "DNS:leaf-copy.example.com" {
		t.Errorf("SAN() = %v, want the CSR SAN", got)
	}
	if got := leaf.KeyUsage(); len(got) != 1 || got[0] != "digitalSignature" {
		t.Errorf("KeyUsage() = %v, want [digitalSignature]", got)
	}
	if got := leaf.ExtendedKeyUsage(); len(got) != 1 || got[0] != "serverAuth" {
		t.Errorf("ExtendedKeyUsage() = %v, want [serverAuth]", got)
	}
	// nsComment 不在白名单，必须被丢弃
	if leaf.HasExtension("nsComment") {
		t.Error("nsComment must not be copied from the CSR")
	}
	// basicConstraints 在白名单内，但其 CA:FALSE 不能把签发证书变成 CA
	if leaf.IsCA() {
		t.Error("issued cert should not become a CA via the CSR")
	}

	// CA 显式扩展优先：CA 指定的 SAN 应覆盖 CSR 的 SAN
	opts2 := &IssueOptions{
		Serial:                102,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		CopyRequestExtensions: true,
		Extensions: []Extension{
			{Nid: 85, Value: "DNS:ca-override.example.com"},
		},
	}
	leaf2, err := IssueCertificateFromRequest(req, ca, caPriv, opts2)
	if err != nil {
		t.Fatalf("IssueCertificateFromRequest(override): %v", err)
	}
	t.Cleanup(func() { _ = leaf2.Close() })
	if got := leaf2.SAN(); len(got) != 1 || got[0] != "DNS:ca-override.example.com" {
		t.Errorf("SAN() = %v, want the CA's override", got)
	}
}

// TestIssueCertificateFromRequestErrors 验证签发入口的参数错误路径。
//
// TestIssueCertificateFromRequestErrors covers the argument error paths of the
// issuing entry point.
func TestIssueCertificateFromRequestErrors(t *testing.T) {
	ca, caPriv := issueTestCA(t, "Err CA")
	req := issueTestCSR(t, "leaf-err.example.com")
	now := time.Now()
	valid := &IssueOptions{
		Serial:    1,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}

	if _, err := IssueCertificateFromRequest(nil, ca, caPriv, valid); err == nil {
		t.Error("nil request should fail")
	}
	if _, err := IssueCertificateFromRequest(req, nil, caPriv, valid); err == nil {
		t.Error("nil issuer should fail")
	}
	if _, err := IssueCertificateFromRequest(req, ca, caPriv, nil); err == nil {
		t.Error("nil options should fail")
	}
	bad := &IssueOptions{
		Serial:    1,
		NotBefore: now,
		NotAfter:  now.Add(-time.Hour),
	}
	if _, err := IssueCertificateFromRequest(req, ca, caPriv, bad); err == nil {
		t.Error("inverted validity should fail")
	}
	// 零值 NotAfter 早于 NotBefore(零值) 之前的边界：同为零值时也应失败
	zero := &IssueOptions{Serial: 1}
	if _, err := IssueCertificateFromRequest(req, ca, caPriv, zero); err == nil {
		t.Error("zero-value validity should fail")
	}
}
