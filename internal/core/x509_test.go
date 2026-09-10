package core

import (
	"testing"
)

// TestNewName 验证 Name 创建与添加条目。
func TestNewName(t *testing.T) {
	n, err := NewName()
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	defer n.Close()
	if err := n.AddEntry("CN", "example.com"); err != nil {
		t.Fatalf("AddEntry CN: %v", err)
	}
	if err := n.AddEntry("O", "Tongsuo"); err != nil {
		t.Fatalf("AddEntry O: %v", err)
	}
	if got := n.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	if got := n.Get("CN"); got != "example.com" {
		t.Fatalf("Get(CN) = %q, want %q", got, "example.com")
	}
	if got := n.Get("O"); got != "Tongsuo" {
		t.Fatalf("Get(O) = %q, want %q", got, "Tongsuo")
	}
	if got := n.Get("non-existent"); got != "" {
		t.Fatalf("Get(nonexistent) = %q, want \"\"", got)
	}
}

// TestNameNilSafe 验证 nil Name 的查询方法返回零值、不 panic。
func TestNameNilSafe(t *testing.T) {
	var n *Name
	if got := n.Get("CN"); got != "" {
		t.Errorf("nil Get = %q, want empty", got)
	}
	if got := n.Text(13); got != "" {
		t.Errorf("nil Text = %q, want empty", got)
	}
	if got := n.Nid("CN"); got != 0 {
		t.Errorf("nil Nid = %d, want 0", got)
	}
	if got := n.Len(); got != 0 {
		t.Errorf("nil Len = %d, want 0", got)
	}
	if got := n.String(); got != "" {
		t.Errorf("nil String = %q, want empty", got)
	}
}

// TestNameCloseIdempotent 验证 Name.Close 幂等。
func TestNameCloseIdempotent(t *testing.T) {
	n, _ := NewName()
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestNameClosedMethods 验证 Name 关闭后方法返回零值或错误。
func TestNameClosedMethods(t *testing.T) {
	n, _ := NewName()
	_ = n.AddEntry("CN", "test")
	_ = n.Close()
	// 关闭后查询类应返回零值
	if got := n.Get("CN"); got != "" {
		t.Errorf("closed Get(CN) = %q, want empty", got)
	}
	if got := n.Len(); got != 0 {
		t.Errorf("closed Len = %d, want 0", got)
	}
	// AddEntry 应报错
	if err := n.AddEntry("O", "test"); err == nil {
		t.Error("AddEntry on closed should error")
	}
}

// TestNewCertificate 验证创建空证书。
func TestNewCertificate(t *testing.T) {
	c, err := NewCertificate()
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	defer c.Close()
	if c == nil {
		t.Fatal("NewCertificate returned nil")
	}
	// 空证书的查询应返回零值
	if got := c.Subject(); got != "" {
		t.Errorf("empty Subject = %q, want empty", got)
	}
	if got := c.Issuer(); got != "" {
		t.Errorf("empty Issuer = %q, want empty", got)
	}
	if got := c.Version(); got != 0 {
		t.Errorf("empty Version = %d, want 0", got)
	}
}

// TestCertificateClosedMethods 验证 Cert 关闭后所有 getter 不 panic、返回零值。
func TestCertificateClosedMethods(t *testing.T) {
	// 构造一个简单自签名证书（RSA + SHA256）
	priv, _ := GenerateRSAKey(2048)
	defer priv.Close()
	c, err := NewCertificate()
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	_ = c.SetVersion(2)
	_ = c.SetSerial(1)
	_ = c.SetPublicKey(priv)
	_ = c.AddBasicConstraints(true)
	_ = c.Sign(priv, SHA256())

	// 取查询值
	_ = c.Subject()
	_ = c.Issuer()
	_ = c.Serial()
	_ = c.Version()
	_ = c.NotBefore()
	_ = c.NotAfter()
	_ = c.IsCA()
	_ = c.SubjectKeyID()
	_ = c.AuthorityKeyID()
	_ = c.Signature()
	_ = c.SignatureAlgorithm()
	_ = c.SignatureAlgorithmOID()
	_ = c.SAN()
	_ = c.KeyUsageBits()
	_ = c.ExtendedKeyUsage()
	_ = c.Extensions()
	_ = c.SubjectEntries()
	_ = c.IssuerEntries()
	_ = c.SubjectText()
	_ = c.IssuerText()
	_ = c.SubjectName()
	_ = c.IssuerName()

	// 关闭后所有上述方法都应返回零值（不 panic）
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := c.Subject(); got != "" {
		t.Errorf("closed Subject = %q, want empty", got)
	}
	if got := c.Issuer(); got != "" {
		t.Errorf("closed Issuer = %q, want empty", got)
	}
	if got := c.Version(); got != 0 {
		t.Errorf("closed Version = %d, want 0", got)
	}
	if got := c.Serial(); got != 0 {
		t.Errorf("closed Serial = %d, want 0", got)
	}
	if got := c.SubjectText(); got != "" {
		t.Errorf("closed SubjectText = %q, want empty", got)
	}
}

// TestLoadCertificatePEMInvalid 验证非法 PEM 返回错误。
func TestLoadCertificatePEMInvalid(t *testing.T) {
	if _, err := LoadCertificatePEM([]byte("garbage")); err == nil {
		t.Fatal("garbage PEM should error")
	}
	if _, err := LoadCertificatePEM(nil); err == nil {
		t.Fatal("nil PEM should error")
	}
}

// TestLoadCertificateDERInvalid 验证非法 DER 返回错误。
func TestLoadCertificateDERInvalid(t *testing.T) {
	if _, err := LoadCertificateDER([]byte("not der")); err == nil {
		t.Fatal("garbage DER should error")
	}
	if _, err := LoadCertificateDER(nil); err == nil {
		t.Fatal("nil DER should error")
	}
}

// TestNewStore 验证 Store 创建与关闭。
func TestNewStore(t *testing.T) {
	s, err := NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	// AddCert nil 应报错
	if err := s.AddCert(nil); err == nil {
		t.Fatal("AddCert(nil) should error")
	}

	// Close 后 AddCert 应报错
	_ = s.Close()
	if err := s.AddCert(nil); err == nil {
		t.Fatal("AddCert on closed store should error")
	}
}

// TestVerifyErrorMessage 验证错误码 → 描述映射。
func TestVerifyErrorMessage(t *testing.T) {
	if got := VerifyErrorMessage(0); got == "" {
		t.Fatal("X509_V_OK message should be non-empty")
	}
	if got := VerifyErrorMessage(2); got == "" {
		t.Fatal("error code message should be non-empty")
	}
}