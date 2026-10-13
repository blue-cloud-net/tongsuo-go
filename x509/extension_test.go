package x509

import (
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// newUnsignedCert 构建一张尚未签名的 SM2 证书，供扩展相关用例复用。
//
// newUnsignedCert builds a not-yet-signed SM2 certificate for reuse across
// the extension test cases.
func newUnsignedCert(t *testing.T, priv asym.PrivateKey) *Certificate {
	t.Helper()
	now := time.Now()
	subject := NewName().Add("CN", "ext.example.com")
	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(9001); err != nil {
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
	return cert
}

// TestCertificateAddExtension 验证通用扩展入口的三条路径：按 NID、按短名、按点分 OID，
// 以及批量添加、空切片 no-op 与未知名字报错。
//
// TestCertificateAddExtension covers the three addressing modes of the
// generic extension entry points (by NID, by short name and by dotted OID) plus
// batch addition, the empty-slice no-op and unknown-name errors.
func TestCertificateAddExtension(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}

	// 按 NID（keyUsage = 83）
	c1 := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = c1.Close() })
	if err := c1.AddExtension(83, "critical,digitalSignature"); err != nil {
		t.Fatalf("AddExtension(nid): %v", err)
	}
	if got := c1.KeyUsage(); len(got) != 1 || got[0] != "digitalSignature" {
		t.Fatalf("KeyUsage() = %v, want [digitalSignature]", got)
	}

	// 按短名
	c2 := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = c2.Close() })
	if err := c2.AddExtensionByName("extendedKeyUsage", "serverAuth,clientAuth"); err != nil {
		t.Fatalf("AddExtensionByName(short): %v", err)
	}
	if got := c2.ExtendedKeyUsage(); len(got) != 2 || got[0] != "serverAuth" || got[1] != "clientAuth" {
		t.Fatalf("ExtendedKeyUsage() = %v, want [serverAuth clientAuth]", got)
	}

	// 按点分 OID（2.5.29.19 = basicConstraints）
	c3 := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = c3.Close() })
	if err := c3.AddExtensionByName("2.5.29.19", "critical,CA:TRUE,pathlen:3"); err != nil {
		t.Fatalf("AddExtensionByName(oid): %v", err)
	}
	if !c3.IsCA() {
		t.Fatal("IsCA() = false, want true")
	}
	if got := c3.PathLen(); got != 3 {
		t.Fatalf("PathLen() = %d, want 3", got)
	}

	// 批量：SAN + KeyUsage + EKU
	c4 := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = c4.Close() })
	if err := c4.AddExtensions(
		Extension{Nid: 85, Value: "DNS:a.example.com,DNS:b.example.com"},
		Extension{Nid: 83, Value: "digitalSignature"},
		Extension{Nid: 126, Value: "serverAuth"},
	); err != nil {
		t.Fatalf("AddExtensions: %v", err)
	}
	if got := c4.SAN(); len(got) != 2 {
		t.Fatalf("SAN() = %v, want 2 entries", got)
	}
	if len(c4.Extensions()) != 3 {
		t.Fatalf("Extensions() = %d entries, want 3", len(c4.Extensions()))
	}

	// 空切片 / nil 为 no-op
	if err := c4.AddExtensions(); err != nil {
		t.Fatalf("AddExtensions() empty: %v", err)
	}
	if err := c4.AddExtensions(nil...); err != nil {
		t.Fatalf("AddExtensions(nil...): %v", err)
	}
	if len(c4.Extensions()) != 3 {
		t.Fatalf("no-op AddExtensions changed extension count: %d", len(c4.Extensions()))
	}

	// 未知名字 / 空名字报错
	c5 := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = c5.Close() })
	if err := c5.AddExtensionByName("noSuchExtension", "x"); err == nil {
		t.Fatal("AddExtensionByName(unknown) should fail")
	} else if !strings.Contains(err.Error(), "unknown extension name") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c5.AddExtensionByName("", "x"); err == nil {
		t.Fatal("AddExtensionByName(\"\") should fail")
	}

	// 非法 value 报错（OpenSSL 配置串语法错误）
	if err := c5.AddExtensionByName("keyUsage", "notAValidBit"); err == nil {
		t.Fatal("AddExtensionByName(bad value) should fail")
	}

	// 已关闭证书上的调用返回错误
	c5.Close()
	if err := c5.AddExtensionByName("keyUsage", "digitalSignature"); err == nil {
		t.Fatal("AddExtensionByName on closed cert should fail")
	}
}

// TestCertificateExtensionDuplicate 验证去重规则：同 NID 重复报错（可重复 OID 除外），
// 覆盖用 ReplaceExtension，删除用 RemoveExtension。
//
// TestCertificateExtensionDuplicate verifies the duplicate rules: adding the
// same NID twice fails (repeatable OIDs excepted), ReplaceExtension overwrites
// and RemoveExtension deletes.
func TestCertificateExtensionDuplicate(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}

	// 非可重复 OID：重复报错
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })
	if err := cert.AddExtensionByName("keyUsage", "digitalSignature"); err != nil {
		t.Fatal(err)
	}
	err = cert.AddExtensionByName("keyUsage", "keyEncipherment")
	if err == nil {
		t.Fatal("duplicate keyUsage should fail")
	}
	if !strings.Contains(err.Error(), "already present") {
		t.Fatalf("unexpected error: %v", err)
	}
	// 原有值未被改动
	if got := cert.KeyUsage(); len(got) != 1 || got[0] != "digitalSignature" {
		t.Fatalf("KeyUsage() after rejected duplicate = %v, want [digitalSignature]", got)
	}

	// 批量内部同样拦截重复
	if err := cert.AddExtensions(
		Extension{Nid: 83, Value: "keyEncipherment"},
	); err == nil {
		t.Fatal("AddExtensions duplicate should fail")
	}

	// 可重复 OID（subjectAltName）：合并进同一条目，不产生第二个扩展
	if err := cert.AddExtensionByName("subjectAltName", "DNS:one.example.com"); err != nil {
		t.Fatalf("first SAN: %v", err)
	}
	if err := cert.AddExtensionByName("subjectAltName", "DNS:two.example.com"); err != nil {
		t.Fatalf("repeatable SAN should be merged, not rejected: %v", err)
	}
	if got := cert.SAN(); len(got) != 2 {
		t.Fatalf("SAN() = %v, want 2 entries after merge", got)
	}
	// 关键：扩展条目数不增（重复条目会让 SAN()/VerifyHostname 全部失效）
	sanCount := 0
	for _, e := range cert.Extensions() {
		if e.Field == "subjectAltName" {
			sanCount++
		}
	}
	if sanCount != 1 {
		t.Fatalf("subjectAltName entries = %d, want exactly 1 (duplicates break SAN())", sanCount)
	}

	// 预置便利方法走同一合并路径
	if err := cert.AddSubjectAltName("DNS:three.example.com"); err != nil {
		t.Fatalf("AddSubjectAltName merge: %v", err)
	}
	if got := cert.SAN(); len(got) != 3 {
		t.Fatalf("SAN() = %v, want 3 entries", got)
	}
	sanCount = 0
	for _, e := range cert.Extensions() {
		if e.Field == "subjectAltName" {
			sanCount++
		}
	}
	if sanCount != 1 {
		t.Fatalf("subjectAltName entries = %d after AddSubjectAltName, want 1", sanCount)
	}
	// 合并后的 SAN 必须真的能用于主机名校验
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"one.example.com", "two.example.com", "three.example.com"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Errorf("VerifyHostname(%q) after merge: %v", host, err)
		}
	}
	if err := cert.VerifyHostname("bogus.example.com"); err == nil {
		t.Error("VerifyHostname(bogus) should fail")
	}
}

// TestCertificateHasRemoveReplaceExtension 验证 HasExtension / RemoveExtension /
// ReplaceExtension 三个出口，含「不存在时报错而非创建」的 BC 语义。
//
// TestCertificateHasRemoveReplaceExtension covers the HasExtension,
// RemoveExtension and ReplaceExtension outlets, including the BouncyCastle
// semantics of failing rather than creating when the extension is absent.
func TestCertificateHasRemoveReplaceExtension(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	if cert.HasExtension("keyUsage") {
		t.Fatal("fresh cert should not have keyUsage")
	}
	if cert.HasExtension("noSuchExtension") {
		t.Fatal("HasExtension(unknown) should be false")
	}
	if err := cert.AddExtensionByName("keyUsage", "digitalSignature"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensionByName("extendedKeyUsage", "serverAuth"); err != nil {
		t.Fatal(err)
	}
	if !cert.HasExtension("keyUsage") || !cert.HasExtension("extendedKeyUsage") {
		t.Fatal("HasExtension should see the added extensions")
	}
	if !cert.HasExtension("2.5.29.15") { // keyUsage 的点分 OID
		t.Fatal("HasExtension(\"2.5.29.15\") should resolve to keyUsage")
	}

	// Replace：覆盖成功
	if err := cert.ReplaceExtension("keyUsage", "digitalSignature,keyEncipherment"); err != nil {
		t.Fatalf("ReplaceExtension: %v", err)
	}
	got := cert.KeyUsage()
	if len(got) != 2 {
		t.Fatalf("KeyUsage() after replace = %v, want 2 entries", got)
	}
	// 位置保持不变：keyUsage 仍在 extendedKeyUsage 之前
	exts := cert.Extensions()
	if len(exts) != 2 || exts[0].Field != "keyUsage" || exts[1].Field != "extendedKeyUsage" {
		t.Fatalf("extension order after replace = %v", exts)
	}

	// Replace 不存在的扩展报错而非创建
	if err := cert.ReplaceExtension("nameConstraints", "permitted;DNS:.example.com"); err == nil {
		t.Fatal("ReplaceExtension on absent extension should fail")
	} else if !strings.Contains(err.Error(), "not present") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert.HasExtension("nameConstraints") {
		t.Fatal("failed ReplaceExtension must not create the extension")
	}

	// Remove：删除成功
	if err := cert.RemoveExtension("keyUsage"); err != nil {
		t.Fatalf("RemoveExtension: %v", err)
	}
	if cert.HasExtension("keyUsage") {
		t.Fatal("keyUsage should be gone after RemoveExtension")
	}
	if err := cert.RemoveExtension("keyUsage"); err == nil {
		t.Fatal("RemoveExtension on absent extension should fail")
	} else if !strings.Contains(err.Error(), "not present") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cert.RemoveExtension("noSuchExtension"); err == nil {
		t.Fatal("RemoveExtension(unknown) should fail")
	} else if !strings.Contains(err.Error(), "unknown extension name") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 删到空再签，签名仍须有效
	if err := cert.RemoveExtension("extendedKeyUsage"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("verify after removing all extensions: %v", err)
	}
}

// TestCertificateSignedLock 验证签名后不可变：Set* / Add* / 二次 Sign 均报错，
// 且由 PEM/DER 加载得到的证书同样锁定。
//
// TestCertificateSignedLock verifies the post-signature immutability: Set*,
// Add* and a repeated Sign all fail, and certificates obtained by loading PEM
// or DER are locked as well.
func TestCertificateSignedLock(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "lock.example.com")

	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	muts := []struct {
		name string
		fn   func() error
	}{
		{"SetVersion", func() error { return cert.SetVersion(2) }},
		{"SetSerial", func() error { return cert.SetSerial(1) }},
		{"SetIssuer", func() error { return cert.SetIssuer(subject) }},
		{"SetSubject", func() error { return cert.SetSubject(subject) }},
		{"SetValidity", func() error {
			return cert.SetValidity(time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		}},
		{"SetPublicKey", func() error { return cert.SetPublicKey(priv.Public()) }},
		{"AddBasicConstraints", func() error { return cert.AddBasicConstraints(true) }},
		{"AddSubjectAltName", func() error { return cert.AddSubjectAltName("DNS:x.example.com") }},
		{"AddKeyUsage", func() error { return cert.AddKeyUsage("digitalSignature") }},
		{"AddExtendedKeyUsage", func() error { return cert.AddExtendedKeyUsage("serverAuth") }},
		{"AddSubjectKeyID", cert.AddSubjectKeyID},
		{"AddExtension", func() error { return cert.AddExtension(83, "digitalSignature") }},
		{"AddExtensionByName", func() error {
			return cert.AddExtensionByName("keyUsage", "digitalSignature")
		}},
		{"AddExtensions", func() error {
			return cert.AddExtensions(Extension{Nid: 83, Value: "digitalSignature"})
		}},
		{"RemoveExtension", func() error { return cert.RemoveExtension("keyUsage") }},
		{"ReplaceExtension", func() error {
			return cert.ReplaceExtension("keyUsage", "digitalSignature")
		}},
		{"Sign", func() error { return cert.Sign(priv) }},
	}
	for _, m := range muts {
		if err := m.fn(); err == nil {
			t.Errorf("%s after Sign should fail", m.name)
		} else if !strings.Contains(err.Error(), "already signed") {
			t.Errorf("%s: unexpected error %v", m.name, err)
		}
	}

	// 只读方法仍可正常工作
	if cert.HasExtension("keyUsage") {
		t.Fatal("HasExtension should still work on a signed certificate")
	}
	if cert.Subject() != "ext.example.com" {
		t.Fatalf("Subject() after Sign = %q", cert.Subject())
	}
	if err := cert.Verify(priv.Public()); err != nil {
		t.Fatalf("Verify after Sign: %v", err)
	}

	// 加载得到的证书同样锁定
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loaded.Close() })
	if err := loaded.AddExtensionByName("keyUsage", "digitalSignature"); err == nil {
		t.Fatal("AddExtensionByName on loaded cert should fail")
	} else if !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := loaded.SetSerial(2); err == nil {
		t.Fatal("SetSerial on loaded cert should fail")
	}

	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	loadedDER, err := LoadCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loadedDER.Close() })
	if err := loadedDER.AddExtensionByName("keyUsage", "digitalSignature"); err == nil {
		t.Fatal("AddExtensionByName on DER-loaded cert should fail")
	}
}

// TestCertificateExtensionsRoundTrip 验证通过通用扩展入口添加的扩展在 PEM/DER
// 往返后仍可按名、按 NID 读到，且签名保持有效。
//
// TestCertificateExtensionsRoundTrip verifies that extensions added through the
// generic entry points survive a PEM/DER round trip, stay readable by name and
// by NID, and keep the signature valid.
func TestCertificateExtensionsRoundTrip(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })
	if err := cert.AddExtensionByName("subjectAltName", "DNS:rt.example.com,IP:192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensionByName("extendedKeyUsage", "serverAuth"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensionByName("nsComment", "UTF8:roundtrip"); err != nil {
		t.Fatalf("AddExtensionByName(nsComment): %v", err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loaded.Close() })
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatalf("verify after PEM round trip: %v", err)
	}
	if !loaded.HasExtension("nsComment") {
		t.Fatal("nsComment lost after PEM round trip")
	}
	if got := loaded.SAN(); len(got) != 2 {
		t.Fatalf("SAN after round trip = %v, want 2 entries", got)
	}
	// 按 NID 也能读到
	found := false
	for _, e := range loaded.Extensions() {
		if e.Nid == 126 && e.Field == "extendedKeyUsage" {
			found = true
			if e.OID != "2.5.29.37" {
				t.Fatalf("extendedKeyUsage OID = %q, want 2.5.29.37", e.OID)
			}
		}
	}
	if !found {
		t.Fatalf("extendedKeyUsage not found by NID: %v", loaded.Extensions())
	}
}

// TestCSRExtensionHelpers 验证 CSR 侧的按名入口与便利扩展方法，并验证签名后锁定。
//
// TestCSRExtensionHelpers covers the by-name entry point and the convenience
// extension methods on the CSR side, plus the post-signature lock.
func TestCSRExtensionHelpers(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "csr-ext.example.com")

	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.AddSubjectAltName("DNS:csr-ext.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := req.AddKeyUsage("critical,digitalSignature,keyEncipherment"); err != nil {
		t.Fatal(err)
	}
	if err := req.AddExtendedKeyUsage("serverAuth"); err != nil {
		t.Fatal(err)
	}
	if err := req.AddBasicConstraints(false); err != nil {
		t.Fatal(err)
	}
	if err := req.AddExtensionByName("nsComment", "UTF8:csr"); err != nil {
		t.Fatalf("AddExtensionByName: %v", err)
	}
	if err := req.AddExtensionByName("noSuchExtension", "x"); err == nil {
		t.Fatal("AddExtensionByName(unknown) should fail")
	}
	if err := req.SetChallengePassword("secret"); err != nil {
		t.Fatal(err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := req.Verify(); err != nil {
		t.Fatalf("CSR verify: %v", err)
	}

	// 扩展内容可读
	exts := req.Extensions()
	if len(exts) != 5 {
		t.Fatalf("CSR Extensions() = %d entries, want 5: %v", len(exts), exts)
	}
	names := map[string]bool{}
	for _, e := range exts {
		names[e.Field] = true
	}
	for _, want := range []string{
		"subjectAltName", "keyUsage", "extendedKeyUsage",
		"basicConstraints", "nsComment",
	} {
		if !names[want] {
			t.Errorf("CSR missing extension %q, got %v", want, exts)
		}
	}

	// 签名后锁定
	if err := req.AddExtensionByName("nsComment", "UTF8:again"); err == nil {
		t.Fatal("AddExtensionByName after Sign should fail")
	} else if !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := req.SetSubject(subject); err == nil {
		t.Fatal("SetSubject after Sign should fail")
	}
	if err := req.Sign(priv); err == nil {
		t.Fatal("repeated Sign should fail")
	}

	// 加载得到的 CSR 同样锁定
	pem, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificateRequestPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.AddExtensionByName("nsComment", "UTF8:x"); err == nil {
		t.Fatal("AddExtensionByName on loaded CSR should fail")
	}
}
