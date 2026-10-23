package x509_test

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestCRLBuilderAddExtension 验证 CRL 通用扩展入口：按名字添加
// issuingDistributionPoint 与 freshestCRL，并按 NID 添加同名扩展。
//
// 回归用例：此前 CRL 侧没有任何任意扩展入口，只能写 crlNumber 与
// authorityKeyIdentifier，无法产出带 IDP / freshestCRL 的 CRL（铜锁
// `openssl ca -crlexts` 是 CLI 上唯一的等价能力）。
//
// TestCRLBuilderAddExtension verifies the generic CRL extension entry points:
// adding issuingDistributionPoint and freshestCRL by name, plus the same
// extension by NID.
//
// Regression case: the CRL side used to have no generic extension entry point
// at all — only crlNumber and authorityKeyIdentifier could be written — so a
// CRL carrying IDP or freshestCRL could not be produced (the Tongsuo
// `openssl ca -crlexts` option is the only equivalent CLI capability).
func TestCRLBuilderAddExtension(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca := newCA(t, "CRL Ext CA", func() (asym.PrivateKey, error) {
		return asym.GenerateSM2()
	}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	b, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b.Close() }()

	if err := b.SetThisUpdate(now.Add(-time.Minute)); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}
	if err := b.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatalf("SetNextUpdate: %v", err)
	}

	// 按名字：issuingDistributionPoint（RFC 5280 §5.2.5）
	if err := b.AddExtensionByName("issuingDistributionPoint", "critical,onlyuser:TRUE"); err != nil {
		t.Fatalf("AddExtensionByName(issuingDistributionPoint): %v", err)
	}
	// 按名字：freshestCRL（RFC 5280 §5.2.6）
	if err := b.AddExtensionByName("freshestCRL", "URI:http://example.com/freshest.crl"); err != nil {
		t.Fatalf("AddExtensionByName(freshestCRL): %v", err)
	}
	// 未知名字必须报错
	if err := b.AddExtensionByName("noSuchCRLExtension", "x"); err == nil {
		t.Fatal("AddExtensionByName(unknown) 应报错")
	}

	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer func() { _ = crl.Close() }()

	// 扩展应出现在 CRL 上。
	want := map[string]bool{
		"issuingDistributionPoint": false,
		"freshestCRL":              false,
	}
	for _, e := range crl.Extensions() {
		if _, ok := want[e.Field]; ok {
			want[e.Field] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("CRL 缺少扩展 %q，实际扩展：%v", name, crl.Extensions())
		}
	}

	// IDP 是 critical 的。
	for _, e := range crl.Extensions() {
		if e.Field == "issuingDistributionPoint" && !e.Critical {
			t.Error("issuingDistributionPoint 应为 critical")
		}
	}

	// 签名后仍可验签。
	if err := crl.Verify(ca.cert); err != nil {
		t.Fatalf("CRL verify: %v", err)
	}
}

// TestCRLBuilderAddExtensionByNID 验证按 NID 添加 CRL 扩展。
//
// TestCRLBuilderAddExtensionByNID verifies adding a CRL extension by NID.
func TestCRLBuilderAddExtensionByNID(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca := newCA(t, "CRL Ext NID CA", func() (asym.PrivateKey, error) {
		return asym.GenerateSM2()
	}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	b, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b.Close() }()

	if err := b.SetThisUpdate(now.Add(-time.Minute)); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}
	// issuingDistributionPoint 的 NID 为 770（RFC 5280 §5.2.5，id-ce 28）。
	if err := b.AddExtension(770, "critical,onlyCA:TRUE"); err != nil {
		t.Fatalf("AddExtension(770): %v", err)
	}

	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer func() { _ = crl.Close() }()

	var found bool
	for _, e := range crl.Extensions() {
		if e.Field == "issuingDistributionPoint" {
			found = true
			if e.OID != "2.5.29.28" {
				t.Errorf("issuingDistributionPoint OID = %q, want 2.5.29.28", e.OID)
			}
		}
	}
	if !found {
		t.Fatalf("CRL 缺少 issuingDistributionPoint：%v", crl.Extensions())
	}
}

// TestCRLBuilderAddExtensionErrors 验证 CRL 扩展入口在 nil 构建器、已签发后
// 与未知名字三种情况下都明确报错，而不是 panic 或静默写入。
//
// TestCRLBuilderAddExtensionErrors verifies that the CRL extension entry
// points report an explicit error for a nil builder, after signing and for an
// unknown name, rather than panicking or writing silently.
func TestCRLBuilderAddExtensionErrors(t *testing.T) {
	// nil 构建器：所有方法都应返回错误而不是 panic。
	var nilBuilder *x509.CRLBuilder
	if err := nilBuilder.AddExtension(770, "critical,onlyuser:TRUE"); err == nil {
		t.Error("nil builder AddExtension 应报错")
	}
	if err := nilBuilder.AddExtensionByName("issuingDistributionPoint", "critical,onlyuser:TRUE"); err == nil {
		t.Error("nil builder AddExtensionByName 应报错")
	}

	now := time.Now().Truncate(time.Second)
	ca := newCA(t, "CRL Ext Err CA", func() (asym.PrivateKey, error) {
		return asym.GenerateSM2()
	}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	b, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.SetThisUpdate(now.Add(-time.Minute)); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}

	// 未知名字应报错（不静默创建）。
	if err := b.AddExtensionByName("noSuchCRLExtension", "x"); err == nil {
		t.Error("AddExtensionByName(未知名字) 应报错")
	}

	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer func() { _ = crl.Close() }()

	// 签发后句柄已转移，扩展入口必须拒绝。
	if err := b.AddExtension(770, "critical,onlyuser:TRUE"); err == nil {
		t.Error("Sign 之后 AddExtension 应报错")
	}
	if err := b.AddExtensionByName("issuingDistributionPoint", "critical,onlyuser:TRUE"); err == nil {
		t.Error("Sign 之后 AddExtensionByName 应报错")
	}
}
