package x509

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// certPolExtensionData 返回证书中 certificatePolicies 扩展的 DER 值；
// 扩展不存在时返回 nil。
//
// certPolExtensionData returns the DER value of the certificatePolicies
// extension of the certificate; it returns nil when the extension is absent.
func certPolExtensionData(exts []Extension) []byte {
	for _, e := range exts {
		if e.OID == certificatePoliciesOID {
			return e.Data
		}
	}
	return nil
}

// TestCertificateAddCertificatePoliciesQualifiers 验证证书上写入带 CPS 与
// userNotice 限定符的 certificatePolicies 扩展，扩展值与黄金向量逐字节一致，
// 且可原样读回。
//
// TestCertificateAddCertificatePoliciesQualifiers verifies that a
// certificatePolicies extension carrying CPS and userNotice qualifiers can be
// written to a certificate, that its extension value matches the golden vector
// byte for byte, and that it reads back unchanged.
func TestCertificateAddCertificatePoliciesQualifiers(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	policy := certPolFullPolicy()
	if err := cert.AddCertificatePolicies([]CertificatePolicy{policy}, false); err != nil {
		t.Fatalf("AddCertificatePolicies: %v", err)
	}

	got := certPolExtensionData(cert.Extensions())
	want, err := hex.DecodeString(certPolGoldenFull)
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("extension DER mismatch\n got: %X\nwant: %X", got, want)
	}

	policies, err := cert.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	if !reflect.DeepEqual(policies, []CertificatePolicy{policy}) {
		t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", policies, policy)
	}
}

// TestCertificateAddCertificatePoliciesCritical 验证 critical 标志被正确写入，
// 且不改变扩展值。
//
// TestCertificateAddCertificatePoliciesCritical verifies that the critical
// flag is recorded correctly and that it does not change the extension value.
func TestCertificateAddCertificatePoliciesCritical(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	if err := cert.AddCertificatePolicies([]CertificatePolicy{{OID: "1.2.3.4"}}, true); err != nil {
		t.Fatalf("AddCertificatePolicies: %v", err)
	}
	var found bool
	for _, e := range cert.Extensions() {
		if e.OID != certificatePoliciesOID {
			continue
		}
		found = true
		if !e.Critical {
			t.Error("Critical = false, want true")
		}
		if got := hex.EncodeToString(e.Data); !strings.EqualFold(got, certPolGoldenBare) {
			t.Errorf("DER = %s, want %s", got, certPolGoldenBare)
		}
	}
	if !found {
		t.Fatal("certificatePolicies not found in Extensions()")
	}
}

// TestCertificateAddCertificatePoliciesMultiple 验证多条策略各自成为一条
// PolicyInformation——这正是 OpenSSL 的 "@section" 配置语法做不到的
// （该语法只产出一条，后写的 policyIdentifier 覆盖先写的）。
//
// TestCertificateAddCertificatePoliciesMultiple verifies that several
// policies each become their own PolicyInformation — something the OpenSSL
// "@section" configuration syntax cannot express (it produces a single entry,
// the later policyIdentifier overwriting the earlier one).
func TestCertificateAddCertificatePoliciesMultiple(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	policies := []CertificatePolicy{
		{OID: "1.2.3.4", CPSURIs: []string{"http://a.example.com"}},
		{OID: "1.5.6.7.8", CPSURIs: []string{"http://b.example.com"}},
	}
	if err := cert.AddCertificatePolicies(policies, false); err != nil {
		t.Fatalf("AddCertificatePolicies: %v", err)
	}
	got, err := cert.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	if !reflect.DeepEqual(got, policies) {
		t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", got, policies)
	}
}

// TestCertificateAddCertificatePoliciesErrors 验证写侧的错误路径：重复添加、
// 空列表、非法输入与签名后不可变。
//
// TestCertificateAddCertificatePoliciesErrors covers the write-side error
// paths: duplicate addition, an empty list, invalid input and the
// post-signing immutability rule.
func TestCertificateAddCertificatePoliciesErrors(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("duplicate", func(t *testing.T) {
		cert := newUnsignedCert(t, priv)
		t.Cleanup(func() { _ = cert.Close() })
		if err := cert.AddCertificatePolicies([]CertificatePolicy{{OID: "1.2.3.4"}}, false); err != nil {
			t.Fatalf("AddCertificatePolicies: %v", err)
		}
		err := cert.AddCertificatePolicies([]CertificatePolicy{{OID: "1.2.3.4"}}, false)
		if err == nil {
			t.Fatal("expected an error for a duplicate extension")
		}
		if !strings.Contains(err.Error(), "extension already present") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		cert := newUnsignedCert(t, priv)
		t.Cleanup(func() { _ = cert.Close() })
		if err := cert.AddCertificatePolicies(nil, false); err == nil {
			t.Fatal("expected an error for an empty policy list")
		}
	})

	t.Run("invalid oid", func(t *testing.T) {
		cert := newUnsignedCert(t, priv)
		t.Cleanup(func() { _ = cert.Close() })
		if err := cert.AddCertificatePolicies([]CertificatePolicy{{OID: "not-an-oid"}}, false); err == nil {
			t.Fatal("expected an error for an invalid OID")
		}
	})

	t.Run("after sign", func(t *testing.T) {
		cert := newUnsignedCert(t, priv)
		t.Cleanup(func() { _ = cert.Close() })
		if err := cert.Sign(priv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		err := cert.AddCertificatePolicies([]CertificatePolicy{{OID: "1.2.3.4"}}, false)
		if err == nil {
			t.Fatal("expected an error after signing")
		}
		if !strings.Contains(err.Error(), "already signed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestCertificateAddCertificatePoliciesRoundTrip 验证扩展在签名并经 PEM 往返后
// 仍然完整可读。
//
// TestCertificateAddCertificatePoliciesRoundTrip verifies that the extension
// stays intact after signing and a PEM round trip.
func TestCertificateAddCertificatePoliciesRoundTrip(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	policy := certPolFullPolicy()
	if err := cert.AddCertificatePolicies([]CertificatePolicy{policy}, false); err != nil {
		t.Fatalf("AddCertificatePolicies: %v", err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatalf("LoadCertificatePEM: %v", err)
	}
	t.Cleanup(func() { _ = loaded.Close() })

	got, err := loaded.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	if !reflect.DeepEqual(got, []CertificatePolicy{policy}) {
		t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", got, policy)
	}
}

// TestCSRCertificatePoliciesQualifiers 验证 CSR 侧可以写入带限定符的
// certificatePolicies 扩展，扩展在 Sign 前即可读，签名后 DER 中依然完整。
//
// TestCSRCertificatePoliciesQualifiers verifies that a certificatePolicies
// extension carrying qualifiers can be written on the CSR side, that it is
// readable before Sign, and that it survives in the DER after signing.
func TestCSRCertificatePoliciesQualifiers(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "certpol-csr.example.com")
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}

	policy := certPolFullPolicy()
	if err := req.AddCertificatePolicies([]CertificatePolicy{policy}, false); err != nil {
		t.Fatalf("AddCertificatePolicies: %v", err)
	}

	// Sign 前即可读出（暂存区对调用方可见）。
	got, err := req.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	if !reflect.DeepEqual(got, []CertificatePolicy{policy}) {
		t.Fatalf("policy mismatch before sign\n got: %+v\nwant: %+v", got, policy)
	}

	if err := req.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pem, err := req.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	loaded, err := LoadCertificateRequestPEM(pem)
	if err != nil {
		t.Fatalf("LoadCertificateRequestPEM: %v", err)
	}
	got, err = loaded.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies after reload: %v", err)
	}
	if !reflect.DeepEqual(got, []CertificatePolicy{policy}) {
		t.Fatalf("policy mismatch after reload\n got: %+v\nwant: %+v", got, policy)
	}
}

// TestCSRCertificatePoliciesAfterSign 验证 CSR 签名后不可再添加扩展。
//
// TestCSRCertificatePoliciesAfterSign verifies that no extension can be
// added to a CSR after signing.
func TestCSRCertificatePoliciesAfterSign(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	subject := NewName().Add("CN", "certpol-csr-signed.example.com")
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	err = req.AddCertificatePolicies([]CertificatePolicy{{OID: "1.2.3.4"}}, false)
	if err == nil {
		t.Fatal("expected an error after signing")
	}
	if !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCRLAddCertificatePolicies 验证 CRL 侧可以写入并读回
// certificatePolicies 扩展。
//
// TestCRLAddCertificatePolicies verifies that a certificatePolicies extension
// can be written to and read back from a CRL.
func TestCRLAddCertificatePolicies(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "certpol-crl.example.com")
	ca := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = ca.Close() })
	if err := ca.SetIssuer(subject); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := ca.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// AKID 的 keyid 取自 CA 的 SKID（缺失时按 CA 公钥计算），因此 CA 需先带上
	// SKID 并签名。
	if err := ca.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign(priv); err != nil {
		t.Fatal(err)
	}

	builder, err := NewCRLBuilder(ca)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	t.Cleanup(func() { _ = builder.Close() })
	if err := builder.SetThisUpdate(now); err != nil {
		t.Fatal(err)
	}
	if err := builder.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	policy := certPolFullPolicy()
	if err := builder.AddCertificatePolicies([]CertificatePolicy{policy}, false); err != nil {
		t.Fatalf("AddCertificatePolicies: %v", err)
	}
	crl, err := builder.Sign(priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Cleanup(func() { _ = crl.Close() })

	got, err := crl.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	if !reflect.DeepEqual(got, []CertificatePolicy{policy}) {
		t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", got, policy)
	}
}

// TestCertificatePoliciesAbsent 验证没有 certificatePolicies 扩展时读接口返回
// (nil, nil) 而不是错误。
//
// TestCertificatePoliciesAbsent verifies that the read side returns
// (nil, nil) rather than an error when the extension is absent.
func TestCertificatePoliciesAbsent(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	policies, err := cert.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	if policies != nil {
		t.Fatalf("policies = %+v, want nil", policies)
	}
}
