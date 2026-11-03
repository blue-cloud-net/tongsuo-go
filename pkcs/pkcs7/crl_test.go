package pkcs7

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// makeCRL 签发一张包含一个吊销条目的 CRL（issuer 为自签 CA，被吊销者为另一张证书）。
//
// makeCRL issues a CRL with a single revoked entry (the issuer is a
// self-signed CA and the revoked certificate is a separate entity).
func makeCRL(t *testing.T, cn string) *x509.CRL {
	t.Helper()
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	now := time.Now()
	caName := x509.NewName().Add("CN", cn)
	// CreateSelfSigned 会自动补 SKID/AKID——CRL 的 authorityKeyIdentifier 依赖它。
	ca, err := x509.CreateSelfSigned(caName, 1,
		now.Add(-48*time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateSelfSigned(ca): %v", err)
	}
	leafName := x509.NewName().Add("CN", "leaf."+cn)
	leaf, err := x509.CreateCertificate(leafName, caName, 2,
		now.Add(-24*time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf): %v", err)
	}

	builder, err := x509.NewCRLBuilder(ca)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	if err := builder.SetNumber(1); err != nil {
		t.Fatalf("SetNumber: %v", err)
	}
	if err := builder.SetThisUpdate(now.Add(-time.Hour)); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}
	if err := builder.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatalf("SetNextUpdate: %v", err)
	}
	if err := builder.Revoke(leaf, now.Add(-30*time.Minute), x509.ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	crl, err := builder.Sign(priv)
	if err != nil {
		t.Fatalf("CRLBuilder.Sign: %v", err)
	}
	return crl
}

// TestFromCRLExtractCRLs 验证 CRL 打包/提取往返（DER 与 PEM 两种输入）。
//
// TestFromCRLExtractCRLs verifies the CRL pack/extract round trip for both
// DER and PEM inputs.
func TestFromCRLExtractCRLs(t *testing.T) {
	c1 := makeCRL(t, "crl-a.pkcs7.dev")
	c2 := makeCRL(t, "crl-b.pkcs7.dev")

	der, err := FromCRL([]*x509.CRL{c1, c2})
	if err != nil {
		t.Fatalf("FromCRL: %v", err)
	}
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"der", der},
		{"pem", MarshalPEM(der)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crls, err := ExtractCRLs(tc.in)
			if err != nil {
				t.Fatalf("ExtractCRLs: %v", err)
			}
			if len(crls) != 2 {
				t.Fatalf("got %d CRLs, want 2", len(crls))
			}
			for _, c := range crls {
				if c.Issuer() == nil {
					t.Error("extracted CRL has no issuer")
				}
				if got := len(c.RevokedEntries()); got != 1 {
					t.Errorf("revoked entries = %d, want 1", got)
				}
			}
		})
	}
}

// TestFromCRLNilAndEmpty 验证 nil 条目被跳过、空输入的行为。
//
// TestFromCRLNilAndEmpty verifies nil entries are skipped and the empty
// input behaviour.
func TestFromCRLNilAndEmpty(t *testing.T) {
	der, err := FromCRL([]*x509.CRL{nil, nil})
	if err != nil {
		t.Fatalf("FromCRL(nil): %v", err)
	}
	crls, err := ExtractCRLs(der)
	if err != nil {
		t.Fatalf("ExtractCRLs: %v", err)
	}
	if len(crls) != 0 {
		t.Errorf("got %d CRLs, want 0", len(crls))
	}
	if _, err := ExtractCRLs(nil); err == nil {
		t.Error("empty input: want error")
	}
}

// TestCertContainerHasNoCRLs 验证「只有证书的容器」提取 CRL 返回空切片。
//
// TestCertContainerHasNoCRLs verifies that a certificate-only container
// yields an empty CRL slice.
func TestCertContainerHasNoCRLs(t *testing.T) {
	cert := makeCert(t, "no-crl.pkcs7.dev", 7)
	der, err := Build([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	crls, err := ExtractCRLs(der)
	if err != nil {
		t.Fatalf("ExtractCRLs: %v", err)
	}
	if len(crls) != 0 {
		t.Errorf("got %d CRLs, want 0", len(crls))
	}
}
