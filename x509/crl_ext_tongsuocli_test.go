//go:build tongsuocli

package x509_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestCLICRLIssuingDistributionPoint 验证 Go 侧创建的 CRL
// issuingDistributionPoint 扩展能被铜锁 openssl CLI 正确解析与展示。
//
// TestCLICRLIssuingDistributionPoint verifies that the issuingDistributionPoint
// extension of a CRL created on the Go side is parsed and displayed correctly
// by the Tongsuo openssl CLI.
func TestCLICRLIssuingDistributionPoint(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca := newCA(t, "CRL IDP CLI CA", func() (asym.PrivateKey, error) {
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
	if err := b.AddExtensionByName("issuingDistributionPoint", "critical,onlyuser:TRUE"); err != nil {
		t.Fatalf("AddExtensionByName(issuingDistributionPoint): %v", err)
	}
	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer func() { _ = crl.Close() }()

	dir := t.TempDir()
	crlFile := dir + "/crl.pem"
	crlPEM, err := crl.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crlFile, crlPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	s := string(testutil.MustRunOpenSSL(t, "crl", "-in", crlFile, "-noout", "-text"))
	if !strings.Contains(s, "Issuing Distribution Point") {
		t.Fatalf("openssl crl text missing Issuing Distribution Point:\n%s", s)
	}
	if !strings.Contains(s, "Only User Certificates") {
		t.Errorf("openssl crl text missing 'Only User Certificates':\n%s", s)
	}
}
