//go:build tongsuocli

package x509

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLICertificatePolicies 验证 Go 侧创建的 certificatePolicies 扩展能被
// 铜锁 openssl CLI 正确解析与展示。
//
// TestCLICertificatePolicies verifies that the certificatePolicies extension
// created on the Go side is parsed and displayed correctly by the Tongsuo
// openssl CLI.
func TestCLICertificatePolicies(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "certpol-cli.example.com")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(16); err != nil {
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
	if err := cert.AddExtensionByName("certificatePolicies", "1.2.3.4,1.5.6.7.8"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	certPEM, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	s := string(testutil.MustRunOpenSSL(t, "x509", "-in", certFile, "-noout", "-text"))
	if !strings.Contains(s, "Certificate Policies") {
		t.Fatalf("openssl text missing Certificate Policies:\n%s", s)
	}
	for _, want := range []string{"Policy: 1.2.3.4", "Policy: 1.5.6.7.8"} {
		if !strings.Contains(s, want) {
			t.Errorf("openssl text missing %q:\n%s", want, s)
		}
	}

	// 铜锁侧按名读取扩展。
	out := testutil.MustRunOpenSSL(t, "x509", "-in", certFile, "-noout", "-ext", "certificatePolicies")
	if !strings.Contains(string(out), "1.2.3.4") {
		t.Fatalf("openssl -ext certificatePolicies mismatch: %s", out)
	}
}
