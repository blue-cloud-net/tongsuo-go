//go:build tongsuocli

package x509

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// certPolCLIConfig 是铜锁 openssl 侧的证书策略配置。
//
// `[ polsect ]` 段用 `certificatePolicies = @polsect` 引用——这是 OpenSSL
// 表达 CPS / userNotice 限定符的**唯一**方式（内联形式只能给策略 OID）。
//
// certPolCLIConfig is the certificate policy configuration for the Tongsuo
// openssl side.
//
// The `[ polsect ]` section is referenced with `certificatePolicies =
// @polsect` — the only way OpenSSL can express CPS / userNotice qualifiers
// (the inline form only carries policy OIDs).
const certPolCLIConfig = `[ req ]
distinguished_name = req_dn
prompt = no
x509_extensions = v3_ca
[ req_dn ]
CN = certpol-cli.example.com
[ v3_ca ]
certificatePolicies = @polsect
[ polsect ]
policyIdentifier = 1.2.3.4
CPS.1 = http://cps.example.com/cps
CPS.2 = https://cps.example.com/cps2
userNotice.1 = @usernotice
[ usernotice ]
explicitText = "This is a user notice"
organization = "Example Org"
noticeNumbers = 1,2,3
`

// TestCLICertificatePoliciesQualifiers 验证本库能读回铜锁 openssl 用
// `@section` 配置生成的 certificatePolicies 扩展。
//
// openssl 的 DisplayText 用 VisibleString 承载（对非 ASCII 内容会产出不合规
// 的 DER），本库必须能正常解析。
//
// TestCLICertificatePoliciesQualifiers verifies that this library can read
// back the certificatePolicies extension that the Tongsuo openssl command
// line generates from an "@section" configuration.
//
// openssl carries DisplayText in a VisibleString (which produces
// non-conformant DER for non-ASCII content), so this library must parse it
// correctly.
func TestCLICertificatePoliciesQualifiers(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "req.cnf")
	if err := os.WriteFile(cfgPath, []byte(certPolCLIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	testutil.MustRunOpenSSLInDir(t, dir, "req", "-x509", "-new", "-newkey",
		"rsa:2048", "-nodes", "-keyout", "key.pem", "-out", certPath,
		"-days", "1", "-config", cfgPath, "-sha256")

	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatalf("LoadCertificatePEM: %v", err)
	}
	t.Cleanup(func() { _ = cert.Close() })

	policies, err := cert.CertificatePolicies()
	if err != nil {
		t.Fatalf("CertificatePolicies: %v", err)
	}
	want := []CertificatePolicy{
		{
			OID: "1.2.3.4",
			CPSURIs: []string{
				"http://cps.example.com/cps",
				"https://cps.example.com/cps2",
			},
			UserNotice: &UserNotice{
				Organization:  "Example Org",
				NoticeNumbers: []int{1, 2, 3},
				ExplicitText:  "This is a user notice",
			},
		},
	}
	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", policies, want)
	}
}

// TestCLICertificatePoliciesRoundTrip 验证本库生成的 certificatePolicies 扩展
// 能被铜锁 openssl 正确解析与展示。
//
// TestCLICertificatePoliciesRoundTrip verifies that the certificatePolicies
// extension produced by this library is parsed and displayed correctly by the
// Tongsuo openssl command line.
func TestCLICertificatePoliciesRoundTrip(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

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
	if err := cert.SetSerial(17); err != nil {
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
	policy := CertificatePolicy{
		OID:     "1.2.3.4",
		CPSURIs: []string{"http://cps.example.com/cps", "https://cps.example.com/cps2"},
		UserNotice: &UserNotice{
			Organization:  "Example Org",
			NoticeNumbers: []int{1, 2, 3},
			ExplicitText:  "This is a user notice",
		},
	}
	if err := cert.AddCertificatePolicies([]CertificatePolicy{policy}, false); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	certPEM, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := string(testutil.MustRunOpenSSL(t, "x509", "-in", certPath, "-noout",
		"-ext", "certificatePolicies"))
	for _, want := range []string{
		"Policy: 1.2.3.4",
		"CPS: http://cps.example.com/cps",
		"CPS: https://cps.example.com/cps2",
		"Organization: Example Org",
		"Explicit Text: This is a user notice",
		"Numbers: 1, 2, 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("openssl -ext certificatePolicies missing %q:\n%s", want, out)
		}
	}
}

// TestCLICertificatePoliciesUTF8 验证本库用 UTF8String 承载的非 ASCII 告示
// 文本能被铜锁 openssl 正确读回。
//
// 铜锁 openssl 的配置文件路径用 VisibleString，对非 ASCII 内容会产出不合规
// 的 DER；本库改用合规的 UTF8String，openssl 读回时不丢字符。
//
// TestCLICertificatePoliciesUTF8 verifies that the non-ASCII notice text
// carried by this library in UTF8String is read back correctly by the Tongsuo
// openssl command line.
//
// The Tongsuo openssl configuration path uses VisibleString, which produces
// non-conformant DER for non-ASCII content; this library uses the conformant
// UTF8String instead, and openssl reads it back without losing characters.
func TestCLICertificatePoliciesUTF8(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "certpol-cli-cn.example.com")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(18); err != nil {
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
	const org = "示例机构"
	const text = "本机构发布的证书策略说明"
	if err := cert.AddCertificatePolicies([]CertificatePolicy{{
		OID:     "1.2.3.4",
		CPSURIs: []string{"http://cps.example.com/cps"},
		UserNotice: &UserNotice{
			Organization:  org,
			NoticeNumbers: []int{1},
			ExplicitText:  text,
		},
	}}, false); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	certPEM, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := string(testutil.MustRunOpenSSL(t, "x509", "-in", certPath, "-noout",
		"-ext", "certificatePolicies"))
	for _, want := range []string{
		"Organization: " + org,
		"Explicit Text: " + text,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("openssl -ext certificatePolicies missing %q:\n%s", want, out)
		}
	}
}
