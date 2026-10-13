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

// TestCLICustomExtensionText 按名字（AddExtensionByName）添加的扩展与铜锁
// `openssl x509 -text` 输出一致，覆盖点分 OID 寻址与批量添加。
//
// TestCLICustomExtensionText checks that extensions added by name
// (AddExtensionByName, including dotted-OID addressing and batch addition) match
// the Tongsuo `openssl x509 -text` output.
func TestCLICustomExtensionText(t *testing.T) {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	subject := NewName().Add("CN", "by-name.example.com")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(14); err != nil {
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

	// 按短名
	if err := cert.AddExtensionByName("extendedKeyUsage", "serverAuth,clientAuth"); err != nil {
		t.Fatal(err)
	}
	// 按点分 OID（2.5.29.15 = keyUsage）
	if err := cert.AddExtensionByName("2.5.29.15", "critical,digitalSignature"); err != nil {
		t.Fatal(err)
	}
	// 批量（SAN + basicConstraints + nsComment）
	if err := cert.AddExtensions(
		Extension{Nid: 85, Value: "DNS:by-name.example.com"},
		Extension{Nid: 87, Value: "critical,CA:FALSE"},
	); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensionByName("nsComment", "UTF8:tongsuo-go"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	certPEM, _ := cert.MarshalPEM()
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	s := string(testutil.MustRunOpenSSL(t, "x509", "-in", certFile, "-noout", "-text"))
	for _, want := range []string{
		"TLS Web Server Authentication",
		"TLS Web Client Authentication",
		"Digital Signature",
		"DNS:by-name.example.com",
		"CA:FALSE",
		"tongsuo-go",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("openssl x509 -text missing %q\n%s", want, s)
		}
	}

	// 铜锁侧也应能按名读取扩展
	out := testutil.MustRunOpenSSL(t, "x509", "-in", certFile, "-noout", "-ext", "extendedKeyUsage")
	if !strings.Contains(string(out), "TLS Web Server Authentication") {
		t.Fatalf("openssl -ext extendedKeyUsage mismatch: %s", out)
	}
}

// TestCLISANMerge 验证可重复 OID 合并后的证书在铜锁侧只有一个 SAN 扩展条目，
// 且 openssl 的主机名校验（-verify_hostname）对合并进来的每个名字都通过。
//
// TestCLISANMerge verifies that a certificate whose SAN was built through
// repeated merging carries a single SAN extension on the Tongsuo side, and that
// `openssl verify -verify_hostname` accepts every merged name.
func TestCLISANMerge(t *testing.T) {
	caPriv, _ := asym.GenerateSM2()
	leafPriv, _ := asym.GenerateSM2()
	now := time.Now()

	caSubject := NewName().Add("CN", "Merge Test CA")
	caCert := NewCertificate()
	if err := caCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSerial(1); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetIssuer(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSubject(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetPublicKey(caPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddSubjectKeyID(); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	// 分三次添加 SAN：应合并为一条
	leafSubject := NewName().Add("CN", "leaf-merge.example.com")
	leaf := NewCertificate()
	if err := leaf.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetSerial(2); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetIssuer(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetSubject(leafSubject); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetPublicKey(leafPriv.Public()); err != nil {
		t.Fatal(err)
	}
	for _, san := range []string{
		"DNS:a-merge.example.com",
		"DNS:b-merge.example.com",
		"IP:192.0.2.10",
	} {
		if err := leaf.AddExtensionByName("subjectAltName", san); err != nil {
			t.Fatalf("merge %s: %v", san, err)
		}
	}
	if err := leaf.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	// 扩展条目数：subjectAltName 只能有一条
	count := 0
	for _, e := range leaf.Extensions() {
		if e.Field == "subjectAltName" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("subjectAltName entries = %d, want 1", count)
	}
	if got := leaf.SAN(); len(got) != 3 {
		t.Fatalf("SAN() = %v, want 3 entries", got)
	}

	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	leafFile := dir + "/leaf.pem"
	caPEM, _ := caCert.MarshalPEM()
	leafPEM, _ := leaf.MarshalPEM()
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafFile, leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// openssl 侧文本应只出现一次 X509v3 Subject Alternative Name 段
	s := string(testutil.MustRunOpenSSL(t, "x509", "-in", leafFile, "-noout", "-text"))
	if n := strings.Count(s, "X509v3 Subject Alternative Name"); n != 1 {
		t.Fatalf("X509v3 SAN section count = %d, want 1\n%s", n, s)
	}
	for _, want := range []string{
		"DNS:a-merge.example.com",
		"DNS:b-merge.example.com",
		"IP Address:192.0.2.10",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("openssl text missing %q\n%s", want, s)
		}
	}

	// 每个合并进来的名字都应通过铜锁的主机名校验
	for _, host := range []string{"a-merge.example.com", "b-merge.example.com"} {
		out := testutil.MustRunOpenSSL(t, "verify", "-CAfile", caFile,
			"-verify_hostname", host, leafFile)
		if !strings.Contains(string(out), "OK") {
			t.Errorf("openssl verify -verify_hostname %s: %s", host, out)
		}
	}
	// 未合并的名字必须失败
	out, err := testutil.RunOpenSSLCombined(
		[]string{"verify", "-CAfile", caFile, "-verify_hostname", "c-merge.example.com", leafFile}, nil)
	if err == nil {
		t.Errorf("openssl verify should reject c-merge.example.com: %s", out)
	}
}

// TestCLIReplaceExtension 验证 ReplaceExtension 覆盖后在铜锁侧读到的是新值。
//
// TestCLIReplaceExtension checks that an extension overwritten through
// ReplaceExtension reads back with the new value on the Tongsuo side.
func TestCLIReplaceExtension(t *testing.T) {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	subject := NewName().Add("CN", "replace-cli.example.com")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(15); err != nil {
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
	if err := cert.AddKeyUsage("critical,digitalSignature"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddSubjectAltName("DNS:before.example.com"); err != nil {
		t.Fatal(err)
	}
	// 覆盖 KeyUsage，去掉 SAN
	if err := cert.ReplaceExtension("keyUsage", "digitalSignature,keyEncipherment"); err != nil {
		t.Fatal(err)
	}
	if err := cert.RemoveExtension("subjectAltName"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	certPEM, _ := cert.MarshalPEM()
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	s := string(testutil.MustRunOpenSSL(t, "x509", "-in", certFile, "-noout", "-text"))
	if !strings.Contains(s, "Key Encipherment") {
		t.Errorf("openssl text missing replaced KeyUsage:\n%s", s)
	}
	if strings.Contains(s, "X509v3 Subject Alternative Name") {
		t.Errorf("openssl text still has removed SAN:\n%s", s)
	}
}
