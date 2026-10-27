//go:build tongsuocli

package x509

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asn1"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// subjectValue 返回证书 DER 中 TBSCertificate.subject 的原始内容字节。
//
// 用于把两个证书的 subject 结构逐字节对比（绕开签名差异）。
func subjectValue(t *testing.T, der []byte) []byte {
	t.Helper()
	root, err := asn1.Parse(der)
	if err != nil {
		t.Fatalf("asn1.Parse: %v", err)
	}
	if len(root.Children) == 0 {
		t.Fatal("certificate DER 没有 TBSCertificate")
	}
	tbs := root.Children[0]
	idx := 0
	if len(tbs.Children) > 0 && tbs.Children[0].Class == asn1.ClassContextSpecific {
		idx = 1 // version [0] EXPLICIT 存在
	}
	// serialNumber, signature, issuer, validity, subject
	if len(tbs.Children) < idx+5 {
		t.Fatalf("TBSCertificate 只有 %d 个子节点，至少需要 %d 个", len(tbs.Children), idx+5)
	}
	return tbs.Children[idx+4].Value
}

// TestCLISubjectDERParity 本库与 `openssl req -x509 -subj` 对同一书写顺序产出逐字节相同的 subject。
//
// 这是 RDN 顺序语义（追加）的核心对拍：两边都按 C → O → OU → CN 的书写顺序生成 DER。
func TestCLISubjectDERParity(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("C", "CN").Add("O", "Example Corp").
		Add("OU", "Engineering").Add("CN", "lib.parity.dev")
	cert, err := CreateCertificate(subject, subject, 11,
		now.Add(-time.Hour), now.Add(time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()
	libDER, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cliCertFile := dir + "/cli.pem"
	testutil.MustRunOpenSSL(t, "req", "-x509", "-newkey", "sm2", "-nodes",
		"-keyout", dir+"/k.pem", "-out", cliCertFile, "-days", "3",
		"-subj", "/C=CN/O=Example Corp/OU=Engineering/CN=lib.parity.dev")
	cliPEM, err := os.ReadFile(cliCertFile)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, err := LoadCertificatePEM(cliPEM)
	if err != nil {
		t.Fatalf("LoadCertificatePEM(cli): %v", err)
	}
	defer cliCert.Close()
	cliDER, err := cliCert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}

	ours := subjectValue(t, libDER)
	theirs := subjectValue(t, cliDER)
	if !bytes.Equal(ours, theirs) {
		t.Fatalf("subject DER 与 openssl -subj 不一致（RDN 顺序或编码类型）\n本库 % x\nCLI  % x", ours, theirs)
	}
}

// squashSpaces 去掉所有空格，抹平铜锁 / OpenSSL 各版本 nameopt 输出的空格差异。
func squashSpaces(s string) string {
	return strings.ReplaceAll(s, " ", "")
}

// TestCLISubjectNonASCII 本库签发 CJK subject 证书 → openssl 读回为 UTF8String 且文本保真。
func TestCLISubjectNonASCII(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "海峰").Add("O", "示例公司").Add("C", "CN")
	cert, err := CreateCertificate(subject, subject, 5,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	certFile := t.TempDir() + "/utf8.pem"
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// subject 用 -nameopt utf8 展示，确认字符未被转义或替换
	out := squashSpaces(string(testutil.MustRunOpenSSL(t, "x509", "-in", certFile,
		"-noout", "-subject", "-nameopt", "utf8")))
	for _, want := range []string{"CN=海峰", "O=示例公司"} {
		if !strings.Contains(out, want) {
			t.Fatalf("openssl subject 缺 %q：%s", want, out)
		}
	}

	// DER 层面确认 CN 是 6 字节的 UTF8String（MBSTRING_ASC 会变成 12 字节）
	parsed := string(testutil.MustRunOpenSSL(t, "asn1parse", "-in", certFile))
	if !strings.Contains(parsed, ":海峰") {
		t.Fatalf("asn1parse 输出中未找到 UTF8String 的 CN=海峰：\n%s", parsed)
	}
	if strings.Contains(parsed, "BMPSTRING") {
		t.Fatalf("asn1parse 输出中出现 BMPSTRING，期望 UTF8STRING：\n%s", parsed)
	}
}

// TestCLIReadNonASCIISubject 铜锁 `req -utf8` 签发的证书 → 本库读回 CN 保真（双向对拍）。
func TestCLIReadNonASCIISubject(t *testing.T) {
	dir := t.TempDir()
	keyFile := dir + "/k.pem"
	certFile := dir + "/c.pem"
	testutil.MustRunOpenSSL(t, "req", "-x509", "-newkey", "sm2", "-nodes",
		"-keyout", keyFile, "-out", certFile, "-days", "3",
		"-subj", "/C=CN/O=Example Corp/CN=海峰", "-utf8")

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("LoadCertificatePEM: %v", err)
	}
	defer cert.Close()

	got := map[string]string{}
	for _, e := range cert.SubjectEntries() {
		got[e.Field] = e.Value
	}
	if got["CN"] != "海峰" {
		t.Fatalf("读取 -utf8 证书的 CN = %q (% x), want 海峰", got["CN"], got["CN"])
	}
	if got["O"] != "Example Corp" {
		t.Fatalf("读取 -utf8 证书的 O = %q, want Example Corp", got["O"])
	}
}

// TestCLINonUTF8SubjectIsDoubleEncoded 记录对照事实：铜锁 CLI 不带 -utf8（MBSTRING_ASC）
// 签发的证书，本库读回就是双重编码的 mojibake——即本库改后的行为对齐 -utf8、
// 不再对齐 CLI 默认行为。
func TestCLINonUTF8SubjectIsDoubleEncoded(t *testing.T) {
	dir := t.TempDir()
	keyFile := dir + "/k.pem"
	certFile := dir + "/c.pem"
	testutil.MustRunOpenSSL(t, "req", "-x509", "-newkey", "sm2", "-nodes",
		"-keyout", keyFile, "-out", certFile, "-days", "3",
		"-subj", "/CN=海峰")

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("LoadCertificatePEM: %v", err)
	}
	defer cert.Close()

	entries := cert.SubjectEntries()
	if len(entries) != 1 {
		t.Fatalf("subject entries = %d, want 1", len(entries))
	}
	// 双重编码后每个原始 UTF-8 字节变成 2 字节：6 字节 → 12 字节
	if got := entries[0].Value; got == "海峰" || len(got) != 12 {
		t.Fatalf("CLI 默认（MBSTRING_ASC）产出的 CN = %q (len %d), 期望 12 字节的 mojibake",
			got, len(got))
	}
}

// TestCLIVerifyNonASCIIChain 本库签发 CJK CA / leaf 链 → openssl verify 通过。
func TestCLIVerifyNonASCIIChain(t *testing.T) {
	caPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	caSubject := NewName().Add("CN", "铜锁测试根").Add("O", "示例公司")
	caCert := NewCertificate()
	t.Cleanup(func() { _ = caCert.Close() })
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
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetPublicKey(caPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	leafCert, err := CreateCertificate(NewName().Add("CN", "海峰"), caSubject, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer leafCert.Close()

	caPEM, err := caCert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := leafCert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	leafFile := dir + "/leaf.pem"
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafFile, leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := testutil.MustRunOpenSSL(t, "verify", "-CAfile", caFile, leafFile)
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("openssl verify 失败：%s", out)
	}
}

// TestCLICSRNonASCII 本库 CJK subject + CJK challengePassword 的 CSR → openssl 验签与展示。
func TestCLICSRNonASCII(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(NewName().Add("CN", "海峰").Add("O", "示例公司")); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := req.SetChallengePassword("口令-abc"); err != nil {
		t.Fatal(err)
	}
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}
	csrPEM, err := req.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	csrFile := t.TempDir() + "/utf8.csr"
	if err := os.WriteFile(csrFile, csrPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// 签名自校验
	verify := string(testutil.MustRunOpenSSL(t, "req", "-in", csrFile, "-noout", "-verify"))
	if !strings.Contains(verify, "verify OK") {
		t.Fatalf("openssl req -verify 未通过：%s", verify)
	}

	// subject 展示
	subj := squashSpaces(string(testutil.MustRunOpenSSL(t, "req", "-in", csrFile,
		"-noout", "-subject", "-nameopt", "utf8")))
	if !strings.Contains(subj, "CN=海峰") {
		t.Fatalf("CSR subject 缺 CN=海峰：%s", subj)
	}

	// challengePassword 文本保真
	text := string(testutil.MustRunOpenSSL(t, "req", "-in", csrFile, "-noout", "-text"))
	if !strings.Contains(text, "口令-abc") {
		t.Fatalf("CSR challengePassword 未保真：\n%s", text)
	}
}

// TestCLICRLNonASCIIIssuer 本库签发的 CRL（CJK 颁发者）→ openssl crl 读回保真。
func TestCLICRLNonASCIIIssuer(t *testing.T) {
	caPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caSubject := NewName().Add("CN", "铜锁测试根").Add("O", "示例公司")

	caCert := NewCertificate()
	t.Cleanup(func() { _ = caCert.Close() })
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
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
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

	leafPriv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := CreateCertificate(NewName().Add("CN", "海峰"), caSubject, 3,
		now.Add(-time.Hour), now.Add(time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()

	b, err := NewCRLBuilder(caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.SetNumber(1); err != nil {
		t.Fatal(err)
	}
	if err := b.SetThisUpdate(now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(leaf, now.Add(-30*time.Minute), ReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	crl, err := b.Sign(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer crl.Close()

	crlPEM, err := crl.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	crlFile := t.TempDir() + "/utf8.crl"
	if err := os.WriteFile(crlFile, crlPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	issuer := squashSpaces(string(testutil.MustRunOpenSSL(t, "crl", "-in", crlFile,
		"-noout", "-issuer", "-nameopt", "utf8")))
	if !strings.Contains(issuer, "CN=铜锁测试根") {
		t.Fatalf("CRL issuer 缺 CN=铜锁测试根：%s", issuer)
	}
}
