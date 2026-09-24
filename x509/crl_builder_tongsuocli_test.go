//go:build tongsuocli

package x509_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// runOpenSSLCmd 在 dir 下运行铜锁 openssl 并返回合并输出（stdout + stderr）。
//
// runOpenSSLCmd runs the Tongsuo openssl CLI inside dir and returns the
// combined output (stdout + stderr).
func runOpenSSLCmd(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// TestCLICRLBuilderInterop 验证本库 CRLBuilder 产出的 CRL 能被铜锁 openssl CLI
// 独立读取与验签：`crl -text` 读出吊销序列号与原因、CRL Number；`crl -verify`
// 用 CA 证书验证签名通过；PEM 与 DER 两种编码均可解析。
//
// 反方向（本库解析 openssl `ca -gencrl` 产物）已由 TestCLICrlParse 覆盖，
// 两者合起来构成双向对拍。
//
// TestCLICRLBuilderInterop verifies that a CRL produced by this library's
// CRLBuilder is independently readable and verifiable by the Tongsuo openssl
// CLI: `crl -text` shows the revoked serial numbers, reasons and CRL Number;
// `crl -verify` succeeds against the CA certificate; and both PEM and DER
// encodings parse. The opposite direction (this library parsing an
// `openssl ca -gencrl` output) is covered by TestCLICrlParse, so together they
// form a bidirectional interop check.
func TestCLICRLBuilderInterop(t *testing.T) {
	if !testutil.OpenSSLAvailable() {
		t.Skip("Tongsuo openssl CLI not available")
	}

	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	ca := newCA(t, "CRL CLI Interop CA", func() (asym.PrivateKey, error) {
		return asym.GenerateSM2()
	}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	leaf1 := newLeaf(t, "cli-revoked-1.example", 4242, ca,
		now.Add(-time.Hour), now.Add(24*time.Hour))
	defer func() { _ = leaf1.Close() }()
	leaf2 := newLeaf(t, "cli-revoked-2.example", 4343, ca,
		now.Add(-time.Hour), now.Add(24*time.Hour))
	defer func() { _ = leaf2.Close() }()

	b, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.SetNumber(99); err != nil {
		t.Fatalf("SetNumber: %v", err)
	}
	if err := b.SetThisUpdate(now.Add(-time.Minute)); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}
	if err := b.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatalf("SetNextUpdate: %v", err)
	}
	if err := b.Revoke(leaf1, now, x509.ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke(leaf1): %v", err)
	}
	if err := b.Revoke(leaf2, now, x509.ReasonCertificateHold); err != nil {
		t.Fatalf("Revoke(leaf2): %v", err)
	}
	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer func() { _ = crl.Close() }()

	crlPEM, err := crl.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	crlDER, err := crl.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	caPEM, err := ca.cert.MarshalPEM()
	if err != nil {
		t.Fatalf("CA MarshalPEM: %v", err)
	}
	for name, data := range map[string][]byte{
		"ours.pem": crlPEM,
		"ours.der": crlDER,
		"ca.pem":   caPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 1) openssl 读取文本形式：吊销序列号（十六进制）、原因长名、CRL Number 与 AKID。
	//    注意 openssl 的 `crl -text` 用十六进制打印序列号（无 0x 前缀），原因码打印
	//    「长名」（带空格），与 `RevokedEntry.Reason` 使用的短名不同。
	text := string(runOpenSSLCmd(t, dir, "crl", "-in", "ours.pem", "-noout", "-text"))
	t.Logf("openssl crl -text:\n%s", text)
	for _, want := range []string{
		"Serial Number: 1092", // 4242
		"Serial Number: 10F7", // 4343
		"Key Compromise",
		"Certificate Hold",
		"X509v3 CRL Number:",
		"X509v3 Authority Key Identifier:",
		"SM2-with-SM3",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl crl -text 缺少 %q", want)
		}
	}

	// 2) openssl 验证 CRL 签名（用 CA 证书作为信任锚）。
	verifyOut := string(runOpenSSLCmd(t, dir, "crl", "-in", "ours.pem", "-noout",
		"-verify", "-CAfile", "ca.pem"))
	if !strings.Contains(verifyOut, "verify OK") {
		t.Errorf("openssl crl -verify 未通过：%s", verifyOut)
	}

	// 3) openssl 读取 CRL Number（0x63 == 99）与签发者。
	if out := string(runOpenSSLCmd(t, dir, "crl", "-in", "ours.pem", "-noout",
		"-crlnumber")); !strings.Contains(out, "0x63") {
		t.Errorf("openssl crl -crlnumber = %q, want 含 0x63 (99)", out)
	}
	if out := string(runOpenSSLCmd(t, dir, "crl", "-in", "ours.pem", "-noout",
		"-issuer")); !strings.Contains(out, "CRL CLI Interop CA") {
		t.Errorf("openssl crl -issuer = %q, want 含 CA CN", out)
	}

	// 4) DER 编码同样可被 openssl 解析。
	if out := string(runOpenSSLCmd(t, dir, "crl", "-in", "ours.der", "-inform", "DER",
		"-noout", "-issuer")); !strings.Contains(out, "CRL CLI Interop CA") {
		t.Errorf("openssl 无法解析我们的 DER CRL：%q", out)
	}
}
