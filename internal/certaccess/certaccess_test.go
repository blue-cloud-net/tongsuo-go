package certaccess_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/certaccess"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// loadSelfSignedCert 用铜锁 CLI 生成一张 SM2 自签证书并加载为 *x509.Certificate。
// 环境无铜锁或 CLI 不支持 SM2 时跳过并说明原因。
//
// loadSelfSignedCert generates an SM2 self-signed certificate with the
// Tongsuo CLI and loads it as *x509.Certificate. When Tongsuo or CLI-side SM2
// support is unavailable the test skips with an explanation.
func loadSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	bin := testutil.SkipIfNoOpenSSL(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	args := []string{
		"req", "-x509", "-newkey", "sm2", "-nodes",
		"-keyout", keyPath, "-out", certPath,
		"-days", "1", "-subj", "/CN=certaccess-test", "-batch",
	}
	if out, err := testutil.RunOpenSSL(args, nil); err != nil {
		t.Skipf("%s cannot generate an SM2 self-signed certificate: %v\n%s", bin, err, out)
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	cert, err := x509.LoadCertificatePEM(pemBytes)
	if err != nil {
		t.Fatalf("LoadCertificatePEM: %v", err)
	}
	t.Cleanup(func() {
		if err := cert.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return cert
}

// TestCertificateAssertsX509Certificate 是桥接机制的核心回归断言：
// certaccess 的结构化断言**必须真的命中** x509.Certificate。
//
// 这条测试的存在理由见 docs/issues/2026-09-24/P1001：internal/keyaccess 曾经因为
// 形状方法名与 asym 实现不一致而恒假，且没有任何测试能发现「恒假」。桥接包必须
// 自带一条「断言确实成功」的用例，而不是只依赖消费方间接覆盖。
//
// TestCertificateAssertsX509Certificate is the core regression assertion of the
// bridge: the certaccess structural assertion MUST actually hit
// x509.Certificate. See docs/issues/2026-09-24/P1001 for why this test exists.
func TestCertificateAssertsX509Certificate(t *testing.T) {
	cert := loadSelfSignedCert(t)

	handle, ok := certaccess.Certificate(cert)
	if !ok || handle == nil {
		t.Fatal("certaccess.Certificate 未命中 x509.Certificate —— 断言形状与 x509 不一致（见 docs/issues/2026-09-24/P1001）")
	}
	if handle != cert.CoreCertificate() {
		t.Error("certaccess 返回的句柄与 x509.Certificate.CoreCertificate() 不是同一个")
	}
	// 句柄本身必须可用（而不是一个碰巧非 nil 的野指针）
	if got := handle.Subject(); got == "" {
		t.Error("取到的句柄不可用：Subject 为空")
	}
	if got := handle.Subject(); got != cert.Subject() {
		t.Errorf("句柄 Subject = %q, 与包装层 %q 不一致", got, cert.Subject())
	}
}

// TestCertificatePassthrough 验证 *core.Certificate 原样透传（不重新包装）。
//
// TestCertificatePassthrough verifies that a *core.Certificate is passed
// through unchanged.
func TestCertificatePassthrough(t *testing.T) {
	cert := loadSelfSignedCert(t)
	handle, ok := certaccess.Certificate(cert)
	if !ok {
		t.Skip("桥接断言不可用，见 TestCertificateAssertsX509Certificate")
	}

	again, ok := certaccess.Certificate(handle)
	if !ok {
		t.Fatal("certaccess.Certificate(*core.Certificate) 应成功")
	}
	if again != handle {
		t.Error("透传应返回同一个句柄")
	}
}

// TestCertificateRejectsUnknown 验证无法识别时返回 (nil, false) 而不是 panic。
//
// TestCertificateRejectsUnknown verifies that unrecognised values yield
// (nil, false) rather than panicking.
func TestCertificateRejectsUnknown(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"nil", nil},
		{"int", 42},
		{"string", "certificate"},
		{"empty struct", struct{}{}},
		{"pointer to unrelated", &core.PKey{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, ok := certaccess.Certificate(tc.v)
			if ok || h != nil {
				t.Errorf("Certificate(%T) = %v, %v; want nil, false", tc.v, h, ok)
			}
		})
	}
}
