//go:build tongsuocli

// 本文件是 x509 自签证书的铜锁 CLI 双向对拍测试。
// Build tag: tongsuocli（默认关闭）；运行方式见 docs/testing-guide.md §2。
//
// These are the bidirectional Tongsuo CLI interop tests for x509 self-signed
// certificates. Build tag: tongsuocli, off by default.
package x509_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// genCLISelfSigned 用 `openssl req -x509` 生成一张 SM2 自签证书，返回证书路径与
// 目录。环境无铜锁或不支持 SM2 时跳过并说明原因。
//
// genCLISelfSigned generates an SM2 self-signed certificate with
// `openssl req -x509` and returns the certificate path and its directory.
func genCLISelfSigned(t *testing.T) (certPath, dir string) {
	t.Helper()
	bin := testutil.SkipIfNoOpenSSL(t)
	dir = t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath = filepath.Join(dir, "cert.pem")
	args := []string{
		"req", "-x509", "-newkey", "sm2", "-nodes",
		"-keyout", keyPath, "-out", certPath,
		"-days", "1", "-batch", "-subj", "/CN=cli-self-signed",
	}
	if out, err := testutil.RunOpenSSL(args, nil); err != nil {
		t.Skipf("%s req -x509 unsupported: %v\n%s", bin, err, out)
	}
	return certPath, dir
}

// TestCLIReqX509Loads 验证 `openssl req -x509` 生成的证书可被本库加载，且以自身为
// 信任锚可通过 ChainVerify（roadmap §3.10 要求的对拍方向：CLI 产物 → 本库验证）。
//
// TestCLIReqX509Loads verifies that a certificate produced by
// `openssl req -x509` loads with this library and passes ChainVerify with itself
// as the trust anchor — the CLI-to-library direction required by roadmap §3.10.
func TestCLIReqX509Loads(t *testing.T) {
	certPath, _ := genCLISelfSigned(t)
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.LoadCertificatePEM(pemBytes)
	if err != nil {
		t.Fatalf("LoadCertificatePEM: %v", err)
	}
	defer func() {
		if err := cert.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if got := cert.Subject(); got != "cli-self-signed" {
		t.Errorf("Subject CN = %q, want cli-self-signed", got)
	}
	if cert.SubjectText() != cert.IssuerText() {
		t.Errorf("自签证书 issuer %q 应等于 subject %q", cert.IssuerText(), cert.SubjectText())
	}
	if got := cert.CertificateType(); got == "" {
		t.Error("CertificateType 为空")
	}

	store := x509.NewStore()
	if err := store.AddCert(cert); err != nil {
		t.Fatalf("AddCert: %v", err)
	}
	chain, err := x509.ChainVerify(cert, store, nil)
	if err != nil {
		t.Fatalf("ChainVerify: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("ChainVerify 返回空链")
	}
}

// TestCLIVerifiesLibrarySelfSigned 验证本库 CreateSelfSigned 生成的证书能被
// `openssl verify` 接受（对拍的另一方向：本库产物 → CLI 验证）。
//
// TestCLIVerifiesLibrarySelfSigned verifies that a certificate produced by
// CreateSelfSigned is accepted by `openssl verify` — the library-to-CLI
// direction.
func TestCLIVerifiesLibrarySelfSigned(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)

	for _, alg := range []string{"SM2", "EC", "Ed25519"} {
		t.Run(alg, func(t *testing.T) {
			var (
				priv asym.PrivateKey
				err  error
			)
			switch alg {
			case "SM2":
				priv, err = asym.GenerateSM2()
			case "EC":
				priv, err = asym.GenerateEC(asym.CurveP256)
			case "Ed25519":
				priv, err = asym.GenerateEd25519()
			}
			if err != nil {
				t.Fatalf("generate %s: %v", alg, err)
			}
			defer func() { _ = asym.Close(priv) }()

			subject := x509.NewName().Add("CN", "lib-"+strings.ToLower(alg))
			now := time.Now()
			cert, err := x509.CreateSelfSigned(subject, 7,
				now.Add(-time.Minute), now.Add(24*time.Hour), priv.Public(), priv)
			if err != nil {
				t.Fatalf("CreateSelfSigned: %v", err)
			}
			defer func() { _ = cert.Close() }()

			pemBytes, err := cert.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			certPath := filepath.Join(dir, "cert.pem")
			if err := os.WriteFile(certPath, pemBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			// 以自身为 -CAfile 验证自身
			out, err := testutil.RunOpenSSL([]string{
				"verify", "-CAfile", certPath, certPath,
			}, nil)
			if err != nil {
				t.Fatalf("%s verify 失败：%v\n%s", bin, err, out)
			}
			if !strings.Contains(string(out), ": OK") {
				t.Fatalf("verify 输出未见 OK：\n%s", out)
			}

			// CLI 侧也应能读出正确的公钥算法
			out, err = testutil.RunOpenSSL([]string{
				"x509", "-in", certPath, "-noout", "-text",
			}, nil)
			if err != nil {
				t.Fatalf("%s x509 -text 失败：%v\n%s", bin, err, out)
			}
			text := string(out)
			if !strings.Contains(text, "Signature Algorithm") {
				t.Errorf("x509 -text 输出缺少签名算法信息：\n%s", text)
			}
			if !strings.Contains(text, "X509v3 Subject Key Identifier") {
				t.Errorf("x509 -text 输出缺少 SKID：\n%s", text)
			}
			if !strings.Contains(text, "X509v3 Authority Key Identifier") {
				t.Errorf("x509 -text 输出缺少 AKID：\n%s", text)
			}
		})
	}
}
