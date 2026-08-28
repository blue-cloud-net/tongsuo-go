//go:build tongsuocli

package ocsp

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/x509"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

func runOpenSSL(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// setupOCSPEnv 搭建 openssl CA + 叶证书环境，返回目录。
func setupOCSPEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(dir+"/demoCA/newcerts", 0o700))
	must(os.WriteFile(dir+"/demoCA/index.txt", nil, 0o600))
	must(os.WriteFile(dir+"/demoCA/serial", []byte("1000\n"), 0o600))
	cnf := `[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ./demoCA
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
private_key = ./ca.key
certificate = ./ca.pem
default_md = sha256
default_days = 365
policy = policy_any
[ policy_any ]
commonName = supplied
`
	must(os.WriteFile(dir+"/openssl.cnf", []byte(cnf), 0o600))
	runOpenSSL(t, dir, "req", "-new", "-x509", "-nodes", "-keyout", "ca.key",
		"-out", "ca.pem", "-subj", "/CN=OCSP Test CA", "-days", "3650")
	runOpenSSL(t, dir, "req", "-new", "-nodes", "-keyout", "leaf.key",
		"-out", "leaf.csr", "-subj", "/CN=leaf.ocsp.dev")
	runOpenSSL(t, dir, "ca", "-batch", "-config", "openssl.cnf", "-in", "leaf.csr", "-out", "leaf.pem")
	return dir
}

// respond 用 openssl ocsp 离线 responder 处理请求并产出响应。
func respond(t *testing.T, dir, reqName, respName string) []byte {
	t.Helper()
	respFile := filepath.Join(dir, respName)
	runOpenSSL(t, dir, "ocsp", "-index", "demoCA/index.txt",
		"-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem",
		"-issuer", "ca.pem", "-cert", "leaf.pem",
		"-reqin", reqName, "-respout", respName, "-noverify")
	resp, err := os.ReadFile(respFile)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestCLIOCSP 本库 CreateRequest → openssl responder → 本库 ParseResponse/Verify。
func TestCLIOCSP(t *testing.T) {
	dir := setupOCSPEnv(t)
	caPEM, _ := os.ReadFile(dir + "/ca.pem")
	leafPEM, _ := os.ReadFile(dir + "/leaf.pem")
	caCert, err := x509.LoadCertificatePEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.LoadCertificatePEM(leafPEM)
	if err != nil {
		t.Fatal(err)
	}

	reqDER, err := CreateRequest(leaf, caCert, "sha1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "req.der"), reqDER, 0o600); err != nil {
		t.Fatal(err)
	}
	respDER := respond(t, dir, "req.der", "resp.der")

	r, err := ParseResponse(respDER, leaf, caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Status != 0 {
		t.Fatalf("response status = %d (%s), want successful", r.Status, r.StatusText)
	}
	if r.CertStatus != Good {
		t.Fatalf("cert status = %d (%s), want good", r.CertStatus, r.CertStatusText)
	}
	if r.ThisUpdate.IsZero() {
		t.Fatal("empty ThisUpdate")
	}

	// 验证响应签名（信任锚为 CA）
	roots := x509.NewStore()
	if err := roots.AddCert(caCert); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(roots, nil); err != nil {
		t.Fatalf("OCSP verify failed: %v", err)
	}
}

// TestCLIOCSPRevoked 验证已吊销证书状态为 revoked（含原因与吊销时间）。
func TestCLIOCSPRevoked(t *testing.T) {
	dir := setupOCSPEnv(t)
	caPEM, _ := os.ReadFile(dir + "/ca.pem")
	leafPEM, _ := os.ReadFile(dir + "/leaf.pem")
	caCert, _ := x509.LoadCertificatePEM(caPEM)
	leaf, _ := x509.LoadCertificatePEM(leafPEM)

	// 吊销叶证书
	runOpenSSL(t, dir, "ca", "-config", "openssl.cnf", "-revoke", "leaf.pem", "-crl_reason", "keyCompromise")

	reqDER, _ := CreateRequest(leaf, caCert, "sha1")
	if err := os.WriteFile(filepath.Join(dir, "req2.der"), reqDER, 0o600); err != nil {
		t.Fatal(err)
	}
	respDER := respond(t, dir, "req2.der", "resp2.der")

	r, err := ParseResponse(respDER, leaf, caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.CertStatus != Revoked {
		t.Fatalf("cert status = %d (%s), want revoked", r.CertStatus, r.CertStatusText)
	}
	if r.RevocationReason < 0 {
		t.Fatalf("revocation reason = %d, want set", r.RevocationReason)
	}
	if r.RevocationTime.IsZero() {
		t.Fatal("revocation time should be set")
	}
}
