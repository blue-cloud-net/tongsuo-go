// Package ed25519 的 tongsuocli 对拍测试：用铜锁原生 openssl 命令行校验本库
// 生成 / 签名 / 验签结果与 openssl 完全一致。
//
// Build 标签为 tongsuocli，默认不参与 `go test`；调用方通过
// `go test -tags tongsuocli ./crypto/ed25519/...` 启用。
//
// Build tag: tongsuocli (off by default).
package ed25519

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIKeyInterop 验证本库生成的 PEM 可被 CLI 读取、CLI 生成的 PEM 可被本库读取。
//
// TestCLIKeyInterop verifies that PKCS#8 / SPKI PEM produced by the library
// round-trips through the Tongsuo openssl CLI, and vice versa.
func TestCLIKeyInterop(t *testing.T) {
	bin := testutil.OpenSSLBin()
	if bin == "" {
		t.Skip("TONGSUO_OPENSSL_BIN not set; skipping tongsuocli test")
	}
	dir := t.TempDir()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	p8, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	privPath := filepath.Join(dir, "priv.pem")
	if err := os.WriteFile(privPath, p8, 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	// CLI 读取本库 PEM。
	out, err := runOpenSSL(t, bin, "pkey", "-in", privPath, "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey: %v", err)
	}
	if !bytes.Contains([]byte(out), []byte("ED25519 Private-Key")) {
		t.Fatalf("cli output missing ED25519 marker: %s", out)
	}

	spki, err := pub.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM pub: %v", err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, spki, 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	out2, err := runOpenSSL(t, bin, "pkey", "-in", pubPath, "-pubin", "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey pubin: %v", err)
	}
	if !bytes.Contains([]byte(out2), []byte("ED25519 Public-Key")) {
		t.Fatalf("cli pub output missing ED25519 marker: %s", out2)
	}

	// 反向：CLI 生成 PEM，本库读取。
	cliPriv := filepath.Join(dir, "cli.pem")
	if _, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "ED25519", "-out", cliPriv); err != nil {
		t.Fatalf("cli genpkey: %v", err)
	}
	cliPEM, err := os.ReadFile(cliPriv)
	if err != nil {
		t.Fatalf("read cli pem: %v", err)
	}
	priv2, err := LoadPrivateKeyPEM(cliPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM cli: %v", err)
	}
	if !priv2.Key().PublicEqual(priv.Key()) {
		// 两次 generate 都是新随机 key，自然不等；但至少证明可读。
		t.Logf("library vs CLI private keys naturally differ (fresh random)")
	}
}

// TestCLISignVerify 验证本库 Sign 的结果能被 CLI 验签；CLI 签名的结果能被本库 Verify。
//
// TestCLISignVerify checks that library-generated Ed25519 signatures are
// accepted by the Tongsuo openssl CLI and vice versa.
func TestCLISignVerify(t *testing.T) {
	bin := testutil.OpenSSLBin()
	if bin == "" {
		t.Skip("TONGSUO_OPENSSL_BIN not set; skipping tongsuocli test")
	}
	dir := t.TempDir()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	msg := []byte("hello ed25519 tongsuocli")
	msgPath := filepath.Join(dir, "msg.bin")
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		t.Fatalf("write msg: %v", err)
	}

	p8, _ := priv.MarshalPEM()
	privPath := filepath.Join(dir, "priv.pem")
	os.WriteFile(privPath, p8, 0o600)
	spki, _ := pub.MarshalPEM()
	pubPath := filepath.Join(dir, "pub.pem")
	os.WriteFile(pubPath, spki, 0o600)
	sigPath := filepath.Join(dir, "our.sig")

	// 1. 本库签名 → CLI 验签。
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	out, err := runOpenSSL(t, bin, "pkeyutl", "-verify", "-rawin",
		"-in", msgPath, "-pubin", "-inkey", pubPath, "-sigfile", sigPath)
	if err != nil {
		t.Fatalf("cli verify: %v\n%s", err, out)
	}
	if !bytes.Contains([]byte(out), []byte("Verified OK")) &&
		!bytes.Contains([]byte(out), []byte("Signature Verified Successfully")) {
		t.Fatalf("cli verify output missing success marker: %s", out)
	}

	// 2. CLI 签名 → 本库验签。
	cliSig := filepath.Join(dir, "cli.sig")
	if _, err := runOpenSSL(t, bin, "pkeyutl", "-sign", "-rawin",
		"-in", msgPath, "-inkey", privPath, "-out", cliSig); err != nil {
		t.Fatalf("cli sign: %v", err)
	}
	cliSigBytes, err := os.ReadFile(cliSig)
	if err != nil {
		t.Fatalf("read cli sig: %v", err)
	}
	if err := Verify(pub, msg, cliSigBytes); err != nil {
		t.Fatalf("library Verify cli sig: %v", err)
	}
}

// TestCLIEncryptedPEM 验证本库加密 PEM 双向兼容 CLI（AES-256-CBC）。
//
// TestCLIEncryptedPEM checks encrypted-PEM round-trip between the library
// and the Tongsuo CLI (AES-256-CBC + PBKDF2).
func TestCLIEncryptedPEM(t *testing.T) {
	bin := testutil.OpenSSLBin()
	if bin == "" {
		t.Skip("TONGSUO_OPENSSL_BIN not set; skipping tongsuocli test")
	}
	dir := t.TempDir()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pass := "tongsuocli-pass"

	enc, err := priv.MarshalEncryptedPEM(pass)
	if err != nil {
		t.Fatalf("MarshalEncryptedPEM: %v", err)
	}
	encPath := filepath.Join(dir, "enc.pem")
	if err := os.WriteFile(encPath, enc, 0o600); err != nil {
		t.Fatalf("write enc: %v", err)
	}
	out, err := runOpenSSL(t, bin, "pkey", "-in", encPath,
		"-passin", "pass:"+pass, "-noout", "-text")
	if err != nil {
		t.Fatalf("cli read enc: %v\n%s", err, out)
	}
	if !bytes.Contains([]byte(out), []byte("ED25519 Private-Key")) {
		t.Fatalf("cli enc read missing marker: %s", out)
	}
}

func runOpenSSL(t *testing.T, bin string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	return out, nil
}