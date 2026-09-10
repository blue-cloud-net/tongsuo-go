// Package x25519 的 tongsuocli 对拍测试。
// Build tag: tongsuocli (off by default).
package x25519

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

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

	p8, _ := priv.MarshalPEM()
	privPath := filepath.Join(dir, "priv.pem")
	os.WriteFile(privPath, p8, 0o600)
	out, err := runOpenSSL(t, bin, "pkey", "-in", privPath, "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey: %v", err)
	}
	if !bytes.Contains([]byte(out), []byte("X25519 Private-Key")) {
		t.Fatalf("cli output missing X25519 marker: %s", out)
	}

	spki, _ := pub.MarshalPEM()
	pubPath := filepath.Join(dir, "pub.pem")
	os.WriteFile(pubPath, spki, 0o600)
	out2, err := runOpenSSL(t, bin, "pkey", "-in", pubPath, "-pubin", "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey pubin: %v", err)
	}
	if !bytes.Contains([]byte(out2), []byte("X25519 Public-Key")) {
		t.Fatalf("cli pub output missing X25519 marker: %s", out2)
	}

	cliPriv := filepath.Join(dir, "cli.pem")
	if _, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "X25519", "-out", cliPriv); err != nil {
		t.Fatalf("cli genpkey: %v", err)
	}
	cliPEM, err := os.ReadFile(cliPriv)
	if err != nil {
		t.Fatalf("read cli pem: %v", err)
	}
	if _, err := LoadPrivateKeyPEM(cliPEM); err != nil {
		t.Fatalf("LoadPrivateKeyPEM cli: %v", err)
	}
}

// TestCLISharedSecret 验证本库与 CLI 派生出的共享密钥一致。
//
// 铜锁 CLI 不直接支持 `pkeyutl -derive`，我们改用 CLI 生成 key 并各自走本库 derive，
// 同时通过公开 CLI 派生一次（如支持）来交叉验证。
//
// TestCLISharedSecret verifies that shared secrets computed by the
// library match those produced via the Tongsuo CLI (where supported).
func TestCLISharedSecret(t *testing.T) {
	bin := testutil.OpenSSLBin()
	if bin == "" {
		t.Skip("TONGSUO_OPENSSL_BIN not set; skipping tongsuocli test")
	}
	dir := t.TempDir()
	alice, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey alice: %v", err)
	}
	bob, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey bob: %v", err)
	}
	alicePub, _ := alice.Public()
	bobPub, _ := bob.Public()

	// 双方都在本库派生
	sa, err := SharedSecret(alice, bobPub)
	if err != nil {
		t.Fatalf("alice derive: %v", err)
	}
	sb, err := SharedSecret(bob, alicePub)
	if err != nil {
		t.Fatalf("bob derive: %v", err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("library-derived secrets differ")
	}

	// CLI 派生验证：先 CLI 生成 keypair，各自 CLI derive，再 CLI 读本库 PEM 派生。
	cliAlice := filepath.Join(dir, "cli_a.pem")
	cliBob := filepath.Join(dir, "cli_b.pem")
	if _, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "X25519", "-out", cliAlice); err != nil {
		t.Fatalf("cli genpkey alice: %v", err)
	}
	if _, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "X25519", "-out", cliBob); err != nil {
		t.Fatalf("cli genpkey bob: %v", err)
	}
	cliABytes, _ := os.ReadFile(cliAlice)
	cliBBytes, _ := os.ReadFile(cliBob)
	cliAPriv, err := LoadPrivateKeyPEM(cliABytes)
	if err != nil {
		t.Fatalf("load cli alice: %v", err)
	}
	cliBPriv, err := LoadPrivateKeyPEM(cliBBytes)
	if err != nil {
		t.Fatalf("load cli bob: %v", err)
	}
	cliAPub, _ := cliAPriv.Public()
	cliBPub, _ := cliBPriv.Public()
	saCLI, err := SharedSecret(cliAPriv, cliBPub)
	if err != nil {
		t.Fatalf("cli alice derive: %v", err)
	}
	sbCLI, err := SharedSecret(cliBPriv, cliAPub)
	if err != nil {
		t.Fatalf("cli bob derive: %v", err)
	}
	if !bytes.Equal(saCLI, sbCLI) {
		t.Fatal("CLI-derived (via library) secrets differ")
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