//go:build tongsuocli

// Package x448 的 tongsuocli 对拍测试。
// Build tag: tongsuocli (off by default).
package x448

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIKeyInterop 验证本库产出的 PEM 能被铜锁 CLI 解析，且 CLI 生成的 X448 私钥
// 能被本库加载。
//
// 若运行时铜锁 provider 不支持 X448，或 CLI 不可用，本测试跳过而非失败。
//
// TestCLIKeyInterop verifies that PEM produced by this library is parsed by
// the Tongsuo CLI and that a CLI-generated X448 private key can be loaded by
// this library. The test skips (instead of failing) when the CLI is missing
// or the runtime provider does not support X448.
func TestCLIKeyInterop(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)
	dir := t.TempDir()

	priv, err := GenerateKey()
	if err != nil {
		t.Skipf("X448 unavailable in this Tongsuo build: %v", err)
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
		t.Fatalf("write priv.pem: %v", err)
	}
	out, err := runOpenSSL(t, bin, "pkey", "-in", privPath, "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("X448 Private-Key")) {
		t.Fatalf("cli output missing X448 marker: %s", out)
	}

	spki, err := pub.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM (public): %v", err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, spki, 0o600); err != nil {
		t.Fatalf("write pub.pem: %v", err)
	}
	out2, err := runOpenSSL(t, bin, "pkey", "-in", pubPath, "-pubin", "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey pubin: %v\n%s", err, out2)
	}
	if !bytes.Contains(out2, []byte("X448 Public-Key")) {
		t.Fatalf("cli pub output missing X448 marker: %s", out2)
	}

	cliPriv := filepath.Join(dir, "cli.pem")
	if out3, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "X448", "-out", cliPriv); err != nil {
		t.Fatalf("cli genpkey: %v\n%s", err, out3)
	}
	cliPEM, err := os.ReadFile(cliPriv)
	if err != nil {
		t.Fatalf("read cli pem: %v", err)
	}
	loaded, err := LoadPrivateKeyPEM(cliPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM cli: %v", err)
	}
	if got := loaded.Key().Algorithm(); got != "X448" {
		t.Fatalf("loaded CLI key algorithm = %q, want X448", got)
	}
}

// TestCLISharedSecret 验证「CLI 造钥 + 本库派生」路径下共享密钥双向一致。
//
// 铜锁 CLI 对 ECX 曲线不提供 `pkeyutl -derive`，因此这里沿用 crypto/x25519 的做法：
// 由 CLI `genpkey` 生成双方密钥，再用本库加载并派生，验证 56 字节共享密钥双向相等。
// 若后续铜锁版本支持 `pkeyutl -derive`，可在此基础上追加逐字节 CLI 对拍。
//
// TestCLISharedSecret verifies that shared secrets derived through the
// "CLI keygen + library derive" path agree in both directions. The Tongsuo
// CLI exposes no `pkeyutl -derive` for ECX curves, so this mirrors the
// crypto/x25519 approach: generate both keys with `genpkey`, load them with
// this library and derive locally.
func TestCLISharedSecret(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)
	dir := t.TempDir()

	alice, err := GenerateKey()
	if err != nil {
		t.Skipf("X448 unavailable in this Tongsuo build: %v", err)
	}
	bob, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey bob: %v", err)
	}
	alicePub, err := alice.Public()
	if err != nil {
		t.Fatalf("alice public: %v", err)
	}
	bobPub, err := bob.Public()
	if err != nil {
		t.Fatalf("bob public: %v", err)
	}

	sa, err := SharedSecret(alice, bobPub)
	if err != nil {
		t.Fatalf("alice derive: %v", err)
	}
	sb, err := SharedSecret(bob, alicePub)
	if err != nil {
		t.Fatalf("bob derive: %v", err)
	}
	if len(sa) != keySize {
		t.Fatalf("shared length = %d, want %d", len(sa), keySize)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatalf("library-derived secrets differ:\n  %x\n  %x", sa, sb)
	}

	cliAlice := filepath.Join(dir, "cli_a.pem")
	cliBob := filepath.Join(dir, "cli_b.pem")
	if out, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "X448", "-out", cliAlice); err != nil {
		t.Fatalf("cli genpkey alice: %v\n%s", err, out)
	}
	if out, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "X448", "-out", cliBob); err != nil {
		t.Fatalf("cli genpkey bob: %v\n%s", err, out)
	}
	cliABytes, err := os.ReadFile(cliAlice)
	if err != nil {
		t.Fatalf("read cli alice: %v", err)
	}
	cliBBytes, err := os.ReadFile(cliBob)
	if err != nil {
		t.Fatalf("read cli bob: %v", err)
	}
	cliAPriv, err := LoadPrivateKeyPEM(cliABytes)
	if err != nil {
		t.Fatalf("load cli alice: %v", err)
	}
	cliBPriv, err := LoadPrivateKeyPEM(cliBBytes)
	if err != nil {
		t.Fatalf("load cli bob: %v", err)
	}
	cliAPub, err := cliAPriv.Public()
	if err != nil {
		t.Fatalf("cli alice public: %v", err)
	}
	cliBPub, err := cliBPriv.Public()
	if err != nil {
		t.Fatalf("cli bob public: %v", err)
	}
	saCLI, err := SharedSecret(cliAPriv, cliBPub)
	if err != nil {
		t.Fatalf("cli alice derive: %v", err)
	}
	sbCLI, err := SharedSecret(cliBPriv, cliAPub)
	if err != nil {
		t.Fatalf("cli bob derive: %v", err)
	}
	if !bytes.Equal(saCLI, sbCLI) {
		t.Fatalf("CLI-generated keys derive different secrets:\n  %x\n  %x", saCLI, sbCLI)
	}
}

// runOpenSSL 执行铜锁 CLI 并返回合并后的输出。
//
// runOpenSSL runs the Tongsuo CLI and returns its combined output.
func runOpenSSL(t *testing.T, bin string, args ...string) ([]byte, error) {
	t.Helper()
	return exec.Command(bin, args...).CombinedOutput()
}
