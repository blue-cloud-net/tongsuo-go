//go:build tongsuocli

package asym

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestEd25519CLIInterop 验证 asym Ed25519 与铜锁 openssl CLI 双向互通。
// Ed25519 为「纯签名」：CLI 侧用 `pkeyutl -rawin`（无 -digest）直接对消息签名。
func TestEd25519CLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "ed-priv.pem")
	pubPath := filepath.Join(dir, "ed-pub.pem")
	dataPath := filepath.Join(dir, "data.bin")
	msg := []byte("tongsuo-go ed25519 CLI interop")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, msg, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) CLI 签名 → 本库验签
	sigCLIPath := filepath.Join(dir, "sig-cli.bin")
	if _, err := testutil.RunOpenSSL([]string{
		"pkeyutl", "-sign", "-inkey", privPath, "-rawin",
		"-in", dataPath, "-out", sigCLIPath,
	}, nil); err != nil {
		t.Fatalf("CLI sign: %v", err)
	}
	sigCLI, err := os.ReadFile(sigCLIPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(priv.Public(), msg, sigCLI); err != nil {
		t.Fatalf("本库对 CLI 签名验签失败：%v", err)
	}

	// 2) 本库签名 → CLI 验签
	sigGo, err := SignEd25519(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 为确定性签名：CLI 与本库应对同一消息产生相同签名
	if !bytes.Equal(sigGo, sigCLI) {
		t.Errorf("确定性签名不一致\n 本库 %x\n CLI  %x", sigGo, sigCLI)
	}
	sigGoPath := filepath.Join(dir, "sig-go.bin")
	if err := os.WriteFile(sigGoPath, sigGo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.RunOpenSSL([]string{
		"pkeyutl", "-verify", "-pubin", "-inkey", pubPath, "-rawin",
		"-in", dataPath, "-sigfile", sigGoPath,
	}, nil); err != nil {
		t.Fatalf("CLI verify: %v", err)
	}

	// 3) 本库导出的私钥结构可被 CLI 读取
	if _, err := testutil.RunOpenSSL([]string{"pkey", "-in", privPath, "-noout"}, nil); err != nil {
		t.Fatalf("CLI pkey -noout: %v", err)
	}

	// 4) 篡改消息后本库验签必须失败
	if err := VerifyEd25519(priv.Public(), append(msg, '!'), sigCLI); err == nil {
		t.Fatal("篡改消息后验签不应通过")
	}
}
