//go:build tongsuocli

package asym

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestX25519CLIInterop 验证 asym 的 X25519 密钥与铜锁 openssl CLI 互通。
// 本 commit 只涉及生成与编解码，故对拍内容为：
//  1. 本库导出的 PEM 可被 CLI 读回，且 CLI 导出的公钥与本库 RawPublicKey 一致；
//  2. CLI 生成的 X25519 密钥可被本库加载并识别为 X25519。
//
// 协商运算（pkeyutl -derive）的对拍随 ecdh 包落地。
func TestX25519CLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	dir := t.TempDir()

	// 1) 本库 → CLI
	priv, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "x25519-priv.pem")
	pubPath := filepath.Join(dir, "x25519-pub.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// CLI 导出公钥（DER 形式再转 PEM）
	if _, err := testutil.RunOpenSSL([]string{"pkey", "-in", privPath, "-pubout", "-out", pubPath}, nil); err != nil {
		t.Fatalf("CLI pkey -pubout: %v", err)
	}
	cliPubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	cliPub, err := LoadPublicKeyPEM(cliPubPEM)
	if err != nil {
		t.Fatalf("加载 CLI 导出的公钥失败：%v", err)
	}
	cliRaw, err := RawPublicKey(cliPub)
	if err != nil {
		t.Fatal(err)
	}
	goRaw, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cliRaw, goRaw) {
		t.Errorf("公钥不一致\n 本库 %x\n CLI  %x", goRaw, cliRaw)
	}

	// 2) CLI → 本库
	cliPrivPath := filepath.Join(dir, "cli-priv.pem")
	if _, err := testutil.RunOpenSSL([]string{
		"genpkey", "-algorithm", "X25519", "-out", cliPrivPath,
	}, nil); err != nil {
		t.Fatalf("CLI genpkey: %v", err)
	}
	cliPrivPEM, err := os.ReadFile(cliPrivPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKeyPEM(cliPrivPEM)
	if err != nil {
		t.Fatalf("加载 CLI 生成的私钥失败：%v", err)
	}
	if loaded.Algorithm() != AlgX25519 {
		t.Errorf("alg = %s, want X25519", loaded.Algorithm())
	}
	seed, err := RawPrivateKey(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 {
		t.Errorf("seed 长度 = %d，应为 32", len(seed))
	}
	// 由 CLI 密钥的种子重建后应派生出同一公钥
	rebuilt, err := GenerateKeyFromSeed(AlgX25519, seed)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltRaw, err := RawPublicKey(rebuilt.Public())
	if err != nil {
		t.Fatal(err)
	}
	loadedRaw, err := RawPublicKey(loaded.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuiltRaw, loadedRaw) {
		t.Error("由种子重建的公钥与 CLI 密钥自身公钥不一致")
	}
}
