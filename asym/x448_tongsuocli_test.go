//go:build tongsuocli

package asym

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestX448CLIInterop 验证 asym 的 X448 密钥与铜锁 openssl CLI 互通。
// 与 X25519 同构：本 commit 只涉及生成与编解码，故对拍内容为：
//  1. 本库导出的 PEM 可被 CLI 读回，且 CLI 导出的公钥与本库 RawPublicKey 一致；
//  2. CLI 生成的 X448 密钥可被本库加载并识别为 X448。
//
// 协商运算（pkeyutl -derive）的对拍随 ecdh 包落地。
func TestX448CLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	dir := t.TempDir()

	// 1) 本库 → CLI
	priv, err := GenerateX448()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "x448-priv.pem")
	pubPath := filepath.Join(dir, "x448-pub.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
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
		"genpkey", "-algorithm", "X448", "-out", cliPrivPath,
	}, nil); err != nil {
		t.Fatalf("CLI genpkey -algorithm X448: %v", err)
	}
	cliPrivPEM, err := os.ReadFile(cliPrivPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKeyPEM(cliPrivPEM)
	if err != nil {
		t.Fatalf("加载 CLI 生成的私钥失败：%v", err)
	}
	if loaded.Algorithm() != AlgX448 {
		t.Errorf("alg = %s, want X448", loaded.Algorithm())
	}
	seed, err := RawPrivateKey(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 56 {
		t.Errorf("seed 长度 = %d，应为 56", len(seed))
	}
	// 由 CLI 密钥的种子重建后应派生出同一公钥
	rebuilt, err := GenerateKeyFromSeed(AlgX448, seed)
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
