//go:build tongsuocli

package asym

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestECCLIInterop 验证 asym ECDSA 与铜锁 openssl CLI 的密钥 / 签名双向互通。
// 流程：本库生成密钥并导出 PEM → CLI `pkeyutl -sign` 签名 → CLI 产出的签名
// 由本库验签通过；本库签名 → CLI `pkeyutl -verify` 通过。
func TestECCLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	priv, err := GenerateEC(CurveP256)
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
	privPath := filepath.Join(dir, "ec-priv.pem")
	pubPath := filepath.Join(dir, "ec-pub.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	data := []byte("tongsuo-go ecdsa CLI interop")
	dataPath := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) CLI 用本库导出的私钥签名 → 本库验签通过
	sigCLIPath := filepath.Join(dir, "sig-cli.bin")
	if _, err := testutil.RunOpenSSL([]string{
		"pkeyutl", "-sign", "-inkey", privPath, "-rawin",
		"-digest", "sha256", "-in", dataPath, "-out", sigCLIPath,
	}, nil); err != nil {
		t.Fatalf("CLI sign: %v", err)
	}
	sigCLI, err := os.ReadFile(sigCLIPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyECDSA(priv.Public(), data, sigCLI); err != nil {
		t.Fatalf("本库对 CLI 签名验签失败：%v", err)
	}

	// 2) 本库签名 → CLI 用本库导出的公钥验签通过
	sigGo, err := SignECDSA(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	sigGoPath := filepath.Join(dir, "sig-go.bin")
	if err := os.WriteFile(sigGoPath, sigGo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.RunOpenSSL([]string{
		"pkeyutl", "-verify", "-pubin", "-inkey", pubPath, "-rawin",
		"-digest", "sha256", "-in", dataPath, "-sigfile", sigGoPath,
	}, nil); err != nil {
		t.Fatalf("CLI verify: %v", err)
	}

	// 3) 本库导出的私钥可被 CLI 读回（pkey -noout 校验结构合法）
	if _, err := testutil.RunOpenSSL([]string{"pkey", "-in", privPath, "-noout"}, nil); err != nil {
		t.Fatalf("CLI pkey -noout: %v", err)
	}

	// 4) 篡改数据后本库验签必须失败（CLI 签名不应通过）
	if err := VerifyECDSA(priv.Public(), append(data, '!'), sigCLI); err == nil {
		t.Fatal("篡改数据后验签不应通过")
	}
}
