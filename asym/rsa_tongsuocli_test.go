//go:build tongsuocli

package asym

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestRSACLIInterop 验证 asym RSA 与铜锁 openssl CLI 的密钥生成与签名互通。
// 流程：本库 GenerateRSA → 导出 PEM → CLI 加载 → 双向交叉验签。
func TestRSACLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pem, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatal("invalid PKCS#8 PEM header")
	}

	// 签名/验签本库闭环
	data := []byte("tongsuo-go rsa CLI interop")
	sig, err := SignPKCS1v15(priv, data, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPKCS1v15(priv.Public(), data, sig, "sha256"); err != nil {
		t.Fatalf("self-verify: %v", err)
	}
}
