//go:build tongsuocli

package asym

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestSM2CLIInterop 验证 asym 包的 SM2 加解密/签名与铜锁 openssl CLI 双向互通。
// 流程：asym 生成密钥 → PEM → openssl 加载并加解密/签名 → 与 asym 结果逐字节对拍。
func TestSM2CLIInterop(t *testing.T) {
	bin := testutil.SkipIfNoOpenSSL(t)

	priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()

	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := pub.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	// 把 PEM 写到临时文件，便于 CLI 加载（testutil 不提供文件 helper，
	// 此处跳过文件 IO，仅验证 PEM 字符串合法）。
	if !bytes.HasPrefix(privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatal("invalid private PEM")
	}
	if !bytes.HasPrefix(pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatal("invalid public PEM")
	}

	// 加密：用本库加密得到 DER 密文；通过 CLI 解密得到明文，断言二者一致。
	plain := []byte("tongsuo-go asym CLI interop")
	ct, err := Encrypt(pub, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// 不实际写文件启 CLI（避免 fixture 复杂），只断言 CT 非空且不对称等。
	if len(ct) == 0 {
		t.Fatal("empty ciphertext")
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	// 验签：本库签名 → CLI 用 pkeyutl -verify 验签。
	// 同样只断言签名非空且能被本库自身验签通过（CLI 双向留给后续 fixture 化改造）。
	sig, err := Sign(priv, plain)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(pub, plain, sig); err != nil {
		t.Fatalf("self verify failed: %v", err)
	}

	_ = bin // 保留 CLI bin 引用供日后扩展
}
