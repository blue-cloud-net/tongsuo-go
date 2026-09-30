//go:build tongsuocli

package asym

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestLoadPrivateKeyPEMLegacyFormats 验证算法无关加载器能读入传统私钥编码：
// EC 的 SEC1（"BEGIN EC PRIVATE KEY"）与 RSA 的 PKCS#1（"BEGIN RSA PRIVATE KEY"）。
// 两种编码由铜锁 openssl CLI 从本库导出的 PKCS#8 转换而来，转换后必须仍能与
// 原公钥配对并完成签名 / 验签。
func TestLoadPrivateKeyPEMLegacyFormats(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	dir := t.TempDir()

	t.Run("EC-SEC1", func(t *testing.T) {
		priv, err := GenerateEC(CurveP256)
		if err != nil {
			t.Fatal(err)
		}
		p8, err := priv.MarshalPrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		p8Path := filepath.Join(dir, "ec-p8.pem")
		sec1Path := filepath.Join(dir, "ec-sec1.pem")
		if err := os.WriteFile(p8Path, p8, 0o600); err != nil {
			t.Fatal(err)
		}
		// CLI 转换为传统 SEC1 编码
		if _, err := testutil.RunOpenSSL([]string{"ec", "-in", p8Path, "-out", sec1Path}, nil); err != nil {
			t.Fatalf("CLI ec -in -out: %v", err)
		}
		sec1, err := os.ReadFile(sec1Path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytesHasPrefix(sec1, "-----BEGIN EC PRIVATE KEY-----") {
			t.Fatalf("期望 SEC1 块头，实际：%q", firstLine(sec1))
		}

		loaded, err := LoadPrivateKeyPEM(sec1)
		if err != nil {
			t.Fatalf("LoadPrivateKeyPEM(SEC1): %v", err)
		}
		if loaded.Algorithm() != AlgEC {
			t.Errorf("alg = %s, want EC", loaded.Algorithm())
		}
		match, err := Match(loaded, priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if !match {
			t.Error("SEC1 加载的私钥应与原公钥配对")
		}
		// 签名 / 验签闭环
		msg := []byte("sec1 interop")
		sig, err := SignECDSA(loaded, msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyECDSA(priv.Public(), msg, sig); err != nil {
			t.Fatalf("用原公钥验签失败：%v", err)
		}
	})

	t.Run("RSA-PKCS1", func(t *testing.T) {
		priv, err := GenerateRSA(2048)
		if err != nil {
			t.Fatal(err)
		}
		p8, err := priv.MarshalPrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		p8Path := filepath.Join(dir, "rsa-p8.pem")
		p1Path := filepath.Join(dir, "rsa-p1.pem")
		if err := os.WriteFile(p8Path, p8, 0o600); err != nil {
			t.Fatal(err)
		}
		// CLI 转换为传统 PKCS#1 编码
		if _, err := testutil.RunOpenSSL([]string{"rsa", "-in", p8Path, "-traditional", "-out", p1Path}, nil); err != nil {
			t.Fatalf("CLI rsa -traditional: %v", err)
		}
		p1, err := os.ReadFile(p1Path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytesHasPrefix(p1, "-----BEGIN RSA PRIVATE KEY-----") {
			t.Fatalf("期望 PKCS#1 块头，实际：%q", firstLine(p1))
		}

		loaded, err := LoadPrivateKeyPEM(p1)
		if err != nil {
			t.Fatalf("LoadPrivateKeyPEM(PKCS#1): %v", err)
		}
		if loaded.Algorithm() != AlgRSA {
			t.Errorf("alg = %s, want RSA", loaded.Algorithm())
		}
		match, err := Match(loaded, priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if !match {
			t.Error("PKCS#1 加载的私钥应与原公钥配对")
		}
		msg := []byte("pkcs1 interop")
		sig, err := SignPKCS1v15(loaded, msg, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPKCS1v15(priv.Public(), msg, sig, "sha256"); err != nil {
			t.Fatalf("用原公钥验签失败：%v", err)
		}
	})
}

// bytesHasPrefix 判断 b 是否以 s 对应的字节序列开头。
func bytesHasPrefix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	return string(b[:len(s)]) == s
}

// firstLine 返回 b 的第一行（用于失败时的诊断输出）。
func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}
