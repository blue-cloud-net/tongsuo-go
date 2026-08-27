//go:build tongsuocli

package sm2

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// runOpenSSLFile 运行铜锁 openssl 命令（基于文件参数），失败即终止测试。
func runOpenSSLFile(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// TestCLISignVerify 与铜锁 openssl 双向交叉验证签名/验签。
func TestCLISignVerify(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := priv.MarshalPEM()
	pubPEM, _ := priv.Public().MarshalPEM()

	dir := t.TempDir()
	privFile := dir + "/priv.pem"
	pubFile := dir + "/pub.pem"
	dataFile := dir + "/data.txt"
	sigFile := dir + "/sig.bin"
	if err := os.WriteFile(privFile, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("tongsuo-go sm2 cli sign verify")
	if err := os.WriteFile(dataFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) 本库签名 → openssl 验签
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigFile, sig, 0o600); err != nil {
		t.Fatal(err)
	}
	out := runOpenSSLFile(t, "dgst", "-sm3", "-verify", pubFile, "-signature", sigFile, dataFile)
	if !bytes.Contains(out, []byte("Verified OK")) {
		t.Fatalf("openssl verify our signature failed: %s", out)
	}

	// 2) openssl 签名 → 本库验签
	cliSigFile := dir + "/cli_sig.bin"
	runOpenSSLFile(t, "dgst", "-sm3", "-sign", privFile, "-out", cliSigFile, dataFile)
	cliSig, err := os.ReadFile(cliSigFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(priv.Public(), data, cliSig); err != nil {
		t.Fatalf("our verify of openssl signature failed: %v", err)
	}
}

// TestCLIEncryptDecrypt 与铜锁 openssl 双向交叉验证加解密。
func TestCLIEncryptDecrypt(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := priv.MarshalPEM()
	pubPEM, _ := priv.Public().MarshalPEM()

	dir := t.TempDir()
	privFile := dir + "/priv.pem"
	pubFile := dir + "/pub.pem"
	dataFile := dir + "/data.txt"
	ctFile := dir + "/ct.bin"
	ptFile := dir + "/pt.bin"
	if err := os.WriteFile(privFile, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("tongsuo-go sm2 cli encrypt decrypt")
	if err := os.WriteFile(dataFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) 本库加密 → openssl 解密
	ct, err := Encrypt(priv.Public(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ctFile, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenSSLFile(t, "pkeyutl", "-decrypt", "-inkey", privFile, "-in", ctFile, "-out", ptFile)
	pt, err := os.ReadFile(ptFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatalf("openssl decrypt of our ciphertext mismatch")
	}

	// 2) openssl 加密 → 本库解密
	cliCtFile := dir + "/cli_ct.bin"
	runOpenSSLFile(t, "pkeyutl", "-encrypt", "-pubin", "-inkey", pubFile, "-in", dataFile, "-out", cliCtFile)
	cliCt, err := os.ReadFile(cliCtFile)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := Decrypt(priv, cliCt)
	if err != nil {
		t.Fatalf("our decrypt of openssl ciphertext failed: %v", err)
	}
	if !bytes.Equal(pt2, data) {
		t.Fatalf("our decrypt of openssl ciphertext mismatch")
	}
}
