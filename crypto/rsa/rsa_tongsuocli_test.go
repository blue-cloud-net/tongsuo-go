//go:build tongsuocli

package rsa

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

func runOpenSSL(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// TestCLIKeyInterop 本库密钥 ↔ openssl pkey / genpkey 互通。
func TestCLIKeyInterop(t *testing.T) {
	priv, _ := GenerateKey(2048)
	dir := t.TempDir()

	// 本库私钥（PKCS#8）→ openssl 可读取
	privPEM, _ := priv.MarshalPEM()
	privFile := filepath.Join(dir, "priv.pem")
	if err := os.WriteFile(privFile, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	out := runOpenSSL(t, "pkey", "-in", privFile, "-noout", "-text")
	if !bytes.Contains(out, []byte("Private-Key")) {
		t.Fatalf("openssl cannot read our PKCS#8 key: %s", out)
	}

	// openssl genpkey RSA → 本库读取
	genFile := filepath.Join(dir, "gen.pem")
	runOpenSSL(t, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", genFile)
	genPEM, _ := os.ReadFile(genFile)
	loaded, err := LoadPrivateKeyPEM(genPEM)
	if err != nil {
		t.Fatalf("load openssl-generated RSA key failed: %v", err)
	}
	if loaded.Params().N.BitLen() != 2048 {
		t.Fatalf("loaded key N bits = %d, want 2048", loaded.Params().N.BitLen())
	}
}

// TestCLISignVerify 本库 PKCS#1 v1.5 签名 ↔ openssl dgst -sha256 双向验签。
func TestCLISignVerify(t *testing.T) {
	priv, _ := GenerateKey(2048)
	dir := t.TempDir()
	data := []byte("interop signature data")
	dataFile := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(dataFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	privPEM, _ := priv.MarshalPEM()
	pubPEM, _ := priv.Public().MarshalPEM()
	privFile := filepath.Join(dir, "priv.pem")
	pubFile := filepath.Join(dir, "pub.pem")
	os.WriteFile(privFile, privPEM, 0o600)
	os.WriteFile(pubFile, pubPEM, 0o600)

	// 本库签名 → openssl dgst -sha256 -verify 通过
	ourSig, err := priv.SignPKCS1v15(data)
	if err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(dir, "our.sig")
	os.WriteFile(sigFile, ourSig, 0o600)
	out := runOpenSSL(t, "dgst", "-sha256", "-verify", pubFile, "-signature", sigFile, dataFile)
	if !bytes.Contains(out, []byte("Verified OK")) {
		t.Fatalf("openssl verify of our sig failed: %s", out)
	}

	// openssl dgst -sign → 本库验签通过
	osslSigFile := filepath.Join(dir, "ossl.sig")
	runOpenSSL(t, "dgst", "-sha256", "-sign", privFile, "-out", osslSigFile, dataFile)
	osslSig, _ := os.ReadFile(osslSigFile)
	if err := priv.Public().VerifyPKCS1v15(data, osslSig); err != nil {
		t.Fatalf("verify openssl sig failed: %v", err)
	}
}

// TestCLIEncryptDecrypt 本库 OAEP ↔ openssl pkeyutl 双向加解密。
func TestCLIEncryptDecrypt(t *testing.T) {
	priv, _ := GenerateKey(2048)
	dir := t.TempDir()
	msg := []byte("interop secret")

	privPEM, _ := priv.MarshalPEM()
	pubPEM, _ := priv.Public().MarshalPEM()
	privFile := filepath.Join(dir, "priv.pem")
	pubFile := filepath.Join(dir, "pub.pem")
	os.WriteFile(privFile, privPEM, 0o600)
	os.WriteFile(pubFile, pubPEM, 0o600)

	// 本库 OAEP 加密 → openssl pkeyutl -decrypt
	ct, err := EncryptOAEP(priv.Public(), msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctFile := filepath.Join(dir, "ct.bin")
	os.WriteFile(ctFile, ct, 0o600)
	decFile := filepath.Join(dir, "dec.bin")
	runOpenSSL(t, "pkeyutl", "-decrypt", "-inkey", privFile, "-in", ctFile,
		"-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-out", decFile)
	dec, _ := os.ReadFile(decFile)
	if !bytes.Equal(dec, msg) {
		t.Fatalf("openssl OAEP decrypt mismatch: %q", dec)
	}

	// openssl OAEP 加密 → 本库解密
	encFile := filepath.Join(dir, "enc.bin")
	runOpenSSL(t, "pkeyutl", "-encrypt", "-pubin", "-inkey", pubFile, "-in", dataTemp(t, dir, msg),
		"-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-out", encFile)
	enc, _ := os.ReadFile(encFile)
	pt, err := DecryptOAEP(priv, enc, nil)
	if err != nil {
		t.Fatalf("decrypt openssl OAEP failed: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("decrypt openssl OAEP mismatch: %q", pt)
	}
}

func dataTemp(t *testing.T, dir string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, "msg.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCLIPKCS1 本库 PKCS#1 PEM ↔ openssl rsa 互通。
func TestCLIPKCS1(t *testing.T) {
	priv, _ := GenerateKey(2048)
	dir := t.TempDir()
	pkcs1, _ := priv.MarshalPKCS1PEM()
	pkcs1File := filepath.Join(dir, "traditional.pem")
	if err := os.WriteFile(pkcs1File, pkcs1, 0o600); err != nil {
		t.Fatal(err)
	}
	out := runOpenSSL(t, "rsa", "-in", pkcs1File, "-traditional", "-noout", "-text")
	if !bytes.Contains(out, []byte("Private-Key")) {
		t.Fatalf("openssl rsa cannot read our PKCS#1 key: %s", out)
	}
}

// TestCLIEncryptedPEM 本库加密 PEM ↔ openssl pkey 互通。
func TestCLIEncryptedPEM(t *testing.T) {
	priv, _ := GenerateKey(2048)
	dir := t.TempDir()

	// 本库加密 → openssl 用口令读取
	enc, _ := priv.MarshalEncryptedPEM("secret123")
	encFile := filepath.Join(dir, "enc.pem")
	os.WriteFile(encFile, enc, 0o600)
	out := runOpenSSL(t, "pkey", "-in", encFile, "-passin", "pass:secret123", "-noout", "-text")
	if !bytes.Contains(out, []byte("Private-Key")) {
		t.Fatalf("openssl cannot read our encrypted PEM: %s", out)
	}

	// openssl 加密 → 本库用口令读取
	privPEM, _ := priv.MarshalPEM()
	plainFile := filepath.Join(dir, "plain.pem")
	osslEncFile := filepath.Join(dir, "ossl_enc.pem")
	os.WriteFile(plainFile, privPEM, 0o600)
	runOpenSSL(t, "pkey", "-in", plainFile, "-aes256", "-passout", "pass:other456", "-out", osslEncFile)
	osslEnc, _ := os.ReadFile(osslEncFile)
	loaded, err := LoadEncryptedPEM(osslEnc, "other456")
	if err != nil {
		t.Fatalf("load openssl encrypted PEM failed: %v", err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("openssl encrypted PEM key mismatch")
	}
}
