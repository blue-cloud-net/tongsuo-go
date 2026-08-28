//go:build tongsuocli

package ecdsa

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

// TestCLIKeyInterop 本库 EC 密钥 ↔ openssl pkey / genpkey 互通。
func TestCLIKeyInterop(t *testing.T) {
	priv, err := GenerateKey("prime256v1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	// 本库私钥 → openssl 可读取（显示 EC 参数）
	privPEM, _ := priv.MarshalPEM()
	privFile := filepath.Join(dir, "priv.pem")
	if err := os.WriteFile(privFile, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	out := runOpenSSL(t, "pkey", "-in", privFile, "-noout", "-text")
	if !bytes.Contains(out, []byte("ASN1 OID: prime256v1")) {
		t.Fatalf("openssl cannot read our EC key (missing prime256v1): %s", out)
	}

	// openssl genpkey EC → 本库读取
	genFile := filepath.Join(dir, "gen.pem")
	runOpenSSL(t, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", genFile)
	genPEM, _ := os.ReadFile(genFile)
	loaded, err := LoadPrivateKeyPEM(genPEM)
	if err != nil {
		t.Fatalf("load openssl-generated EC key failed: %v", err)
	}
	if loaded.Params().Curve != "prime256v1" {
		t.Fatalf("loaded curve = %q, want prime256v1", loaded.Params().Curve)
	}
}

// TestCLISignVerify 本库 ECDSA 签名 ↔ openssl dgst -sha256 双向验签。
func TestCLISignVerify(t *testing.T) {
	priv, _ := GenerateKey("prime256v1")
	dir := t.TempDir()
	data := []byte("interop ecdsa data")
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
	ourSig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(dir, "our.sig")
	os.WriteFile(sigFile, ourSig, 0o600)
	out := runOpenSSL(t, "dgst", "-sha256", "-verify", pubFile, "-signature", sigFile, dataFile)
	if !bytes.Contains(out, []byte("Verified OK")) {
		t.Fatalf("openssl verify of our ECDSA sig failed: %s", out)
	}

	// openssl dgst -sign → 本库验签通过
	osslSigFile := filepath.Join(dir, "ossl.sig")
	runOpenSSL(t, "dgst", "-sha256", "-sign", privFile, "-out", osslSigFile, dataFile)
	osslSig, _ := os.ReadFile(osslSigFile)
	if err := Verify(priv.Public(), data, osslSig); err != nil {
		t.Fatalf("verify openssl ECDSA sig failed: %v", err)
	}
}
