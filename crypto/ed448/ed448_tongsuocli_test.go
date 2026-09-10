// Package ed448 的 tongsuocli 对拍测试。
// Build tag: tongsuocli (off by default).
package ed448

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

func TestCLIKeyInterop(t *testing.T) {
	bin := testutil.OpenSSLBin()
	if bin == "" {
		t.Skip("TONGSUO_OPENSSL_BIN not set; skipping tongsuocli test")
	}
	dir := t.TempDir()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	p8, _ := priv.MarshalPEM()
	privPath := filepath.Join(dir, "priv.pem")
	os.WriteFile(privPath, p8, 0o600)
	out, err := runOpenSSL(t, bin, "pkey", "-in", privPath, "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey: %v", err)
	}
	if !bytes.Contains([]byte(out), []byte("ED448 Private-Key")) {
		t.Fatalf("cli output missing ED448 marker: %s", out)
	}

	spki, _ := pub.MarshalPEM()
	pubPath := filepath.Join(dir, "pub.pem")
	os.WriteFile(pubPath, spki, 0o600)
	out2, err := runOpenSSL(t, bin, "pkey", "-in", pubPath, "-pubin", "-noout", "-text")
	if err != nil {
		t.Fatalf("cli pkey pubin: %v", err)
	}
	if !bytes.Contains([]byte(out2), []byte("ED448 Public-Key")) {
		t.Fatalf("cli pub output missing ED448 marker: %s", out2)
	}

	cliPriv := filepath.Join(dir, "cli.pem")
	if _, err := runOpenSSL(t, bin, "genpkey", "-algorithm", "ED448", "-out", cliPriv); err != nil {
		t.Fatalf("cli genpkey: %v", err)
	}
	cliPEM, err := os.ReadFile(cliPriv)
	if err != nil {
		t.Fatalf("read cli pem: %v", err)
	}
	if _, err := LoadPrivateKeyPEM(cliPEM); err != nil {
		t.Fatalf("LoadPrivateKeyPEM cli: %v", err)
	}
}

func TestCLISignVerify(t *testing.T) {
	bin := testutil.OpenSSLBin()
	if bin == "" {
		t.Skip("TONGSUO_OPENSSL_BIN not set; skipping tongsuocli test")
	}
	dir := t.TempDir()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	msg := []byte("hello ed448 tongsuocli")
	msgPath := filepath.Join(dir, "msg.bin")
	os.WriteFile(msgPath, msg, 0o600)

	p8, _ := priv.MarshalPEM()
	privPath := filepath.Join(dir, "priv.pem")
	os.WriteFile(privPath, p8, 0o600)
	spki, _ := pub.MarshalPEM()
	pubPath := filepath.Join(dir, "pub.pem")
	os.WriteFile(pubPath, spki, 0o600)
	sigPath := filepath.Join(dir, "our.sig")

	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	os.WriteFile(sigPath, sig, 0o600)
	out, err := runOpenSSL(t, bin, "pkeyutl", "-verify", "-rawin",
		"-in", msgPath, "-pubin", "-inkey", pubPath, "-sigfile", sigPath)
	if err != nil {
		t.Fatalf("cli verify: %v\n%s", err, out)
	}
	if !bytes.Contains([]byte(out), []byte("Verified OK")) &&
		!bytes.Contains([]byte(out), []byte("Signature Verified Successfully")) {
		t.Fatalf("cli verify output missing success marker: %s", out)
	}

	cliSig := filepath.Join(dir, "cli.sig")
	if _, err := runOpenSSL(t, bin, "pkeyutl", "-sign", "-rawin",
		"-in", msgPath, "-inkey", privPath, "-out", cliSig); err != nil {
		t.Fatalf("cli sign: %v", err)
	}
	cliSigBytes, _ := os.ReadFile(cliSig)
	if err := Verify(pub, msg, cliSigBytes); err != nil {
		t.Fatalf("library Verify cli sig: %v", err)
	}
}

func runOpenSSL(t *testing.T, bin string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	return out, nil
}