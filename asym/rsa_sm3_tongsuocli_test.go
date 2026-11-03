//go:build tongsuocli

package asym

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestRSASM3CLIInterop 验证 RSA + SM3 与铜锁 openssl CLI 的双向互验：
// 本库签名 → CLI 验签，CLI 签名 → 本库验签。PKCS#1 v1.5 与 PSS 各覆盖一次。
//
// TestRSASM3CLIInterop verifies RSA + SM3 interop in both directions
// against the Tongsuo openssl CLI: library signs / CLI verifies, and CLI
// signs / library verifies. Both PKCS#1 v1.5 and PSS are covered.
func TestRSASM3CLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "data.bin")
	privPath := filepath.Join(dir, "key.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	sigPath := filepath.Join(dir, "sig.bin")

	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	data := []byte("tongsuo-go rsa-sm3 interop")

	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatalf("write data: %v", err)
	}
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	pubPEM, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	supported, err := SupportsRSASignatureDigest(priv, "sm3")
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		for _, extra := range [][]string{nil, {"-sigopt", "rsa_padding_mode:pss"}} {
			args := append([]string{"dgst", "-sm3", "-sign", privPath, "-out", sigPath}, extra...)
			args = append(args, dataPath)
			if out, e := testutil.RunOpenSSLCombined(args, nil); e == nil {
				t.Fatalf("provider probe disagrees with CLI: %s", out)
			}
		}
		return
	}

	pssOpts := []string{"-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest"}

	t.Run("library-sign-cli-verify/PKCS1v15", func(t *testing.T) {
		sig, err := SignPKCS1v15(priv, data, "sm3")
		if err != nil {
			t.Fatalf("SignPKCS1v15: %v", err)
		}
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			t.Fatalf("write signature: %v", err)
		}
		out, err := testutil.RunOpenSSL([]string{
			"dgst", "-sm3", "-verify", pubPath, "-signature", sigPath, dataPath,
		}, nil)
		if err != nil {
			t.Fatalf("CLI verify failed: %v (%s)", err, out)
		}
		if !bytes.Contains(out, []byte("Verified OK")) {
			t.Errorf("CLI output = %q, want Verified OK", out)
		}
	})

	t.Run("library-sign-cli-verify/PSS", func(t *testing.T) {
		sig, err := SignPSS(priv, data, PSSSaltLenDigest, "sm3")
		if err != nil {
			t.Fatalf("SignPSS: %v", err)
		}
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			t.Fatalf("write signature: %v", err)
		}
		args := append([]string{"dgst", "-sm3", "-verify", pubPath, "-signature", sigPath}, pssOpts...)
		args = append(args, dataPath)
		out, err := testutil.RunOpenSSL(args, nil)
		if err != nil {
			t.Fatalf("CLI verify failed: %v (%s)", err, out)
		}
		if !bytes.Contains(out, []byte("Verified OK")) {
			t.Errorf("CLI output = %q, want Verified OK", out)
		}
	})

	t.Run("cli-sign-library-verify/PKCS1v15", func(t *testing.T) {
		if _, err := testutil.RunOpenSSL([]string{
			"dgst", "-sm3", "-sign", privPath, "-out", sigPath, dataPath,
		}, nil); err != nil {
			t.Fatalf("CLI sign failed: %v", err)
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			t.Fatalf("read signature: %v", err)
		}
		if err := VerifyPKCS1v15(priv.Public(), data, sig, "sm3"); err != nil {
			t.Errorf("library verify failed: %v", err)
		}
	})

	t.Run("cli-sign-library-verify/PSS", func(t *testing.T) {
		args := append([]string{"dgst", "-sm3", "-sign", privPath, "-out", sigPath}, pssOpts...)
		args = append(args, dataPath)
		if _, err := testutil.RunOpenSSL(args, nil); err != nil {
			t.Fatalf("CLI sign failed: %v", err)
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			t.Fatalf("read signature: %v", err)
		}
		if err := VerifyPSS(priv.Public(), data, sig, PSSSaltLenDigest, "sm3"); err != nil {
			t.Errorf("library verify failed: %v", err)
		}
	})
}
