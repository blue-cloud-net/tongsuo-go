//go:build tongsuocli

package asym

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

// TestCLIRSASignatureOctets 验证相关操作的正确性、边界与错误处理。
//
// TestCLIRSASignatureOctets checks operation correctness, boundaries and error handling.
func TestCLIRSASignatureOctets(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	key, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(key)
	priv, err := key.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	messagePath := filepath.Join(dir, "message.bin")
	sigPath := filepath.Join(dir, "sig.bin")
	message := []byte("RSA signature octets\x00\r\n")
	for p, d := range map[string][]byte{keyPath: priv, pubPath: pub, messagePath: message} {
		if err := os.WriteFile(p, d, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, pss := range []bool{false, true} {
		var sig []byte
		var err error
		var flags []string
		if pss {
			sig, err = SignPSS(key, message, PSSSaltLenDigest, "sha256")
			flags = []string{"-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest", "-sigopt", "rsa_mgf1_md:sha256"}
		} else {
			sig, err = SignPKCS1v15(key, message, "sha256")
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 256 {
			t.Fatalf("signature length = %d, want modulus length 256", len(sig))
		}
		if err := os.WriteFile(sigPath, sig, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"dgst", "-sha256", "-verify", pubPath, "-signature", sigPath}
		args = append(args, flags...)
		args = append(args, messagePath)
		if out, err := testutil.RunOpenSSLCombined(args, nil); err != nil {
			t.Fatalf("CLI verify: %v %s", err, out)
		}
		args = []string{"dgst", "-sha256", "-sign", keyPath}
		args = append(args, flags...)
		args = append(args, messagePath)
		sig, err = testutil.RunOpenSSL(args, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 256 {
			t.Fatal("CLI signature length")
		}
		if pss {
			err = VerifyPSS(key.Public(), message, sig, PSSSaltLenDigest, "sha256")
		} else {
			err = VerifyPKCS1v15(key.Public(), message, sig, "sha256")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}
