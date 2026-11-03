//go:build tongsuocli

package pkcs7

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"os"
	"path/filepath"
	"testing"
)

// TestCLIOperations 验证相关操作的正确性、边界与错误处理。
//
// TestCLIOperations checks operation correctness, boundaries and error handling.
func TestCLIOperations(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	for _, alg := range []string{"RSA", "EC"} {
		t.Run(alg, func(t *testing.T) {
			cert, key := operationIdentity(t, alg)
			dir := t.TempDir()
			certPath := filepath.Join(dir, "cert.pem")
			keyPath := filepath.Join(dir, "key.pem")
			dataPath := filepath.Join(dir, "message.bin")
			sigPath := filepath.Join(dir, "sig.der")
			certPEM, err := cert.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			keyPEM, err := key.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("CLI\x00binary\r\nline\n")
			for path, value := range map[string][]byte{certPath: certPEM, keyPath: keyPEM, dataPath: data} {
				if err := os.WriteFile(path, value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, detached := range []bool{false, true} {
				der, err := Sign(data, &SignOptions{SignerCert: cert, SignerKey: key, Detached: detached})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sigPath, der, 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"smime", "-verify", "-binary", "-inform", "DER", "-in", sigPath, "-noverify"}
				if detached {
					args = append(args, "-content", dataPath)
				}
				got, err := testutil.RunOpenSSL(args, nil)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("CLI verify: %q %v", got, err)
				}
				args = []string{"smime", "-sign", "-binary", "-in", dataPath, "-signer", certPath, "-inkey", keyPath, "-md", "sha256", "-outform", "DER"}
				if !detached {
					args = append(args, "-nodetach")
				}
				signed, err := testutil.RunOpenSSL(args, nil)
				if err != nil {
					t.Fatal(err)
				}
				opts := &VerifyOptions{SignatureOnly: true}
				if detached {
					opts.DetachedContent = data
				}
				result, err := Verify(signed, opts)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(result.Content, data) {
					t.Fatal("CLI signature changed content")
				}
				result.Close()
			}
			if alg == "RSA" {
				encrypted, err := Encrypt(data, &EncryptOptions{Recipients: []*x509.Certificate{cert}})
				if err != nil {
					t.Fatal(err)
				}
				got, err := testutil.RunOpenSSL([]string{"smime", "-decrypt", "-binary", "-inform", "DER", "-recip", certPath, "-inkey", keyPath}, encrypted)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatal("CLI decrypt", err)
				}
				encrypted, err = testutil.RunOpenSSL([]string{"smime", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER", certPath}, data)
				if err != nil {
					t.Fatal(err)
				}
				got, err = Decrypt(encrypted, &DecryptOptions{cert, key})
				if err != nil || !bytes.Equal(got, data) {
					t.Fatal("library decrypt", err)
				}
			}
		})
	}
}

// TestCLIMultipleSigners 验证相关操作的正确性、边界与错误处理。
//
// TestCLIMultipleSigners checks operation correctness, boundaries and error handling.
func TestCLIMultipleSigners(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	dir := t.TempDir()
	data := []byte("multiple signer verification")
	args := []string{"smime", "-sign", "-binary", "-nodetach", "-outform", "DER"}
	roots := x509.NewStore()
	defer roots.Close()
	for i := 0; i < 2; i++ {
		cert, key := operationIdentity(t, "RSA")
		if err := roots.AddCert(cert); err != nil {
			t.Fatal(err)
		}
		certPEM, err := cert.MarshalPEM()
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := key.MarshalPrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		c := filepath.Join(dir, string(rune('a'+i))+".crt")
		k := filepath.Join(dir, string(rune('a'+i))+".key")
		if err := os.WriteFile(c, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(k, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-signer", c, "-inkey", k)
	}
	signed, err := testutil.RunOpenSSL(args, data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(signed, &VerifyOptions{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(result.Signers) != 2 || !result.TrustVerified || !bytes.Equal(result.Content, data) {
		t.Fatal("not all signers verified")
	}
	signed[len(signed)-1] ^= 1
	if result, err := Verify(signed, &VerifyOptions{Roots: roots}); err == nil || result != nil {
		t.Fatal("one invalid signature accepted")
	}
}
