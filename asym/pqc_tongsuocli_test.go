//go:build tongsuocli

package asym

import (
	"bytes"
	"crypto/sha512"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestPQCCLIInterop 验证签名和 KEM 与铜锁 CLI 双向互操作。
//
// TestPQCCLIInterop verifies two-way signature and KEM interoperability with the Tongsuo CLI.
func TestPQCCLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	for _, alg := range []Algorithm{AlgMLDSA44, AlgSLHDSASHAKE128F, AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024} {
		if !PQCAvailable(alg) {
			continue
		}
		t.Run(string(alg), func(t *testing.T) {
			run := func(args ...string) []byte {
				t.Helper()
				out, err := testutil.RunOpenSSL(args, nil)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			dir := t.TempDir()
			write := func(name string, data []byte) string {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			read := func(path string) []byte {
				t.Helper()
				out, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}

			pem := run("genpkey", "-algorithm", string(alg))
			priv, err := LoadPrivateKeyPEM(pem)
			if err != nil {
				t.Fatal(err)
			}
			defer Close(priv)
			privPath := write("private.pem", pem)
			pubPEM, err := priv.Public().MarshalPublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			pubPath := write("public.pem", pubPEM)
			if mlkemCiphertextSize(priv) != 0 {
				ctPath, secretPath := filepath.Join(dir, "ct"), filepath.Join(dir, "secret")
				run("pkeyutl", "-encap", "-inkey", pubPath, "-pubin", "-out", ctPath, "-secret", secretPath)
				secret, err := Decapsulate(priv, read(ctPath))
				if err != nil || !bytes.Equal(secret, read(secretPath)) {
					t.Fatalf("CLI to SDK: %v", err)
				}
				ct, secret, err := Encapsulate(priv.Public())
				if err != nil {
					t.Fatal(err)
				}
				write("ct", ct)
				run("pkeyutl", "-decap", "-inkey", privPath, "-in", ctPath, "-secret", secretPath)
				if !bytes.Equal(secret, read(secretPath)) {
					t.Fatal("SDK to CLI secrets differ")
				}
				return
			}

			message := []byte("PQC interop")
			messagePath := write("message", message)
			opts := &PQCSignatureOptions{Context: []byte("interop")}
			signature := run("pkeyutl", "-sign", "-rawin", "-inkey", privPath, "-in", messagePath, "-pkeyopt", "hexcontext-string:696e7465726f70")
			if err := VerifyPQC(priv.Public(), message, signature, opts); err != nil {
				t.Fatal(err)
			}
			signature, err = SignPQC(priv, message, opts)
			if err != nil {
				t.Fatal(err)
			}
			signaturePath := write("signature", signature)
			run("pkeyutl", "-verify", "-rawin", "-inkey", pubPath, "-pubin", "-in", messagePath,
				"-sigfile", signaturePath, "-pkeyopt", "hexcontext-string:696e7465726f70")

			// Independently construct the FIPS 204/205 SHA-512 prehash input.
			digest := sha512.Sum512(message)
			framed := append([]byte("\x01\x07interop\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"), digest[:]...)
			framedPath := write("prehash", framed)
			opts.Prehash = "SHA-512"
			signature = run("pkeyutl", "-sign", "-rawin", "-inkey", privPath, "-in", framedPath, "-pkeyopt", "message-encoding:0")
			if err := VerifyPQC(priv.Public(), message, signature, opts); err != nil {
				t.Fatal(err)
			}
			signature, err = SignPQC(priv, message, opts)
			if err != nil {
				t.Fatal(err)
			}
			write("signature", signature)
			run("pkeyutl", "-verify", "-rawin", "-inkey", pubPath, "-pubin", "-in", framedPath,
				"-sigfile", signaturePath, "-pkeyopt", "message-encoding:0")
		})
	}
}
