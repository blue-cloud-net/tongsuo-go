//go:build tongsuocli

package asym

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestEdDSAInstanceCLIInterop 验证四种上下文/ph 入口与铜锁 CLI 确定性签名双向互通。
//
// TestEdDSAInstanceCLIInterop checks deterministic signatures and bidirectional CLI interop for context/ph entries.
func TestEdDSAInstanceCLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	for _, name := range []string{"Ed25519ctx", "Ed25519ph", "Ed448", "Ed448ph"} {
		t.Run(name, func(t *testing.T) {
			var key PrivateKey
			var err error
			if name == "Ed448" || name == "Ed448ph" {
				key, err = GenerateEd448()
			} else {
				key, err = GenerateEd25519()
			}
			if err != nil {
				t.Fatal(err)
			}
			defer Close(key)
			dir := t.TempDir()
			privFile, pubFile, msgFile, sigFile := filepath.Join(dir, "key.pem"), filepath.Join(dir, "pub.pem"), filepath.Join(dir, "msg"), filepath.Join(dir, "sig")
			priv, err := key.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			pub, err := key.Public().MarshalPublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			msg, context := []byte("EdDSA context CLI interop"), []byte("ctx")
			for path, data := range map[string][]byte{privFile: priv, pubFile: pub, msgFile: msg} {
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			opts := []string{"-pkeyopt", "instance:" + name, "-pkeyopt", "hexcontext-string:" + hex.EncodeToString(context)}
			args := append([]string{"pkeyutl", "-sign", "-rawin", "-inkey", privFile, "-in", msgFile, "-out", sigFile}, opts...)
			supported, err := SupportsEdDSAInstance(key, name, context)
			if err != nil {
				t.Fatal(err)
			}
			if !supported {
				if out, e := testutil.RunOpenSSLCombined(args, nil); e == nil {
					t.Fatalf("unsupported probe disagrees with CLI: %s", out)
				}
				return
			}
			if out, e := testutil.RunOpenSSLCombined(args, nil); e != nil {
				t.Fatalf("CLI sign: %v %s", e, out)
			}
			cli, err := os.ReadFile(sigFile)
			if err != nil {
				t.Fatal(err)
			}
			got, err := signEdDSA(key, msg, context, name)
			if err != nil || !bytes.Equal(got, cli) {
				t.Fatalf("deterministic signature mismatch: %v", err)
			}
			if err = verifyEdDSA(key.Public(), msg, cli, context, name); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(sigFile, got, 0600); err != nil {
				t.Fatal(err)
			}
			args = append([]string{"pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pubFile, "-in", msgFile, "-sigfile", sigFile}, opts...)
			if out, e := testutil.RunOpenSSLCombined(args, nil); e != nil {
				t.Fatalf("CLI verify: %v %s", e, out)
			}
		})
	}
}
