//go:build tongsuocli

package asym

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"testing"
)

// TestCLIPKCS8Options 验证 PKCS#8 PBE/PRF 双向互操作及 PKCS#1 公钥。
//
// TestCLIPKCS8Options checks bidirectional PKCS#8 PBE/PRF interop and PKCS#1 public keys.
func TestCLIPKCS8Options(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(priv)
	want, err := MarshalPKCS8(priv, meta.FormatDER, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []*PKCS8Options{{Encrypt: true, Version: 1, Passphrase: "secret", Iterations: 1234}, {Encrypt: true, Cipher: "AES-128-CBC", PRF: "hmacWithSHA512", Iterations: 2345, Passphrase: "secret"}} {
		enc, err := MarshalPKCS8(priv, meta.FormatPEM, o)
		if err != nil {
			t.Fatal(err)
		}
		got, err := testutil.RunOpenSSL([]string{"pkcs8", "-passin", "pass:secret", "-topk8", "-nocrypt", "-outform", "DER"}, enc)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("CLI decode: %v", err)
		}
		args := []string{"pkcs8", "-topk8", "-passout", "pass:secret", "-iter", "2345"}
		if o.Version == 1 {
			args = append(args, "-v1", "PBE-SHA1-3DES")
		} else {
			args = append(args, "-v2", "aes-128-cbc", "-v2prf", "hmacWithSHA512")
		}
		enc, err = testutil.RunOpenSSL(args, plain)
		if err != nil {
			t.Fatal(err)
		}
		k, err := LoadPKCS8(enc, meta.FormatPEM, true, "secret")
		if err != nil {
			t.Fatal(err)
		}
		got, err = MarshalPKCS8(k, meta.FormatDER, nil)
		Close(k)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("CLI-generated key changed")
		}
	}
	pub, err := MarshalRSAPublicKeyPKCS1PEM(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := testutil.RunOpenSSL([]string{"rsa", "-RSAPublicKey_in", "-pubout"}, pub)
	if err != nil {
		t.Fatal(err)
	}
	wantPublic, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil || !bytes.Equal(spki, wantPublic) {
		t.Fatal("PKCS1 public mismatch")
	}
}
