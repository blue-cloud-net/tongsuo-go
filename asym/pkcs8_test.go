package asym

import (
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestPKCS8Options 验证 PBE v1/v2、PRF、PEM/DER 往返和错误口令。
//
// TestPKCS8Options checks PBE v1/v2, PRFs, PEM/DER round trips and wrong passwords.
func TestPKCS8Options(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(priv)
	for _, format := range []meta.Format{meta.FormatPEM, meta.FormatDER} {
		for _, o := range []*PKCS8Options{nil, {Encrypt: true, Version: 1, Passphrase: "secret", Iterations: 1024}, {Encrypt: true, PRF: "hmacWithSHA512", Cipher: "AES-128-CBC", Passphrase: "secret", Iterations: 1234}, {Encrypt: true}} {
			data, err := MarshalPKCS8(priv, format, o)
			if err != nil {
				t.Fatal(err)
			}
			encrypted := o != nil && o.Encrypt
			pass := ""
			if o != nil {
				pass = o.Passphrase
			}
			got, err := LoadPKCS8(data, format, encrypted, pass)
			if err != nil {
				t.Fatal(err)
			}
			same, err := Match(got, priv.Public())
			if err != nil || !same {
				t.Fatalf("mismatched key: %v", err)
			}
			Close(got)
			if encrypted {
				if k, err := LoadPKCS8(data, format, true, "wrong"); err == nil {
					Close(k)
					t.Fatal("wrong password accepted")
				}
			}
		}
	}
	for _, o := range []*PKCS8Options{{Encrypt: true, Version: 3}, {Encrypt: true, Version: 1, PRF: "hmacWithSHA256"}, {Encrypt: true, Iterations: -1}, {Encrypt: true, Cipher: "AES-128-GCM"}, {Encrypt: true, PRF: "unknown"}} {
		if _, err = MarshalPKCS8(priv, meta.FormatPEM, o); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	pubPEM, err := MarshalRSAPublicKeyPKCS1PEM(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadRSAPublicKeyPKCS1PEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(pub)
	if err = PublicCheck(pub); err != nil {
		t.Fatal(err)
	}
	same, err := Match(priv, pub)
	if err != nil || !same {
		t.Fatal("public key mismatch")
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		t.Fatal("wrong PKCS1 type")
	}
	if bytes.Contains(pubPEM, []byte("PRIVATE")) {
		t.Fatal("private material in public export")
	}
	if err = Check(priv); err != nil {
		t.Fatal(err)
	}
	Close(priv)
	if err = Check(priv); err == nil {
		t.Fatal("closed key accepted")
	}
}
