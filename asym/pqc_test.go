package asym

import (
	"bytes"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestPQC 验证各变体的加载、操作和错误边界。
//
// TestPQC verifies loading, operations and error boundaries across variants.
func TestPQC(t *testing.T) {
	for _, alg := range []Algorithm{
		AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
		AlgSLHDSASHA2128S, AlgSLHDSASHA2128F, AlgSLHDSASHA2192S, AlgSLHDSASHA2192F,
		AlgSLHDSASHA2256S, AlgSLHDSASHA2256F, AlgSLHDSASHAKE128S, AlgSLHDSASHAKE128F,
		AlgSLHDSASHAKE192S, AlgSLHDSASHAKE192F, AlgSLHDSASHAKE256S, AlgSLHDSASHAKE256F,
		AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024,
	} {
		t.Run(string(alg), func(t *testing.T) {
			priv, err := GenerateKey(alg, nil)
			if !PQCAvailable(alg) {
				if !errors.Is(err, ErrUnsupported) {
					t.Fatalf("unavailable generation: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer Close(priv)
			der, err := MarshalPKCS8(priv, meta.FormatDER, nil)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := LoadPKCS8(der, meta.FormatDER, false, "")
			if err != nil {
				t.Fatal(err)
			}
			defer Close(reloaded)
			spki, err := MarshalSPKI(priv.Public(), meta.FormatDER)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := LoadSPKI(spki, meta.FormatDER)
			if err != nil {
				t.Fatal(err)
			}
			defer Close(pub)
			if reloaded.Algorithm() != alg || pub.Algorithm() != alg {
				t.Fatalf("reloaded algorithms: %s, %s", reloaded.Algorithm(), pub.Algorithm())
			}
			if mlkemCiphertextSize(pub) != 0 {
				ct, secret, err := Encapsulate(pub)
				if err != nil {
					t.Fatal(err)
				}
				recovered, err := Decapsulate(reloaded, ct)
				if err != nil || len(secret) != 32 || !bytes.Equal(recovered, secret) {
					t.Fatalf("decapsulation failed: %v", err)
				}
				if _, err := Decapsulate(reloaded, ct[:len(ct)-1]); err == nil {
					t.Fatal("truncated ciphertext accepted")
				}
				ct[0] ^= 1
				recovered, err = Decapsulate(reloaded, ct)
				if err != nil || bytes.Equal(recovered, secret) {
					t.Fatalf("implicit rejection failed: %v", err)
				}
				return
			}
			message := []byte("PQC test")
			for _, opts := range []*PQCSignatureOptions{nil, {Context: []byte("test")}, {Context: []byte("test"), Prehash: "SHA-512"}, {Prehash: "SHAKE256"}} {
				signature, err := SignPQC(reloaded, message, opts)
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyPQC(pub, message, signature, opts); err != nil {
					t.Fatal(err)
				}
				if opts != nil && !errors.Is(VerifyPQC(pub, message, signature, nil), ErrSignature) {
					t.Fatal("signature verified with different parameters")
				}
				signature[0] ^= 1
				if !errors.Is(VerifyPQC(pub, message, signature, opts), ErrSignature) {
					t.Fatal("tampered signature verified")
				}
			}
			signature, err := SignPQC(reloaded, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyPQC(pub, nil, signature, nil); err != nil {
				t.Fatal(err)
			}
			if err := Close(reloaded); err != nil {
				t.Fatal(err)
			}
			if _, err := SignPQC(reloaded, message, nil); err == nil {
				t.Fatal("closed key signed a message")
			}
		})
	}
}
