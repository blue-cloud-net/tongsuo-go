package asym

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestPQCPrehashACVP 验证 NIST ACVP 的 HashML-DSA 和 HashSLH-DSA 签名。
//
// TestPQCPrehashACVP verifies NIST ACVP signatures for HashML-DSA and HashSLH-DSA.
func TestPQCPrehashACVP(t *testing.T) {
	data, err := os.ReadFile("testdata/pqc-acvp-prehash.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Algorithm Algorithm
		OID       int
		HashAlg   string
		PK        string
		Message   string
		Context   string
		Signature string
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if !PQCAvailable(v.Algorithm) {
			continue
		}
		t.Run(string(v.Algorithm), func(t *testing.T) {
			decode := func(s string) []byte {
				t.Helper()
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			publicKey := decode(v.PK)
			spki, err := asn1.Marshal(struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}{
				Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, v.OID}},
				PublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
			})
			if err != nil {
				t.Fatal(err)
			}
			pub, err := LoadSPKI(spki, meta.FormatDER)
			if err != nil {
				t.Fatal(err)
			}
			defer Close(pub)
			opts := &PQCSignatureOptions{Context: decode(v.Context), Prehash: v.HashAlg}
			if err := VerifyPQC(pub, decode(v.Message), decode(v.Signature), opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}
