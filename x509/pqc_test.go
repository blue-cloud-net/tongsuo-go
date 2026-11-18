package x509

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestPQCCertificates 验证 PQC 证书和 CSR 的应用层签验与编码。
//
// TestPQCCertificates verifies PQC certificate and CSR signing, verification, and encoding.
func TestPQCCertificates(t *testing.T) {
	for _, alg := range []asym.Algorithm{
		asym.AlgMLDSA44, asym.AlgMLDSA65, asym.AlgMLDSA87,
		asym.AlgSLHDSASHA2128S, asym.AlgSLHDSASHA2128F, asym.AlgSLHDSASHA2192S, asym.AlgSLHDSASHA2192F,
		asym.AlgSLHDSASHA2256S, asym.AlgSLHDSASHA2256F, asym.AlgSLHDSASHAKE128S, asym.AlgSLHDSASHAKE128F,
		asym.AlgSLHDSASHAKE192S, asym.AlgSLHDSASHAKE192F, asym.AlgSLHDSASHAKE256S, asym.AlgSLHDSASHAKE256F,
	} {
		if !asym.PQCAvailable(alg) {
			continue
		}
		t.Run(string(alg), func(t *testing.T) {
			key, err := asym.GenerateKey(alg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer asym.Close(key)
			subject := NewName().Add("CN", "pqc.example")
			now := time.Now()
			cert, err := CreateSelfSigned(subject, 1, now.Add(-time.Hour), now.Add(time.Hour), key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			defer cert.Close()
			pub, err := cert.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			defer asym.Close(pub)
			if pub.Algorithm() != alg {
				t.Fatalf("certificate public algorithm: %s", pub.Algorithm())
			}
			if err := cert.Verify(pub); err != nil {
				t.Fatal(err)
			}
			req, err := NewCertificateRequest(subject, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			defer req.Close()
			if err := req.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
