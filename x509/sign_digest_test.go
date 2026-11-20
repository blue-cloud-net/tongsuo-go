package x509

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// TestSignWithDigest 验证证书和 CSR 的显式摘要、默认摘要及失败重试。
//
// TestSignWithDigest checks explicit digests, defaults, and retries for
// certificates and CSRs.
func TestSignWithDigest(t *testing.T) {
	rsa := func() (asym.PrivateKey, error) { return asym.GenerateRSA(2048) }
	ec := func() (asym.PrivateKey, error) { return asym.GenerateEC(asym.CurveP256) }
	for _, tc := range []struct {
		name         string
		generate     func() (asym.PrivateKey, error)
		digest       string
		oid          string
		incompatible string
	}{
		{"RSA/SHA-384", rsa, "SHA-384", "1.2.840.113549.1.1.12", ""},
		{"RSA/SHA-256", rsa, "SHA-256", "1.2.840.113549.1.1.11", ""},
		{"RSA/SHA256", rsa, "SHA256", "1.2.840.113549.1.1.11", ""},
		{"RSA/default", rsa, "", "1.2.840.113549.1.1.11", ""},
		{"ECDSA/SHA-512", ec, "SHA-512", "1.2.840.10045.4.3.4", ""},
		{"ECDSA/default", ec, "", "1.2.840.10045.4.3.2", ""},
		{"SM2/SM3", asym.GenerateSM2, "SM3", "1.2.156.10197.1.501", "SHA-256"},
		{"SM2/default", asym.GenerateSM2, "", "1.2.156.10197.1.501", ""},
		{"Ed25519/default", asym.GenerateEd25519, "", "1.3.101.112", "SHA-256"},
		{"Ed448/default", asym.GenerateEd448, "", "1.3.101.113", "SHA-384"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := tc.generate()
			if err != nil {
				t.Fatal(err)
			}
			defer asym.Close(priv)
			pub := priv.Public()
			defer asym.Close(pub)

			subject := NewName().Add("CN", "example.test")
			defer subject.Close()
			cert := NewCertificate()
			defer cert.Close()
			now := time.Now()
			for _, err := range []error{
				cert.SetVersion(2), cert.SetSerial(1),
				cert.SetSubject(subject), cert.SetIssuer(subject),
				cert.SetValidity(now, now.Add(time.Hour)), cert.SetPublicKey(pub),
			} {
				if err != nil {
					t.Fatal(err)
				}
			}

			req := NewEmptyCertificateRequest()
			defer req.Close()
			if err := req.SetSubject(subject); err != nil {
				t.Fatal(err)
			}
			if err := req.SetPublicKey(pub); err != nil {
				t.Fatal(err)
			}
			if err := req.AddExtensionByName("subjectAltName", "DNS:example.test"); err != nil {
				t.Fatal(err)
			}

			checkSignWithDigest(t, cert.SignWithDigest, priv, tc.digest, tc.incompatible)
			certDER, err := cert.MarshalDER()
			if err != nil {
				t.Fatal(err)
			}
			loadedCert, err := LoadCertificateDER(certDER)
			if err != nil {
				t.Fatal(err)
			}
			defer loadedCert.Close()
			if got := loadedCert.SignatureAlgorithmOID(); got != tc.oid {
				t.Errorf("certificate signature OID = %s, want %s", got, tc.oid)
			}
			if err := loadedCert.Verify(pub); err != nil {
				t.Fatal(err)
			}

			checkSignWithDigest(t, req.SignWithDigest, priv, tc.digest, tc.incompatible)
			reqDER, err := req.MarshalDER()
			if err != nil {
				t.Fatal(err)
			}
			loadedReq, err := LoadCertificateRequestDER(reqDER)
			if err != nil {
				t.Fatal(err)
			}
			defer loadedReq.Close()
			if got := loadedReq.SignatureAlgorithmOID(); got != tc.oid {
				t.Errorf("CSR signature OID = %s, want %s", got, tc.oid)
			}
			if err := loadedReq.Verify(); err != nil {
				t.Fatal(err)
			}
			wantSAN, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("example.test")}})
			if err != nil {
				t.Fatal(err)
			}
			if exts := loadedReq.Extensions(); len(exts) != 1 || exts[0].OID != "2.5.29.17" || !bytes.Equal(exts[0].Data, wantSAN) {
				t.Errorf("CSR extensions = %+v, want one DNS:example.test SAN", exts)
			}
		})
	}
}

func checkSignWithDigest(t *testing.T, sign func(asym.PrivateKey, string) error, priv asym.PrivateKey, digest, incompatible string) {
	t.Helper()
	for _, name := range []string{"unknown-digest", "SHA256\x00suffix"} {
		if err := sign(priv, name); err == nil || !strings.Contains(err.Error(), "unknown signing digest") {
			t.Fatalf("SignWithDigest(%q) = %v, want digest lookup error", name, err)
		}
	}
	if incompatible != "" {
		var opErr *core.OpError
		if err := sign(priv, incompatible); !errors.As(err, &opErr) {
			t.Fatalf("SignWithDigest(%q) = %v, want native signing error", incompatible, err)
		}
	}
	if err := sign(priv, digest); err != nil {
		t.Fatalf("SignWithDigest(%q): %v", digest, err)
	}
	if err := sign(priv, digest); err == nil || !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("repeated SignWithDigest(%q) = %v, want already signed error", digest, err)
	}
}
