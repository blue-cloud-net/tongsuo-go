package pkcs7

import (
	"bytes"
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"sync/atomic"
	"testing"
	"time"
)

var operationSerial atomic.Int64

func operationIdentity(t *testing.T, alg string) (*x509.Certificate, asym.PrivateKey) {
	t.Helper()
	var key asym.PrivateKey
	var err error
	switch alg {
	case "RSA":
		key, err = asym.GenerateRSA(2048)
	case "EC":
		key, err = asym.GenerateEC("P-256")
	case "SM2":
		key, err = asym.GenerateSM2()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { asym.Close(key) })
	cert := x509.NewCertificate()
	t.Cleanup(func() { cert.Close() })
	serial := operationSerial.Add(1)
	name := x509.NewName().Add("CN", fmt.Sprintf("PKCS7 %s %d", alg, serial))
	now := time.Now()
	for _, err := range []error{cert.SetVersion(2), cert.SetSerial(serial), cert.SetSubject(name), cert.SetIssuer(name), cert.SetValidity(now.Add(-time.Hour), now.Add(time.Hour)), cert.SetPublicKey(key.Public()), cert.AddBasicConstraints(true), cert.Sign(key)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

// TestSignVerifyOptions 验证相关操作的正确性、边界与错误处理。
//
// TestSignVerifyOptions checks operation correctness, boundaries and error handling.
func TestSignVerifyOptions(t *testing.T) {
	for _, alg := range []string{"RSA", "EC"} {
		t.Run(alg, func(t *testing.T) {
			cert, key := operationIdentity(t, alg)
			roots := x509.NewStore()
			defer roots.Close()
			if err := roots.AddCert(cert); err != nil {
				t.Fatal(err)
			}
			for _, detached := range []bool{false, true} {
				for _, message := range [][]byte{[]byte("binary\x00\r\nline\n"), {}} {
					der, err := Sign(message, &SignOptions{SignerCert: cert, SignerKey: key, Detached: detached})
					if err != nil {
						t.Fatal(err)
					}
					opts := &VerifyOptions{Roots: roots}
					if detached {
						opts.DetachedContent = message
					}
					result, err := Verify(MarshalPEM(der), opts)
					if err != nil {
						t.Fatal(err)
					}
					if !result.TrustVerified || len(result.Signers) != 1 || !bytes.Equal(result.Content, message) {
						t.Fatalf("bad verified result %+v", result)
					}
					if err := result.Close(); err != nil {
						t.Fatal(err)
					}
					if err := result.Close(); err != nil {
						t.Fatal(err)
					}
					if result, err := Verify(der, nil); err == nil || result != nil {
						t.Fatal("implicit trust accepted")
					}
					empty := x509.NewStore()
					opts.Roots = empty
					result, err = Verify(der, opts)
					empty.Close()
					if err == nil || result != nil {
						t.Fatal("untrusted signer accepted")
					}
					opts.SignatureOnly = true
					result, err = Verify(der, opts)
					if err != nil {
						t.Fatal(err)
					}
					if result.TrustVerified {
						t.Fatal("signature only trusted")
					}
					result.Close()
					corrupt := append([]byte(nil), der...)
					corrupt[len(corrupt)-1] ^= 1
					if result, err := Verify(corrupt, opts); err == nil || result != nil {
						t.Fatal("corrupted signature accepted")
					}
					if detached {
						opts.DetachedContent = nil
						if result, err := Verify(der, opts); err == nil || result != nil {
							t.Fatal("missing detached content accepted")
						}
						opts.DetachedContent = []byte("different")
						if result, err := Verify(der, opts); err == nil || result != nil {
							t.Fatal("wrong detached content accepted")
						}
					}
				}
			}
		})
	}
}

// TestEnvelopeRecipients 验证相关操作的正确性、边界与错误处理。
//
// TestEnvelopeRecipients checks operation correctness, boundaries and error handling.
func TestEnvelopeRecipients(t *testing.T) {
	first, key := operationIdentity(t, "RSA")
	second, key2 := operationIdentity(t, "RSA")
	wrong, wrongKey := operationIdentity(t, "RSA")
	for _, cipher := range []string{"", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "DES-EDE3-CBC"} {
		for _, data := range [][]byte{[]byte("envelope\x00\r\n\xff"), {}} {
			der, err := Encrypt(data, &EncryptOptions{Recipients: []*x509.Certificate{first, second}, Cipher: cipher})
			if err != nil {
				t.Fatal(err)
			}
			for _, opts := range []*DecryptOptions{{first, key}, {second, key2}} {
				got, err := Decrypt(MarshalPEM(der), opts)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("decrypt: %x %v", got, err)
				}
			}
			if got, err := Decrypt(der, &DecryptOptions{wrong, wrongKey}); err == nil || got != nil {
				t.Fatal("wrong recipient accepted")
			}
			if got, err := Decrypt(der, &DecryptOptions{first, wrongKey}); err == nil || got != nil {
				t.Fatal("mismatched key accepted")
			}
		}
	}
}

// TestOperationErrors 验证相关操作的正确性、边界与错误处理。
//
// TestOperationErrors checks operation correctness, boundaries and error handling.
func TestOperationErrors(t *testing.T) {
	rsa, key := operationIdentity(t, "RSA")
	ec, _ := operationIdentity(t, "EC")
	sm2, smkey := operationIdentity(t, "SM2")
	if _, err := Sign(nil, nil); err == nil {
		t.Fatal("nil signing options")
	}
	if _, err := Encrypt(nil, nil); err == nil {
		t.Fatal("nil encrypt options")
	}
	if _, err := Decrypt(nil, nil); err == nil {
		t.Fatal("nil decrypt options")
	}
	if _, err := Sign(nil, &SignOptions{SignerCert: sm2, SignerKey: smkey}); err == nil {
		t.Fatal("SM2 signature accepted")
	}
	if _, err := Sign(nil, &SignOptions{SignerCert: rsa, SignerKey: key, Digest: "missing"}); err == nil {
		t.Fatal("bad digest accepted")
	}
	for _, recipients := range [][]*x509.Certificate{nil, {nil}, {ec}, {sm2}} {
		if _, err := Encrypt(nil, &EncryptOptions{Recipients: recipients}); err == nil {
			t.Fatal("bad recipients accepted")
		}
	}
	if _, err := Encrypt(nil, &EncryptOptions{Recipients: []*x509.Certificate{rsa}, Cipher: "AES-256-GCM"}); err == nil {
		t.Fatal("unsupported cipher accepted")
	}
	bag, err := Build([]*x509.Certificate{rsa})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Verify(bag, &VerifyOptions{SignatureOnly: true}); err == nil || result != nil {
		t.Fatal("certificate bag verified")
	}
	for _, data := range [][]byte{nil, []byte("invalid"), append(bag, 0), bytes.Replace(MarshalPEM(bag), []byte("PKCS7"), []byte("CERTIFICATE"), -1)} {
		if result, err := Verify(data, &VerifyOptions{SignatureOnly: true}); err == nil || result != nil {
			t.Fatal("malformed container verified")
		}
	}
}

// BenchmarkSignPKCS7 验证相关操作的正确性、边界与错误处理。
//
// BenchmarkSignPKCS7 checks operation correctness, boundaries and error handling.
func BenchmarkSignPKCS7(b *testing.B) {
	key, err := asym.GenerateRSA(2048)
	if err != nil {
		b.Fatal(err)
	}
	defer asym.Close(key)
	name := x509.NewName().Add("CN", "bench")
	cert, err := x509.CreateSelfSigned(name, 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), key.Public(), key)
	if err != nil {
		b.Fatal(err)
	}
	defer cert.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign([]byte("bench"), &SignOptions{SignerCert: cert, SignerKey: key}); err != nil {
			b.Fatal(err)
		}
	}
}
