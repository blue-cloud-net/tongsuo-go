package pkcs7

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"testing"
)

// FuzzPKCS7EnvelopeRoundTrip 验证任意二进制内容经 RSA/AES 信封往返保持一致。
//
// FuzzPKCS7EnvelopeRoundTrip checks that arbitrary binary content survives an RSA/AES envelope round trip.
func FuzzPKCS7EnvelopeRoundTrip(f *testing.F) {
	cert, key := operationIdentity(f, "RSA")
	f.Add([]byte{})
	f.Add([]byte("binary\x00\r\n\xff"))
	f.Fuzz(func(t *testing.T, content []byte) {
		der, err := Encrypt(content, &EncryptOptions{Recipients: []*x509.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(der, &DecryptOptions{RecipientCert: cert, RecipientKey: key})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, content) {
			t.Fatal("envelope round trip changed content")
		}
	})
}
