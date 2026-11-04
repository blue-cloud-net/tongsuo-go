package x509_test

import (
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"math/big"
	"time"
)

// ExampleCertificate_AddExtensionDER 演示大序列号、原始 DER 扩展和签名前分步构建。
//
// ExampleCertificate_AddExtensionDER demonstrates a large serial, raw DER extensions and construction before signing.
func ExampleCertificate_AddExtensionDER() {
	key, err := asym.GenerateSM2()
	if err != nil {
		panic(err)
	}
	defer asym.Close(key)
	cert := x509.NewCertificate()
	defer cert.Close()
	name := x509.NewName().Add("CN", "stepwise")
	serial := new(big.Int).Lsh(big.NewInt(1), 100)
	for _, err := range []error{cert.SetVersion(2), cert.SetSerialBigInt(serial), cert.SetSubject(name), cert.SetIssuer(name), cert.SetPublicKey(key.Public()), cert.SetValidity(time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), cert.AddSubjectAltName("DNS:example.test"), cert.AddKeyUsage("digitalSignature"), cert.AddSubjectKeyID(), cert.AddAuthorityKeyID(cert), cert.AddExtensionDER("1.2.3.4.55", false, []byte{4, 3, 1, 2, 3}), cert.Sign(key), cert.Verify(key.Public())} {
		if err != nil {
			panic(err)
		}
	}
	got, err := cert.SerialBigInt()
	if err != nil {
		panic(err)
	}
	fmt.Println(got.Cmp(serial) == 0, cert.VerifyHostname("example.test") == nil)
	// Output: true true
}
