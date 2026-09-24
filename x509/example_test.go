package x509_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ExampleCreateCertificate 演示创建一张自签 SM2 证书。
//
// subject 与 signer 主题相同即为自签；返回的证书可调用 MarshalPEM 导出，
// 并用 Verify 自验签。
//
// ExampleCreateCertificate demonstrates creating a self-signed SM2 certificate.
//
// Using the same subject name for both subject and signer yields a self-signed certificate. The returned certificate can be exported with MarshalPEM and self-verified with Verify.
func ExampleCreateCertificate() {
	priv, _ := sm2.GenerateKey()
	now := time.Now()

	subject := x509.NewName().Add("CN", "example.com").Add("O", "Example Org").Add("C", "CN")
	cert, err := x509.CreateCertificate(
		subject, subject, 1001,
		now.Add(-time.Hour), now.Add(365*24*time.Hour),
		priv.Public(), priv,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(cert.Subject())
	fmt.Println(cert.Issuer())
	fmt.Println(cert.IsCA())
	// Output:
	// example.com
	// example.com
	// false
}

// ExampleCertificate_Fingerprint 演示计算证书指纹。
//
// alg 支持 sha1 / sha256 / sm3 / md5 / sha384 / sha512。
//
// ExampleCertificate_Fingerprint demonstrates computing a certificate fingerprint.
//
// The alg parameter accepts sha1, sha256, sm3, md5, sha384, and sha512.
func ExampleCertificate_Fingerprint() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		time.Now(), time.Now().Add(time.Hour), priv.Public(), priv)

	fp, err := cert.Fingerprint("sha256")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(fp)) // 64 hex chars = 32 bytes
	// Output: 64
}

// ExampleCertificate_MarshalPEM 演示证书 PEM 往返。
//
// ExampleCertificate_MarshalPEM demonstrates a PEM round trip for a certificate.
func ExampleCertificate_MarshalPEM() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		time.Now(), time.Now().Add(time.Hour), priv.Public(), priv)

	pem, err := cert.MarshalPEM()
	if err != nil {
		panic(err)
	}
	loaded, err := x509.LoadCertificatePEM(pem)
	if err != nil {
		panic(err)
	}
	fmt.Println(loaded.Subject())
	// Output: example.com
}

// ExampleNewCertificateRequest 演示生成 CSR 并校验签名。
//
// ExampleNewCertificateRequest demonstrates generating a CSR and verifying its signature.
func ExampleNewCertificateRequest() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com").Add("O", "Example Org")

	csr, err := x509.NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	fmt.Println(csr.SubjectName().String())
	// Output: /O=Example Org/CN=example.com
}

// ExampleCreateSelfSigned 演示一步生成自签证书（等价 `openssl req -x509`）。
//
// 与 CreateCertificate 的差异：issuer 自动取 subject；自动补 SKID / AKID；
// pub / signer 使用 asym 接口，生成密钥也更省事。
//
// ExampleCreateSelfSigned demonstrates building a self-signed certificate in one
// call (the equivalent of `openssl req -x509`).
//
// Unlike CreateCertificate it derives the issuer from subject, adds the SKID and
// AKID extensions automatically, and takes asym interfaces for pub / signer.
func ExampleCreateSelfSigned() {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		panic(err)
	}
	defer func() { _ = asym.Close(priv) }()

	now := time.Now()
	subject := x509.NewName().Add("CN", "self.example.com").Add("O", "Example Org")
	cert, err := x509.CreateSelfSigned(subject, 1001,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	defer func() { _ = cert.Close() }()

	fmt.Println(cert.Subject())
	fmt.Println(cert.SubjectText() == cert.IssuerText())
	fmt.Println(len(cert.SubjectKeyID()) > 0, len(cert.AuthorityKeyID()) > 0)
	// Output:
	// self.example.com
	// true
	// true true
}
