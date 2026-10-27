package x509_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
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
	priv, _ := asym.GenerateSM2()
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
	priv, _ := asym.GenerateSM2()
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
	priv, _ := asym.GenerateSM2()
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

// ExampleCertificate_AddExtensionByName 演示按名字添加任意 X.509 扩展。
//
// name 支持扩展短名与点分 OID，内部经 OBJ_txt2nid 解析，无需事先知道 NID 数值。
// subjectAltName 属于可重复 OID：多次调用会把新值合并进同一条目，而不是产生
// 第二个扩展条目。Sign 之后证书不可变，任何 Set* / Add* 调用都会返回错误。
//
// ExampleCertificate_AddExtensionByName demonstrates adding an arbitrary X.509
// extension by name.
//
// name accepts an extension short name or a dotted OID and is resolved through
// OBJ_txt2nid, so callers need not know the numeric NID. subjectAltName is a
// repeatable OID: repeated calls merge the new values into the single existing
// entry rather than producing a second extension entry. The certificate becomes
// immutable after Sign, and any Set* / Add* call then returns an error.
func ExampleCertificate_AddExtensionByName() {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	subject := x509.NewName().Add("CN", "ext.example.com")

	cert := x509.NewCertificate()
	_ = cert.SetVersion(2) // v3
	_ = cert.SetSerial(2002)
	_ = cert.SetIssuer(subject)
	_ = cert.SetSubject(subject)
	_ = cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour))
	_ = cert.SetPublicKey(priv.Public())

	// 按短名添加
	_ = cert.AddExtensionByName("extendedKeyUsage", "serverAuth,clientAuth")
	// 按点分 OID 添加（2.5.29.15 = keyUsage）
	_ = cert.AddExtensionByName("2.5.29.15", "critical,digitalSignature")
	// 重复的 SAN 会被合并进同一条目
	_ = cert.AddExtensionByName("subjectAltName", "DNS:ext.example.com")
	_ = cert.AddExtensionByName("subjectAltName", "DNS:www.ext.example.com")

	fmt.Println(cert.ExtendedKeyUsage())
	fmt.Println(cert.KeyUsage())
	fmt.Println(cert.SAN())

	_ = cert.Sign(priv)
	// 签名之后证书不可变
	fmt.Println(cert.AddKeyUsage("keyEncipherment") != nil)
	fmt.Println(cert.VerifyHostname("www.ext.example.com"))
	// Output:
	// [serverAuth clientAuth]
	// [digitalSignature]
	// [DNS:ext.example.com DNS:www.ext.example.com]
	// true
	// <nil>
}

// ExampleNewCertificateRequest 演示生成 CSR 并校验签名。
//
// ExampleNewCertificateRequest demonstrates generating a CSR and verifying its signature.
func ExampleNewCertificateRequest() {
	priv, _ := asym.GenerateSM2()
	subject := x509.NewName().Add("CN", "example.com").Add("O", "Example Org")

	csr, err := x509.NewCertificateRequest(subject, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	fmt.Println(csr.SubjectName().String())
	// Output: /CN=example.com/O=Example Org
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

// ExampleNewCRLBuilder 演示分步构建并签发 CRL（等价 `openssl ca -gencrl`）。
//
// 构建器自动取 CA 证书的 subject 作为 CRL 签发者并补齐 AKID；签发后句柄转移给
// 返回的 *CRL，构建器随之失效。CRL 的 issuer / 签名 / 到期状态本身在链验证之外，
// 使用前请先用 CRL.Verify 建立信任（见 RevocationCheck 的信任前提说明）。
//
// ExampleNewCRLBuilder demonstrates building and signing a CRL step by step
// (the equivalent of `openssl ca -gencrl`).
//
// The builder takes the CA certificate's subject as the CRL issuer and adds the
// AKID automatically; after signing, ownership of the handle moves to the
// returned *CRL and the builder expires. A CRL's issuer, signature and expiry
// are outside chain validation, so establish trust with CRL.Verify first (see
// the trust precondition documented on RevocationCheck).
func ExampleNewCRLBuilder() {
	priv, err := asym.GenerateSM2()
	if err != nil {
		panic(err)
	}
	defer func() { _ = asym.Close(priv) }()

	now := time.Now()
	ca, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "Example CA"),
		1, now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	defer func() { _ = ca.Close() }()

	b, err := x509.NewCRLBuilder(ca)
	if err != nil {
		panic(err)
	}
	defer func() { _ = b.Close() }()
	if err := b.SetNumber(12); err != nil {
		panic(err)
	}
	if err := b.SetThisUpdate(now.Add(-time.Minute)); err != nil {
		panic(err)
	}
	if err := b.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		panic(err)
	}
	if err := b.Revoke(ca, now, x509.ReasonKeyCompromise); err != nil {
		panic(err)
	}

	crl, err := b.Sign(priv)
	if err != nil {
		panic(err)
	}
	defer func() { _ = crl.Close() }()

	for _, e := range crl.RevokedEntries() {
		fmt.Printf("serial=%d reason=%s\n", e.Serial, e.Reason)
	}
	fmt.Println("number:", crl.Number())
	fmt.Println("verify:", crl.Verify(ca) == nil)
	// Output:
	// serial=1 reason=keyCompromise
	// number: 12
	// verify: true
}
