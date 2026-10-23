package x509_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ExampleCertificate_AddCertificatePolicies 演示为证书写入带 CPS 与
// userNotice 限定符的 certificatePolicies 扩展，并读回。
//
// 证书策略的 CPS / userNotice 限定符无法用 OpenSSL 的扩展配置串表达——
// 那个语法只认配置文件的 "@section" 形式——因此本库提供了类型化的入口。
//
// ExampleCertificate_AddCertificatePolicies demonstrates writing a
// certificatePolicies extension carrying CPS and userNotice qualifiers, and
// reading it back.
//
// The CPS / userNotice qualifiers of a certificate policy cannot be expressed
// with OpenSSL's extension configuration string — that syntax only accepts
// the "@section" form of a configuration file — so this library offers a
// typed entry point instead.
func ExampleCertificate_AddCertificatePolicies() {
	priv, _ := asym.GenerateSM2()
	now := time.Now()
	subject := x509.NewName().Add("CN", "policy.example.com")

	cert := x509.NewCertificate()
	_ = cert.SetVersion(2) // v3
	_ = cert.SetSerial(3003)
	_ = cert.SetIssuer(subject)
	_ = cert.SetSubject(subject)
	_ = cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour))
	_ = cert.SetPublicKey(priv.Public())

	err := cert.AddCertificatePolicies([]x509.CertificatePolicy{
		{
			OID:     "1.2.3.4",
			CPSURIs: []string{"http://cps.example.com/cps"},
			UserNotice: &x509.UserNotice{
				Organization:  "Example Org",
				NoticeNumbers: []int{1, 2},
				ExplicitText:  "This is a user notice",
			},
		},
	}, false)
	if err != nil {
		panic(err)
	}

	policies, err := cert.CertificatePolicies()
	if err != nil {
		panic(err)
	}
	for _, p := range policies {
		fmt.Println("policy:", p.OID)
		for _, u := range p.CPSURIs {
			fmt.Println("  cps:", u)
		}
		if p.UserNotice != nil {
			fmt.Println("  organization:", p.UserNotice.Organization)
			fmt.Println("  notice numbers:", p.UserNotice.NoticeNumbers)
			fmt.Println("  explicit text:", p.UserNotice.ExplicitText)
		}
	}
	// Output:
	// policy: 1.2.3.4
	//   cps: http://cps.example.com/cps
	//   organization: Example Org
	//   notice numbers: [1 2]
	//   explicit text: This is a user notice
}

// ExampleCertificateRequest_AddCertificatePolicies 演示为 CSR 写入
// certificatePolicies 扩展。
//
// 扩展在 Sign 之前即可读出，签名后 DER 中依然完整。
//
// ExampleCertificateRequest_AddCertificatePolicies demonstrates writing a
// certificatePolicies extension onto a CSR.
//
// The extension is readable before Sign and survives in the DER afterwards.
func ExampleCertificateRequest_AddCertificatePolicies() {
	priv, _ := asym.GenerateSM2()
	subject := x509.NewName().Add("CN", "policy-csr.example.com")

	req := x509.NewEmptyCertificateRequest()
	_ = req.SetSubject(subject)
	_ = req.SetPublicKey(priv.Public())

	err := req.AddCertificatePolicies([]x509.CertificatePolicy{
		{OID: "1.2.3.4", CPSURIs: []string{"http://cps.example.com/cps"}},
	}, false)
	if err != nil {
		panic(err)
	}

	policies, err := req.CertificatePolicies()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(policies))
	fmt.Println(policies[0].OID)
	fmt.Println(policies[0].CPSURIs[0])
	// Output:
	// 1
	// 1.2.3.4
	// http://cps.example.com/cps
}
