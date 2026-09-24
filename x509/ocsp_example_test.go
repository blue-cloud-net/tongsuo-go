package x509_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil/legacykeys/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ExampleCreateOCSPRequest 演示生成 OCSP 请求（DER）。
// 请求由 OCSP responder 接收并处理；本包不负责传输（应用层 HTTP POST）。
//
// ExampleCreateOCSPRequest demonstrates building an OCSP request
// (DER-encoded). The request is consumed by an OCSP responder; this
// package does not perform the HTTP transport — the application layer
// is expected to POST the DER bytes.
func ExampleCreateOCSPRequest() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		time.Now(), time.Now().Add(time.Hour), priv.Public(), priv)

	req, err := x509.CreateOCSPRequest(cert, cert, "sm3")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(req) > 0)
	// Output: true
}

// ExampleParseOCSPResponse 演示解析 OCSP 响应（DER）。
// 返回的 Response 包含响应级状态、目标证书状态、吊销时间/原因（如已吊销）、
// 响应内证书链（签名者）等。验证签名请用 Response.Verify 配合 x509.Store。
// 使用完毕需 defer resp.Close()。
//
// ExampleParseOCSPResponse demonstrates parsing an OCSP response (DER). The
// returned *Response exposes the response-level status, the target
// certificate status (with revocation time and reason when revoked),
// and the signer certificate chain embedded in the response. Use
// Response.Verify together with an x509.Store to check the signature,
// and call defer resp.Close() when done.
func ExampleParseOCSPResponse() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		time.Now(), time.Now().Add(time.Hour), priv.Public(), priv)

	// 仅演示解析结构；真实响应需由 OCSP responder 生成。
	// 这里直接构造一个空 DER 仅用于说明 API 形状。
	var raw []byte
	resp, err := x509.ParseOCSPResponse(raw, cert, cert)
	if err != nil {
		fmt.Println("parse err:", err)
		return
	}
	defer resp.Close()

	fmt.Println(resp.StatusText)
}
