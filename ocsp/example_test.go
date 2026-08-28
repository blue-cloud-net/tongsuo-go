package ocsp_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/ocsp"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ExampleCreateRequest 演示生成 OCSP 请求（DER）。
//
// 请求由 OCSP responder 接收并处理；本包不负责传输（应用层 HTTP POST）。
func ExampleCreateRequest() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		time.Now(), time.Now().Add(time.Hour), priv.Public(), priv)

	req, err := ocsp.CreateRequest(cert, cert, "sm3")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(req) > 0)
	// Output: true
}

// ExampleParseResponse 演示解析 OCSP 响应（DER）。
//
// 返回的 Response 包含响应级状态、目标证书状态、吊销时间/原因（如已吊销）、
// 响应内证书链（签名者）等。验证签名请用 Response.Verify 配合 x509.Store。
func ExampleParseResponse() {
	priv, _ := sm2.GenerateKey()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		time.Now(), time.Now().Add(time.Hour), priv.Public(), priv)

	// 仅演示解析结构；真实响应需由 OCSP responder 生成。
	// 这里直接构造一个空 DER 仅用于说明 API 形状。
	var raw []byte
	resp, err := ocsp.ParseResponse(raw, cert, cert)
	if err != nil {
		fmt.Println("parse err:", err)
		return
	}
	defer resp.Close()

	fmt.Println(resp.StatusText)
}
