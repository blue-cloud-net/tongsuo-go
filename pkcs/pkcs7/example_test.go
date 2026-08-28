package pkcs7_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/pkcs/pkcs7"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ExampleBuild 演示用证书集合构建 PKCS#7（DER）。
//
// 当前实现支持 Certs-only 类型——多个 X.509 证书的 DER 串接封装，常用扩展名 .p7b。
// 等价于 `openssl crl2pkcs7 -nocrl` 的输出。
func ExampleBuild() {
	// 生成两张自签证书模拟证书链
	caPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()

	now := time.Now()
	caName := x509.NewName().Add("CN", "Test CA")
	leafName := x509.NewName().Add("CN", "example.com")
	caCert, _ := x509.CreateCertificate(caName, caName, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), caPriv.Public(), caPriv)
	leafCert, _ := x509.CreateCertificate(leafName, caName, 2,
		now.Add(-time.Hour), now.Add(180*24*time.Hour), leafPriv.Public(), caPriv)

	der, err := pkcs7.Build([]*x509.Certificate{caCert, leafCert})
	if err != nil {
		panic(err)
	}
	fmt.Println(len(der) > 0)
	// Output: true
}

// ExampleMarshalPEM 演示 DER → PEM 转换。
func ExampleMarshalPEM() {
	pem := pkcs7.MarshalPEM([]byte{0x30, 0x00})
	fmt.Println(string(pem[:10]))
	// Output: -----BEGIN
}

// ExampleExtract 演示从 PEM 中提取证书。
func ExampleExtract() {
	// 用 Build 构造 DER 后转 PEM，再用 Extract 提取——形成完整往返
	caPriv, _ := sm2.GenerateKey()
	caName := x509.NewName().Add("CN", "Test CA")
	caCert, _ := x509.CreateCertificate(caName, caName, 1,
		time.Now(), time.Now().Add(time.Hour), caPriv.Public(), caPriv)

	der, _ := pkcs7.Build([]*x509.Certificate{caCert})
	pem := pkcs7.MarshalPEM(der)

	certs, err := pkcs7.Extract(pem)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(certs))
	// Output: 1
}
