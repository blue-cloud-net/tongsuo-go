package pkcs12_test

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/pkcs/pkcs12"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ExamplePack 演示把证书 + 私钥 + CA 链打包为 PKCS#12（DER）。
//
// 浏览器与操作系统用此格式导入/导出客户端身份（.p12 / .pfx）。
// 安全注意：PKCS#12 文件本身不对内容加密（仅 MAC），所有数据依赖口令加密；
// 选择高熵口令并妥善保管。
func ExamplePack() {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)

	p12, err := pkcs12.Pack(cert, priv, nil, "password", "my-identity")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(p12) > 0)
	// Output: true
}

// ExampleParse 演示从 DER 解析 PKCS#12。
//
// 返回的 Bundle 包含 PrivateKey（核心 PKey）、Certificate 主证书、CACerts CA 链。
func ExampleParse() {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)

	p12, _ := pkcs12.Pack(cert, priv, nil, "password", "")

	bundle, err := pkcs12.Parse(p12, "password")
	if err != nil {
		panic(err)
	}
	fmt.Println(bundle.Certificate.Subject())
	// Output: example.com
}

// ExampleChangePassword 演示修改 PKCS#12 口令（输入输出均为 DER）。
func ExampleChangePassword() {
	priv, _ := sm2.GenerateKey()
	now := time.Now()
	subject := x509.NewName().Add("CN", "example.com")
	cert, _ := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)

	p12, _ := pkcs12.Pack(cert, priv, nil, "old", "")

	newP12, err := pkcs12.ChangePassword(p12, "old", "new")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(newP12) > 0)
	// Output: true
}
