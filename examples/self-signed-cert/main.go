// Package main 演示使用 SM2 + SM3 自签证书的最小可运行示例。
//
// 运行：
//
//	TONGSUO_HOME=/opt/tongsuo LD_LIBRARY_PATH=${TONGSUO_HOME}/lib64 \
//	CGO_CFLAGS="-I${TONGSUO_HOME}/include" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib64" \
//	go run ./examples/self-signed-cert
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func main() {
	// 1. 生成 SM2 密钥对
	priv, err := sm2.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// 2. 构造主题（多字段）
	subject := x509.NewName().
		Add("CN", "example.com").
		Add("O", "Example Org").
		Add("C", "CN").
		Add("serialNumber", "1234567890")

	// 3. 创建自签证书
	now := time.Now()
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	cert, err := x509.CreateCertificate(
		subject, // 主题
		subject, // 签发者（自签：相同）
		1001,    // 序列号
		notBefore,
		notAfter,
		priv.Public(), // 公钥
		priv,          // 签名私钥
	)
	if err != nil {
		log.Fatal(err)
	}

	// 4. 自验签（自签证书用同一密钥验签）
	if err := cert.Verify(priv.Public()); err != nil {
		log.Fatalf("自签验签失败：%v", err)
	}
	fmt.Println("自签验签成功")

	// 5. 读取关键字段
	fmt.Printf("主题：%s\n", cert.Subject())
	fmt.Printf("签发者：%s\n", cert.Issuer())
	fmt.Printf("序列号：%d\n", cert.Serial())
	fmt.Printf("有效期：%s ~ %s\n",
		cert.NotBefore().Format(time.RFC3339),
		cert.NotAfter().Format(time.RFC3339))
	fmt.Printf("是否 CA：%v\n", cert.IsCA())
	fmt.Printf("公钥算法：%s\n", cert.CertificateType())

	// 6. 指纹（多种算法）
	for _, alg := range []string{"sm3", "sha256"} {
		fp, err := cert.Fingerprint(alg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s 指纹：%s\n", alg, fp)
	}

	// 7. PEM 导出与重新加载
	pem, err := cert.MarshalPEM()
	if err != nil {
		log.Fatal(err)
	}
	loaded, err := x509.LoadCertificatePEM(pem)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PEM 往返成功，加载主题：%s\n", loaded.Subject())

	// 8. 构建带 SAN / KeyUsage / EKU / SKID / AKID 的证书
	withExt := x509.NewCertificate()
	if err := withExt.SetVersion(2); err != nil { // v3
		log.Fatal(err)
	}
	if err := withExt.SetSerial(2002); err != nil {
		log.Fatal(err)
	}
	if err := withExt.SetSubject(subject); err != nil {
		log.Fatal(err)
	}
	if err := withExt.SetIssuer(subject); err != nil {
		log.Fatal(err)
	}
	if err := withExt.SetValidity(notBefore, notAfter); err != nil {
		log.Fatal(err)
	}
	if err := withExt.SetPublicKey(priv.Public()); err != nil {
		log.Fatal(err)
	}
	if err := withExt.AddBasicConstraints(false); err != nil {
		log.Fatal(err)
	}
	if err := withExt.AddSubjectAltName("DNS:example.com,DNS:www.example.com,IP:127.0.0.1"); err != nil {
		log.Fatal(err)
	}
	if err := withExt.AddKeyUsage("critical,digitalSignature,keyEncipherment"); err != nil {
		log.Fatal(err)
	}
	if err := withExt.AddExtendedKeyUsage("serverAuth,clientAuth"); err != nil {
		log.Fatal(err)
	}
	if err := withExt.AddSubjectKeyID(); err != nil {
		log.Fatal(err)
	}
	// 注：AddAuthorityKeyID 需要 issuer 证书的 SKID 先就位；
	// 一次性 CreateCertificate 路径下未自动生成，故此处省略 AKID。
	if err := withExt.Sign(priv); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("构建器证书 SAN：%v\n", withExt.SAN())
	fmt.Printf("构建器证书 KeyUsage：%v\n", withExt.KeyUsage())
	fmt.Printf("构建器证书 EKU：%v\n", withExt.ExtendedKeyUsage())
	fmt.Printf("构建器证书 SKID：%x\n", withExt.SubjectKeyID())
}
