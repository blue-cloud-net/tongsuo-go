package ecdsa_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdsa"
)
// ExampleGenerateKey 演示生成 NIST P-256 ECDSA 私钥。
//
// 曲线名通过铜锁 EVP_PKEY 表达，常用值："prime256v1" / "secp384r1" / "secp521r1"。
// 推荐曲线 P-256 及以上。
//
// ExampleGenerateKey demonstrates generating a NIST P-256 ECDSA private
// key.
//
// Curve names are forwarded to Tongsuo EVP_PKEY; common values are
// "prime256v1" / "secp384r1" / "secp521r1". P-256 or stronger is
// recommended for new protocols.
func ExampleGenerateKey() {
	priv, err := ecdsa.GenerateKey("prime256v1")
	if err != nil {
		panic(err)
	}
	pem, err := priv.MarshalPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pem[:27]))
	// Output: -----BEGIN PRIVATE KEY-----
}
// ExampleSign 演示 ECDSA 签名与验签（ASN.1 DER）。
//
// 摘要为 SHA-256（铜锁侧强制 ECDSA-SHA256）。
// Sign 返回的签名采用 ASN.1 DER 编码，正是 Verify 期望的输入格式。
//
// ExampleSign demonstrates ECDSA sign and verify with ASN.1 DER output.
//
// The digest is fixed to SHA-256 on the Tongsuo side (i.e. ECDSA-SHA256).
// The signature returned by Sign is ASN.1 DER encoded and is exactly
// what Verify expects to consume.
func ExampleSign() {
	priv, _ := ecdsa.GenerateKey("prime256v1")
	msg := []byte("hello ECDSA")

	sig, err := ecdsa.Sign(priv, msg)
	if err != nil {
		panic(err)
	}
	fmt.Println(ecdsa.Verify(priv.Public(), msg, sig))
	// Output: <nil>
}
// ExamplePrivateKey_publicPEM 演示导出公钥 PEM。
// 将 ECDSA 公钥导出为 SubjectPublicKeyInfo PEM 块（"-----BEGIN PUBLIC KEY-----"）。
//
// ExamplePrivateKey_publicPEM demonstrates exporting an ECDSA public key
// as a SubjectPublicKeyInfo PEM block ("-----BEGIN PUBLIC KEY-----").
func ExamplePrivateKey_publicPEM() {
	priv, _ := ecdsa.GenerateKey("prime256v1")
	pem, err := priv.Public().MarshalPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pem[:26]))
	// Output: -----BEGIN PUBLIC KEY-----
}
