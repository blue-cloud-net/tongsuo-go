package ecdsa_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdsa"
)

// ExampleGenerateKey 演示生成 NIST P-256 ECDSA 私钥。
//
// 曲线名通过铜锁 EVP_PKEY 表达，常用值："prime256v1" / "secp384r1" / "secp521r1"。
// 推荐曲线 P-256 及以上。
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
func ExamplePrivateKey_publicPEM() {
	priv, _ := ecdsa.GenerateKey("prime256v1")
	pem, err := priv.Public().MarshalPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pem[:26]))
	// Output: -----BEGIN PUBLIC KEY-----
}
