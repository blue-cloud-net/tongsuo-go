package asym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateRSA 演示生成 2048 位 RSA 密钥并导出 PEM。
func ExampleGenerateRSA() {
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	pem, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(string(pem[:27]) == "-----BEGIN PRIVATE KEY-----")
	// Output: true
}

// ExampleSignPKCS1v15 演示 RSA PKCS#1 v1.5 签名验签往返。
func ExampleSignPKCS1v15() {
	priv, _ := asym.GenerateRSA(2048)
	data := []byte("tongsuo-go rsa example")

	sig, err := asym.SignPKCS1v15(priv, data, "sha256")
	if err != nil {
		fmt.Println("sign err:", err)
		return
	}
	if err := asym.VerifyPKCS1v15(priv.Public(), data, sig, "sha256"); err != nil {
		fmt.Println("verify err:", err)
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// ExampleSignPSS 演示 RSA-PSS 签名（salt 长度按摘要长度）。
func ExampleSignPSS() {
	priv, _ := asym.GenerateRSA(2048)
	data := []byte("pss example")

	sig, err := asym.SignPSS(priv, data, asym.PSSSaltLenDigest, "sha256")
	if err != nil {
		fmt.Println("sign err:", err)
		return
	}
	if err := asym.VerifyPSS(priv.Public(), data, sig, asym.PSSSaltLenDigest, "sha256"); err != nil {
		fmt.Println("verify err:", err)
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// ExampleEncryptOAEP 演示 RSA-OAEP 加解密。
func ExampleEncryptOAEP() {
	priv, _ := asym.GenerateRSA(2048)
	data := []byte("oaep-message")

	ct, err := asym.EncryptOAEP(priv.Public(), data, "sha256")
	if err != nil {
		fmt.Println("encrypt err:", err)
		return
	}
	pt, err := asym.DecryptOAEP(priv, ct, "sha256")
	if err != nil {
		fmt.Println("decrypt err:", err)
		return
	}
	fmt.Println(string(pt))
	// Output: oaep-message
}
