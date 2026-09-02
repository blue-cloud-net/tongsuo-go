package rsa_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
)
// ExampleGenerateKey 演示生成 2048 位 RSA 私钥。
//
// 推荐密钥长度 ≥ 2048 位；4096 位更安全但运算更慢。
//
// ExampleGenerateKey demonstrates generating a 2048-bit RSA private key.
//
// 2048 bits is the recommended minimum for new protocols (matching
// SP 800-131A / FIPS 186-4); 4096 bits is more conservative but
// significantly slower for both key generation and signature operations.
func ExampleGenerateKey() {
	priv, err := rsa.GenerateKey(2048)
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
// ExamplePrivateKey_SignPKCS1v15 演示 RSA PKCS#1 v1.5 签名与验签。
//
// PKCS#1 v1.5 是兼容性最广的签名方案；新协议推荐使用 PSS。
//
// ExamplePrivateKey_SignPKCS1v15 demonstrates RSA PKCS#1 v1.5 (RFC 8017)
// sign and verify with SHA-256 as the digest.
//
// PKCS#1 v1.5 has the broadest compatibility (TLS 1.2, JWT RS256, etc.);
// new protocols should prefer the more robust RSA-PSS via SignPSS.
func ExamplePrivateKey_SignPKCS1v15() {
	priv, _ := rsa.GenerateKey(2048)
	msg := []byte("hello RSA")

	sig, err := priv.SignPKCS1v15(msg)
	if err != nil {
		panic(err)
	}
	fmt.Println(priv.Public().VerifyPKCS1v15(msg, sig))
	// Output: <nil>
}
// ExamplePrivateKey_SignPSS 演示 RSA-PSS 签名与验签。
//
// saltLen 为盐长字节数；推荐 ≥ 32。
//
// ExamplePrivateKey_SignPSS demonstrates RSA-PSS (RFC 8017) sign and
// verify with SHA-256 as the digest.
//
// saltLen is the salt length in bytes; values ≥ 32 are recommended for
// new protocols (the OpenSSL negative-value conventions are also
// accepted by the underlying pipeline).
func ExamplePrivateKey_SignPSS() {
	priv, _ := rsa.GenerateKey(2048)
	msg := []byte("hello RSA-PSS")

	sig, err := priv.SignPSS(msg, 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(priv.Public().VerifyPSS(msg, sig, 32))
	// Output: <nil>
}
// ExampleEncryptOAEP 演示 RSA-OAEP 加密与解密。
//
// OAEP 是 PKCS#1 v2 中定义的安全填充，优于 PKCS#1 v1.5 加密。
//
// ExampleEncryptOAEP demonstrates RSA-OAEP (RFC 8017) public-key
// encryption with SHA-256 (passing nil for md selects the SHA-256
// default for both the OAEP encoding hash and MGF1).
//
// OAEP is the secure padding defined by PKCS#1 v2 (RFC 8017) and is
// strictly preferred over PKCS#1 v1.5 encryption, which suffers from
// Bleichenbacher padding-oracle attacks.
func ExampleEncryptOAEP() {
	priv, _ := rsa.GenerateKey(2048)
	msg := []byte("secret payload")

	ct, err := rsa.EncryptOAEP(priv.Public(), msg, nil)
	if err != nil {
		panic(err)
	}
	pt, err := rsa.DecryptOAEP(priv, ct, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pt))
	// Output: secret payload
}
// ExamplePrivateKey_MarshalPKCS1PEM 演示导出 PKCS#1 传统格式 PEM。
// 将 RSA 私钥导出为传统 PKCS#1 PEM 块（"-----BEGIN RSA PRIVATE KEY-----"）。
// 新协议应优先使用 MarshalPEM（PKCS#8）——本函数仅用于兼容只接受传统格式的工具。
//
// ExamplePrivateKey_MarshalPKCS1PEM demonstrates exporting an RSA private
// key as a legacy PKCS#1 PEM block ("-----BEGIN RSA PRIVATE KEY-----").
// New protocols should prefer MarshalPEM (PKCS#8) — this helper exists
// for compatibility with tools that only accept the traditional format.
func ExamplePrivateKey_MarshalPKCS1PEM() {
	priv, _ := rsa.GenerateKey(2048)
	pem, err := priv.MarshalPKCS1PEM()
	if err != nil {
		panic(err)
	}
	// Println 会附加 \n；pem 末尾也有 \n，最终输出末尾有两个 \n
	fmt.Println(string(pem[:len("-----BEGIN RSA PRIVATE KEY-----")]))
	// Output: -----BEGIN RSA PRIVATE KEY-----
}
