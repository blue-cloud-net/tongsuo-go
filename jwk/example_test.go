package jwk_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/jwk"
)

// ExampleMarshalKey 演示 asym 私钥 → JWK。
// 输入为 asym.PrivateKey / asym.PublicKey（SM2 / RSA / EC 等）；输出遵循
// RFC 7517 / 7518。
// 注意：JWK 文本本身不含加密 / MAC 保护，禁止在公开信道传输私钥 JWK。
//
// ExampleMarshalKey shows converting an asym private key into a JWK.
// The input is an asym.PrivateKey / asym.PublicKey (SM2 / RSA / EC …); the output
// follows RFC 7517 / 7518. Note that a private JWK has no integrity or
// confidentiality protection and must not be sent over an untrusted channel.
func ExampleMarshalKey() {
	priv, _ := asym.GenerateRSA(2048)
	defer func() { _ = asym.Close(priv) }()

	key, err := jwk.MarshalKey(priv)
	if err != nil {
		panic(err)
	}
	fmt.Println(key.Kty)
	// Output: RSA
}

// ExampleFromPEM 演示 JWK JSON → 内部 Key 结构。
// 解析后再用 ToPEM / ToPublicPEM 转回 PEM，与铜锁 / OpenSSL 互通。
//
// ExampleFromPEM shows parsing JWK JSON back into a Key.
// After parsing, ToPEM / ToPublicPEM can round-trip back to PEM, interoperable with Tongsuo and OpenSSL.
func ExampleFromPEM() {
	priv, _ := asym.GenerateRSA(2048)
	defer func() { _ = asym.Close(priv) }()
	jwkBytes, err := jwk.MarshalKey(priv)
	if err != nil {
		panic(err)
	}
	data, err := jwkBytes.MarshalJSON()
	if err != nil {
		panic(err)
	}

	loaded, err := jwk.Parse(data)
	if err != nil {
		panic(err)
	}
	fmt.Println(loaded.Kty)
	// Output: RSA
}

// ExampleKey_ToPublicPEM 演示 JWK 公钥提取并转 SPKI PEM。
// 从私钥 JWK 中剥离私钥字段（d/p/q/dp/dq/qi）并导出 SubjectPublicKeyInfo PEM。
//
// ExampleKey_ToPublicPEM shows extracting the public key from a private JWK and exporting it as SPKI PEM.
// Private fields (d/p/q/dp/dq/qi) are stripped before the SubjectPublicKeyInfo PEM is produced.
func ExampleKey_ToPublicPEM() {
	priv, _ := asym.GenerateRSA(2048)
	defer func() { _ = asym.Close(priv) }()
	jwkBytes, _ := jwk.MarshalKey(priv)

	pem, err := jwkBytes.ToPublicPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pem[:26]))
	// Output: -----BEGIN PUBLIC KEY-----
}
