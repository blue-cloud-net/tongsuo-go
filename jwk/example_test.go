package jwk_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	"github.com/blue-cloud-net/tongsuo-go/jwk"
)

// ExampleMarshal 演示 RSA PEM 私钥 → JWK。
//
// 输入须为各密钥类型私钥（或公钥）的 Key() 返回值，输出遵循 RFC 7517 / 7518。
// 注意：JWK 文本本身不含加密 / MAC 保护，禁止在公开信道传输私钥 JWK。
func ExampleMarshal() {
	priv, _ := rsa.GenerateKey(2048)

	key, err := jwk.Marshal(priv.Key())
	if err != nil {
		panic(err)
	}
	fmt.Println(key.Kty)
	// Output: RSA
}

// ExampleFromPEM 演示 JWK JSON → 内部 Key 结构。
//
// 解析后再用 ToPEM / ToPublicPEM 转回 PEM，与铜锁 / OpenSSL 互通。
func ExampleFromPEM() {
	priv, _ := rsa.GenerateKey(2048)
	jwkBytes, err := jwk.Marshal(priv.Key())
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
//
// 从私钥 JWK 中剥离私钥字段（d/p/q/dp/dq/qi）并导出 SubjectPublicKeyInfo PEM。
func ExampleKey_ToPublicPEM() {
	priv, _ := rsa.GenerateKey(2048)
	jwkBytes, _ := jwk.Marshal(priv.Key())

	pem, err := jwkBytes.ToPublicPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pem[:26]))
	// Output: -----BEGIN PUBLIC KEY-----
}
