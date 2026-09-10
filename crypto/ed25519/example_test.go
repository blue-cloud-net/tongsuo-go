// Package ed25519 的外部可执行示例（不参与 go test 默认 lint）。
package ed25519_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ed25519"
)

// ExampleGenerateKey 演示 Ed25519 密钥生成。
//
// ExampleGenerateKey demonstrates Ed25519 key generation.
func ExampleGenerateKey() {
	priv, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub, _ := priv.Public()
	pb, _ := pub.MarshalPEM()
	fmt.Println(string(pb[:27]))
	// Output: -----BEGIN PUBLIC KEY-----
}

// ExampleSign 演示 Ed25519 签名 + 验签全流程。
//
// ExampleSign demonstrates the full Ed25519 sign / verify round trip.
func ExampleSign() {
	priv, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub, _ := priv.Public()

	msg := []byte("hello ed25519 example")
	sig, err := ed25519.Sign(priv, msg)
	if err != nil {
		panic(err)
	}
	if err := ed25519.Verify(pub, msg, sig); err != nil {
		panic(err)
	}
	fmt.Println(ed25519.Verify(pub, msg, sig))
	// Output: <nil>
}

// ExamplePrivateKey_publicPEM 演示从 PEM 加载私钥并导出公钥 PEM。
//
// ExamplePrivateKey_publicPEM shows loading a private key from PEM and
// exporting the matching public key as PEM.
func ExamplePrivateKey_publicPEM() {
	priv, _ := ed25519.GenerateKey()
	p8, _ := priv.MarshalPEM()
	priv2, err := ed25519.LoadPrivateKeyPEM(p8)
	if err != nil {
		panic(err)
	}
	pub, _ := priv2.Public()
	pb, _ := pub.MarshalPEM()
	fmt.Println(string(pb[:27]))
	// Output: -----BEGIN PUBLIC KEY-----
}