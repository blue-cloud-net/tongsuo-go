// Package ed448 的外部可执行示例。
package ed448_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ed448"
)

// ExampleGenerateKey 演示 Ed448 密钥生成。
//
// ExampleGenerateKey demonstrates Ed448 key generation.
func ExampleGenerateKey() {
	priv, err := ed448.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub, _ := priv.Public()
	pb, _ := pub.MarshalPEM()
	fmt.Println(string(pb[:27]))
	// Output: -----BEGIN PUBLIC KEY-----
}

// ExampleSign 演示 Ed448 签名 + 验签全流程。
//
// ExampleSign demonstrates the full Ed448 sign / verify round trip.
func ExampleSign() {
	priv, err := ed448.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub, _ := priv.Public()

	msg := []byte("hello ed448 example")
	sig, err := ed448.Sign(priv, msg)
	if err != nil {
		panic(err)
	}
	if err := ed448.Verify(pub, msg, sig); err != nil {
		panic(err)
	}
	fmt.Println(ed448.Verify(pub, msg, sig))
	// Output: <nil>
}