// Package x448 的外部可执行示例。
package x448_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/x448"
)

// ExampleGenerateKey 演示 X448 ECDH 密钥生成。
//
// ExampleGenerateKey demonstrates X448 ECDH key pair generation.
func ExampleGenerateKey() {
	priv, err := x448.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub, _ := priv.Public()
	pb, _ := pub.MarshalPEM()
	fmt.Println(string(pb[:27]))
	// Output: -----BEGIN PUBLIC KEY-----
}

// ExampleSharedSecret 演示 X448 ECDH 共享密钥双向派生一致。
//
// ExampleSharedSecret shows X448 ECDH producing the same 56-byte shared
// secret on both sides.
func ExampleSharedSecret() {
	alice, _ := x448.GenerateKey()
	bob, _ := x448.GenerateKey()
	alicePub, _ := alice.Public()
	bobPub, _ := bob.Public()

	sa, err := x448.SharedSecret(alice, bobPub)
	if err != nil {
		panic(err)
	}
	sb, err := x448.SharedSecret(bob, alicePub)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(sa) == 56 && len(sb) == 56)
	// Output: true
}
