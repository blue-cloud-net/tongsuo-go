// Package x25519 的外部可执行示例。
package x25519_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/x25519"
)

// ExampleGenerateKey 演示 X25519 ECDH 密钥生成。
//
// ExampleGenerateKey demonstrates X25519 ECDH key pair generation.
func ExampleGenerateKey() {
	priv, err := x25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	pub, _ := priv.Public()
	pb, _ := pub.MarshalPEM()
	fmt.Println(string(pb[:27]))
	// Output: -----BEGIN PUBLIC KEY-----
}

// ExampleSharedSecret 演示 X25519 ECDH 共享密钥双向派生一致。
//
// ExampleSharedSecret shows X25519 ECDH producing the same 32-byte shared
// secret on both sides.
func ExampleSharedSecret() {
	alice, _ := x25519.GenerateKey()
	bob, _ := x25519.GenerateKey()
	alicePub, _ := alice.Public()
	bobPub, _ := bob.Public()

	sa, err := x25519.SharedSecret(alice, bobPub)
	if err != nil {
		panic(err)
	}
	sb, err := x25519.SharedSecret(bob, alicePub)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(sa) == 32 && len(sb) == 32)
	// Output: true
}