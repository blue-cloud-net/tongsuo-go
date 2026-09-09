// Package ecdh 的外部可执行示例。
package ecdh_test

import (
	"bytes"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdh"
)

// ExampleCurve_GenerateKey 演示 P-256 ECDH 密钥对生成与公钥 PEM 导出。
//
// ExampleCurve_GenerateKey demonstrates P-256 ECDH key pair generation
// and public-key PEM export.
func ExampleCurve_GenerateKey() {
	priv, err := ecdh.P256().GenerateKey()
	if err != nil {
		panic(err)
	}
	pb, err := priv.Public().MarshalPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pb[:27]))
	// Output: -----BEGIN PUBLIC KEY-----
}

// ExamplePrivateKey_ECDH 演示双方在 P-256 上派生出一致的共享密钥。
//
// ExamplePrivateKey_ECDH shows both sides deriving the same shared
// secret on P-256.
func ExamplePrivateKey_ECDH() {
	alice, _ := ecdh.P256().GenerateKey()
	bob, _ := ecdh.P256().GenerateKey()

	sa, err := alice.ECDH(bob.Public())
	if err != nil {
		panic(err)
	}
	sb, err := bob.ECDH(alice.Public())
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.Equal(sa, sb), len(sa))
	// Output: true 32
}
