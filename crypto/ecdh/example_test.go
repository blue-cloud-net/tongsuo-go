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

// ExampleX25519 演示 OKP 曲线 X25519 上的共享密钥派生（32 字节）。
//
// ExampleX25519 demonstrates shared-secret derivation on the OKP X25519
// curve (32-byte secret).
func ExampleX25519() {
	alice, err := ecdh.X25519().GenerateKey()
	if err != nil {
		panic(err)
	}
	bob, err := ecdh.X25519().GenerateKey()
	if err != nil {
		panic(err)
	}

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

// ExampleX448 演示 OKP 曲线 X448 上的共享密钥派生（56 字节）。
//
// 需要运行时铜锁 provider 支持 X448（OpenSSL 3.x 默认支持）；provider 不支持时
// 本示例会失败，相关能力测试（`TestX448Roundtrip` 等）则按设计跳过。
//
// ExampleX448 demonstrates shared-secret derivation on the OKP X448 curve
// (56-byte secret).
//
// It requires a runtime Tongsuo provider with X448 support (enabled by
// default in OpenSSL 3.x); on a build without X448 this example fails, while
// capability tests such as TestX448Roundtrip skip by design.
func ExampleX448() {
	alice, err := ecdh.X448().GenerateKey()
	if err != nil {
		panic(err)
	}
	bob, err := ecdh.X448().GenerateKey()
	if err != nil {
		panic(err)
	}

	sa, err := alice.ECDH(bob.Public())
	if err != nil {
		panic(err)
	}
	sb, err := bob.ECDH(alice.Public())
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.Equal(sa, sb), len(sa))
	// Output: true 56
}
