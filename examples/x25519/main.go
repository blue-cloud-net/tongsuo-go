// Package main 演示 X25519 ECDH 共享密钥派生与原始字节互操作的最小可运行示例。
//
// 运行：
//
//	TONGSUO_HOME=/opt/tongsuo LD_LIBRARY_PATH=${TONGSUO_HOME}/lib64 \
//	CGO_CFLAGS="-I${TONGSUO_HOME}/include" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib64" \
//	go run ./examples/x25519
//
// Package main demonstrates a minimal runnable example for X25519
// ECDH shared-secret derivation and raw 32-byte byte interop.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/crypto/x25519"
)

func main() {
	// 1. 生成 X25519 密钥对
	alice, err := x25519.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := x25519.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	alicePub, err := alice.Public()
	if err != nil {
		log.Fatal(err)
	}
	bobPub, err := bob.Public()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Alice 与 Bob X25519 密钥对已生成")

	// 2. 双方各自派生 32 字节共享密钥
	aliceShared, err := x25519.SharedSecret(alice, bobPub)
	if err != nil {
		log.Fatal(err)
	}
	bobShared, err := x25519.SharedSecret(bob, alicePub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Alice 派生共享密钥 hex: %x\n", aliceShared)
	fmt.Printf("Bob   派生共享密钥 hex: %x\n", bobShared)
	if !bytes.Equal(aliceShared, bobShared) {
		log.Fatal("shared secrets differ!")
	}
	fmt.Println("双向派生一致 ✓")

	// 3. 原始 32B 字节互操作（与 Go 标准库 crypto/ecdh、WireGuard 等兼容）
	alicePrivBytes, err := alice.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	aliceFromBytes, err := x25519.PrivateKeyFromBytes(alicePrivBytes)
	if err != nil {
		log.Fatal(err)
	}
	aliceFromPub, err := aliceFromBytes.Public()
	if err != nil {
		log.Fatal(err)
	}
	alicePubPEM, err := alicePub.MarshalPEM()
	if err != nil {
		log.Fatal(err)
	}
	aliceFromPEM, err := x25519.LoadPublicKeyPEM(alicePubPEM)
	if err != nil {
		log.Fatal(err)
	}
	if !alicePub.Key().PublicEqual(aliceFromPub.Key()) || !alicePub.Key().PublicEqual(aliceFromPEM.Key()) {
		log.Fatal("raw bytes / PEM roundtrip mismatch")
	}
	fmt.Println("32B 原始字节 + PEM 互操作一致 ✓")
}