// Package main 演示 X25519 ECDH 共享密钥派生与原始字节互操作的最小可运行示例。
//
// 运行（examples 下每个示例都是独立 module）：
//
//	cd examples/x25519 && go run .
//
// Package main demonstrates a minimal runnable example for X25519
// ECDH shared-secret derivation and raw 32-byte byte interop.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

func main() {
	// 1. 生成 X25519 密钥对（密钥生成在 asym 包）
	alice, err := asym.GenerateX25519()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := asym.GenerateX25519()
	if err != nil {
		log.Fatal(err)
	}
	alicePub := alice.Public()
	bobPub := bob.Public()
	fmt.Println("Alice 与 Bob X25519 密钥对已生成")

	// 2. 双方各自派生 32 字节共享密钥（协商在 ecdh 包）
	aliceECDH, err := ecdh.LoadPrivateKey(alice)
	if err != nil {
		log.Fatal(err)
	}
	bobECDH, err := ecdh.LoadPrivateKey(bob)
	if err != nil {
		log.Fatal(err)
	}
	aliceECDHPub, err := ecdh.LoadPublicKey(alicePub)
	if err != nil {
		log.Fatal(err)
	}
	bobECDHPub, err := ecdh.LoadPublicKey(bobPub)
	if err != nil {
		log.Fatal(err)
	}
	aliceShared, err := ecdh.SharedSecret(aliceECDH, bobECDHPub)
	if err != nil {
		log.Fatal(err)
	}
	bobShared, err := ecdh.SharedSecret(bobECDH, aliceECDHPub)
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
	alicePrivBytes, err := asym.RawPrivateKey(alice)
	if err != nil {
		log.Fatal(err)
	}
	aliceFromBytes, err := asym.GenerateKeyFromSeed(asym.AlgX25519, alicePrivBytes)
	if err != nil {
		log.Fatal(err)
	}
	alicePubPEM, err := alicePub.MarshalPublicKeyPEM()
	if err != nil {
		log.Fatal(err)
	}
	aliceFromPEM, err := asym.LoadPublicKeyPEM(alicePubPEM)
	if err != nil {
		log.Fatal(err)
	}
	// 用原始公钥字节比对（asym 不向外暴露底层句柄）
	want, err := asym.RawPublicKey(alicePub)
	if err != nil {
		log.Fatal(err)
	}
	gotBytes, err := asym.RawPublicKey(aliceFromBytes.Public())
	if err != nil {
		log.Fatal(err)
	}
	gotPEM, err := asym.RawPublicKey(aliceFromPEM)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(want, gotBytes) || !bytes.Equal(want, gotPEM) {
		log.Fatal("raw bytes / PEM roundtrip mismatch")
	}
	fmt.Println("32B 原始字节 + PEM 互操作一致 ✓")
}
