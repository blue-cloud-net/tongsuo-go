package ecdh_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

// ExampleCurves 列出本包支持的协商曲线。
func ExampleCurves() {
	for _, name := range ecdh.Curves() {
		fmt.Println(name)
	}
	// Output:
	// P-256
	// P-384
	// P-521
	// secp256k1
	// X25519
	// X448
}

// ExampleCurveByName 按名取曲线，支持大小写不敏感与 openssl 别名。
func ExampleCurveByName() {
	c, err := ecdh.CurveByName("prime256v1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(c.Name())
	// Output: P-256
}

// ExampleLoadPrivateKey 演示「asym 生成、ecdh 协商」的组合用法。
func ExampleLoadPrivateKey() {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		log.Fatal(err)
	}
	k, err := ecdh.LoadPrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(k.Curve().Name())
	// Output: P-256
}

// ExampleSharedSecret 用 RFC 7748 §6.1 的 X25519 标准向量演示双方协商。
func ExampleSharedSecret() {
	aliceRaw, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bobRaw, _ := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

	aliceAsym, err := asym.GenerateKeyFromSeed(asym.AlgX25519, aliceRaw)
	if err != nil {
		log.Fatal(err)
	}
	bobAsym, err := asym.GenerateKeyFromSeed(asym.AlgX25519, bobRaw)
	if err != nil {
		log.Fatal(err)
	}
	alice, err := ecdh.LoadPrivateKey(aliceAsym)
	if err != nil {
		log.Fatal(err)
	}
	bobPub, err := ecdh.LoadPublicKey(bobAsym.Public())
	if err != nil {
		log.Fatal(err)
	}

	shared, err := ecdh.SharedSecret(alice, bobPub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", shared)
	// Output:
	// 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
}
