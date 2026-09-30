package asym_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateX448 演示生成 X448 密钥对并读回原始公钥。
//
// X448 只用于密钥协商，不具备签名能力；协商运算见 ecdh 包。
//
// ExampleGenerateX448 generates an X448 key pair and reads back the raw
// public key. X448 is for key agreement only (no signing); the agreement
// operation lives in the ecdh package.
func ExampleGenerateX448() {
	priv, err := asym.GenerateX448()
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	raw, err := asym.RawPublicKey(priv.Public())
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(priv.Algorithm(), len(raw))
	// Output: X448 56
}

// ExampleGenerateKeyFromSeed_x448 演示由 56 字节种子恢复 X448 密钥对，
// 并复现 RFC 7748 §6.2 的 Alice 公私钥对。
func ExampleGenerateKeyFromSeed_x448() {
	// RFC 7748 §6.2 的 Alice 私钥标量
	seed, err := hex.DecodeString("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d" +
		"d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
	if err != nil {
		fmt.Println("decode err:", err)
		return
	}
	priv, err := asym.GenerateKeyFromSeed(asym.AlgX448, seed)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	raw, err := asym.RawPublicKey(priv.Public())
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	// RFC 7748 §6.2 期望的 Alice 公钥
	fmt.Printf("%x\n", raw)
	// Output: 9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0
}
