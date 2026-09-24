package asym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateEd25519 演示生成 Ed25519 密钥对并导出 PEM。
func ExampleGenerateEd25519() {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(priv.Algorithm())
	// Output: ED25519
}

// ExampleSignEd25519 演示 Ed25519 纯签名与验签往返。
func ExampleSignEd25519() {
	priv, _ := asym.GenerateEd25519()
	msg := []byte("tongsuo-go ed25519 example")

	sig, err := asym.SignEd25519(priv, msg)
	if err != nil {
		fmt.Println("sign err:", err)
		return
	}
	if err := asym.VerifyEd25519(priv.Public(), msg, sig); err != nil {
		fmt.Println("verify err:", err)
		return
	}
	fmt.Println(len(sig))
	// Output: 64
}

// ExampleGenerateKeyFromSeed 演示由 32 字节种子恢复 Ed25519 密钥对。
func ExampleGenerateKeyFromSeed() {
	seed := make([]byte, 32) // 实际使用请填入高熵随机种子
	priv, err := asym.GenerateKeyFromSeed(asym.AlgEd25519, seed)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	raw, err := asym.RawPublicKey(priv.Public())
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(len(raw))
	// Output: 32
}
