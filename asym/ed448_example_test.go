package asym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateEd448 演示生成 Ed448 密钥对。
func ExampleGenerateEd448() {
	priv, err := asym.GenerateEd448()
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(priv.Algorithm())
	// Output: ED448
}

// ExampleSignEd448 演示 Ed448 纯签名与验签往返（签名 114 字节）。
func ExampleSignEd448() {
	priv, _ := asym.GenerateEd448()
	msg := []byte("tongsuo-go ed448 example")

	sig, err := asym.SignEd448(priv, msg)
	if err != nil {
		fmt.Println("sign err:", err)
		return
	}
	if err := asym.VerifyEd448(priv.Public(), msg, sig); err != nil {
		fmt.Println("verify err:", err)
		return
	}
	fmt.Println(len(sig))
	// Output: 114
}

// ExampleGenerateKeyFromSeed_ed448 演示由 57 字节种子恢复 Ed448 密钥对。
func ExampleGenerateKeyFromSeed_ed448() {
	seed := make([]byte, 57) // 实际使用请填入高熵随机种子
	priv, err := asym.GenerateKeyFromSeed(asym.AlgEd448, seed)
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
	// Output: 57
}
