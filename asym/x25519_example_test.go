package asym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateX25519 演示生成 X25519 密钥对并读回原始公钥。
//
// X25519 只用于密钥协商，不具备签名能力；协商运算见 ecdh 包。
//
// ExampleGenerateX25519 generates an X25519 key pair and reads back the
// raw public key. X25519 is for key agreement only (no signing); the
// agreement operation lives in the ecdh package.
func ExampleGenerateX25519() {
	priv, err := asym.GenerateX25519()
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
	// Output: X25519 32
}

// ExampleGenerateKeyFromSeed_x25519 演示由 32 字节种子恢复 X25519 密钥对。
func ExampleGenerateKeyFromSeed_x25519() {
	// RFC 7748 §6.1 的 Alice 私钥标量
	seed := []byte{
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
		0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
	}
	priv, err := asym.GenerateKeyFromSeed(asym.AlgX25519, seed)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	raw, err := asym.RawPublicKey(priv.Public())
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	// RFC 7748 §6.1 期望的 Alice 公钥
	fmt.Printf("%x\n", raw)
	// Output: 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
}
