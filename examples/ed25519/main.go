// Package main 演示 Ed25519 签名 / 验签与 PEM 序列化的最小可运行示例。
//
// 运行（examples 下每个示例都是独立 module）：
//
//	cd examples/ed25519 && go run .
//
// Package main demonstrates a minimal runnable example for Ed25519
// signing / verification and PEM serialization.
package main

import (
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

func main() {
	// 1. 生成 Ed25519 签名密钥对
	priv, err := asym.GenerateEd25519()
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.Public()
	fmt.Println("Ed25519 密钥对已生成")

	// 2. 导出 32 字节原始公钥（与 Go 标准库 crypto/ed25519 等兼容）
	pubBytes, err := asym.RawPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("公钥字节（hex, 32B）: %x\n", pubBytes)

	// 3. 对消息进行签名（EdDSA 纯签名，无 SHA-256 预哈希）
	msg := []byte("hello ed25519 from tongsuo-go!")
	sig, err := asym.SignEd25519(priv, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("签名长度: %d 字节（Ed25519 固定 64B）\n", len(sig))

	// 4. 验签
	if err := asym.VerifyEd25519(pub, msg, sig); err != nil {
		log.Fatalf("verify failed: %v", err)
	}
	fmt.Println("验签成功")

	// 5. 篡改消息应验签失败
	if err := asym.VerifyEd25519(pub, []byte("tampered"), sig); err == nil {
		log.Fatal("tampered verify should fail")
	}
	fmt.Println("篡改消息正确拒绝")

	// 6. PEM 往返（PKCS#8 / SPKI）
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("私钥 PEM 头: %.32s...\n", privPEM)

	loaded, err := asym.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("从 PEM 重载成功，种子 hex: %x\n", seedHex(loaded))

	pubPEM, err := pub.MarshalPublicKeyPEM()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("公钥 PEM 头: %.32s...\n", pubPEM)
}

// seedHex 返回私钥种子的 hex（演示用；调用方应清零）。
//
// seedHex returns the hex form of the private key seed (demo only; the caller
// should zeroise it).
func seedHex(priv asym.PrivateKey) []byte {
	seed, err := asym.RawPrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	out := make([]byte, len(seed)*2)
	for i, b := range seed {
		const hexdigits = "0123456789abcdef"
		out[2*i] = hexdigits[b>>4]
		out[2*i+1] = hexdigits[b&0x0F]
	}
	return out
}
