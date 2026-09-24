// Package main 演示 SM2 加解密与签名验签的最小可运行示例。
//
// 运行（examples 下每个示例都是独立 module）：
//
//	cd examples/sm2 && go run .
//
// Package main demonstrates a minimal runnable example covering SM2
// public-key encryption/decryption and signature/verification.
package main

import (
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/rand"
)

func main() {
	// 1. 生成 SM2 密钥对
	priv, err := asym.GenerateSM2()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("SM2 密钥对已生成")

	// 2. 加密与解密（ASN.1 DER 格式）
	plaintext := []byte("国密 SM2 加密示例：hello SM2!")
	ciphertext, err := asym.Encrypt(priv.Public(), plaintext)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := asym.Decrypt(priv, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("解密结果：%s\n", decrypted)

	// 3. 签名与验签（SM2withSM3，ASN.1 DER）
	msg := []byte("待签名消息")
	sig, err := asym.Sign(priv, msg)
	if err != nil {
		log.Fatal(err)
	}
	if err := asym.Verify(priv.Public(), msg, sig); err != nil {
		log.Fatalf("验签失败：%v", err)
	}
	fmt.Println("SM2withSM3 签名验签成功")

	// 4. PEM 往返
	privPEM, _ := priv.MarshalPrivateKeyPEM()
	pubPEM, _ := priv.Public().MarshalPublicKeyPEM()
	loaded, err := asym.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := asym.LoadPublicKeyPEM(pubPEM); err != nil {
		log.Fatal(err)
	}
	loadedPEM, _ := loaded.MarshalPrivateKeyPEM()
	fmt.Printf("PEM 往返成功，私钥长度 %d 字节\n", len(loadedPEM))

	// 5. 自定义 userId（默认是 GM/T 0003-2012 规定的 "1234567812345678"）
	customID := []byte("alice@example.com")
	sig2, err := asym.SignWithID(priv, msg, customID)
	if err != nil {
		log.Fatal(err)
	}
	// 验签时必须使用相同的 userId，否则失败
	if err := asym.VerifyWithID(priv.Public(), msg, sig2, customID); err != nil {
		log.Fatalf("userId 验签失败：%v", err)
	}
	fmt.Println("自定义 userId 签名验签成功")

	_ = rand.Read // 保留 import：签名/验签会用到安全随机源
}
