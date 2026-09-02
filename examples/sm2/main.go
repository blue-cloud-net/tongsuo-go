// Package main 演示 SM2 加解密与签名验签的最小可运行示例。
//
// 运行：
//
//	TONGSUO_HOME=/opt/tongsuo LD_LIBRARY_PATH=${TONGSUO_HOME}/lib64 \
//	CGO_CFLAGS="-I${TONGSUO_HOME}/include" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib64" \
//	go run ./examples/sm2
//
// Package main demonstrates a minimal runnable example covering SM2
// public-key encryption/decryption and signature/verification.
package main

import (
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rand"
	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
)

func main() {
	// 1. 生成 SM2 密钥对
	priv, err := sm2.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("SM2 密钥对已生成")

	// 2. 加密与解密（ASN.1 DER 格式）
	plaintext := []byte("国密 SM2 加密示例：hello SM2!")
	ciphertext, err := sm2.Encrypt(priv.Public(), plaintext)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := sm2.Decrypt(priv, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("解密结果：%s\n", decrypted)

	// 3. 签名与验签（SM2withSM3，ASN.1 DER）
	msg := []byte("待签名消息")
	sig, err := sm2.Sign(priv, msg)
	if err != nil {
		log.Fatal(err)
	}
	if err := sm2.Verify(priv.Public(), msg, sig); err != nil {
		log.Fatalf("验签失败：%v", err)
	}
	fmt.Println("SM2withSM3 签名验签成功")

	// 4. PEM 往返
	privPEM, _ := priv.MarshalPEM()
	pubPEM, _ := priv.Public().MarshalPEM()
	loaded, err := sm2.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := sm2.LoadPublicKeyPEM(pubPEM); err != nil {
		log.Fatal(err)
	}
	loadedPEM, _ := loaded.MarshalPEM()
	fmt.Printf("PEM 往返成功，私钥长度 %d 字节\n", len(loadedPEM))

	// 5. 自定义 userId（默认是 GM/T 0003-2012 规定的 "1234567812345678"）
	customID := []byte("alice@example.com")
	sig2, err := sm2.SignWithID(priv, msg, customID)
	if err != nil {
		log.Fatal(err)
	}
	// 验签时必须使用相同的 userId，否则失败
	if err := sm2.VerifyWithID(priv.Public(), msg, sig2, customID); err != nil {
		log.Fatalf("userId 验签失败：%v", err)
	}
	fmt.Println("自定义 userId 签名验签成功")

	_ = rand.Read // 保留 import：签名/验签会用到安全随机源
}
