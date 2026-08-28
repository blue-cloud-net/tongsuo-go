package aes_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/aes"
)

// ExampleNewCipher 演示使用 16 字节密钥构造 AES-128 cipher.Block。
//
// AES-256 用 32 字节密钥。
func ExampleNewCipher() {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	fmt.Println(block.BlockSize())
	// Output: 16
}

// ExampleNewGCM 演示 AES-GCM AEAD。
//
// GCM 提供认证加密：除密文外还输出 16 字节认证标签，可防篡改。
// 重要：相同 (key, nonce) 组合绝不可重用，否则将泄露明文并可伪造认证。
func ExampleNewGCM() {
	key := make([]byte, 16)
	nonce := make([]byte, aes.NonceSize) // 96 位 Nonce

	aead, err := aes.NewGCM(key)
	if err != nil {
		panic(err)
	}

	plaintext := []byte("secret message")
	aad := []byte("header-metadata")

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	fmt.Println(len(sealed))

	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(opened))
	// Output:
	// 30
	// secret message
}

// ExampleEncryptCBC 演示 AES-CBC 加密与解密（PKCS7 填充）。
//
// IV 必须唯一不可预测；推荐使用 crypto/rand 生成。
func ExampleEncryptCBC() {
	key := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)

	ct, err := aes.EncryptCBC(key, iv, []byte("hello AES-CBC"))
	if err != nil {
		panic(err)
	}
	out, err := aes.DecryptCBC(key, iv, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
	// Output: hello AES-CBC
}
